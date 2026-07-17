use crate::pinning::PinnedFingerprintVerifier;
use crate::state::AppState;
use crate::types::{
    FileMeta, Peer, TransferDirection, TransferDoneEvent, TransferProgressEvent,
    TransferRequestPayload, TransferRequestResponse,
};
use futures_util::StreamExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tauri::Emitter;
use tauri_plugin_fs::{FilePath, FsExt, OpenOptions};
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

/// Opens a file the user picked, whether it's a regular filesystem path (desktop,
/// and most mobile pickers) or a `content://` URI (the only thing Android's file
/// picker hands back for items in the gallery/Downloads/etc, since scoped storage
/// forbids exposing a real path). Plain `tokio::fs`/`std::fs` cannot open the
/// latter at all — only the platform's ContentResolver can — which is what made
/// sending a photo or screenshot from Android fail before it ever reached the peer.
fn open_source(app: &tauri::AppHandle, path: &str) -> std::io::Result<tokio::fs::File> {
    let file_path: FilePath = path
        .parse()
        .expect("FilePath::from_str is infallible");
    let mut opts = OpenOptions::new();
    opts.read(true);
    let std_file = app.fs().open(file_path, opts)?;
    Ok(tokio::fs::File::from_std(std_file))
}

/// Best-effort filename for a picked source: the real file name for plain paths,
/// or the last URI segment for content/file URIs (Android rarely exposes the
/// original display name through the picker, only an opaque document id).
fn display_name(path: &str) -> String {
    match path.parse::<FilePath>() {
        Ok(FilePath::Path(p)) => p
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .filter(|n| !n.is_empty()),
        Ok(FilePath::Url(u)) => u
            .path_segments()
            .and_then(|mut s| s.next_back())
            .filter(|s| !s.is_empty())
            .map(percent_decode),
        Err(_) => None,
    }
    .unwrap_or_else(|| "fichier".to_string())
}

/// Decodes the `%XX` escapes in a single URI path segment, dependency-free.
/// Malformed escapes are left verbatim so a weird name never collapses to
/// something empty. Used for `file://` display names — a `photo%20final.jpg`
/// segment should reach the peer (and the user) as "photo final.jpg", not with
/// the literal `%20`. Android content URIs usually carry an opaque document id
/// here regardless, so this is a best-effort nicety for real filesystem URLs.
fn percent_decode(seg: &str) -> String {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = seg.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Reads until `buf` is full or EOF, returning how many bytes were filled. A
/// single `read` is allowed to return fewer bytes than requested (short reads
/// are legal and common on `content://` streams), which would otherwise make
/// signature sniffing miss a type it should have recognised.
async fn read_up_to(file: &mut tokio::fs::File, buf: &mut [u8]) -> usize {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]).await {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => break,
        }
    }
    filled
}

/// Formats the error a receiver returned (HTTP status + body) into a message
/// fit to show the user. The body is peer-controlled text, so it is stripped of
/// control characters and bounded before being surfaced.
fn peer_error(status: reqwest::StatusCode, body: &str) -> String {
    let detail: String = body
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    let code = status.as_u16();
    if detail.is_empty() {
        format!("le destinataire a refusé la demande (code {code})")
    } else {
        format!("{detail} (code {code})")
    }
}

/// Sniffs a handful of common file signatures from the first bytes of a file.
/// Android content URIs rarely carry a usable extension, so without this a
/// received screenshot would land with no extension and nothing would know
/// how to open it.
fn sniff_type(buf: &[u8]) -> Option<(&'static str, &'static str)> {
    if buf.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some(("png", "image/png"));
    }
    if buf.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some(("jpg", "image/jpeg"));
    }
    if buf.starts_with(b"GIF87a") || buf.starts_with(b"GIF89a") {
        return Some(("gif", "image/gif"));
    }
    if buf.len() >= 12 && &buf[0..4] == b"RIFF" && &buf[8..12] == b"WEBP" {
        return Some(("webp", "image/webp"));
    }
    if buf.starts_with(b"%PDF") {
        return Some(("pdf", "application/pdf"));
    }
    None
}

/// Builds a client that only trusts `expected_fingerprint` for this connection.
/// Peers use a self-signed certificate (no external CA on a LAN-only protocol),
/// so authenticity comes from pinning to the exact fingerprint last announced by
/// that peer over LAN discovery, rather than from chain-of-trust validation.
///
/// The connection also presents *our* certificate as a TLS client certificate:
/// the receiving side requires it (mTLS) and checks its fingerprint against the
/// `sender_fingerprint` we declare in the transfer request, which is what makes
/// that declaration provable instead of free-form JSON.
fn build_client(
    expected_fingerprint: &str,
    identity: &crate::tls::TlsIdentity,
) -> Result<reqwest::Client, String> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let cert = CertificateDer::from_pem_slice(identity.cert_pem.as_bytes())
        .map_err(|e| format!("certificat local invalide: {e:?}"))?;
    let key = PrivateKeyDer::from_pem_slice(identity.key_pem.as_bytes())
        .map_err(|e| format!("clé privée locale invalide: {e:?}"))?;

    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedFingerprintVerifier::new(
            expected_fingerprint.to_string(),
        )))
        .with_client_auth_cert(vec![cert], key)
        .map_err(|e| format!("identité TLS locale invalide: {e}"))?;

    reqwest::Client::builder()
        .use_preconfigured_tls(tls_config)
        .timeout(Duration::from_secs(3600))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())
}

/// Kicks off a background send and returns a local transfer id the UI can
/// track immediately via "transfer-progress" / "transfer-complete" events.
pub fn send_files(state: Arc<AppState>, peer: Peer, paths: Vec<String>) -> String {
    let local_transfer_id = Uuid::new_v4().to_string();
    let task_state = state.clone();
    let task_transfer_id = local_transfer_id.clone();
    tokio::spawn(async move {
        if let Err(err) = run_send(task_state.clone(), peer, paths, task_transfer_id.clone()).await {
            let _ = task_state.app_handle.emit(
                "transfer-complete",
                TransferDoneEvent {
                    transfer_id: task_transfer_id,
                    direction: TransferDirection::Send,
                    ok: false,
                    error: Some(err),
                },
            );
        }
    });
    local_transfer_id
}

async fn run_send(
    state: Arc<AppState>,
    peer: Peer,
    paths: Vec<String>,
    local_transfer_id: String,
) -> Result<(), String> {
    let client = build_client(&peer.fingerprint, &state.tls)?;

    let mut files = Vec::with_capacity(paths.len());
    let mut entries = Vec::with_capacity(paths.len());
    for path in &paths {
        let mut file = open_source(&state.app_handle, path).map_err(|e| format!("{path}: {e}"))?;
        let size = file
            .metadata()
            .await
            .map_err(|e| format!("{path}: {e}"))?
            .len();

        let mut sniff_buf = [0u8; 16];
        let filled = read_up_to(&mut file, &mut sniff_buf).await;
        let sniffed = sniff_type(&sniff_buf[..filled]);

        let mut name = display_name(path);
        if std::path::Path::new(&name).extension().is_none() {
            if let Some((ext, _)) = sniffed {
                name = format!("{name}.{ext}");
            }
        }
        let mime = sniffed
            .map(|(_, mime)| mime.to_string())
            .unwrap_or_else(|| mime_guess::from_path(&name).first_or_octet_stream().to_string());

        let file_id = Uuid::new_v4().to_string();
        files.push(FileMeta {
            id: file_id.clone(),
            name,
            size,
            mime,
        });
        entries.push((file_id, path.clone(), size));
    }

    let sender_name = state.settings.read().await.device_name.clone();
    let payload = TransferRequestPayload {
        sender_id: state.identity.id.clone(),
        sender_name,
        sender_fingerprint: state.tls.fingerprint.clone(),
        files,
    };

    let base = format!("https://{}:{}", peer.address, peer.https_port);
    let response = client
        .post(format!("{base}/api/transfer/request"))
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("connexion impossible: {e}"))?;
    let status = response.status();
    if !status.is_success() {
        // The receiver rejects a request with an explanatory body (impersonation
        // detected, batch too large, unknown-device approval refused, ...).
        // Surface that reason instead of the opaque "réponse invalide" that
        // `.json()` would otherwise produce when it fails to parse an error body.
        let body = response.text().await.unwrap_or_default();
        return Err(peer_error(status, &body));
    }
    let resp: TransferRequestResponse = response
        .json()
        .await
        .map_err(|e| format!("réponse invalide du destinataire: {e}"))?;

    if !resp.accepted {
        return Err("Transfert refusé par le destinataire".to_string());
    }

    // Progress is reported cumulatively across the whole batch so the UI bar
    // advances once from 0 to 100% instead of restarting on every file.
    let batch_total = entries
        .iter()
        .fold(0u64, |acc, (_, _, size)| acc.saturating_add(*size));
    let mut sent_before = 0u64;
    for (file_id, path, size) in entries {
        upload_one_file(
            &client,
            &state,
            &base,
            &resp.transfer_id,
            &local_transfer_id,
            &file_id,
            &path,
            size,
            sent_before,
            batch_total,
        )
        .await?;
        sent_before = sent_before.saturating_add(size);
    }

    let _ = state.app_handle.emit(
        "transfer-complete",
        TransferDoneEvent {
            transfer_id: local_transfer_id,
            direction: TransferDirection::Send,
            ok: true,
            error: None,
        },
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn upload_one_file(
    client: &reqwest::Client,
    state: &Arc<AppState>,
    base: &str,
    remote_transfer_id: &str,
    local_transfer_id: &str,
    file_id: &str,
    path: &str,
    size: u64,
    sent_before: u64,
    batch_total: u64,
) -> Result<(), String> {
    let file = open_source(&state.app_handle, path).map_err(|e| format!("{path}: {e}"))?;

    let counter = Arc::new(AtomicU64::new(0));
    let last_emit = Arc::new(StdMutex::new(Instant::now()));
    let progress_state = state.clone();
    let progress_transfer_id = local_transfer_id.to_string();
    let progress_file_id = file_id.to_string();

    let stream = ReaderStream::new(file).inspect(move |chunk| {
        if let Ok(bytes) = chunk {
            let done = counter.fetch_add(bytes.len() as u64, Ordering::Relaxed) + bytes.len() as u64;
            let mut last = last_emit.lock().unwrap();
            if last.elapsed() > Duration::from_millis(120) || done >= size {
                let _ = progress_state.app_handle.emit(
                    "transfer-progress",
                    TransferProgressEvent {
                        transfer_id: progress_transfer_id.clone(),
                        file_id: progress_file_id.clone(),
                        direction: TransferDirection::Send,
                        bytes_done: sent_before.saturating_add(done),
                        bytes_total: batch_total,
                    },
                );
                *last = Instant::now();
            }
        }
    });

    let body = reqwest::Body::wrap_stream(stream);
    let url = format!("{base}/api/transfer/{remote_transfer_id}/files/{file_id}");
    let response = client
        .put(url)
        .header("content-length", size.to_string())
        .body(body)
        .send()
        .await
        .map_err(|e| format!("envoi échoué: {e}"))?;

    let status = response.status();
    if !status.is_success() {
        // Relay the receiver's own reason (size mismatch, transfer gone, ...)
        // rather than just the numeric code.
        let body = response.text().await.unwrap_or_default();
        return Err(peer_error(status, &body));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use axum_server::tls_rustls::RustlsConfig;

    #[test]
    fn percent_decode_handles_escapes_and_malformed_input() {
        assert_eq!(percent_decode("photo%20final.jpg"), "photo final.jpg");
        assert_eq!(percent_decode("plain.txt"), "plain.txt");
        // UTF-8 multi-byte (é = %C3%A9) round-trips.
        assert_eq!(percent_decode("caf%C3%A9.pdf"), "café.pdf");
        // Malformed / truncated escapes are left verbatim rather than dropped.
        assert_eq!(percent_decode("100%.txt"), "100%.txt");
        assert_eq!(percent_decode("a%2"), "a%2");
        assert_eq!(percent_decode("a%zz"), "a%zz");
    }

    #[test]
    fn peer_error_prefers_body_and_stays_bounded() {
        let s = reqwest::StatusCode::FORBIDDEN;
        assert_eq!(
            peer_error(s, "  identité déjà associée  "),
            "identité déjà associée (code 403)"
        );
        // Empty body falls back to a generic message.
        assert_eq!(
            peer_error(s, "   "),
            "le destinataire a refusé la demande (code 403)"
        );
        // Control characters stripped, length bounded.
        let noisy = format!("bad\u{0007}news{}", "x".repeat(500));
        let out = peer_error(s, &noisy);
        assert!(!out.contains('\u{0007}'));
        assert!(out.chars().count() <= 220);
    }

    /// Spins up a real HTTPS server on loopback with a throwaway self-signed
    /// identity and returns its port, so tests can exercise the actual TLS
    /// handshake `build_client` performs rather than mocking it.
    async fn spawn_test_server(identity: &crate::tls::TlsIdentity) -> u16 {
        let tls_config = RustlsConfig::from_pem(
            identity.cert_pem.clone().into_bytes(),
            identity.key_pem.clone().into_bytes(),
        )
        .await
        .expect("valid throwaway cert/key");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("local addr").port();

        let router = axum::Router::new().route("/ping", get(|| async { "pong" }));
        tokio::spawn(async move {
            let _ = axum_server::from_tcp_rustls(listener, tls_config)
                .serve(router.into_make_service())
                .await;
        });
        // Give the listener a moment to actually start accepting.
        tokio::time::sleep(Duration::from_millis(50)).await;
        port
    }

    #[tokio::test]
    async fn pinned_client_connects_when_fingerprint_matches() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let identity = crate::tls::generate();
        let client_identity = crate::tls::generate();
        let port = spawn_test_server(&identity).await;

        let client = build_client(&identity.fingerprint, &client_identity).expect("client builds");
        let resp = client
            .get(format!("https://127.0.0.1:{port}/ping"))
            .send()
            .await
            .expect("request should succeed against the pinned fingerprint");

        assert!(resp.status().is_success());
        assert_eq!(resp.text().await.unwrap(), "pong");
    }

    #[tokio::test]
    async fn pinned_client_rejects_wrong_fingerprint() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let identity = crate::tls::generate();
        let client_identity = crate::tls::generate();
        let port = spawn_test_server(&identity).await;

        // A well-formed but wrong fingerprint — simulates a spoofed/hijacked
        // peer address answering with a certificate that isn't the one the
        // user's device last saw announced for that peer.
        let wrong_fingerprint = "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:\
            00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF";

        let client = build_client(wrong_fingerprint, &client_identity).expect("client builds");
        let result = client
            .get(format!("https://127.0.0.1:{port}/ping"))
            .send()
            .await;

        assert!(
            result.is_err(),
            "connection must fail when the certificate doesn't match the pinned fingerprint"
        );
    }
}
