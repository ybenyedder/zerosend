use crate::mtls::{ClientFingerprint, MtlsAcceptor};
use crate::state::{now_ms, AppState, PendingTransfer};
use crate::trust;
use crate::types::{
    FileMeta, IncomingTransferEvent, TransferDirection, TransferDoneEvent, TransferProgressEvent,
    TransferRequestPayload, TransferRequestResponse,
};
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{post, put};
use axum::{Extension, Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use futures_util::StreamExt;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tauri::Emitter;
use tokio::io::AsyncWriteExt;
use tokio::sync::oneshot;
use uuid::Uuid;

const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
/// How long a transfer may sit with no progress (no accepted upload finishing,
/// nothing actively being written) before the sweeper evicts it. Activity-based
/// rather than a fixed lifetime, so a large multi-file batch that legitimately
/// takes longer than the TTL keeps its entry as long as files keep arriving.
const STALE_TRANSFER_TTL: Duration = Duration::from_secs(600);

/// Upper bound on transfers simultaneously known to the server. Each pending
/// entry holds file metadata (up to the 2 MB axum JSON body cap) and, with
/// approval on, spawns an accept/reject card in the UI — without a bound a
/// malicious peer could pile these up faster than their 120 s timeouts expire.
const MAX_PENDING_TRANSFERS: usize = 64;
/// Per-sender slice of the pending pool, keyed by the mTLS-proven fingerprint,
/// so one noisy device cannot consume the whole global cap by itself.
const MAX_PENDING_PER_SENDER: usize = 4;
/// Cap on files in a single request: keeps the accept/reject card and the
/// per-file bookkeeping within sane bounds (a single batch this large is
/// already far beyond any real use of the app).
const MAX_FILES_PER_TRANSFER: usize = 500;

pub async fn spawn(state: Arc<AppState>) {
    // Mutual TLS: peers must present a client certificate (proof of identity
    // possession), whose fingerprint the handlers below check against both the
    // declared sender fingerprint and the persistent TOFU store.
    let server_config = match crate::mtls::server_config(&state.tls.cert_pem, &state.tls.key_pem) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("zerosend: invalid TLS identity: {e}");
            return;
        }
    };
    let tls_config = RustlsConfig::from_config(Arc::new(server_config));

    let std_listener = match std::net::TcpListener::bind("0.0.0.0:0") {
        Ok(l) => l,
        Err(e) => {
            eprintln!("zerosend: could not bind local HTTPS port: {e}");
            return;
        }
    };
    std_listener.set_nonblocking(true).ok();
    let port = std_listener.local_addr().map(|a| a.port()).unwrap_or(0);
    state.set_https_port(port);

    let router = build_router(state);
    let acceptor = MtlsAcceptor::new(tls_config);

    tokio::spawn(async move {
        if let Err(e) = axum_server::from_tcp(std_listener)
            .acceptor(acceptor)
            .serve(router.into_make_service())
            .await
        {
            eprintln!("zerosend: local HTTPS server stopped: {e}");
        }
    });
}

fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/transfer/request", post(handle_transfer_request))
        .route(
            "/api/transfer/:transfer_id/files/:file_id",
            put(handle_file_upload),
        )
        .with_state(state)
}

async fn handle_transfer_request(
    State(state): State<Arc<AppState>>,
    Extension(client): Extension<ClientFingerprint>,
    Json(payload): Json<TransferRequestPayload>,
) -> Result<Json<TransferRequestResponse>, (StatusCode, String)> {
    // The declared sender fields are attacker-writable JSON; the client
    // certificate fingerprint is the only identity the TLS handshake actually
    // proved. Refuse any request where the two disagree, so everything shown
    // on the accept/reject card is backed by the proven identity.
    let Some(client_fp) = client.0 else {
        return Err((
            StatusCode::FORBIDDEN,
            "certificat client absent".to_string(),
        ));
    };
    if client_fp != payload.sender_fingerprint {
        return Err((
            StatusCode::FORBIDDEN,
            "l'empreinte déclarée ne correspond pas au certificat présenté".to_string(),
        ));
    }

    let trust_status = {
        let known = state.known_peers.read().await;
        trust::evaluate_incoming(&known, &payload.sender_id, &client_fp)
    };
    if trust_status == trust::IncomingTrust::Impersonation {
        return Err((
            StatusCode::FORBIDDEN,
            "cet identifiant d'appareil est déjà associé à une autre empreinte".to_string(),
        ));
    }

    validate_files(&payload.files).map_err(|msg| (StatusCode::BAD_REQUEST, msg.to_string()))?;

    let (require_approval, max_transfer_mb) = {
        let settings = state.settings.read().await;
        (settings.require_approval, settings.max_transfer_mb)
    };
    // Defense in depth on top of the per-file declared-size ceiling: with a
    // cap configured, even an already-trusted (or auto-accepted) device cannot
    // propose more than this in one batch — the request is refused before any
    // approval card or disk write.
    if exceeds_transfer_cap(total_declared_size(&payload.files), max_transfer_mb) {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "le transfert dépasse la taille maximale acceptée par cet appareil ({max_transfer_mb} Mo)"
            ),
        ));
    }
    // Auto-accept is a statement of trust in *devices the user already knows*
    // (pinned via a past explicit approval or LAN discovery). A never-seen
    // device always goes through the manual accept/reject card, even with
    // approval turned off — otherwise "skip confirmation" would mean "any
    // stranger on this network may write to my disk".
    let auto_accept = !require_approval && trust_status == trust::IncomingTrust::KnownPeer;

    let transfer_id = Uuid::new_v4().to_string();
    let event = IncomingTransferEvent {
        transfer_id: transfer_id.clone(),
        sender_id: payload.sender_id.clone(),
        sender_name: payload.sender_name.clone(),
        sender_fingerprint: payload.sender_fingerprint.clone(),
        files: payload.files.clone(),
        auto_accepted: auto_accept,
    };

    let accepted = if auto_accept {
        insert_pending(
            &state,
            &transfer_id,
            PendingTransfer {
                files: payload.files.clone(),
                responder: None,
                accepted: true,
                received_files: HashSet::new(),
                sender_fingerprint: client_fp.clone(),
                in_flight: HashSet::new(),
                last_activity_ms: now_ms(),
            },
        )
        .await?;
        let _ = state.app_handle.emit("incoming-transfer", event);
        true
    } else {
        let (tx, rx) = oneshot::channel();
        insert_pending(
            &state,
            &transfer_id,
            PendingTransfer {
                files: payload.files.clone(),
                responder: Some(tx),
                accepted: false,
                received_files: HashSet::new(),
                sender_fingerprint: client_fp.clone(),
                in_flight: HashSet::new(),
                last_activity_ms: now_ms(),
            },
        )
        .await?;
        let _ = state.app_handle.emit("incoming-transfer", event);

        matches!(tokio::time::timeout(APPROVAL_TIMEOUT, rx).await, Ok(Ok(true)))
    };

    if accepted {
        if let Some(t) = state.pending_transfers.lock().await.get_mut(&transfer_id) {
            t.accepted = true;
            t.last_activity_ms = now_ms();
        }
        // The user's explicit approval (or the auto-accept of an already-known
        // peer) is the trust act — record a first-contact sender now, so future
        // impersonation of this id gets rejected and auto-accept can apply.
        {
            let mut known = state.known_peers.write().await;
            match trust::pin(&mut known, &payload.sender_id, &client_fp) {
                trust::PinOutcome::Inserted => trust::save(&known),
                trust::PinOutcome::StoreFull => eprintln!(
                    "zerosend: store de pairs connus plein ({} entrées) — pair {} accepté sans être mémorisé",
                    trust::MAX_KNOWN_PEERS,
                    payload.sender_id
                ),
                trust::PinOutcome::AlreadyPinned => {}
            }
            let mut names = state.peer_names.write().await;
            if trust::remember_name(&known, &mut names, &payload.sender_id, &payload.sender_name) {
                trust::save_names(&names);
            }
        }
        schedule_cleanup(state.clone(), transfer_id.clone());
    } else {
        state.pending_transfers.lock().await.remove(&transfer_id);
    }

    Ok(Json(TransferRequestResponse {
        accepted,
        transfer_id,
    }))
}

/// Admission control + insertion under a single lock, so two racing requests
/// cannot both slip past the caps.
async fn insert_pending(
    state: &Arc<AppState>,
    transfer_id: &str,
    transfer: PendingTransfer,
) -> Result<(), (StatusCode, String)> {
    let mut pending = state.pending_transfers.lock().await;
    let from_sender = pending
        .values()
        .filter(|t| t.sender_fingerprint == transfer.sender_fingerprint)
        .count();
    if let Some(msg) = admission_error(pending.len(), from_sender) {
        return Err((StatusCode::TOO_MANY_REQUESTS, msg.to_string()));
    }
    pending.insert(transfer_id.to_string(), transfer);
    Ok(())
}

fn admission_error(total_pending: usize, pending_from_sender: usize) -> Option<&'static str> {
    if total_pending >= MAX_PENDING_TRANSFERS {
        return Some("trop de transferts en attente sur cet appareil");
    }
    if pending_from_sender >= MAX_PENDING_PER_SENDER {
        return Some("trop de transferts en attente pour cet expéditeur");
    }
    None
}

/// Sum of the sizes the sender declared, saturating rather than wrapping on
/// absurd (attacker-chosen) values.
fn total_declared_size(files: &[FileMeta]) -> u64 {
    files.iter().fold(0u64, |acc, f| acc.saturating_add(f.size))
}

/// Whether a declared total breaches the user-configured per-transfer cap
/// (in MiB); a cap of 0 means unlimited.
fn exceeds_transfer_cap(total_bytes: u64, cap_mb: u64) -> bool {
    cap_mb != 0 && total_bytes > cap_mb.saturating_mul(1024 * 1024)
}

fn validate_files(files: &[FileMeta]) -> Result<(), &'static str> {
    if files.is_empty() {
        return Err("aucun fichier dans la demande");
    }
    if files.len() > MAX_FILES_PER_TRANSFER {
        return Err("trop de fichiers dans une seule demande");
    }
    let mut seen = HashSet::with_capacity(files.len());
    for f in files {
        // Duplicate ids would make the received-files count never reach the
        // file count (the entry would only die by TTL) — reject them upfront.
        if !seen.insert(f.id.as_str()) {
            return Err("identifiants de fichiers dupliqués dans la demande");
        }
    }
    Ok(())
}

fn schedule_cleanup(state: Arc<AppState>, transfer_id: String) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(STALE_TRANSFER_TTL).await;
            let mut pending = state.pending_transfers.lock().await;
            match pending.get(&transfer_id) {
                // A file is actively being written, or one finished recently:
                // the transfer is alive, keep waiting.
                Some(t)
                    if !t.in_flight.is_empty()
                        || now_ms().saturating_sub(t.last_activity_ms)
                            < STALE_TRANSFER_TTL.as_millis() as u64 =>
                {
                    continue;
                }
                Some(_) => {
                    pending.remove(&transfer_id);
                    drop(pending);
                    // An accepted transfer went idle long enough to be swept
                    // (sender crashed, connection died mid-batch). Resolve its
                    // still-open receive card as failed instead of leaving it
                    // spinning at "Réception…" indefinitely.
                    let _ = state.app_handle.emit(
                        "transfer-complete",
                        TransferDoneEvent {
                            transfer_id: transfer_id.clone(),
                            direction: TransferDirection::Receive,
                            ok: false,
                            error: Some("transfert expiré (aucune activité)".to_string()),
                        },
                    );
                    return;
                }
                None => return,
            }
        }
    });
}

async fn handle_file_upload(
    State(state): State<Arc<AppState>>,
    Extension(client): Extension<ClientFingerprint>,
    Path((transfer_id, file_id)): Path<(String, String)>,
    body: Body,
) -> Result<StatusCode, (StatusCode, String)> {
    let Some(client_fp) = client.0 else {
        return Err((
            StatusCode::FORBIDDEN,
            "certificat client absent".to_string(),
        ));
    };

    let (file_meta, bytes_before, batch_total) = {
        let mut pending = state.pending_transfers.lock().await;
        let transfer = pending
            .get_mut(&transfer_id)
            .ok_or((StatusCode::NOT_FOUND, "transfert inconnu".to_string()))?;
        // The transfer id travels back to the requester over its own TLS
        // session, but tie every upload to the identity that opened the
        // transfer anyway — a bearer token alone shouldn't move files.
        if transfer.sender_fingerprint != client_fp {
            return Err((
                StatusCode::FORBIDDEN,
                "ce transfert appartient à un autre expéditeur".to_string(),
            ));
        }
        if !transfer.accepted {
            return Err((
                StatusCode::FORBIDDEN,
                "transfert non accepté".to_string(),
            ));
        }
        let meta = transfer
            .files
            .iter()
            .find(|f| f.id == file_id)
            .cloned()
            .ok_or((StatusCode::NOT_FOUND, "fichier inconnu".to_string()))?;
        if transfer.received_files.contains(&file_id) {
            return Err((
                StatusCode::CONFLICT,
                "fichier déjà reçu pour ce transfert".to_string(),
            ));
        }
        // Two concurrent PUTs for the same file id would each create their own
        // "name (N)" copy on disk; first one wins, the other is turned away.
        if !transfer.in_flight.insert(file_id.clone()) {
            return Err((
                StatusCode::CONFLICT,
                "fichier déjà en cours de réception".to_string(),
            ));
        }
        // Cumulative progress spans the whole batch, not the single file: sum
        // the declared sizes of everything (total) and of what already landed
        // (offset) so the UI bar advances once across the transfer instead of
        // snapping back to zero on every file.
        let batch_total = total_declared_size(&transfer.files);
        let bytes_before = transfer
            .files
            .iter()
            .filter(|f| transfer.received_files.contains(&f.id))
            .fold(0u64, |acc, f| acc.saturating_add(f.size));
        (meta, bytes_before, batch_total)
    };

    let outcome = receive_file(
        &state,
        &transfer_id,
        &file_id,
        &file_meta,
        bytes_before,
        batch_total,
        body,
    )
    .await;

    let mut all_done = false;
    let mut failed = false;
    {
        let mut pending = state.pending_transfers.lock().await;
        if let Some(t) = pending.get_mut(&transfer_id) {
            t.in_flight.remove(&file_id);
            t.last_activity_ms = now_ms();
            if outcome.is_ok() {
                t.received_files.insert(file_id.clone());
                all_done = t.received_files.len() >= t.files.len();
            } else {
                // The sender aborts the whole batch on the first rejected file,
                // so tear the transfer down here too rather than leaving it to
                // expire — and tell our own UI it failed instead of stranding
                // the receive card at "Réception…" forever.
                failed = true;
            }
        }
        if all_done || failed {
            pending.remove(&transfer_id);
        }
    }

    if all_done {
        let _ = state.app_handle.emit(
            "transfer-complete",
            TransferDoneEvent {
                transfer_id: transfer_id.clone(),
                direction: TransferDirection::Receive,
                ok: true,
                error: None,
            },
        );
    } else if failed {
        let error = outcome.as_ref().err().map(|(_, msg)| msg.clone());
        let _ = state.app_handle.emit(
            "transfer-complete",
            TransferDoneEvent {
                transfer_id: transfer_id.clone(),
                direction: TransferDirection::Receive,
                ok: false,
                error,
            },
        );
    }

    outcome?;
    Ok(StatusCode::OK)
}

/// Streams one upload body to disk, enforcing the declared size, and relays it
/// into the platform gallery on Android. On any error the partial file is
/// removed; in-flight bookkeeping is the caller's job.
#[allow(clippy::too_many_arguments)]
async fn receive_file(
    state: &Arc<AppState>,
    transfer_id: &str,
    file_id: &str,
    file_meta: &FileMeta,
    bytes_before: u64,
    batch_total: u64,
    body: Body,
) -> Result<(), (StatusCode, String)> {
    let download_dir = state.settings.read().await.download_dir.clone();
    tokio::fs::create_dir_all(&download_dir)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let safe_name = sanitize_filename(&file_meta.name);
    let (mut file, dest_path) = create_unique(std::path::Path::new(&download_dir), &safe_name)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut stream = body.into_data_stream();
    let mut received: u64 = 0;
    let total = file_meta.size;
    let mut last_emit = std::time::Instant::now();

    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(e) => {
                drop(file);
                let _ = tokio::fs::remove_file(&dest_path).await;
                return Err((StatusCode::BAD_REQUEST, e.to_string()));
            }
        };
        // The declared size is what the user actually saw and approved on the
        // incoming-transfer card. Without enforcing it as a hard ceiling, a peer
        // could declare a small, harmless-looking size to get approval (or rely
        // on auto-accept) and then stream an unbounded amount of data in the PUT
        // body, filling the receiver's disk with far more than was consented to.
        if would_exceed_declared_size(received, chunk.len() as u64, total) {
            drop(file);
            let _ = tokio::fs::remove_file(&dest_path).await;
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                "le fichier envoyé dépasse la taille annoncée".to_string(),
            ));
        }
        if let Err(e) = file.write_all(&chunk).await {
            drop(file);
            let _ = tokio::fs::remove_file(&dest_path).await;
            return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
        }
        received += chunk.len() as u64;
        if last_emit.elapsed() > Duration::from_millis(120) || received >= total {
            let _ = state.app_handle.emit(
                "transfer-progress",
                TransferProgressEvent {
                    transfer_id: transfer_id.to_string(),
                    file_id: file_id.to_string(),
                    direction: TransferDirection::Receive,
                    bytes_done: bytes_before.saturating_add(received),
                    bytes_total: batch_total,
                },
            );
            last_emit = std::time::Instant::now();
        }
    }
    if let Err(e) = file.flush().await {
        drop(file);
        let _ = tokio::fs::remove_file(&dest_path).await;
        return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
    }
    drop(file);

    // The stream ended without an error but short of the declared size (e.g. the
    // sender closed the connection early): without this check the transfer would
    // still be marked "received" and reported as a success to both sides, even
    // though the file on disk is silently truncated.
    if received != total {
        let _ = tokio::fs::remove_file(&dest_path).await;
        return Err((
            StatusCode::BAD_REQUEST,
            format!("transfert incomplet : {received} sur {total} octets reçus"),
        ));
    }

    // On Android, `download_dir` is an app-private staging folder (scoped storage
    // has no writable "Downloads"/"Pictures" path apps can target directly) — relay
    // the finished file into the public MediaStore so it actually shows up in the
    // Gallery/Files apps, the way a normal received file would.
    #[cfg(target_os = "android")]
    {
        use tauri_plugin_gallery_saver::GallerySaverExt;
        if let Err(e) =
            state
                .app_handle
                .gallery_saver()
                .save(&dest_path.to_string_lossy(), &safe_name, &file_meta.mime)
        {
            eprintln!("zerosend: could not relay {safe_name} into the gallery: {e}");
        }
    }

    Ok(())
}

/// Whether accepting `chunk_len` more bytes on top of `received` would exceed
/// the size the sender declared in `TransferRequestPayload` — the same number
/// the user was shown on the incoming-transfer card before approving.
fn would_exceed_declared_size(received: u64, chunk_len: u64, total: u64) -> bool {
    received.saturating_add(chunk_len) > total
}

/// Device names Windows reserves at the filesystem level, regardless of extension
/// (e.g. "con.txt" is just as unwritable as "con").
const WINDOWS_RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Longest file name we will create, in bytes — the actual limit on ext4, NTFS
/// and APFS is 255 bytes/UTF-16 units, so anything longer would make the
/// receive fail with an IO error chosen by the sender.
const MAX_FILENAME_BYTES: usize = 255;

/// Cuts a string to at most `max_bytes` bytes without splitting a UTF-8
/// code point.
fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Caps a sanitized name to [`MAX_FILENAME_BYTES`], keeping a reasonably-sized
/// extension intact so the received file still opens with the right app.
fn enforce_name_length(name: String) -> String {
    if name.len() <= MAX_FILENAME_BYTES {
        return name;
    }
    let path = std::path::Path::new(&name);
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_string())
        // An "extension" longer than this is not something any app dispatches
        // on — don't let it eat the whole budget.
        .filter(|e| !e.is_empty() && e.len() <= 32);
    match ext {
        Some(ext) => {
            let stem = path
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let budget = MAX_FILENAME_BYTES - ext.len() - 1;
            let stem = truncate_utf8(&stem, budget);
            let stem = if stem.trim().is_empty() { "fichier" } else { stem };
            format!("{stem}.{ext}")
        }
        None => truncate_utf8(&name, MAX_FILENAME_BYTES).to_string(),
    }
}

/// Keeps only the file's base name and strips anything that could escape the
/// download directory (no path separators, no NUL bytes), and dodges Windows'
/// reserved device names so the receive doesn't fail with a confusing IO error
/// when a peer sends a file like "con.txt".
fn sanitize_filename(name: &str) -> String {
    // Take the last path segment ourselves instead of relying solely on `Path`,
    // whose notion of a separator is platform-specific (backslash isn't one on
    // Unix) — a peer-supplied name must never let a raw '/' or '\' survive on
    // any host OS.
    let base = name
        .rsplit(['/', '\\'])
        .find(|segment| !segment.is_empty())
        .unwrap_or("fichier");
    let cleaned: String = base.chars().filter(|c| *c != '\0').collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return "fichier".to_string();
    }
    // Windows reserves these names for the text up to the *first* dot, no matter
    // how many extensions follow (`nul.tar.gz` is just as unwritable as `nul`) —
    // `file_stem()` would only strip the last extension, so it's not used here.
    let head = trimmed.split('.').next().unwrap_or(trimmed);
    let named = if WINDOWS_RESERVED_NAMES.iter().any(|r| r.eq_ignore_ascii_case(head)) {
        format!("_{trimmed}")
    } else {
        trimmed.to_string()
    };
    enforce_name_length(named)
}

/// How many "(1)", "(2)", ... candidates `create_unique` will try before giving
/// up and falling back to a random suffix. Bounds the number of filesystem
/// calls a single upload can trigger: without a cap, a peer (malicious or just
/// a script re-sending the same batch many times) sending hundreds of files
/// that all share a name would make every one of those uploads walk an
/// ever-growing run of existing "name (N).ext" files.
const MAX_COLLISION_ATTEMPTS: u32 = 1000;

/// Atomically creates the destination file, resolving name collisions as it
/// goes. Every candidate is opened with `create_new` (O_EXCL / CREATE_NEW), so
/// two uploads racing for the same sanitized name can never both land on the
/// same file: the loser gets `AlreadyExists` and moves to the next candidate
/// instead of silently truncating the winner's data (the old `exists()`-then-
/// `create()` split had exactly that window). Returns the opened handle and the
/// path it committed to.
async fn create_unique(
    dir: &std::path::Path,
    name: &str,
) -> std::io::Result<(tokio::fs::File, std::path::PathBuf)> {
    create_unique_bounded(dir, name, MAX_COLLISION_ATTEMPTS).await
}

async fn try_create_new(path: &std::path::Path) -> std::io::Result<tokio::fs::File> {
    tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await
}

async fn create_unique_bounded(
    dir: &std::path::Path,
    name: &str,
    max_attempts: u32,
) -> std::io::Result<(tokio::fs::File, std::path::PathBuf)> {
    let stem = std::path::Path::new(name)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| name.to_string());
    let ext = std::path::Path::new(name)
        .extension()
        .map(|s| s.to_string_lossy().to_string());

    for i in 0..=max_attempts {
        let candidate = if i == 0 {
            dir.join(name)
        } else {
            match &ext {
                Some(e) => dir.join(format!("{stem} ({i}).{e}")),
                None => dir.join(format!("{stem} ({i})")),
            }
        };
        match try_create_new(&candidate).await {
            Ok(file) => return Ok((file, candidate)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }

    // Pathological case: `max_attempts` sequential names are all taken.
    // Disambiguate with a short random suffix instead of scanning further —
    // collision odds are negligible (1 in 16^8) and, unlike the sequential
    // counter, this can't be driven into a long loop by however many files
    // already exist. Still bounded, so an unwritable directory surfaces its
    // real error rather than spinning here forever.
    for _ in 0..16 {
        let suffix = Uuid::new_v4().simple().to_string();
        let suffix = &suffix[..8];
        let candidate = match &ext {
            Some(e) => dir.join(format!("{stem} ({suffix}).{e}")),
            None => dir.join(format!("{stem} ({suffix})")),
        };
        match try_create_new(&candidate).await {
            Ok(file) => return Ok((file, candidate)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "impossible de trouver un nom de fichier libre dans le dossier de réception",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_filename_strips_path_separators() {
        assert_eq!(sanitize_filename("a/b/c.txt"), "c.txt");
        assert_eq!(sanitize_filename("a\\b\\c.txt"), "c.txt");
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("..\\..\\Windows\\system.ini"), "system.ini");
    }

    #[test]
    fn sanitize_filename_rejects_nul_bytes() {
        assert!(!sanitize_filename("evil\0.txt").contains('\0'));
    }

    #[test]
    fn sanitize_filename_falls_back_on_empty_or_dot() {
        assert_eq!(sanitize_filename(""), "fichier");
        assert_eq!(sanitize_filename("."), "fichier");
        assert_eq!(sanitize_filename(".."), "fichier");
        assert_eq!(sanitize_filename("/"), "fichier");
    }

    #[test]
    fn sanitize_filename_dodges_windows_reserved_names() {
        assert_eq!(sanitize_filename("CON"), "_CON");
        assert_eq!(sanitize_filename("con.txt"), "_con.txt");
        assert_eq!(sanitize_filename("Nul.tar.gz"), "_Nul.tar.gz");
        assert_eq!(sanitize_filename("COM1"), "_COM1");
        // Not reserved: only an exact device-name stem should be prefixed.
        assert_eq!(sanitize_filename("console.txt"), "console.txt");
        assert_eq!(sanitize_filename("conclusion.pdf"), "conclusion.pdf");
    }

    #[test]
    fn sanitize_filename_keeps_normal_names_untouched() {
        assert_eq!(sanitize_filename("rapport final.pdf"), "rapport final.pdf");
        assert_eq!(sanitize_filename("photo.jpg"), "photo.jpg");
    }

    #[test]
    fn sanitize_filename_caps_length_and_keeps_extension() {
        let long = format!("{}.pdf", "x".repeat(400));
        let out = sanitize_filename(&long);
        assert!(out.len() <= MAX_FILENAME_BYTES, "got {} bytes", out.len());
        assert!(out.ends_with(".pdf"), "extension must survive: {out}");

        // Multi-byte characters must not be split mid-codepoint.
        let long_utf8 = format!("{}.jpg", "é".repeat(300));
        let out = sanitize_filename(&long_utf8);
        assert!(out.len() <= MAX_FILENAME_BYTES);
        assert!(out.ends_with(".jpg"));
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());

        // No usable extension: plain byte-bounded cut.
        let no_ext = "y".repeat(400);
        let out = sanitize_filename(&no_ext);
        assert_eq!(out.len(), MAX_FILENAME_BYTES);

        // A gigantic "extension" must not survive whole.
        let huge_ext = format!("a.{}", "z".repeat(400));
        let out = sanitize_filename(&huge_ext);
        assert!(out.len() <= MAX_FILENAME_BYTES);
    }

    #[test]
    fn truncate_utf8_respects_char_boundaries() {
        assert_eq!(truncate_utf8("abc", 10), "abc");
        assert_eq!(truncate_utf8("abc", 2), "ab");
        // 'é' is two bytes: cutting at 3 must not split the second 'é'.
        assert_eq!(truncate_utf8("ééé", 3), "é");
        assert_eq!(truncate_utf8("ééé", 4), "éé");
    }

    #[tokio::test]
    async fn create_unique_appends_counter_on_collision() {
        let dir = std::env::temp_dir().join(format!("zerosend-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"x").unwrap();

        // The plain name is taken: the next free candidate is "a (1).txt", and
        // it is actually created (atomic O_EXCL), not merely proposed.
        let (_f1, p1) = create_unique(&dir, "a.txt").await.unwrap();
        assert_eq!(p1, dir.join("a (1).txt"));
        assert!(p1.exists());

        let (_f2, p2) = create_unique(&dir, "a.txt").await.unwrap();
        assert_eq!(p2, dir.join("a (2).txt"));
        assert!(p2.exists());

        // No collision at all: the original name is used untouched.
        let (_f3, p3) = create_unique(&dir, "b.txt").await.unwrap();
        assert_eq!(p3, dir.join("b.txt"));
        assert!(p3.exists());

        // The pre-existing "a.txt" was never truncated by any of the above.
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"x");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn would_exceed_declared_size_examples() {
        assert!(!would_exceed_declared_size(0, 10, 10));
        assert!(!would_exceed_declared_size(5, 5, 10));
        assert!(would_exceed_declared_size(5, 6, 10));
        assert!(would_exceed_declared_size(10, 1, 10));
        assert!(!would_exceed_declared_size(0, 0, 0));
        assert!(would_exceed_declared_size(0, 1, 0));
    }

    #[tokio::test]
    async fn create_unique_falls_back_to_random_suffix_past_max_attempts() {
        let dir = std::env::temp_dir().join(format!("zerosend-test-bound-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        for i in 1..=3 {
            std::fs::write(dir.join(format!("a ({i}).txt")), b"x").unwrap();
        }

        // With max_attempts capped below the number of existing collisions,
        // every sequential candidate is taken, so this must fall back to a
        // random-suffix name rather than looping forever — and it must have
        // actually created that file.
        let (_f, result) = create_unique_bounded(&dir, "a.txt", 3).await.unwrap();
        assert!(result.exists(), "fallback file must have been created");
        let result_name = result.file_name().unwrap().to_string_lossy().to_string();
        assert!(
            !["a (1).txt", "a (2).txt", "a (3).txt"].contains(&result_name.as_str()),
            "fallback must not reuse a sequential candidate: {result_name}"
        );
        assert!(result_name.starts_with("a ("), "unexpected fallback name: {result_name}");
        assert!(result_name.ends_with(").txt"), "unexpected fallback name: {result_name}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn admission_error_enforces_both_caps() {
        assert_eq!(admission_error(0, 0), None);
        assert_eq!(
            admission_error(MAX_PENDING_TRANSFERS - 1, MAX_PENDING_PER_SENDER - 1),
            None
        );
        assert!(admission_error(MAX_PENDING_TRANSFERS, 0).is_some());
        assert!(admission_error(0, MAX_PENDING_PER_SENDER).is_some());
    }

    #[test]
    fn transfer_cap_applies_only_when_configured() {
        const MIB: u64 = 1024 * 1024;
        // Cap of 0 = unlimited, whatever the size.
        assert!(!exceeds_transfer_cap(u64::MAX, 0));
        assert!(!exceeds_transfer_cap(100 * MIB, 100));
        assert!(exceeds_transfer_cap(100 * MIB + 1, 100));
        // Saturating on absurd caps rather than overflowing.
        assert!(!exceeds_transfer_cap(u64::MAX - 1, u64::MAX));
    }

    #[test]
    fn total_declared_size_saturates() {
        let file = |size: u64| FileMeta {
            id: size.to_string(),
            name: "a".to_string(),
            size,
            mime: String::new(),
        };
        assert_eq!(total_declared_size(&[file(1), file(2)]), 3);
        assert_eq!(total_declared_size(&[file(u64::MAX), file(10)]), u64::MAX);
    }

    #[test]
    fn validate_files_rejects_empty_oversized_and_duplicates() {
        let file = |id: &str| FileMeta {
            id: id.to_string(),
            name: "a.txt".to_string(),
            size: 1,
            mime: String::new(),
        };
        assert!(validate_files(&[]).is_err());
        assert!(validate_files(&[file("a"), file("b")]).is_ok());
        assert!(validate_files(&[file("a"), file("a")]).is_err());
        let too_many: Vec<_> = (0..=MAX_FILES_PER_TRANSFER).map(|i| file(&i.to_string())).collect();
        assert!(validate_files(&too_many).is_err());
    }
}
