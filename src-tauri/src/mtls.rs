//! Server-side mutual-TLS plumbing: require every incoming connection to
//! present a client certificate and expose that certificate's SHA-256
//! fingerprint to the request handlers.
//!
//! Why this exists: the fields of `TransferRequestPayload` (`sender_id`,
//! `sender_name`, `sender_fingerprint`) are plain JSON written by whoever
//! connects — without mTLS they are pure self-declaration, so any device on
//! the LAN could show a trusted peer's name *and fingerprint* on the
//! accept/reject card and the user would have no way to tell. Requiring a
//! client certificate turns the fingerprint into something the sender must
//! *prove* (rustls verifies the handshake signature against the certificate's
//! public key, so presenting someone else's certificate without their private
//! key fails), and the handlers can then check it against both the declared
//! `sender_fingerprint` and the persistent TOFU store.

use crate::pinning::fingerprint_of;
use axum::middleware::AddExtension;
use axum::Extension;
use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use futures_util::future::BoxFuture;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tower_layer::Layer;

/// SHA-256 fingerprint of the client certificate presented on this connection,
/// inserted into every request's extensions by [`MtlsAcceptor`]. `None` can
/// only happen if client auth were made optional — with the mandatory verifier
/// below the handshake itself fails first — but handlers still treat `None`
/// as "reject" rather than assuming.
#[derive(Debug, Clone)]
pub struct ClientFingerprint(pub Option<String>);

/// Accepts any *well-formed* client certificate, without chain-of-trust
/// validation (peers are self-signed on a LAN-only protocol — there is no CA).
/// The signature-verification methods delegate to rustls' real implementations,
/// which is what makes the handshake prove possession of the private key:
/// replaying a known peer's public certificate without its key fails there.
#[derive(Debug)]
pub struct AnyPeerCertVerifier {
    supported: WebPkiSupportedAlgorithms,
}

impl AnyPeerCertVerifier {
    pub fn new() -> Self {
        Self {
            supported: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }
}

impl ClientCertVerifier for AnyPeerCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        // A connection that presents no certificate has no provable identity at
        // all, and nothing in the API is meant to be reachable anonymously —
        // fail the handshake outright instead of letting handlers sort it out.
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // No CA hints: peers use self-signed certificates, the client sends
        // whatever identity it has.
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

/// Builds the server TLS config: our own cert/key for the server side, plus
/// mandatory client-certificate auth via [`AnyPeerCertVerifier`].
pub fn server_config(cert_pem: &str, key_pem: &str) -> Result<rustls::ServerConfig, String> {
    let cert = CertificateDer::from_pem_slice(cert_pem.as_bytes())
        .map_err(|e| format!("certificat serveur invalide: {e:?}"))?;
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| format!("clé privée invalide: {e:?}"))?;
    rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(AnyPeerCertVerifier::new()))
        .with_single_cert(vec![cert], key)
        .map_err(|e| format!("configuration TLS invalide: {e}"))
}

/// Wraps axum-server's `RustlsAcceptor` to pull the client certificate out of
/// the finished handshake and expose its fingerprint as a request extension.
#[derive(Clone)]
pub struct MtlsAcceptor {
    inner: RustlsAcceptor,
}

impl MtlsAcceptor {
    pub fn new(config: RustlsConfig) -> Self {
        Self {
            inner: RustlsAcceptor::new(config),
        }
    }
}

impl<I, S> Accept<I, S> for MtlsAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = AddExtension<S, ClientFingerprint>;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.inner.clone();
        Box::pin(async move {
            let (stream, service) = acceptor.accept(stream, service).await?;
            let fingerprint = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .map(fingerprint_of);
            let service = Extension(ClientFingerprint(fingerprint)).layer(service);
            Ok((stream, service))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pinning::PinnedFingerprintVerifier;
    use axum::routing::get;
    use axum::Router;
    use std::time::Duration;

    /// Real HTTPS server on loopback with mandatory client-certificate auth and
    /// a route that echoes back the fingerprint the acceptor extracted — the
    /// exact plumbing `server::spawn` uses in production.
    async fn spawn_mtls_server(server_identity: &crate::tls::TlsIdentity) -> u16 {
        let config = server_config(&server_identity.cert_pem, &server_identity.key_pem)
            .expect("valid throwaway server identity");
        let rustls_config = RustlsConfig::from_config(Arc::new(config));

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("local addr").port();

        let router = Router::new().route(
            "/whoami",
            get(|Extension(fp): Extension<ClientFingerprint>| async move {
                fp.0.unwrap_or_default()
            }),
        );
        let acceptor = MtlsAcceptor::new(rustls_config);
        tokio::spawn(async move {
            let _ = axum_server::from_tcp(listener)
                .acceptor(acceptor)
                .serve(router.into_make_service())
                .await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        port
    }

    fn pinned_client_config(
        expected_fingerprint: &str,
    ) -> rustls::ConfigBuilder<rustls::ClientConfig, rustls::client::WantsClientCert> {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedFingerprintVerifier::new(
                expected_fingerprint.to_string(),
            )))
    }

    #[tokio::test]
    async fn server_reports_the_proven_client_fingerprint() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let server_identity = crate::tls::generate();
        let client_identity = crate::tls::generate();
        let port = spawn_mtls_server(&server_identity).await;

        let cert = CertificateDer::from_pem_slice(client_identity.cert_pem.as_bytes()).unwrap();
        let key = PrivateKeyDer::from_pem_slice(client_identity.key_pem.as_bytes()).unwrap();
        let tls = pinned_client_config(&server_identity.fingerprint)
            .with_client_auth_cert(vec![cert], key)
            .expect("client auth config");
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .build()
            .unwrap();

        let body = client
            .get(format!("https://127.0.0.1:{port}/whoami"))
            .send()
            .await
            .expect("mTLS handshake with a client certificate must succeed")
            .text()
            .await
            .unwrap();

        // What the handler sees must be the *client's* proven fingerprint —
        // this is the identity every transfer-request check builds on.
        assert_eq!(body, client_identity.fingerprint);
    }

    #[tokio::test]
    async fn server_rejects_connections_without_a_client_certificate() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let server_identity = crate::tls::generate();
        let port = spawn_mtls_server(&server_identity).await;

        let tls = pinned_client_config(&server_identity.fingerprint).with_no_client_auth();
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .build()
            .unwrap();

        let result = client
            .get(format!("https://127.0.0.1:{port}/whoami"))
            .send()
            .await;

        assert!(
            result.is_err(),
            "a connection with no client certificate must fail the handshake"
        );
    }
}
