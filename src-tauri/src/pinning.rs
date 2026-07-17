use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};

/// SHA-256 fingerprint of a DER certificate, formatted "AA:BB:CC:..." — the
/// same format `tls::fingerprint_from_pem` produces and the UI displays.
pub fn fingerprint_of(der: &CertificateDer<'_>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(der.as_ref());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Accepts a server certificate only if it hashes to the exact fingerprint the
/// peer announced over LAN discovery. This is what actually binds an outgoing
/// transfer to the device the user picked in the UI: `peer.address` comes from
/// an unauthenticated UDP broadcast, so without pinning, a spoofed announce
/// reusing a known peer's id could redirect a send to a different machine that
/// simply answers with any self-signed certificate.
#[derive(Debug)]
pub struct PinnedFingerprintVerifier {
    expected_fingerprint: String,
    supported: WebPkiSupportedAlgorithms,
}

impl PinnedFingerprintVerifier {
    pub fn new(expected_fingerprint: String) -> Self {
        Self {
            expected_fingerprint,
            supported: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PinnedFingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if fingerprint_of(end_entity) == self.expected_fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General(
                "le certificat présenté par le pair ne correspond pas à l'empreinte attendue"
                    .to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}
