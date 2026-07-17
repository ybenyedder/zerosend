use crate::identity::config_dir;
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use std::fs;

#[derive(Clone)]
pub struct TlsIdentity {
    pub cert_pem: String,
    pub key_pem: String,
    /// SHA-256 fingerprint of the certificate, formatted as "AA:BB:CC:..."
    /// Shown to the user so two devices can be verified visually on first contact.
    pub fingerprint: String,
}

fn cert_path() -> std::path::PathBuf {
    config_dir().join("cert.pem")
}
fn key_path() -> std::path::PathBuf {
    config_dir().join("key.pem")
}

pub fn load_or_create() -> TlsIdentity {
    if let (Ok(cert_pem), Ok(key_pem)) =
        (fs::read_to_string(cert_path()), fs::read_to_string(key_path()))
    {
        if let Some(fingerprint) = fingerprint_from_pem(&cert_pem) {
            return TlsIdentity {
                cert_pem,
                key_pem,
                fingerprint,
            };
        }
    }
    generate_and_persist()
}

/// Generates a fresh, self-signed identity in memory only — no disk I/O. Used to
/// create the long-lived on-disk identity, and directly by tests that need a real
/// certificate without touching the machine's actual config directory.
pub fn generate() -> TlsIdentity {
    let mut params = CertificateParams::new(vec!["zerosend.local".to_string(), "localhost".to_string()])
        .expect("invalid certificate params");
    params.distinguished_name = DistinguishedName::new();
    let key_pair = KeyPair::generate().expect("key generation failed");
    let cert = params
        .self_signed(&key_pair)
        .expect("self-signed certificate generation failed");

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let fingerprint = fingerprint_from_pem(&cert_pem).expect("fingerprint of freshly generated cert");
    TlsIdentity {
        cert_pem,
        key_pem,
        fingerprint,
    }
}

fn generate_and_persist() -> TlsIdentity {
    // Long-lived: this identity is what peers recognize across sessions.
    let identity = generate();
    let (cert_path, key_path) = (cert_path(), key_path());
    let _ = fs::write(&cert_path, &identity.cert_pem);
    let _ = fs::write(&key_path, &identity.key_pem);
    // key.pem holds the device's private key; without this it inherits the
    // process umask and is typically world-readable to any other local user.
    crate::identity::restrict_to_owner(&key_path);
    crate::identity::restrict_to_owner(&cert_path);
    identity
}

fn fingerprint_from_pem(pem: &str) -> Option<String> {
    let der = CertificateDer::from_pem_slice(pem.as_bytes()).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(der.as_ref());
    let digest = hasher.finalize();
    Some(
        digest
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":"),
    )
}
