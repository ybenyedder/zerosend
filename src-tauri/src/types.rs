use serde::{Deserialize, Serialize};

/// Wire format broadcast over UDP on the local network so peers can find each other.
/// Never leaves the LAN: it is sent to a broadcast/multicast address only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Announce {
    pub app: String, // always "zerosend", lets us ignore foreign broadcast traffic
    pub proto: u32,
    pub id: String,
    pub name: String,
    pub platform: String,
    pub fingerprint: String,
    pub https_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub fingerprint: String,
    pub address: String,
    pub https_port: u16,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMeta {
    pub id: String,
    pub name: String,
    pub size: u64,
    #[serde(default)]
    pub mime: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRequestPayload {
    pub sender_id: String,
    pub sender_name: String,
    pub sender_fingerprint: String,
    pub files: Vec<FileMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRequestResponse {
    pub accepted: bool,
    pub transfer_id: String,
}

/// Emitted to the frontend ("incoming-transfer") when a peer asks to send files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingTransferEvent {
    pub transfer_id: String,
    pub sender_id: String,
    pub sender_name: String,
    pub sender_fingerprint: String,
    pub files: Vec<FileMeta>,
    /// True when `require_approval` is off and the transfer was accepted without
    /// asking — the frontend should show progress only, not an accept/reject card
    /// whose buttons would no longer have any effect on the outcome.
    pub auto_accepted: bool,
}

/// Emitted to the frontend ("transfer-progress") while bytes move in either direction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferProgressEvent {
    pub transfer_id: String,
    pub file_id: String,
    pub direction: TransferDirection,
    pub bytes_done: u64,
    pub bytes_total: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransferDirection {
    Send,
    Receive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferDoneEvent {
    pub transfer_id: String,
    pub direction: TransferDirection,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub device_name: String,
    pub download_dir: String,
    pub require_approval: bool,
    /// Stealth mode: stop broadcasting our presence on the LAN. Other devices
    /// can no longer discover this one (sending *to* them still works) —
    /// `serde(default)` keeps settings.json files from older versions valid.
    #[serde(default)]
    pub stealth_mode: bool,
    /// Hard cap, in MiB, on the *total declared size* of a single incoming
    /// transfer request; 0 means unlimited. Defense in depth on top of the
    /// per-file declared-size ceiling: even a trusted (or auto-accepted)
    /// device cannot propose more than this in one batch.
    #[serde(default)]
    pub max_transfer_mb: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_from_older_versions_parse_with_defaults() {
        // Exactly what a v0.1/v0.2 settings.json contains — the new fields
        // must default instead of making the whole file unreadable (which
        // would silently reset every setting).
        let old = r#"{"device_name":"pc","download_dir":"/tmp/zs","require_approval":true}"#;
        let s: Settings = serde_json::from_str(old).expect("older settings must stay parseable");
        assert_eq!(s.device_name, "pc");
        assert!(s.require_approval);
        assert!(!s.stealth_mode);
        assert_eq!(s.max_transfer_mb, 0);
    }
}

/// One entry of the persistent TOFU store, as shown in the "trusted devices"
/// section of the settings panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPeer {
    pub id: String,
    pub fingerprint: String,
    /// Best-effort display name: the live one when the device is currently
    /// announced on the LAN, otherwise the last name it was seen with.
    pub name: Option<String>,
    pub online: bool,
}
