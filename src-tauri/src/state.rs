use crate::identity::{self, config_dir, DeviceIdentity};
use crate::tls::{self, TlsIdentity};
use crate::trust;
use crate::types::{FileMeta, Peer, Settings};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::AppHandle;
use tokio::sync::{oneshot, Mutex, RwLock};

pub struct PendingTransfer {
    pub files: Vec<FileMeta>,
    pub responder: Option<oneshot::Sender<bool>>,
    pub accepted: bool,
    pub received_files: HashSet<String>,
    /// TLS-proven fingerprint of the device that opened this transfer (mTLS
    /// client certificate) — every subsequent file upload must come from the
    /// same identity.
    pub sender_fingerprint: String,
    /// File ids currently being written to disk, to refuse duplicate/parallel
    /// uploads of the same file and to keep the stale-entry sweeper from
    /// dropping a transfer that is still actively receiving.
    pub in_flight: HashSet<String>,
    /// Last time this transfer made progress (accepted, or a file finished) —
    /// lets the sweeper evict abandoned entries without killing long batches.
    pub last_activity_ms: u64,
}

pub struct AppState {
    pub identity: DeviceIdentity,
    pub tls: TlsIdentity,
    pub app_handle: AppHandle,
    pub settings: RwLock<Settings>,
    pub peers: RwLock<HashMap<String, Peer>>,
    /// Persistent id -> fingerprint pins built from past discovery. See `trust`
    /// module docs for why this — not the live `peers` table — is what the
    /// outgoing-send TLS pinning actually needs to be meaningful.
    pub known_peers: RwLock<HashMap<String, String>>,
    /// Persistent id -> last-seen display name for pinned peers. Presentation
    /// data only — never part of a trust decision.
    pub peer_names: RwLock<HashMap<String, String>>,
    pub pending_transfers: Mutex<HashMap<String, PendingTransfer>>,
    pub https_port: AtomicU16,
}

fn settings_path() -> std::path::PathBuf {
    config_dir().join("settings.json")
}

fn default_download_dir() -> String {
    dirs::download_dir()
        .or_else(dirs::document_dir)
        .or_else(dirs::home_dir)
        .unwrap_or_else(std::env::temp_dir)
        .join("ZeroSend")
        .to_string_lossy()
        .to_string()
}

fn load_settings(device_name: &str) -> Settings {
    if let Ok(bytes) = fs::read(settings_path()) {
        if let Ok(settings) = serde_json::from_slice::<Settings>(&bytes) {
            return settings;
        }
    }
    let settings = Settings {
        device_name: device_name.to_string(),
        download_dir: default_download_dir(),
        require_approval: true,
        stealth_mode: false,
        max_transfer_mb: 0,
    };
    save_settings(&settings);
    settings
}

pub fn save_settings(settings: &Settings) {
    if let Ok(bytes) = serde_json::to_vec_pretty(settings) {
        let path = settings_path();
        let _ = fs::write(&path, bytes);
        identity::restrict_to_owner(&path);
    }
    let _ = fs::create_dir_all(&settings.download_dir);
}

impl AppState {
    pub fn new(app_handle: AppHandle) -> Self {
        let identity = identity::load_or_create();
        let tls = tls::load_or_create();
        let settings = load_settings(&identity.name);
        let _ = fs::create_dir_all(&settings.download_dir);
        AppState {
            identity,
            tls,
            app_handle,
            settings: RwLock::new(settings),
            peers: RwLock::new(HashMap::new()),
            known_peers: RwLock::new(trust::load()),
            peer_names: RwLock::new(trust::load_names()),
            pending_transfers: Mutex::new(HashMap::new()),
            https_port: AtomicU16::new(0),
        }
    }

    pub fn https_port(&self) -> u16 {
        self.https_port.load(Ordering::SeqCst)
    }

    pub fn set_https_port(&self, port: u16) {
        self.https_port.store(port, Ordering::SeqCst);
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
