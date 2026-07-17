use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub id: String,
    pub name: String,
}

pub fn config_dir() -> PathBuf {
    let dir = dirs::data_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("ZeroSend");
    let _ = fs::create_dir_all(&dir);
    restrict_dir_to_owner(&dir);
    dir
}

/// Restricts a just-written config/key file to the current user only. These files
/// (identity, TLS private key, settings) would otherwise inherit the process umask,
/// which on typical Linux setups leaves them world-readable to any other local user.
#[cfg(unix)]
pub fn restrict_to_owner(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
pub fn restrict_to_owner(_path: &std::path::Path) {}

/// Same idea as [`restrict_to_owner`] but for the config directory itself — the
/// executable bit must stay set for the owner to still traverse it.
#[cfg(unix)]
fn restrict_dir_to_owner(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_dir_to_owner(_path: &std::path::Path) {}

fn identity_path() -> PathBuf {
    config_dir().join("identity.json")
}

pub fn load_or_create() -> DeviceIdentity {
    let path = identity_path();
    if let Ok(bytes) = fs::read(&path) {
        if let Ok(identity) = serde_json::from_slice::<DeviceIdentity>(&bytes) {
            return identity;
        }
    }
    let identity = DeviceIdentity {
        id: Uuid::new_v4().to_string(),
        name: default_device_name(),
    };
    save(&identity);
    identity
}

pub fn save(identity: &DeviceIdentity) {
    if let Ok(bytes) = serde_json::to_vec_pretty(identity) {
        let path = identity_path();
        let _ = fs::write(&path, bytes);
        restrict_to_owner(&path);
    }
}

fn default_device_name() -> String {
    if let Ok(name) = std::env::var("COMPUTERNAME") {
        if !name.trim().is_empty() {
            return name;
        }
    }
    if let Ok(name) = std::env::var("HOSTNAME") {
        if !name.trim().is_empty() {
            return name;
        }
    }
    #[cfg(unix)]
    {
        if let Ok(out) = std::process::Command::new("hostname").output() {
            if let Ok(s) = String::from_utf8(out.stdout) {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
    }
    "Mon Appareil".to_string()
}

pub fn platform_label() -> &'static str {
    match std::env::consts::OS {
        "windows" => "windows",
        "macos" => "macos",
        "linux" => "linux",
        "android" => "android",
        "ios" => "ios",
        _ => "unknown",
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn restrict_to_owner_clears_group_and_world_bits() {
        let path = std::env::temp_dir().join(format!("zerosend-perm-test-{}", std::process::id()));
        fs::write(&path, b"secret").unwrap();
        // Simulate a permissive umask (e.g. 022 -> 644) before restricting.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        restrict_to_owner(&path);

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected owner-only permissions, got {mode:o}");

        fs::remove_file(&path).ok();
    }
}
