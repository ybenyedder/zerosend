use crate::client;
use crate::identity::platform_label;
use crate::state::{save_settings, AppState};
use crate::trust;
use crate::types::{DeviceInfo, Peer, Settings, TrustedPeer};
use std::sync::Arc;
use tauri::{Emitter, State};

#[tauri::command]
pub async fn get_device(state: State<'_, Arc<AppState>>) -> Result<DeviceInfo, String> {
    let name = state.settings.read().await.device_name.clone();
    Ok(DeviceInfo {
        id: state.identity.id.clone(),
        name,
        platform: platform_label().to_string(),
        fingerprint: state.tls.fingerprint.clone(),
    })
}

#[tauri::command]
pub async fn list_peers(state: State<'_, Arc<AppState>>) -> Result<Vec<Peer>, String> {
    let peers = state.peers.read().await;
    Ok(peers.values().cloned().collect())
}

#[tauri::command]
pub async fn get_settings(state: State<'_, Arc<AppState>>) -> Result<Settings, String> {
    Ok(state.settings.read().await.clone())
}

#[tauri::command]
pub async fn update_settings(
    state: State<'_, Arc<AppState>>,
    device_name: String,
    download_dir: String,
    require_approval: bool,
    stealth_mode: bool,
    max_transfer_mb: u64,
) -> Result<Settings, String> {
    if device_name.trim().is_empty() {
        return Err("Le nom de l'appareil ne peut pas être vide".to_string());
    }
    let trimmed_dir = download_dir.trim();
    if trimmed_dir.is_empty() {
        return Err("Le dossier de réception ne peut pas être vide".to_string());
    }
    // The device name is broadcast in every announce and shown on peers'
    // screens: normalise it the same way an incoming peer name is (control
    // characters stripped, length bounded) rather than storing raw input.
    let clean_name = trust::clean_display_name(&device_name);
    let mut settings = state.settings.write().await;
    settings.device_name = clean_name;
    settings.download_dir = trimmed_dir.to_string();
    settings.require_approval = require_approval;
    settings.stealth_mode = stealth_mode;
    settings.max_transfer_mb = max_transfer_mb;
    save_settings(&settings);
    Ok(settings.clone())
}

#[tauri::command]
pub async fn send_files_to_peer(
    state: State<'_, Arc<AppState>>,
    peer_id: String,
    paths: Vec<String>,
) -> Result<String, String> {
    if paths.is_empty() {
        return Err("Aucun fichier sélectionné".to_string());
    }
    let peer = {
        let peers = state.peers.read().await;
        peers.get(&peer_id).cloned()
    }
    .ok_or_else(|| "Appareil introuvable (hors ligne ?)".to_string())?;

    let inner: Arc<AppState> = state.inner().clone();
    Ok(client::send_files(inner, peer, paths))
}

/// The persistent TOFU pins, decorated with whatever display data is at hand,
/// so the settings panel can show which devices this one currently trusts.
#[tauri::command]
pub async fn list_trusted_peers(
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<TrustedPeer>, String> {
    let known = state.known_peers.read().await;
    let names = state.peer_names.read().await;
    let peers = state.peers.read().await;
    let mut list: Vec<TrustedPeer> = known
        .iter()
        .map(|(id, fingerprint)| {
            let live = peers.get(id);
            TrustedPeer {
                id: id.clone(),
                fingerprint: fingerprint.clone(),
                name: live
                    .map(|p| p.name.clone())
                    .or_else(|| names.get(id).cloned()),
                online: live.is_some(),
            }
        })
        .collect();
    list.sort_by(|a, b| {
        b.online
            .cmp(&a.online)
            .then_with(|| {
                a.name
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .cmp(&b.name.as_deref().unwrap_or("").to_lowercase())
            })
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(list)
}

/// Drops the TOFU pin for a peer whose identity legitimately changed
/// (reinstall, regenerated certificate) so it can be trusted again on next
/// contact. Until the user does this, a mismatched fingerprint stays rejected
/// — fail-closed is the right default, this command is the recovery path.
#[tauri::command]
pub async fn forget_peer(state: State<'_, Arc<AppState>>, peer_id: String) -> Result<(), String> {
    {
        let mut known = state.known_peers.write().await;
        if known.remove(&peer_id).is_none() {
            return Err("Appareil inconnu".to_string());
        }
        trust::save(&known);
        let mut names = state.peer_names.write().await;
        if names.remove(&peer_id).is_some() {
            trust::save_names(&names);
        }
    }
    // Drop it from the live table too: the next announce re-pins from scratch
    // instead of the stale entry lingering until the prune timeout.
    state.peers.write().await.remove(&peer_id);
    let _ = state.app_handle.emit("peers-changed", ());
    Ok(())
}

#[tauri::command]
pub async fn respond_to_transfer(
    state: State<'_, Arc<AppState>>,
    transfer_id: String,
    accept: bool,
) -> Result<(), String> {
    let mut pending = state.pending_transfers.lock().await;
    let transfer = pending
        .get_mut(&transfer_id)
        .ok_or_else(|| "Transfert déjà expiré".to_string())?;
    if let Some(tx) = transfer.responder.take() {
        let _ = tx.send(accept);
    }
    if !accept {
        pending.remove(&transfer_id);
    }
    Ok(())
}
