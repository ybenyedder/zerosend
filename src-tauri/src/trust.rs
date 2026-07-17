use crate::identity::{config_dir, restrict_to_owner};
use std::collections::HashMap;
use std::fs;

/// Persistent map of peer id -> TLS certificate fingerprint, built up from past
/// LAN discovery. This is what makes `pinning::PinnedFingerprintVerifier` mean
/// something: `Peer.id` and `Peer.fingerprint` both come from the same
/// unauthenticated UDP broadcast (see `discovery::Announce`), so pinning a send
/// to "whatever fingerprint the last announce for this id claimed" is worthless
/// against an attacker who controls that announce — they simply broadcast their
/// own certificate's fingerprint alongside a spoofed, already-known id. Recording
/// the fingerprint the *first* time an id is seen and refusing to silently accept
/// a different one afterwards (TOFU, same model as SSH's `known_hosts`) is what
/// actually stops that spoof: the attacker cannot reproduce the real device's
/// private key, so their differing fingerprint gets rejected instead of trusted.
///
/// This does not (and cannot, without a shared PKI or a manual verification
/// step) protect a peer id that is being seen for the very first time — exactly
/// like SSH TOFU, first contact is trust-on-faith, which is why the UI also
/// exposes the fingerprint for manual visual comparison.
fn known_peers_path() -> std::path::PathBuf {
    config_dir().join("known_peers.json")
}

pub fn load() -> HashMap<String, String> {
    fs::read(known_peers_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub fn save(known: &HashMap<String, String>) {
    if let Ok(bytes) = serde_json::to_vec_pretty(known) {
        let path = known_peers_path();
        let _ = fs::write(&path, bytes);
        restrict_to_owner(&path);
    }
}

/// Whether an announce claiming `id` with `fingerprint` should be trusted given
/// the pins recorded so far: yes on first contact or on a match, no if `id` was
/// already pinned to a *different* fingerprint.
pub fn should_trust(known: &HashMap<String, String>, id: &str, fingerprint: &str) -> bool {
    match known.get(id) {
        Some(pinned) => pinned == fingerprint,
        None => true,
    }
}

/// Hard cap on the number of pins the store will hold. Every announce (and
/// every manually accepted transfer) from a never-seen id inserts an entry, so
/// without a bound, a device flooding the LAN with random ids would grow
/// `known_peers.json` — and the in-memory map — indefinitely.
pub const MAX_KNOWN_PEERS: usize = 512;

#[derive(Debug, PartialEq, Eq)]
pub enum PinOutcome {
    /// The id was already pinned to this same fingerprint — nothing to save.
    AlreadyPinned,
    /// A new pin was recorded — the caller should persist the store.
    Inserted,
    /// The store is at capacity and the id is new — nothing was recorded, so
    /// no TOFU guarantee exists for this id. Callers should fail closed.
    StoreFull,
}

/// Records `id -> fingerprint` on first contact. Callers must have already
/// checked [`should_trust`] — pinning over a *different* existing fingerprint
/// is never done here (the existing pin always wins).
pub fn pin(known: &mut HashMap<String, String>, id: &str, fingerprint: &str) -> PinOutcome {
    if known.contains_key(id) {
        return PinOutcome::AlreadyPinned;
    }
    if known.len() >= MAX_KNOWN_PEERS {
        return PinOutcome::StoreFull;
    }
    known.insert(id.to_string(), fingerprint.to_string());
    PinOutcome::Inserted
}

/// Trust status of an *incoming* transfer request, based on the TLS-proven
/// client fingerprint (mTLS) rather than anything declared in the payload.
#[derive(Debug, PartialEq, Eq)]
pub enum IncomingTrust {
    /// The sender id is pinned to a different fingerprint — either an
    /// impersonation attempt or a peer whose identity was legitimately
    /// regenerated; both must be rejected until the user forgets the pin.
    Impersonation,
    /// The sender id is pinned to exactly this fingerprint.
    KnownPeer,
    /// Never-seen sender id: cannot be authenticated automatically (same
    /// first-contact limit as SSH TOFU) — requires explicit user approval.
    FirstContact,
}

pub fn evaluate_incoming(
    known: &HashMap<String, String>,
    sender_id: &str,
    client_fingerprint: &str,
) -> IncomingTrust {
    match known.get(sender_id) {
        Some(pinned) if pinned == client_fingerprint => IncomingTrust::KnownPeer,
        Some(_) => IncomingTrust::Impersonation,
        None => IncomingTrust::FirstContact,
    }
}

/// Longest display name accepted from the network. Announce and transfer
/// payloads are peer-controlled — without a bound a peer could persist and
/// render arbitrarily large strings.
pub const MAX_DISPLAY_NAME_CHARS: usize = 64;

/// Normalizes a peer-supplied display name before it is rendered or persisted:
/// bounded length, no control characters, sensible fallback when empty.
pub fn clean_display_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_DISPLAY_NAME_CHARS)
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "Appareil".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Best-effort id -> last-seen display name, persisted separately from the
/// TOFU pins: names are presentation data with no security weight (any peer
/// can call itself anything), so they never influence a trust decision — but
/// they make the "trusted devices" list readable when a device is offline.
/// Only ids that are actually pinned get a stored name, which also bounds
/// this map by [`MAX_KNOWN_PEERS`].
fn peer_names_path() -> std::path::PathBuf {
    config_dir().join("peer_names.json")
}

pub fn load_names() -> HashMap<String, String> {
    fs::read(peer_names_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub fn save_names(names: &HashMap<String, String>) {
    if let Ok(bytes) = serde_json::to_vec_pretty(names) {
        let path = peer_names_path();
        let _ = fs::write(&path, bytes);
        restrict_to_owner(&path);
    }
}

/// Records the display name for a *pinned* id if it changed. Returns true when
/// the map was modified (callers persist only in that case, since discovery
/// re-announces every couple of seconds).
pub fn remember_name(
    known: &HashMap<String, String>,
    names: &mut HashMap<String, String>,
    id: &str,
    raw_name: &str,
) -> bool {
    if !known.contains_key(id) {
        return false;
    }
    let cleaned = clean_display_name(raw_name);
    if names.get(id) == Some(&cleaned) {
        return false;
    }
    names.insert(id.to_string(), cleaned);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_trust_first_contact() {
        let known = HashMap::new();
        assert!(should_trust(&known, "peer-a", "AA:BB"));
    }

    #[test]
    fn should_trust_matching_pin() {
        let mut known = HashMap::new();
        known.insert("peer-a".to_string(), "AA:BB".to_string());
        assert!(should_trust(&known, "peer-a", "AA:BB"));
    }

    #[test]
    fn should_not_trust_mismatched_pin() {
        let mut known = HashMap::new();
        known.insert("peer-a".to_string(), "AA:BB".to_string());
        assert!(!should_trust(&known, "peer-a", "FF:EE"));
    }

    #[test]
    fn pin_inserts_on_first_contact_and_is_idempotent() {
        let mut known = HashMap::new();
        assert_eq!(pin(&mut known, "peer-a", "AA:BB"), PinOutcome::Inserted);
        assert_eq!(known.get("peer-a").map(String::as_str), Some("AA:BB"));
        assert_eq!(pin(&mut known, "peer-a", "AA:BB"), PinOutcome::AlreadyPinned);
    }

    #[test]
    fn pin_never_overwrites_an_existing_pin() {
        let mut known = HashMap::new();
        known.insert("peer-a".to_string(), "AA:BB".to_string());
        assert_eq!(pin(&mut known, "peer-a", "FF:EE"), PinOutcome::AlreadyPinned);
        assert_eq!(known.get("peer-a").map(String::as_str), Some("AA:BB"));
    }

    #[test]
    fn pin_refuses_new_entries_once_full() {
        let mut known = HashMap::new();
        for i in 0..MAX_KNOWN_PEERS {
            known.insert(format!("peer-{i}"), "AA:BB".to_string());
        }
        assert_eq!(pin(&mut known, "peer-new", "CC:DD"), PinOutcome::StoreFull);
        assert!(!known.contains_key("peer-new"));
        // An id already present is still recognized at capacity.
        assert_eq!(pin(&mut known, "peer-0", "AA:BB"), PinOutcome::AlreadyPinned);
    }

    #[test]
    fn clean_display_name_bounds_and_falls_back() {
        assert_eq!(clean_display_name("  Mon PC  "), "Mon PC");
        assert_eq!(clean_display_name(""), "Appareil");
        assert_eq!(clean_display_name(" \t\n "), "Appareil");
        assert_eq!(clean_display_name("a\u{0007}b\u{001b}[31mc"), "ab[31mc");
        let long = "x".repeat(500);
        assert_eq!(clean_display_name(&long).chars().count(), MAX_DISPLAY_NAME_CHARS);
    }

    #[test]
    fn remember_name_only_records_pinned_ids_and_reports_changes() {
        let mut known = HashMap::new();
        let mut names = HashMap::new();

        // Unpinned id: nothing recorded.
        assert!(!remember_name(&known, &mut names, "peer-a", "PC"));
        assert!(names.is_empty());

        known.insert("peer-a".to_string(), "AA:BB".to_string());
        assert!(remember_name(&known, &mut names, "peer-a", " PC "));
        assert_eq!(names.get("peer-a").map(String::as_str), Some("PC"));
        // Unchanged name: no write needed.
        assert!(!remember_name(&known, &mut names, "peer-a", "PC"));
        // Renamed device: recorded again.
        assert!(remember_name(&known, &mut names, "peer-a", "Portable"));
        assert_eq!(names.get("peer-a").map(String::as_str), Some("Portable"));
    }

    #[test]
    fn evaluate_incoming_matches_pin_state() {
        let mut known = HashMap::new();
        assert_eq!(
            evaluate_incoming(&known, "peer-a", "AA:BB"),
            IncomingTrust::FirstContact
        );
        known.insert("peer-a".to_string(), "AA:BB".to_string());
        assert_eq!(
            evaluate_incoming(&known, "peer-a", "AA:BB"),
            IncomingTrust::KnownPeer
        );
        assert_eq!(
            evaluate_incoming(&known, "peer-a", "FF:EE"),
            IncomingTrust::Impersonation
        );
    }
}
