use crate::identity::platform_label;
use crate::state::{now_ms, AppState};
use crate::trust;
use crate::types::{Announce, Peer};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tauri::Emitter;
use tokio::net::UdpSocket;
use tokio::time::interval;

/// Fixed local-network discovery port. Traffic on this port never leaves the LAN:
/// it is sent strictly to the IPv4 broadcast address (255.255.255.255).
pub const DISCOVERY_PORT: u16 = 58017;
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(2);
const PEER_TIMEOUT_MS: u64 = 8_000;

/// Protocol version this build announces. v2 = the receiving API requires a
/// TLS client certificate (mTLS); a v1 sender can no longer complete the
/// handshake against us, so the bump makes the incompatibility explicit.
const PROTO_VERSION: u32 = 2;
/// Oldest announce version still displayed as a peer: we can still *send to*
/// a v1 device (its server doesn't request a client certificate — presenting
/// one is then simply skipped), it just can't send to us anymore.
const MIN_PROTO: u32 = 1;

/// Generous byte bounds on peer-controlled announce fields, far above anything
/// this app itself emits (ids are 36-char UUIDs, fingerprints 95 chars): a
/// packet exceeding them is either garbage or someone probing — not a peer.
const MAX_ID_LEN: usize = 64;
const MAX_FINGERPRINT_LEN: usize = 128;
/// Bounds on the two free-text announce fields. Both are peer-controlled and
/// end up rendered (name after `clean_display_name`, platform after mapping),
/// so reject a packet whose fields are absurdly long outright — real values are
/// a short label and a ≤64-char device name.
const MAX_NAME_LEN: usize = 256;
const MAX_PLATFORM_LEN: usize = 32;

/// Whether an announce is structurally acceptable before any trust decision.
fn announce_is_sane(a: &Announce) -> bool {
    a.app == "zerosend"
        && (MIN_PROTO..=PROTO_VERSION).contains(&a.proto)
        && !a.id.is_empty()
        && a.id.len() <= MAX_ID_LEN
        && !a.fingerprint.is_empty()
        && a.fingerprint.len() <= MAX_FINGERPRINT_LEN
        && a.name.len() <= MAX_NAME_LEN
        && a.platform.len() <= MAX_PLATFORM_LEN
        && a.https_port != 0
}

/// Strips control characters from a peer-supplied platform label before it is
/// stored and rendered. Length is already bounded by `announce_is_sane`; the
/// frontend maps known values ("linux", "android", ...) and shows anything else
/// verbatim, so a stray control character would otherwise reach the DOM.
fn clean_platform(platform: &str) -> String {
    platform.chars().filter(|c| !c.is_control()).collect()
}

fn make_socket() -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_broadcast(true)?;
    socket.set_nonblocking(true)?;
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DISCOVERY_PORT);
    socket.bind(&addr.into())?;
    UdpSocket::from_std(socket.into())
}

pub fn spawn(state: Arc<AppState>) {
    let socket = match make_socket() {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("discovery: failed to bind UDP {DISCOVERY_PORT}: {e}");
            return;
        }
    };

    let announcer_socket = socket.clone();
    let announcer_state = state.clone();
    tokio::spawn(async move { run_announcer(announcer_state, announcer_socket).await });

    let listener_state = state.clone();
    tokio::spawn(async move { run_listener(listener_state, socket).await });

    tokio::spawn(async move { run_prune(state).await });
}

async fn run_announcer(state: Arc<AppState>, socket: Arc<UdpSocket>) {
    let broadcast_addr = SocketAddr::from((Ipv4Addr::BROADCAST, DISCOVERY_PORT));
    let mut ticker = interval(ANNOUNCE_INTERVAL);
    loop {
        ticker.tick().await;
        let https_port = state.https_port();
        if https_port == 0 {
            continue; // local HTTPS server not ready yet, nothing to advertise
        }
        let (name, stealth) = {
            let settings = state.settings.read().await;
            (settings.device_name.clone(), settings.stealth_mode)
        };
        if stealth {
            // Stealth mode: say nothing on the network. Peers prune us from
            // their lists within seconds; we can still see and send to them.
            continue;
        }
        let announce = Announce {
            app: "zerosend".to_string(),
            proto: PROTO_VERSION,
            id: state.identity.id.clone(),
            name,
            platform: platform_label().to_string(),
            fingerprint: state.tls.fingerprint.clone(),
            https_port,
        };
        if let Ok(bytes) = serde_json::to_vec(&announce) {
            let _ = socket.send_to(&bytes, broadcast_addr).await;
        }
    }
}

async fn run_listener(state: Arc<AppState>, socket: Arc<UdpSocket>) {
    let mut buf = [0u8; 2048];
    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Ok(announce) = serde_json::from_slice::<Announce>(&buf[..len]) else {
            continue;
        };
        if !announce_is_sane(&announce) || announce.id == state.identity.id {
            continue;
        }

        // `id` and `fingerprint` both come from this same unauthenticated UDP
        // packet, so trusting whichever fingerprint the latest announce for a
        // given id happens to carry (i.e. just overwriting the live peers table
        // unconditionally) would let an attacker impersonate an already-known
        // peer by broadcasting a spoofed id alongside their own certificate's
        // fingerprint — the outgoing TLS pin would then match trivially. Pin on
        // first contact and reject a later, different fingerprint for the same
        // id instead (TOFU, same model as SSH `known_hosts`).
        {
            let mut known = state.known_peers.write().await;
            if !trust::should_trust(&known, &announce.id, &announce.fingerprint) {
                eprintln!(
                    "discovery: annonce ignoree pour le pair {} — l'empreinte ne correspond plus \
                     a celle memorisee (usurpation possible ou identite du pair regeneree)",
                    announce.id
                );
                continue;
            }
            match trust::pin(&mut known, &announce.id, &announce.fingerprint) {
                trust::PinOutcome::Inserted => trust::save(&known),
                // No pin means no TOFU guarantee for this id — showing the peer
                // anyway would make an outgoing send trust whatever the latest
                // announce claims. Fail closed until the store has room.
                trust::PinOutcome::StoreFull => {
                    eprintln!(
                        "discovery: store de pairs connus plein — annonce de {} ignoree",
                        announce.id
                    );
                    continue;
                }
                trust::PinOutcome::AlreadyPinned => {}
            }

            let mut names = state.peer_names.write().await;
            if trust::remember_name(&known, &mut names, &announce.id, &announce.name) {
                trust::save_names(&names);
            }
        }

        let peer = Peer {
            id: announce.id.clone(),
            name: trust::clean_display_name(&announce.name),
            platform: clean_platform(&announce.platform),
            fingerprint: announce.fingerprint,
            address: src.ip().to_string(),
            https_port: announce.https_port,
            last_seen_ms: now_ms(),
        };
        let mut peers = state.peers.write().await;
        // Emit not only when a brand-new peer appears but also when a known one
        // changes anything the UI shows (rename, moved to a new address/port,
        // regenerated fingerprint) — otherwise those updates wait up to the 5 s
        // frontend poll instead of refreshing promptly.
        let changed = match peers.get(&peer.id) {
            None => true,
            Some(existing) => {
                existing.name != peer.name
                    || existing.platform != peer.platform
                    || existing.address != peer.address
                    || existing.https_port != peer.https_port
                    || existing.fingerprint != peer.fingerprint
            }
        };
        peers.insert(peer.id.clone(), peer);
        drop(peers);
        if changed {
            let _ = state.app_handle.emit("peers-changed", ());
        }
    }
}

async fn run_prune(state: Arc<AppState>) {
    let mut ticker = interval(Duration::from_secs(3));
    loop {
        ticker.tick().await;
        let now = now_ms();
        let mut peers = state.peers.write().await;
        let before = peers.len();
        peers.retain(|_, p| now.saturating_sub(p.last_seen_ms) < PEER_TIMEOUT_MS);
        let changed = peers.len() != before;
        drop(peers);
        if changed {
            let _ = state.app_handle.emit("peers-changed", ());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_announce() -> Announce {
        Announce {
            app: "zerosend".to_string(),
            proto: PROTO_VERSION,
            id: "3e9f9c66-3a3e-4d38-9c56-1b2f7a1a2b3c".to_string(),
            name: "PC".to_string(),
            platform: "linux".to_string(),
            fingerprint: "AA:BB".to_string(),
            https_port: 40123,
        }
    }

    #[test]
    fn announce_is_sane_accepts_current_and_previous_proto() {
        assert!(announce_is_sane(&valid_announce()));
        let mut v1 = valid_announce();
        v1.proto = MIN_PROTO;
        assert!(announce_is_sane(&v1));
    }

    #[test]
    fn announce_is_sane_rejects_foreign_or_malformed_packets() {
        let mut wrong_app = valid_announce();
        wrong_app.app = "autre".to_string();
        assert!(!announce_is_sane(&wrong_app));

        let mut proto_zero = valid_announce();
        proto_zero.proto = 0;
        assert!(!announce_is_sane(&proto_zero));

        let mut proto_future = valid_announce();
        proto_future.proto = PROTO_VERSION + 1;
        assert!(!announce_is_sane(&proto_future));

        let mut empty_id = valid_announce();
        empty_id.id = String::new();
        assert!(!announce_is_sane(&empty_id));

        let mut huge_id = valid_announce();
        huge_id.id = "x".repeat(MAX_ID_LEN + 1);
        assert!(!announce_is_sane(&huge_id));

        let mut huge_fp = valid_announce();
        huge_fp.fingerprint = "A".repeat(MAX_FINGERPRINT_LEN + 1);
        assert!(!announce_is_sane(&huge_fp));

        let mut huge_name = valid_announce();
        huge_name.name = "x".repeat(MAX_NAME_LEN + 1);
        assert!(!announce_is_sane(&huge_name));

        let mut huge_platform = valid_announce();
        huge_platform.platform = "p".repeat(MAX_PLATFORM_LEN + 1);
        assert!(!announce_is_sane(&huge_platform));

        let mut no_port = valid_announce();
        no_port.https_port = 0;
        assert!(!announce_is_sane(&no_port));
    }

    #[test]
    fn clean_platform_strips_control_characters() {
        assert_eq!(clean_platform("linux"), "linux");
        assert_eq!(clean_platform("lin\u{0007}ux\u{001b}"), "linux");
    }
}
