//! Connect plan (ticket 08, spec slice 3): tailnet first, the Hosted servers as fallback.
//!
//! A saved machine is its Machine ID plus, when known, its tailnet address. The address is
//! learned only over a stream that verified the Target against the baked server key
//! (`remember_tailnet`): the Target reports it, after login, in `PeerInfo.platform_additions`.
//! Connect order for a saved Machine ID: Direct IP to the tailnet address (`TAILNET_TIMEOUT_MS`),
//! then the Machine ID through the Hosted servers (RustDesk's punch-through, relay last). A typed
//! address or tailnet name keeps today's Direct IP path, with no fallback.
//!
//! `plan` is pure; the I/O stays in `client.rs` (`boring_tailnet_first`, then upstream's
//! rendezvous path).
use std::{collections::HashMap, net::IpAddr};

/// Peer option holding a saved Machine ID's tailnet address.
pub const TAILNET_OPTION: &str = "boring-tailnet-addr";
/// The Target's tailnet address in `PeerInfo.platform_additions` (JSON, no protocol change).
pub const ADDITIONS_KEY: &str = "boring_tailnet";
/// How long the tailnet address gets before the Hosted servers are tried.
pub const TAILNET_TIMEOUT_MS: u64 = 3_000;
/// Stream label for a direct path across the tailnet (the session shows "Tailnet direct").
pub const TAILNET_STREAM: &str = "Tailnet";
/// The Hosted servers didn't answer. Also the translation key (src/lang/*.rs).
pub const HOSTED_DOWN: &str = "Can't reach the Boring Remote servers (rs.theboringremote.com). Check this computer's internet connection, or connect by Tailscale name or IP.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attempt {
    /// A typed address or tailnet name: today's Direct IP path, nothing after it.
    DirectIp(String),
    /// A saved Machine ID's tailnet address, Direct IP, for `TAILNET_TIMEOUT_MS`.
    Tailnet(String),
    /// The Machine ID through the Hosted servers: punch-through first, relay last.
    Hosted(String),
}

/// What the connect box was given, and what is saved for it.
#[derive(Debug, Clone, Copy)]
pub struct PeerRecord<'a> {
    pub id: &'a str,
    pub tailnet: Option<&'a str>,
}

/// What is known about the paths before trying them.
#[derive(Debug, Clone, Copy)]
pub struct Reach {
    /// This computer has a tailnet address (Tailscale is up here).
    pub tailnet_up: bool,
    /// The peer is set to always connect via relay.
    pub relay_only: bool,
}

fn is_tailnet(ip: IpAddr) -> bool {
    crate::client::boring_is_tailnet(std::net::SocketAddr::new(ip, 0))
}

/// The attempts, in order. The caller stops at the first that connects.
pub fn plan(peer: &PeerRecord, reach: Reach) -> Vec<Attempt> {
    if !crate::client::boring_is_machine_id(peer.id) {
        return vec![Attempt::DirectIp(peer.id.to_owned())];
    }
    let mut attempts = Vec::new();
    let saved = peer.tailnet.and_then(|a| a.parse::<IpAddr>().ok()).filter(|ip| is_tailnet(*ip));
    if let Some(ip) = saved {
        if reach.tailnet_up && !reach.relay_only {
            attempts.push(Attempt::Tailnet(ip.to_string()));
        }
    }
    attempts.push(Attempt::Hosted(peer.id.to_owned()));
    attempts
}

/// The stream label the session shows: `TAILNET_STREAM` for a direct path whose local end is a
/// tailnet address (WireGuard), else upstream's label (direct or relayed, shown from `direct`).
pub fn stream_label(stream_type: &'static str, direct: bool, local: IpAddr) -> &'static str {
    if direct && is_tailnet(local) {
        TAILNET_STREAM
    } else {
        stream_type
    }
}

/// After login: a Machine ID keeps the tailnet address its Target reports, only over a stream
/// that verified that Target against the baked server key (`verified`: the stream is keyed, and
/// `Client::start` runs a Machine ID with the baked key only; ticket 07). Nothing else writes the
/// option, so a typed name, a tailnet-first stream or an unverified one can't point a saved
/// machine at another address. A verified Target that reports none (off its tailnet, or older)
/// clears it.
pub fn remember_tailnet(options: &mut HashMap<String, String>, id: &str, verified: bool, additions: &str) {
    if !verified || !crate::client::boring_is_machine_id(id) {
        return;
    }
    let reported = serde_json::from_str::<serde_json::Value>(additions)
        .ok()
        .and_then(|v| v.get(ADDITIONS_KEY)?.as_str()?.parse::<IpAddr>().ok())
        .filter(|ip| is_tailnet(*ip));
    match reported {
        Some(ip) => options.insert(TAILNET_OPTION.to_owned(), ip.to_string()),
        None => options.remove(TAILNET_OPTION),
    };
}

/// `remember_tailnet` on the saved machine `id`, from the stream that carried its login
/// (`secured`). Before `handle_peer_info`, which loads the config it saves.
pub fn save_reported_tailnet(id: &str, secured: bool, additions: &str) {
    if !(secured && crate::client::boring_is_machine_id(id)) {
        return;
    }
    let mut config = hbb_common::config::PeerConfig::load(id);
    let before = config.options.get(TAILNET_OPTION).cloned();
    remember_tailnet(&mut config.options, id, secured, additions);
    if config.options.get(TAILNET_OPTION) != before.as_ref() {
        config.store(id);
    }
}

/// This computer's tailnet address, if Tailscale is up: the local address the system picks to
/// reach Tailscale's own 100.100.100.100. Connecting a UDP socket sends nothing.
pub fn own_tailnet_addr() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("100.100.100.100:53").ok()?;
    let ip = socket.local_addr().ok()?.ip();
    is_tailnet(ip).then_some(ip)
}

/// Target side: report this computer's tailnet address after login (`remember_tailnet`).
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
pub fn add_own_tailnet(additions: &mut serde_json::Map<String, serde_json::Value>) {
    if let Some(ip) = own_tailnet_addr() {
        additions.insert(ADDITIONS_KEY.to_owned(), serde_json::Value::String(ip.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "123456789";
    const UP: Reach = Reach { tailnet_up: true, relay_only: false };

    fn saved(tailnet: Option<&str>) -> Vec<Attempt> {
        plan(&PeerRecord { id: ID, tailnet }, UP)
    }

    #[test]
    fn tailnet_known_tries_the_tailnet_first_then_the_machine_id() {
        assert_eq!(
            saved(Some("100.101.102.103")),
            vec![Attempt::Tailnet("100.101.102.103".into()), Attempt::Hosted(ID.into())]
        );
    }

    #[test]
    fn no_tailnet_goes_by_machine_id_only() {
        assert_eq!(saved(None), vec![Attempt::Hosted(ID.into())]);
    }

    #[test]
    fn typed_tailnet_address_or_name_keeps_direct_ip_only() {
        for typed in ["100.101.102.103", "studio", "studio.tail1234.ts.net"] {
            let record = PeerRecord { id: typed, tailnet: Some("100.64.0.9") };
            assert_eq!(plan(&record, UP), vec![Attempt::DirectIp(typed.into())]);
        }
    }

    #[test]
    fn tailscale_off_here_or_relay_only_skips_the_tailnet() {
        let record = PeerRecord { id: ID, tailnet: Some("100.101.102.103") };
        let off = Reach { tailnet_up: false, relay_only: false };
        let relay = Reach { tailnet_up: true, relay_only: true };
        assert_eq!(plan(&record, off), vec![Attempt::Hosted(ID.into())]);
        assert_eq!(plan(&record, relay), vec![Attempt::Hosted(ID.into())]);
    }

    #[test]
    fn a_saved_address_outside_tailscale_is_never_dialed() {
        assert_eq!(saved(Some("192.168.1.20")), vec![Attempt::Hosted(ID.into())]);
    }

    #[test]
    fn the_session_shows_tailnet_direct_direct_or_relayed() {
        let tailnet: IpAddr = "100.70.1.2".parse().unwrap();
        let lan: IpAddr = "192.168.1.5".parse().unwrap();
        assert_eq!(stream_label("TCP", true, tailnet), "Tailnet");
        assert_eq!(stream_label("TCP", true, lan), "TCP");
        assert_eq!(stream_label("Relay", false, tailnet), "Relay");
    }

    #[test]
    fn hosted_down_error_names_our_servers() {
        assert!(HOSTED_DOWN.contains("rs.theboringremote.com"));
        assert!(!HOSTED_DOWN.starts_with("Failed"), "start() would append 'Please try later'");
    }

    fn remembered(verified: bool, additions: &str) -> Option<String> {
        let mut options = HashMap::from([(TAILNET_OPTION.to_owned(), "100.64.0.1".to_owned())]);
        remember_tailnet(&mut options, ID, verified, additions);
        options.get(TAILNET_OPTION).cloned()
    }

    #[test]
    fn a_verified_target_records_its_tailnet_address() {
        let reported = r#"{"boring_tailnet":"100.101.102.103"}"#;
        assert_eq!(remembered(true, reported).as_deref(), Some("100.101.102.103"));
        assert_eq!(remembered(true, "{}"), None);
        assert_eq!(remembered(true, r#"{"boring_tailnet":"192.168.1.20"}"#), None);
    }

    #[test]
    fn an_unverified_or_tailnet_first_stream_changes_nothing() {
        let reported = r#"{"boring_tailnet":"100.101.102.103"}"#;
        assert_eq!(remembered(false, reported).as_deref(), Some("100.64.0.1"));
        let mut options = HashMap::new();
        remember_tailnet(&mut options, "studio.tail1.ts.net", true, reported);
        assert!(options.is_empty());
    }
}
