//! Connect plan (tickets 08 and 16 on 1.7's Direct Link, spec slice 3): a Machine ID tries a
//! Direct Link first, the Hosted servers after.
//!
//! A name or address typed in the connect box is 1.7's Direct Link and nothing else. A Machine ID
//! (digits) is dialled where Boring Remote has met it, as a Direct Link (encrypted, the Target's
//! identity key pinned): its LAN addresses while LAN Discovery sees it on this network, and the
//! Tailscale address it last gave (over a Direct Link, or reported after login over a verified
//! Hosted session, `save_reported`). The Tailscale and last address get `DIRECT_FIRST_MS`. Only that
//! Machine ID answering counts (`base::direct_link::connect_machine_id`). Anything else, a timeout
//! or a refusal, goes on to the Hosted servers (RustDesk's punch-through, relay last), where the
//! servers' word under the baked key and the same pin (`pin_target`) verify the Target again. So a
//! tailnet path is never trusted for its address range: it is the Direct Link handshake that
//! verifies who answered (ticket 16 resolved by 1.7's encrypted Direct Link).
//!
//! `plan` is pure; `direct_first` is the one hook in `client.rs` `_start`.
use hbb_common::{
    anyhow::{anyhow, Error},
    log, Stream,
};
use std::net::IpAddr;

/// The Target's tailnet address in `PeerInfo.platform_additions` (JSON, no protocol change).
pub const ADDITIONS_KEY: &str = "boring_tailnet";
/// How long a Machine ID's Tailscale (or last) address gets before the Hosted servers are tried.
pub const DIRECT_FIRST_MS: u64 = 3_000;
/// The Hosted servers didn't answer. Also the translation key (src/lang/*.rs).
pub const HOSTED_DOWN: &str = "Can't reach the Boring Remote servers (rs.theboringremote.com). Check this computer's internet connection, or connect by Tailscale name or IP.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    /// 1.7's Direct Link: encrypted, the Target's identity key pinned.
    DirectLink,
    /// The Machine ID through the Hosted servers: punch-through first, relay last.
    Hosted,
}

/// The attempts, in order; the caller stops at the first that connects. `known`: Boring Remote
/// has somewhere to dial this Machine ID as a Direct Link. `relay_only`: the session is set to
/// always go through the relay.
pub fn plan(peer: &str, known: bool, relay_only: bool) -> Vec<Attempt> {
    if !crate::client::boring_is_machine_id(peer) {
        return vec![Attempt::DirectLink];
    }
    let mut attempts = Vec::new();
    if known && !relay_only {
        attempts.push(Attempt::DirectLink);
    }
    attempts.push(Attempt::Hosted);
    attempts
}

/// A Machine ID's Direct Link attempt (`plan`): the stream, its route and the Target's identity
/// key, or None to go on to the Hosted servers.
pub async fn direct_first(
    peer: &str,
    relay_only: bool,
) -> Option<(Stream, base::direct_link::Route, Option<Vec<u8>>)> {
    let known = base::direct_link::Known::load();
    let first = plan(peer, base::direct_link::machine_id_known(peer, &known), relay_only);
    if first.first() != Some(&Attempt::DirectLink) {
        return None;
    }
    match base::direct_link::connect_machine_id(peer, DIRECT_FIRST_MS, known).await {
        Ok(x) => Some(x),
        Err(err) => {
            log::info!("Direct Link to {peer} didn't connect ({err}); trying the Hosted servers");
            None
        }
    }
}

/// io_loop and port_forward, on a keyed stream to a Machine ID: the Target's identity key keeps
/// the one this Controller first verified for that Machine ID (`base::direct_link::Known`, the same
/// pin a Direct Link holds). A new Machine ID is pinned now. False: another key (refused; a
/// reinstalled Target needs Forget), or none.
pub fn pin_target(id: &str, pk: Option<&[u8]>) -> bool {
    let Some(pk) = pk.filter(|pk| pk.len() == 32) else {
        return false;
    };
    let mut known = base::direct_link::Known::load();
    let before = known.clone();
    let ok = known.pin_id(id, pk);
    if known != before {
        known.save();
    }
    ok
}

/// After login on a keyed stream to a Machine ID (`secured`; pinned by `pin_target`): keep the
/// tailnet address its Target reports, for the next connect's Direct Link. Only a Tailscale address
/// counts, only for a Target already pinned.
pub fn save_reported(id: &str, secured: bool, additions: &str) {
    if !(secured && crate::client::boring_is_machine_id(id)) {
        return;
    }
    let reported = serde_json::from_str::<serde_json::Value>(additions)
        .ok()
        .and_then(|v| v.get(ADDITIONS_KEY)?.as_str()?.parse::<IpAddr>().ok());
    if let Some(ip) = reported {
        let mut known = base::direct_link::Known::load();
        if known.learn_tailscale(id, ip) {
            known.save();
        }
    }
}

/// The Hosted servers' rendezvous connection failed: the plain error naming them.
pub fn hosted_down(err: Error) -> Error {
    log::warn!("Hosted servers unreachable: {err}");
    anyhow!(HOSTED_DOWN)
}

/// A connection error from the Hosted path, said plainly when it is our relay that failed.
pub fn hosted_error(err: Error) -> Error {
    if err.to_string().starts_with("Failed to connect via relay server") {
        hosted_down(err)
    } else {
        err
    }
}

/// This computer's tailnet address, if Tailscale is up: the local address the system picks to
/// reach Tailscale's own 100.100.100.100. Connecting a UDP socket sends nothing.
pub fn own_tailnet_addr() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("100.100.100.100:53").ok()?;
    let ip = socket.local_addr().ok()?.ip();
    base::direct_link::is_tailscale(ip).then_some(ip)
}

/// Target side: report this computer's tailnet address after login (`save_reported`).
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

    #[test]
    fn a_machine_id_met_before_tries_a_direct_link_first_then_the_hosted_servers() {
        assert_eq!(plan(ID, true, false), vec![Attempt::DirectLink, Attempt::Hosted]);
    }

    #[test]
    fn a_machine_id_never_met_goes_by_the_hosted_servers_only() {
        assert_eq!(plan(ID, false, false), vec![Attempt::Hosted]);
    }

    #[test]
    fn relay_only_skips_the_direct_link() {
        assert_eq!(plan(ID, true, true), vec![Attempt::Hosted]);
    }

    #[test]
    fn a_typed_name_or_address_is_a_direct_link_only() {
        for typed in ["100.101.102.103", "edit-bay-2", "edit-bay-2.tail1234.ts.net:21118", "192.168.1.20", "123@x"] {
            assert_eq!(plan(typed, true, false), vec![Attempt::DirectLink], "{typed}");
            assert_eq!(plan(typed, false, true), vec![Attempt::DirectLink], "{typed}");
        }
    }

    #[test]
    fn hosted_down_error_names_our_servers() {
        assert!(HOSTED_DOWN.contains("rs.theboringremote.com"));
        let e = hosted_error(anyhow!("Failed to connect via relay server: x"));
        assert_eq!(e.to_string(), HOSTED_DOWN);
        assert_eq!(hosted_error(anyhow!("Remote desktop is offline")).to_string(), "Remote desktop is offline");
    }
}
