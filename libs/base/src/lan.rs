use hbb_common::config::DiscoveryPeer;
use std::{net::IpAddr, sync::Mutex};

/// Tailscale, RFC 1918 and IPv6 ULA / link-local: the addresses a Target
/// accepts and the Home list shows (ADR 0003). Public addresses never pass.
pub fn is_allowed(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            (a == 100 && (b & 0xc0) == 64) || v4.is_private()
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

/// Who answered the last finished discovery cycle (see [`end_cycle`]).
static ON_NETWORK: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// The address Home shows and connects to: an allowed one, IPv4 first. Empty when the peer only
/// answered from addresses a Target would refuse, or has left the network: it answered neither
/// the cycle running now nor the last finished one.
pub fn peer_ip(peer: &DiscoveryPeer) -> String {
    let answered = peer.online || ON_NETWORK.lock().map_or(false, |on| on.contains(&peer.id));
    if !answered {
        return String::new();
    }
    let mut ips: Vec<IpAddr> = peer
        .ip_mac
        .keys()
        .filter_map(|k| k.parse().ok())
        .filter(|ip| is_allowed(*ip))
        .collect();
    ips.sort_by_key(|ip| (!ip.is_ipv4(), *ip));
    ips.first().map(|ip| ip.to_string()).unwrap_or_default()
}

/// The end of a discovery cycle, which marks every stored peer offline and back online as it
/// answers. Whoever stayed offline has left: Home drops it, while the stored list keeps it for
/// the old LAN tab and wake-on-LAN.
pub fn end_cycle(peers: &[DiscoveryPeer]) {
    if let Ok(mut on) = ON_NETWORK.lock() {
        *on = peers.iter().filter(|p| p.online).map(|p| p.id.clone()).collect();
    }
}

/// The name this Mac was given in Setup / Settings (v1.7 t09 writes it).
pub const DEVICE_NAME_OPTION: &str = "boring-device-name";

/// What the LAN Discovery pong calls this Mac: the chosen name, else the hostname.
pub fn advertised_name(chosen: &str, hostname: String) -> String {
    let chosen = chosen.trim();
    if chosen.is_empty() {
        hostname
    } else {
        chosen.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: &str, online: bool, ips: &[&str]) -> DiscoveryPeer {
        DiscoveryPeer {
            id: id.to_owned(),
            hostname: format!("{}-mac", id),
            online,
            ip_mac: ips.iter().map(|i| (i.to_string(), "aa:bb".to_owned())).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn peer_ip_is_an_allowed_address_v4_first() {
        assert_eq!(peer_ip(&peer("a", true, &["fe80::1", "192.168.1.20"])), "192.168.1.20");
        assert_eq!(peer_ip(&peer("a", true, &["8.8.8.8", "fe80::1"])), "fe80::1");
        assert_eq!(peer_ip(&peer("a", true, &["8.8.8.8", "junk"])), "");
    }

    #[test]
    fn a_mac_that_left_drops_off_home_but_stays_in_the_stored_list() {
        let mut peers = vec![peer("left-a", true, &["10.0.0.2"]), peer("left-b", true, &["10.0.0.3"])];
        end_cycle(&peers);
        // Next cycle: everyone is offline until they answer. "a" answers, "b" has left.
        peers[0].online = true;
        peers[1].online = false;
        assert_eq!(peer_ip(&peers[1]), "10.0.0.3", "still listed while the cycle runs");
        end_cycle(&peers);
        assert_eq!(peer_ip(&peers[0]), "10.0.0.2");
        assert_eq!(peer_ip(&peers[1]), "", "gone from Home after one cycle");
        assert_eq!(peers.len(), 2, "the LAN tab and wake-on-LAN keep it");
    }

    #[test]
    fn pong_carries_the_chosen_mac_name_else_the_hostname() {
        assert_eq!(advertised_name(" Edit Bay 2 ", "edit-bay.local".to_owned()), "Edit Bay 2");
        assert_eq!(advertised_name("  ", "edit-bay.local".to_owned()), "edit-bay.local");
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn tailscale_and_private_lan_are_allowed() {
        for s in [
            "100.64.0.1", "100.127.255.254", "10.0.0.5", "172.16.0.1", "172.31.255.1",
            "192.168.1.20", "fd7a:115c:a1e0::1", "fd12:3456::1", "fe80::1", "::ffff:192.168.1.20",
        ] {
            assert!(is_allowed(ip(s)), "{}", s);
        }
    }

    #[test]
    fn public_addresses_stay_blocked() {
        for s in [
            "8.8.8.8", "100.128.0.1", "100.63.255.255", "172.32.0.1", "172.15.0.1", "192.169.0.1",
            "11.0.0.1", "2606:4700::1111", "::ffff:8.8.8.8",
        ] {
            assert!(!is_allowed(ip(s)), "{}", s);
        }
    }
}
