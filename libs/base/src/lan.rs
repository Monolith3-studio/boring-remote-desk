use hbb_common::config::DiscoveryPeer;
use std::net::IpAddr;

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

/// The address Home shows and connects to: an allowed one, IPv4 first.
/// Empty when the peer only answered from addresses a Target would refuse.
pub fn peer_ip(peer: &DiscoveryPeer) -> String {
    let mut ips: Vec<IpAddr> = peer
        .ip_mac
        .keys()
        .filter_map(|k| k.parse().ok())
        .filter(|ip| is_allowed(*ip))
        .collect();
    ips.sort_by_key(|ip| (!ip.is_ipv4(), *ip));
    ips.first().map(|ip| ip.to_string()).unwrap_or_default()
}

/// A discovery cycle marks every stored peer offline and back online as it
/// answers; whoever stayed offline has left the network.
pub fn drop_stale(peers: &mut Vec<DiscoveryPeer>) {
    peers.retain(|p| p.online);
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
    fn peers_that_did_not_answer_this_cycle_drop_off() {
        let mut peers = vec![peer("a", true, &["10.0.0.2"]), peer("b", false, &["10.0.0.3"])];
        drop_stale(&mut peers);
        assert_eq!(peers.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(), ["a"]);
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
