use hbb_common::config::{Config, DiscoveryPeer};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

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

// --- v1.7 t21: discovery that finds the other computer both ways --------------------------
// Upstream discovery is one broadcast to 255.255.255.255 from every interface. A computer is
// listed only if that broadcast reached it and its reply came back in the same 3 s. Broadcast is
// the first thing Wi-Fi loses (lowest rate, no retries, held for sleeping laptops), so a laptop on
// Wi-Fi can list nobody while a wired Mac lists everyone. So each cycle also asks, one to one,
// every computer this one has seen before and every computer that pinged this one lately.

/// Where one discovery socket sends its ping. `locals` is every interface IPv4 with its prefix.
/// The catch-all socket (0.0.0.0) sends the plain broadcast and asks each `known` computer directly;
/// a socket on an interface sends that interface's own broadcast (it follows the interface, not the
/// default route). Loopback, point-to-point links (Tailscale's utun is a /32) and addresses no
/// interface has get nothing: sending there only fails (macOS: "No route to host", "Can't assign
/// requested address").
pub fn ping_targets(socket_ip: Ipv4Addr, locals: &[(Ipv4Addr, u8)], known: &[Ipv4Addr], port: u16) -> Vec<SocketAddr> {
    if socket_ip.is_unspecified() {
        let mut out = vec![SocketAddr::from((Ipv4Addr::BROADCAST, port))];
        out.extend(
            known
                .iter()
                .filter(|ip| !locals.iter().any(|(l, _)| l == *ip))
                .map(|ip| SocketAddr::from((*ip, port))),
        );
        return out;
    }
    if socket_ip.is_loopback() {
        return vec![];
    }
    match locals.iter().find(|(l, _)| *l == socket_ip) {
        Some((_, prefix)) if *prefix < 31 => {
            let host_bits = u32::MAX >> *prefix;
            vec![SocketAddr::from((Ipv4Addr::from(u32::from(socket_ip) | host_bits), port))]
        }
        _ => vec![],
    }
}

/// Most computers asked directly per cycle, so a long stored list can't turn a ping into a flood.
const MAX_KNOWN: usize = 64;

/// The computers to ask directly: every allowed IPv4 a stored peer answered from, then whoever
/// pinged this one lately ([`heard_ips`]), each once.
pub fn known_ips(peers: &[DiscoveryPeer], heard: &[IpAddr]) -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = Vec::new();
    let stored = peers.iter().flat_map(|p| p.ip_mac.keys().filter_map(|k| k.parse::<IpAddr>().ok()));
    for ip in stored.chain(heard.iter().copied()) {
        let v4 = match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(v6) => v6.to_ipv4_mapped(),
        };
        if let Some(v4) = v4 {
            if is_allowed(IpAddr::V4(v4)) && !out.contains(&v4) && out.len() < MAX_KNOWN {
                out.push(v4);
            }
        }
    }
    out
}

/// Sends `ping` from every socket to its [`ping_targets`]. Expected failures stay out of the log
/// file; if most pings fail (macOS Local Network turned off for Boring Remote does that), one line
/// a minute says so.
pub fn send_pings(sockets: &[UdpSocket], ping: &[u8], port: u16, peers: &[DiscoveryPeer], locals: &[(Ipv4Addr, u8)]) {
    let known = known_ips(peers, &heard_ips(&heard_path(), now_secs()));
    let (mut sent, mut failed) = (0, 0);
    let mut last_err = None;
    for socket in sockets {
        let ip = match socket.local_addr() {
            Ok(SocketAddr::V4(a)) => *a.ip(),
            _ => continue,
        };
        for to in ping_targets(ip, locals, &known, port) {
            match socket.send_to(ping, to) {
                Ok(_) => sent += 1,
                Err(e) => {
                    log::trace!("LAN discovery ping {} -> {}: {}", ip, to, e);
                    failed += 1;
                    last_err = Some(e);
                }
            }
        }
    }
    if let Some(e) = last_err {
        if failed > sent {
            hbb_common::throttled_log!(
                std::time::Duration::from_secs(60),
                warn,
                "LAN discovery: {} of {} pings failed, last: {}",
                failed,
                sent + failed,
                e
            );
        }
    }
}

/// Seconds a ping from another computer keeps it on the ask-directly list.
const HEARD_FOR: u64 = 600;
/// A computer pinging every 6 s rewrites its line at most this often.
const HEARD_REFRESH: u64 = 30;
const MAX_HEARD: usize = 32;

/// The listener (in the process that serves sessions) and discovery (in the window) share this
/// file. On a Mac both run as the signed-in user, so they share the folder; on Windows the service
/// has its own folder and this is a no-op, which is fine: the PC asks known computers directly too.
fn heard_path() -> PathBuf {
    Config::path("lan_heard")
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `heard` file lines: "<ip> <unix seconds>". Fresh entries only, newest first.
fn parse_heard(text: &str, now: u64) -> Vec<(IpAddr, u64)> {
    let mut out: Vec<(IpAddr, u64)> = text
        .lines()
        .filter_map(|l| {
            let (ip, at) = l.trim().split_once(' ')?;
            Some((ip.parse().ok()?, at.parse().ok()?))
        })
        .filter(|(_, at)| *at <= now && now - *at <= HEARD_FOR)
        .collect();
    out.sort_by(|a, b| b.1.cmp(&a.1));
    out
}

/// The file's new text once `ip` pinged at `now`, or None when nothing needs writing (it is
/// already there and fresh) or `ip` is not an address a Target accepts.
pub fn heard_update(text: &str, ip: IpAddr, now: u64) -> Option<String> {
    if !is_allowed(ip) {
        return None;
    }
    let mut list = parse_heard(text, now);
    if list.iter().any(|(i, at)| *i == ip && now - *at < HEARD_REFRESH) {
        return None;
    }
    list.retain(|(i, _)| *i != ip);
    list.insert(0, (ip, now));
    list.truncate(MAX_HEARD);
    Some(list.iter().map(|(i, at)| format!("{} {}\n", i, at)).collect())
}

/// Who pinged this computer within [`HEARD_FOR`], from the shared file at `path`.
pub fn heard_ips(path: &Path, now: u64) -> Vec<IpAddr> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    parse_heard(&text, now).into_iter().map(|(ip, _)| ip).collect()
}

/// The listener got a ping from `ip`: next cycle, discovery asks it directly. So if either
/// computer's broadcast gets through, both end up listing each other.
pub fn heard_ping(ip: IpAddr) {
    let path = heard_path();
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    if let Some(new) = heard_update(&text, ip, now_secs()) {
        if let Err(e) = std::fs::write(&path, new) {
            hbb_common::throttled_log!(std::time::Duration::from_secs(300), warn, "LAN heard list: {}", e);
        }
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

    // --- t21 ---
    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    const PORT: u16 = 21119;

    fn studio() -> Vec<(Ipv4Addr, u8)> {
        // The Studio on 2026-11-03: Ethernet and Wi-Fi on one /24, Tailscale /32, loopback.
        vec![(v4("192.168.1.123"), 24), (v4("192.168.1.106"), 24), (v4("100.117.206.90"), 32), (v4("127.0.0.1"), 8)]
    }

    #[test]
    fn unusable_interfaces_get_no_ping_so_the_log_stays_quiet() {
        assert!(ping_targets(v4("127.0.0.1"), &studio(), &[], PORT).is_empty(), "loopback: error 49");
        assert!(ping_targets(v4("100.117.206.90"), &studio(), &[], PORT).is_empty(), "Tailscale /32: error 65");
        assert!(ping_targets(v4("10.9.9.9"), &studio(), &[], PORT).is_empty(), "no interface has it");
    }

    #[test]
    fn an_interface_socket_sends_its_own_broadcast() {
        assert_eq!(ping_targets(v4("192.168.1.106"), &studio(), &[], PORT), vec!["192.168.1.255:21119".parse().unwrap()]);
        assert_eq!(ping_targets(v4("10.0.4.7"), &[(v4("10.0.4.7"), 16)], &[], PORT), vec!["10.0.255.255:21119".parse().unwrap()]);
    }

    #[test]
    fn the_catch_all_socket_broadcasts_and_asks_each_known_computer_directly() {
        let known = [v4("192.168.1.124"), v4("192.168.1.123")];
        let got = ping_targets(Ipv4Addr::UNSPECIFIED, &studio(), &known, PORT);
        assert_eq!(got, vec!["255.255.255.255:21119".parse().unwrap(), "192.168.1.124:21119".parse().unwrap()],
                   "never itself");
    }

    #[test]
    fn known_computers_are_the_stored_ones_then_whoever_pinged_once_each_lan_only() {
        // Tori's list on 2026-11-03: M1-D2 stored but offline, so it was never asked again.
        let mut pc = peer("303012600", false, &["192.168.1.124"]);
        pc.hostname = "M1-D2".to_owned();
        let peers = vec![pc, peer("x", false, &["8.8.8.8", "fe80::1"])];
        let heard = [ip("192.168.1.123"), ip("192.168.1.124"), ip("::ffff:10.0.0.9"), ip("1.1.1.1")];
        assert_eq!(known_ips(&peers, &heard), vec![v4("192.168.1.124"), v4("192.168.1.123"), v4("10.0.0.9")]);
    }

    #[test]
    fn known_computers_are_capped() {
        let heard: Vec<IpAddr> = (0..200u32).map(|i| IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i))).collect();
        assert_eq!(known_ips(&[], &heard).len(), 64);
    }

    #[test]
    fn a_ping_heard_is_remembered_for_ten_minutes() {
        let t = heard_update("", ip("192.168.1.124"), 1000).unwrap();
        assert_eq!(parse_heard(&t, 1000 + 600).len(), 1);
        assert!(parse_heard(&t, 1000 + 601).is_empty(), "gone after ten minutes");
        assert!(parse_heard("junk\n192.168.1.5 notanumber\n", 10).is_empty());
    }

    #[test]
    fn a_ping_every_six_seconds_rewrites_the_file_at_most_every_thirty() {
        let t = heard_update("", ip("192.168.1.124"), 1000).unwrap();
        assert_eq!(heard_update(&t, ip("192.168.1.124"), 1006), None);
        let t2 = heard_update(&t, ip("192.168.1.124"), 1030).unwrap();
        assert_eq!(t2, "192.168.1.124 1030\n", "one line per computer");
        let t3 = heard_update(&t2, ip("192.168.1.123"), 1031).unwrap();
        assert_eq!(t3, "192.168.1.123 1031\n192.168.1.124 1030\n", "newest first");
    }

    #[test]
    fn only_addresses_a_target_accepts_are_remembered() {
        assert_eq!(heard_update("", ip("8.8.8.8"), 1000), None);
    }

    #[test]
    fn the_heard_list_is_capped() {
        let mut t = String::new();
        for i in 0..40u32 {
            t = heard_update(&t, IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i)), 1000 + i as u64).unwrap();
        }
        assert_eq!(parse_heard(&t, 1040).len(), 32);
    }

    #[test]
    fn heard_ips_reads_the_shared_file() {
        let dir = std::env::temp_dir().join(format!("boring-lan-heard-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lan_heard");
        std::fs::write(&path, heard_update("", ip("192.168.1.124"), 1000).unwrap()).unwrap();
        assert_eq!(heard_ips(&path, 1001), vec![ip("192.168.1.124")]);
        assert!(heard_ips(&dir.join("missing"), 1001).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_direct_ask_reaches_a_listener() {
        // A stand-in listener on loopback, found through the catch-all socket's direct ask.
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        listener.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        let port = listener.local_addr().unwrap().port();
        let known = [v4("127.0.0.1")];
        let catch_all = UdpSocket::bind("0.0.0.0:0").unwrap();
        for to in ping_targets(Ipv4Addr::UNSPECIFIED, &[], &known, port).into_iter().skip(1) {
            catch_all.send_to(b"ping", to).unwrap();
        }
        let mut buf = [0u8; 8];
        let (n, _) = listener.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ping");
    }
}
