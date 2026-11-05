use hbb_common::config::{Config, DiscoveryPeer};
use serde_derive::{Deserialize, Serialize};
use std::{
    collections::HashMap,
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
    // boring-remote (v1.7 t25): a Target that listed its addresses is shown at its fastest one.
    if let Some(best) = ranked(&advert_of(&peer.id), &local_nics()).first() {
        return best.ip.to_string();
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
    // boring-remote (v1.7 t25): who stayed silent has no live addresses; Known keeps the stored ones.
    if let Ok(mut adverts) = ADVERTS.lock() {
        if let Some(adverts) = adverts.as_mut() {
            adverts.retain(|id, _| !peers.iter().any(|p| !p.online && p.id == *id));
        }
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

// --- v1.7 t25: every LAN address of a computer, fastest first ---------------------------------
// A computer with Ethernet and Wi-Fi on one network answers discovery from whichever its routing
// picks, so Home listed the Wi-Fi address and sessions and file transfers crawled over it. The pong
// now lists every LAN address with its link type and speed, in `PeerDiscovery.misc` (a field
// upstream never fills, so the protocol files stay upstream's). An old peer sends none and an old
// Controller ignores it: both behave exactly as before. What arrives here is unauthenticated, so
// it only ever picks what to dial: every dial is still encrypted and pinned (direct_link.rs).

/// What carries an address. Serialized lowercase; a word from a newer build reads as `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkKind {
    Wired,
    #[serde(rename = "wifi")]
    WiFi,
    #[default]
    #[serde(other)]
    Other,
}

impl LinkKind {
    /// The path through two ends: as slow as its slower end, and unknown if either end is unknown
    /// and neither is Wi-Fi, so the badge never claims a wire it can't vouch for.
    pub fn and(self, other: LinkKind) -> LinkKind {
        match (self, other) {
            (LinkKind::WiFi, _) | (_, LinkKind::WiFi) => LinkKind::WiFi,
            (LinkKind::Wired, LinkKind::Wired) => LinkKind::Wired,
            _ => LinkKind::Other,
        }
    }

    fn order(self) -> u8 {
        match self {
            LinkKind::Wired => 0,
            LinkKind::Other => 1,
            LinkKind::WiFi => 2,
        }
    }
}

/// One address a computer can be dialled at. `mbps` 0 is unknown (a Mac can't say for Wi-Fi).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    pub ip: IpAddr,
    #[serde(default)]
    pub link: LinkKind,
    #[serde(default)]
    pub mbps: u32,
}

/// One IPv4 address of one of this computer's interfaces. `label` is the OS's words for it (Windows
/// keeps the useful ones there, its `name` is a GUID). src/lan.rs reads them from default_net.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nic {
    pub name: String,
    pub label: String,
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub link: LinkKind,
    pub mbps: u32,
}

/// Most addresses one computer can list, so a spoofed pong can't turn into a scan.
pub const MAX_ADDRS: usize = 8;

/// A private LAN address, not Tailscale's: Tailscale keeps its own fallback slot. Never public (ADR 0003).
pub fn is_lan(ip: IpAddr) -> bool {
    is_allowed(ip) && !crate::direct_link::is_tailscale(ip)
}

/// Adapters that hold a private address nobody across the room can reach.
fn is_virtual(nic: &Nic) -> bool {
    const WORDS: [&str; 22] = [
        "virtual", "vethernet", "veth", "vmnet", "vmware", "vbox", "vnic", "hyper-v", "parallels", "wsl", "docker",
        "br-", "bridge", "tun", "tap", "vpn", "wireguard", "zerotier", "awdl", "llw", "bluetooth", "loopback",
    ];
    let text = format!("{} {}", nic.name, nic.label).to_lowercase();
    WORDS.iter().any(|w| text.contains(w))
}

/// Windows reports a disconnected adapter's speed as all ones.
pub fn mbps_from_bps(bps: Option<u64>) -> u32 {
    match bps {
        Some(b) if b < 1_000_000_000_000 => (b / 1_000_000) as u32,
        _ => 0,
    }
}

fn on_subnet(ip: IpAddr, nic: &Nic) -> bool {
    let IpAddr::V4(v4) = ip else { return false };
    let mask = u32::MAX.checked_shl(32 - nic.prefix.min(32) as u32).unwrap_or(0);
    u32::from(v4) & mask == u32::from(nic.ip) & mask
}

fn nic_for(ip: IpAddr, here: &[Nic]) -> bool {
    here.is_empty() || here.iter().any(|n| on_subnet(ip, n))
}

/// Fastest first: on a network this computer is on, then wired before unknown before Wi-Fi, then
/// the higher speed. With `here` empty (no interface list yet) every address counts as reachable.
pub fn ranked(list: &[Address], here: &[Nic]) -> Vec<Address> {
    let mut out = list.to_vec();
    out.sort_by_key(|a| (!nic_for(a.ip, here), a.link.order(), std::cmp::Reverse(a.mbps), !a.ip.is_ipv4(), a.ip));
    out
}

#[derive(Serialize, Deserialize)]
struct Advert {
    addrs: Vec<serde_json::Value>,
}

/// What the pong's `misc` says: this computer's LAN addresses, best first. "" when it has none.
pub fn advert(nics: &[Nic]) -> String {
    let list: Vec<Address> = nics
        .iter()
        .filter(|n| is_lan(IpAddr::V4(n.ip)) && !is_virtual(n))
        .map(|n| Address { ip: IpAddr::V4(n.ip), link: n.link, mbps: n.mbps })
        .collect();
    if list.is_empty() {
        return String::new();
    }
    let addrs = ranked(&list, &[]).into_iter().take(MAX_ADDRS).filter_map(|a| serde_json::to_value(a).ok()).collect();
    serde_json::to_string(&Advert { addrs }).unwrap_or_default()
}

/// The addresses in a pong's `misc`, each checked here: public, Tailscale and junk entries are dropped.
pub fn parse_advert(misc: &str) -> Vec<Address> {
    let Ok(advert) = serde_json::from_str::<Advert>(misc) else { return vec![] };
    lenient(advert.addrs)
}

/// JSON values to addresses: one bad entry never costs the others, and only LAN addresses pass.
pub fn lenient(values: Vec<serde_json::Value>) -> Vec<Address> {
    values
        .into_iter()
        .filter_map(|v| serde_json::from_value::<Address>(v).ok())
        .filter(|a| is_lan(a.ip))
        .take(MAX_ADDRS)
        .collect()
}

/// Target ID -> the addresses it listed in its latest pong.
static ADVERTS: Mutex<Option<HashMap<String, Vec<Address>>>> = Mutex::new(None);
/// This computer's interfaces as of the last discovery cycle ([`set_local_nics`]).
static LOCAL_NICS: Mutex<Vec<Nic>> = Mutex::new(Vec::new());

/// A pong came in. Remembers what it listed and returns the `ip_mac` to store: the address it came
/// from plus every address it listed, so the next cycle asks each of them directly and a computer
/// that lost one is still found on the other. A pong listing nothing gives exactly what it always did.
pub fn pong_addresses(id: &str, source: IpAddr, mac: &str, misc: &str) -> HashMap<String, String> {
    let mut list = parse_advert(misc);
    let mut map = HashMap::from([(source.to_string(), mac.to_owned())]);
    for a in &list {
        map.entry(a.ip.to_string()).or_insert_with(|| mac.to_owned());
    }
    if let Ok(mut adverts) = ADVERTS.lock() {
        let adverts = adverts.get_or_insert_with(HashMap::new);
        if list.is_empty() {
            adverts.remove(id);
        } else {
            if is_lan(source) && !list.iter().any(|a| a.ip == source) {
                list.push(Address { ip: source, link: LinkKind::Other, mbps: 0 });
            }
            adverts.insert(id.to_owned(), list);
        }
    }
    map
}

/// What `id` listed in its latest pong. Empty for an old peer, or one that has left.
pub fn advert_of(id: &str) -> Vec<Address> {
    ADVERTS.lock().ok().and_then(|a| a.as_ref().and_then(|a| a.get(id).cloned())).unwrap_or_default()
}

/// Which computer last listed `ip`.
pub fn advert_owner(ip: IpAddr) -> Option<String> {
    let adverts = ADVERTS.lock().ok()?;
    adverts.as_ref()?.iter().find(|(_, list)| list.iter().any(|a| a.ip == ip)).map(|(id, _)| id.clone())
}

pub fn set_local_nics(nics: Vec<Nic>) {
    if let Ok(mut here) = LOCAL_NICS.lock() {
        *here = nics;
    }
}

pub fn local_nics() -> Vec<Nic> {
    LOCAL_NICS.lock().map(|n| n.clone()).unwrap_or_default()
}

/// The link under one of this computer's own addresses.
pub fn local_link(ip: IpAddr, here: &[Nic]) -> LinkKind {
    here.iter().find(|n| IpAddr::V4(n.ip) == ip).map_or(LinkKind::Other, |n| n.link)
}

/// The source address to dial `target` from. This computer with two ways onto that network leaves
/// by the fastest: without this the OS uses whichever service comes first, which on a Mac can be
/// Wi-Fi with a wire plugged in. One way, or none, is the OS's call.
pub fn source_for(target: IpAddr, here: &[Nic]) -> Option<IpAddr> {
    let ways: Vec<&Nic> = here.iter().filter(|n| on_subnet(target, n) && !is_virtual(n)).collect();
    if ways.len() < 2 {
        return None;
    }
    ways.into_iter().min_by_key(|n| (n.link.order(), std::cmp::Reverse(n.mbps))).map(|n| IpAddr::V4(n.ip))
}

/// A wire's speed from ifconfig's media line: "autoselect (5000Base-T <full-duplex>)", "1000baseT",
/// "10Gbase-T". 0 when it doesn't say (Wi-Fi never does).
fn media_mbps(line: &str) -> u32 {
    let Some(inner) = line.split('(').nth(1) else { return 0 };
    let word = inner.split_whitespace().next().unwrap_or_default().to_lowercase();
    if !word.contains("base") {
        return 0;
    }
    let digits: String = word.chars().take_while(|c| c.is_ascii_digit()).collect();
    let n: u32 = digits.parse().unwrap_or(0);
    if word[digits.len()..].starts_with('g') {
        n.saturating_mul(1000)
    } else {
        n
    }
}

/// Fills in what default_net doesn't give on a Mac, from `ifconfig` text: each wire's speed. An
/// interface ifconfig calls inactive is dropped: a static IP stays on an unplugged port.
pub fn with_media(nics: Vec<Nic>, ifconfig: &str) -> Vec<Nic> {
    let mut seen: HashMap<&str, (bool, u32)> = HashMap::new();
    let mut name = "";
    for line in ifconfig.lines() {
        if !line.starts_with(|c: char| c.is_whitespace()) {
            name = line.split(':').next().unwrap_or_default();
        } else if let Some(media) = line.trim().strip_prefix("media:") {
            seen.entry(name).or_insert((true, 0)).1 = media_mbps(media);
        } else if let Some(status) = line.trim().strip_prefix("status:") {
            seen.entry(name).or_insert((true, 0)).0 = status.trim() == "active";
        }
    }
    nics.into_iter()
        .filter(|n| seen.get(n.name.as_str()).map_or(true, |(active, _)| *active))
        .map(|mut n| {
            if n.mbps == 0 {
                n.mbps = seen.get(n.name.as_str()).map_or(0, |(_, mbps)| *mbps);
            }
            n
        })
        .collect()
}

/// [`with_media`] with this Mac's own `ifconfig`, read at most once per 5 s: a discovery cycle
/// answers several pings. Other systems report speed through default_net.
#[cfg(target_os = "macos")]
pub fn with_live_media(nics: Vec<Nic>) -> Vec<Nic> {
    static CACHE: Mutex<Option<(std::time::Instant, String)>> = Mutex::new(None);
    let Ok(mut cache) = CACHE.lock() else { return nics };
    if cache.as_ref().map_or(true, |(at, _)| at.elapsed().as_secs() >= 5) {
        let out = std::process::Command::new("/sbin/ifconfig").output();
        let text = out.map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
        *cache = Some((std::time::Instant::now(), text));
    }
    with_media(nics, cache.as_ref().map_or("", |(_, t)| t.as_str()))
}

#[cfg(not(target_os = "macos"))]
pub fn with_live_media(nics: Vec<Nic>) -> Vec<Nic> {
    nics
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

    // --- v1.7 t25: every LAN address, fastest first -----------------------------------------
    fn nic(name: &str, ip: &str, prefix: u8, link: LinkKind, mbps: u32) -> Nic {
        Nic { name: name.into(), label: String::new(), ip: v4(ip), prefix, link, mbps }
    }

    fn addr(ip: &str, link: LinkKind, mbps: u32) -> Address {
        Address { ip: self::ip(ip), link, mbps }
    }

    /// Tori's laptop on 2026-11-04: USB Ethernet en10, Wi-Fi en0, Tailscale, loopback.
    fn tori() -> Vec<Nic> {
        vec![
            nic("en0", "192.168.1.79", 24, LinkKind::WiFi, 0),
            nic("en10", "192.168.1.112", 24, LinkKind::Wired, 1000),
            nic("utun4", "100.117.206.91", 32, LinkKind::Other, 0),
            nic("lo0", "127.0.0.1", 8, LinkKind::Other, 0),
        ]
    }

    fn ips(list: &[Address]) -> Vec<String> {
        list.iter().map(|a| a.ip.to_string()).collect()
    }

    #[test]
    fn the_pong_lists_lan_addresses_with_link_and_speed_and_nothing_else() {
        let got = parse_advert(&advert(&tori()));
        assert_eq!(got, vec![addr("192.168.1.112", LinkKind::Wired, 1000), addr("192.168.1.79", LinkKind::WiFi, 0)]);
    }

    #[test]
    fn virtual_adapters_public_and_link_local_addresses_are_not_advertised() {
        let mut nics = vec![
            nic("docker0", "172.17.0.1", 16, LinkKind::Other, 0),
            nic("bridge100", "192.168.64.1", 24, LinkKind::Other, 0),
            nic("en5", "169.254.10.2", 16, LinkKind::Wired, 1000),
            nic("en6", "8.8.4.4", 24, LinkKind::Wired, 1000),
        ];
        let mut hyperv = nic("{GUID}", "172.20.0.1", 20, LinkKind::Wired, 10_000);
        hyperv.label = "vEthernet (WSL) Hyper-V Virtual Ethernet Adapter".into();
        nics.push(hyperv);
        assert_eq!(advert(&nics), "", "nothing to say: a pong as an old build sends it");
    }

    #[test]
    fn an_advert_keeps_only_private_lan_addresses_and_survives_junk() {
        assert!(parse_advert("").is_empty(), "an old peer");
        assert!(parse_advert("not json").is_empty());
        assert!(parse_advert(r#"{"addrs":"nope"}"#).is_empty());
        let got = parse_advert(
            r#"{"addrs":[{"ip":"8.8.8.8","link":"wired","mbps":1000},{"ip":"junk"},{"ip":"100.100.1.1","link":"wired"},
                {"ip":"127.0.0.1"},{"ip":"192.168.1.112","link":"warp","mbps":10}]}"#,
        );
        assert_eq!(got, vec![addr("192.168.1.112", LinkKind::Other, 10)], "never a public address (ADR 0003)");
    }

    #[test]
    fn an_advert_is_capped_so_a_spoofed_pong_cannot_become_a_scan() {
        let list: Vec<String> = (1..200).map(|i| format!(r#"{{"ip":"10.0.0.{}"}}"#, i)).collect();
        assert_eq!(parse_advert(&format!(r#"{{"addrs":[{}]}}"#, list.join(","))).len(), MAX_ADDRS);
    }

    #[test]
    fn a_full_advert_fits_the_discovery_buffer() {
        let nics: Vec<Nic> = (1..=20).map(|i| nic("en1", &format!("192.168.100.{}", 100 + i), 24, LinkKind::Wired, 10_000)).collect();
        assert!(advert(&nics).len() < 1024, "the reply buffer is 2048 with the other fields");
    }

    #[test]
    fn wired_beats_wifi_and_the_faster_wire_beats_the_slower() {
        let studio = [nic("en0", "192.168.1.200", 24, LinkKind::Wired, 5000)];
        let tori_list = [addr("192.168.1.79", LinkKind::WiFi, 0), addr("192.168.1.112", LinkKind::Wired, 1000)];
        assert_eq!(ips(&ranked(&tori_list, &studio)), ["192.168.1.112", "192.168.1.79"]);
        // The Studio's own pair, and the PC's 1 Gb Ethernet against a 130 Mb USB Wi-Fi stick.
        let list = [addr("192.168.1.106", LinkKind::WiFi, 0), addr("192.168.1.123", LinkKind::Wired, 5000)];
        assert_eq!(ips(&ranked(&list, &[])), ["192.168.1.123", "192.168.1.106"]);
        let list = [addr("192.168.1.124", LinkKind::WiFi, 130), addr("192.168.1.127", LinkKind::Wired, 1000)];
        assert_eq!(ips(&ranked(&list, &[])), ["192.168.1.127", "192.168.1.124"]);
        let list = [addr("10.0.0.2", LinkKind::Wired, 1000), addr("10.0.0.3", LinkKind::Wired, 5000), addr("10.0.0.4", LinkKind::Wired, 0)];
        assert_eq!(ips(&ranked(&list, &[])), ["10.0.0.3", "10.0.0.2", "10.0.0.4"]);
    }

    #[test]
    fn a_link_type_nobody_named_ranks_between_wired_and_wifi() {
        let list = [addr("10.0.0.2", LinkKind::WiFi, 900), addr("10.0.0.3", LinkKind::Other, 0), addr("10.0.0.4", LinkKind::Wired, 0)];
        assert_eq!(ips(&ranked(&list, &[])), ["10.0.0.4", "10.0.0.3", "10.0.0.2"]);
    }

    #[test]
    fn an_address_on_a_network_this_computer_is_on_comes_first_even_if_slower() {
        // The Target's 10 Gb wire goes to a storage network this Controller isn't on.
        let here = [nic("en0", "192.168.1.200", 24, LinkKind::WiFi, 0)];
        let list = [addr("10.10.0.5", LinkKind::Wired, 10_000), addr("192.168.1.79", LinkKind::WiFi, 0)];
        assert_eq!(ips(&ranked(&list, &here)), ["192.168.1.79", "10.10.0.5"]);
    }

    #[test]
    fn home_lists_the_wired_address_of_tori_not_the_wifi_one() {
        // The pong came from .79, the address Home lists today.
        let map = pong_addresses("t25-tori", ip("192.168.1.79"), "aa:bb", &advert(&tori()));
        assert_eq!(map.len(), 2, "the stored list keeps both, so discovery asks both directly");
        let mut p = peer("t25-tori", true, &[]);
        p.ip_mac = map;
        assert_eq!(peer_ip(&p), "192.168.1.112");
    }

    #[test]
    fn an_old_peer_with_one_address_behaves_as_it_does_today() {
        let map = pong_addresses("t25-old", ip("192.168.1.50"), "aa:bb", "");
        assert_eq!(map, std::collections::HashMap::from([("192.168.1.50".to_owned(), "aa:bb".to_owned())]));
        let mut p = peer("t25-old", true, &[]);
        p.ip_mac = map;
        assert_eq!(peer_ip(&p), "192.168.1.50");
        assert!(advert_of("t25-old").is_empty());
    }

    #[test]
    fn a_laptop_unplugged_moves_home_to_its_wifi_address_on_the_next_pong() {
        let mut p = peer("t25-unplug", true, &[]);
        p.ip_mac = pong_addresses("t25-unplug", ip("192.168.1.112"), "aa:bb", &advert(&tori()));
        assert_eq!(peer_ip(&p), "192.168.1.112");
        let unplugged: Vec<Nic> = tori().into_iter().filter(|n| n.name != "en10").collect();
        p.ip_mac = pong_addresses("t25-unplug", ip("192.168.1.79"), "aa:bb", &advert(&unplugged));
        assert_eq!(peer_ip(&p), "192.168.1.79");
        assert_eq!(ips(&advert_of("t25-unplug")), ["192.168.1.79"]);
    }

    #[test]
    fn a_pong_from_an_address_it_does_not_list_still_counts() {
        let list = r#"{"addrs":[{"ip":"192.168.1.60","link":"wired","mbps":1000}]}"#;
        let map = pong_addresses("t25-source", ip("192.168.1.61"), "aa:bb", list);
        assert!(map.contains_key("192.168.1.61") && map.contains_key("192.168.1.60"));
        assert_eq!(ips(&advert_of("t25-source")), ["192.168.1.60", "192.168.1.61"]);
    }

    #[test]
    fn who_left_the_network_loses_its_live_addresses() {
        pong_addresses("t25-gone", ip("192.168.1.70"), "aa:bb", &advert(&tori()));
        assert!(!advert_of("t25-gone").is_empty());
        end_cycle(&[peer("t25-gone", false, &["192.168.1.70"])]);
        assert!(advert_of("t25-gone").is_empty());
    }

    #[test]
    fn the_address_finds_its_computer() {
        pong_addresses("t25-owner", ip("192.168.77.1"), "aa:bb", r#"{"addrs":[{"ip":"192.168.77.2"}]}"#);
        assert_eq!(advert_owner(ip("192.168.77.2")).as_deref(), Some("t25-owner"));
        assert_eq!(advert_owner(ip("192.168.77.3")), None);
    }

    const IFCONFIG: &str = "en5: flags=8963<UP,BROADCAST> mtu 1500\n\tmedia: autoselect <full-duplex>\n\tstatus: inactive\n\
en0: flags=8863<UP,BROADCAST> mtu 1500\n\tinet 192.168.1.123 netmask 0xffffff00 broadcast 192.168.1.255\n\
\tmedia: autoselect (5000Base-T <full-duplex,flow-control,energy-efficient-ethernet>)\n\tstatus: active\n\
en1: flags=8863<UP,BROADCAST> mtu 1500\n\tinet 192.168.1.106 netmask 0xffffff00\n\tmedia: autoselect\n\tstatus: active\n\
en10: flags=8863<UP> mtu 1500\n\tmedia: autoselect (1000baseT <full-duplex>)\n\tstatus: active\n\
en11: flags=8863<UP> mtu 1500\n\tmedia: autoselect (10Gbase-T <full-duplex>)\n\tstatus: active\n\
en12: flags=8863<UP> mtu 1500\n\tmedia: autoselect (100baseTX <full-duplex>)\n\tstatus: active\n";

    #[test]
    fn windows_all_ones_speed_is_unknown() {
        assert_eq!(mbps_from_bps(Some(1_000_000_000)), 1000);
        assert_eq!(mbps_from_bps(Some(u64::MAX)), 0);
        assert_eq!(mbps_from_bps(None), 0);
    }

    #[test]
    fn a_macs_wire_speed_comes_from_ifconfig() {
        let nics = vec![
            nic("en0", "192.168.1.123", 24, LinkKind::Wired, 0),
            nic("en1", "192.168.1.106", 24, LinkKind::WiFi, 0),
            nic("en10", "10.0.0.2", 24, LinkKind::Wired, 0),
            nic("en11", "10.0.0.3", 24, LinkKind::Wired, 0),
            nic("en12", "10.0.0.4", 24, LinkKind::Wired, 0),
            nic("utun1", "100.100.1.1", 32, LinkKind::Other, 0),
        ];
        let got: Vec<(String, u32)> = with_media(nics, IFCONFIG).into_iter().map(|n| (n.name, n.mbps)).collect();
        let want = [("en0", 5000), ("en1", 0), ("en10", 1000), ("en11", 10_000), ("en12", 100), ("utun1", 0)];
        assert_eq!(got, want.map(|(n, m)| (n.to_owned(), m)));
    }

    #[test]
    fn an_interface_the_mac_says_is_inactive_is_not_offered() {
        // A static IP stays on an unplugged port: its status is what says so.
        let nics = vec![nic("en5", "192.168.1.200", 24, LinkKind::Wired, 0)];
        assert!(with_media(nics, IFCONFIG).is_empty());
    }

    #[test]
    fn a_controller_with_two_ways_out_leaves_by_the_wire() {
        let studio = [nic("en1", "192.168.1.106", 24, LinkKind::WiFi, 0), nic("en0", "192.168.1.123", 24, LinkKind::Wired, 5000)];
        assert_eq!(source_for(ip("192.168.1.112"), &studio), Some(ip("192.168.1.123")));
        assert_eq!(source_for(ip("10.0.0.5"), &studio), None, "no shared network: the OS routes it");
        assert_eq!(source_for(ip("192.168.1.112"), &studio[..1]), None, "one way out: nothing to pick");
    }

    #[test]
    fn the_path_is_as_slow_as_its_slower_end() {
        use LinkKind::*;
        assert_eq!(Wired.and(Wired), Wired);
        assert_eq!(Wired.and(WiFi), WiFi);
        assert_eq!(WiFi.and(Wired), WiFi);
        assert_eq!(WiFi.and(Other), WiFi);
        assert_eq!(Wired.and(Other), Other, "an old peer's end is unknown, so nothing is claimed");
    }
}
