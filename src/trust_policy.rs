//! Trusted Controllers (ticket 06, spec slice 4).
//!
//! The Target keeps a list of approved Controllers: each one's Machine ID and its own Ed25519
//! public key (`Config::get_key_pair()`, the key it signs its ID with when it is a Target). A
//! Controller not on the list needs a click on the Target's existing accept prompt, even with
//! the right password. Approved → remembered. Nobody answers → the connection times out
//! (`LOGIN_GRACE` in `server/connection.rs`).
//!
//! Trust binding: a Machine ID isn't secret, so the ID alone never skips the click. Every login
//! carries the Controller's public key and its signature over `login_message`: this
//! connection's challenge (`Hash`), the Target it dialed and its own ID. A login skips the click
//! only when the ID is on the list with that key and the signature checks out. A stolen
//! password plus a known Controller ID is not enough.
//!
//! "The Target it dialed" is one of two names, each one only this Target can answer to:
//! - a tailnet address: the one the Controller connected to (dialed as an address, or the
//!   address a tailnet name resolved to; `dialed_target`; or, ticket 08, the saved tailnet
//!   address a Machine ID's tailnet-first stream reached, `reached_target`, signed once per
//!   stream: a password retry on it clicks), which has to be the address the
//!   connection arrived on here, from a tailnet address (`target_name`). WireGuard means only
//!   this Target answers at its tailnet address.
//! - its Machine ID (ticket 07): signed only over a stream that verified the Target against the
//!   server key baked into the app (`signed_target`, called with the stream that carries the
//!   login): the Hosted servers vouched for the Target's key under that server key (`Client::start`
//!   refuses a Machine ID with any other key), the Target signed this connection's key exchange
//!   with it, and the stream is encrypted to it. The signature travels inside that stream, so
//!   nobody between the two can read it and pass it on. A Machine-ID connection that doesn't
//!   verify is refused outright, no Continue. The Target takes its own Machine ID as a name only
//!   on a connection whose key exchange completed (`secured`). That is defense in depth only:
//!   anyone can complete a key exchange with a Target, so it says nothing about who the
//!   Controller is. What makes the name safe is the Controller's check.
//! A Target the Controller logs in to can't pass the signature on to another one.
//!
//! A Controller without a signature (1.7 and older, stock RustDesk) gets a click every time and
//! is never remembered. The list used to hold IDs only; `load` drops those entries once, so each
//! of those Controllers needs one more click. A prompt for an ID already on the list that shows
//! another key lets that session in on the click but doesn't replace the stored key: Remove the
//! old entry first (a reinstalled Controller has a new key).
//!
//! Known limits:
//! - A Controller's identity is its key file (the key pair in its config). Whoever copies that
//!   file and has the password gets in with no click, as that Controller; Remove ends it.
//!   Reinstalling or wiping a Controller's config makes a new key, so it needs approving again.
//! - Never trusted, so a click every time: Direct IP to a LAN or other non-tailnet address
//!   (someone else can answer at it on another network), Direct IP through NAT or a port
//!   forward, a Machine-ID session that didn't verify the Target against the baked server key
//!   (no signed identity from the servers, a key that doesn't check out, the plaintext fallback
//!   upstream keeps for those, or another server's key), Controllers on another server
//!   (`id@server` isn't a storable ID and never takes the Hosted path), a tailnet name typed
//!   differently from the one that resolved (`note_dialed` is keyed by the exact text), and a
//!   Controller UI that has no key pair yet (it never makes one; the service does).
//! - The Machine-ID name is only as good as the Hosted servers' word on which key belongs to a
//!   Machine ID. Three ways that word can be wrong, each letting an attacker sit between a
//!   trusted Controller and that Target and relay the Controller's signed login (no click; the
//!   Target's password is still needed):
//!   - whoever holds the server's private key (on the Hosted box and in Keychain) can vouch any
//!     key for any Machine ID;
//!   - stock `hbbs` lets a Machine ID's key change when the registration carries the same UUID
//!     from the same IP (RegisterPk is plaintext UDP; the UUID is the machine UID, readable by
//!     any local user and visible on the path), so someone behind the Target's own NAT who has
//!     its UUID can re-bind its key.
//!   Closing the second needs an `hbbs` that never lets a registered key change: a server
//!   change, so Jason's call. Separately, squatting a MAC-derived ID before the Target first
//!   registers gives the Target a new ID (`update_id`), so Controllers dialing the old one reach
//!   the squatter: phishing, not a bypass (the squatter can't log in as the Controller).
//! - The server's public key is not access control. It ships in every app, and stock `hbbs`
//!   checks it only on punch and relay requests, not on registration: a stock RustDesk client
//!   can register with the Hosted servers and be dialed. It can't get a trusted no-click login
//!   (no Boring Controller key on any Target's list). Per-buyer checks wait for stage 1-2
//!   (ADR 0005).
//! - Tailscale addresses are unique only per tailnet: a Controller logged in to the attacker's
//!   tailnet, dialing the address its trusted Target has on its own tailnet, could be relayed.
//! - The port isn't bound: another listener on the Target's own tailnet address could relay a
//!   Controller that dials that port. The challenge is ~30 bits, fresh per connection.
//!
//! No Permanent password set on the Target (a 1.7 Target before setup): no unattended access,
//! but someone at the Target can still click Accept, so tailnet access keeps working while
//! setup is pending (spec slice 4). That approval is not remembered.
//!
//! Every Ask counts against the IP's login failure budget in `server/connection.rs`, so the
//! prompt can't be raised without limit. A new login on a connection already waiting on the
//! prompt closes it, so the click can't land on a different login than the one shown.
use base::message_proto::LoginRequest;
use hbb_common::{config::Config, log, sodiumoxide::crypto::sign};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
};

/// Config option holding the trusted Controllers, `id:key` (key in lowercase hex), comma
/// separated. Written only by the daemon (`on_accept`, `load`); the UI's copy is never taken.
pub const TRUSTED_OPTION: &str = "boring-trusted-controllers";
/// Option the Settings list sends to remove IDs (comma separated). Never stored.
pub const REMOVE_OPTION: &str = "boring-trusted-controllers-remove";

/// A Controller's Ed25519 public key.
pub type Key = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Password {
    /// The Target has a Permanent password and the Controller gave it.
    Right,
    /// The Target has no Permanent password: nothing to check, no unattended access.
    NotSet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtTarget {
    NotAsked,
    Approved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Show the Target's accept prompt and wait.
    Ask,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trusted(Vec<(String, Key)>);

/// RustDesk IDs are digits or a custom `[A-Za-z0-9_-]` name. Anything else (empty, commas,
/// colons, spaces) is never trusted, remembered or logged.
fn storable(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn hex(key: &Key) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Key> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(key)
}

/// One stored entry, `id:key`. An ID without a key (the list before trust binding) is None.
fn entry(s: &str) -> Option<(&str, Key)> {
    let (id, key) = s.trim().split_once(':')?;
    Some((id, unhex(key)?))
}

impl Trusted {
    pub fn parse(option: &str) -> Self {
        let mut t = Trusted::default();
        for (id, key) in option.split(',').filter_map(entry) {
            t.add(id, &key);
        }
        t
    }

    pub fn to_option(&self) -> String {
        self.0
            .iter()
            .map(|(id, key)| format!("{id}:{}", hex(key)))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// This ID with this key. The ID alone is never enough.
    pub fn contains(&self, id: &str, key: &Key) -> bool {
        storable(id) && self.0.iter().any(|(t, k)| t == id && k == key)
    }

    pub fn has_id(&self, id: &str) -> bool {
        self.0.iter().any(|(t, _)| t == id)
    }

    /// One key per ID: approving a Controller again (a new key after a reinstall) replaces it.
    pub fn add(&mut self, id: &str, key: &Key) {
        if storable(id) {
            self.remove(id);
            self.0.push((id.to_owned(), *key));
        }
    }

    pub fn remove(&mut self, id: &str) {
        self.0.retain(|(t, _)| t != id);
    }

    #[cfg(test)]
    pub fn ids(&self) -> Vec<&str> {
        self.0.iter().map(|(id, _)| id.as_str()).collect()
    }
}

// --- the signed login -------------------------------------------------------------------

/// Leads every signed login. The leading zero byte is never a valid protobuf tag, so a signed
/// login can't be read as a `SignedId` (`IdPk`), which the same key signs as a Target.
const LOGIN_DOMAIN: &[u8] = b"\0boring-remote trusted Controller login v1\0";

/// The bytes a Controller signs: the domain, then the Target's challenge, the Target it dialed
/// and its own ID, each length-prefixed. None for a challenge no Target makes (they are short
/// alphanumeric strings): the Target picks the challenge, so the Controller signs nothing else.
pub fn login_message(challenge: &str, target: &str, controller: &str) -> Option<Vec<u8>> {
    let challenge_ok = !challenge.is_empty()
        && challenge.len() <= 64
        && challenge.bytes().all(|b| b.is_ascii_alphanumeric());
    if !challenge_ok {
        return None;
    }
    let mut m = LOGIN_DOMAIN.to_vec();
    for part in [challenge, target, controller] {
        m.extend_from_slice(&(part.len() as u32).to_be_bytes());
        m.extend_from_slice(part.as_bytes());
    }
    Some(m)
}

/// The Controller's signature over this login, from its secret key. None without a usable key
/// or challenge.
pub fn signature(challenge: &str, target: &str, controller: &str, sk: &[u8]) -> Option<Vec<u8>> {
    let sk = sign::SecretKey(sk.try_into().ok()?);
    Some(sign::sign(&login_message(challenge, target, controller)?, &sk))
}

/// The pure verifier: `pk`, if `sig` is its signature over this login (`challenge`, `target`,
/// `controller`). None for no signature (1.7 Controllers), a bad one, or one made for another
/// challenge, Target or Controller ID.
pub fn proven_key(controller: &str, pk: &[u8], sig: &[u8], challenge: &str, target: &str) -> Option<Key> {
    let key: Key = pk.try_into().ok()?;
    let want = login_message(challenge, target, controller)?;
    let signed = sign::verify(sig, &sign::PublicKey(key)).ok()?;
    (signed == want).then_some(key)
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

fn ip_in(peer: &str) -> Option<IpAddr> {
    peer.parse::<IpAddr>()
        .ok()
        .or_else(|| peer.parse::<SocketAddr>().ok().map(|a| a.ip()))
        .map(canonical)
}

/// Tailscale's ranges: the connect box's own test (`boring_is_tailnet` in `client.rs`).
fn is_tailnet(ip: IpAddr) -> bool {
    crate::client::boring_is_tailnet(SocketAddr::new(ip, 0))
}

/// What a Controller may have signed as this Target: the tailnet address the connection arrived
/// on (`arrived_on`), only when it came from a tailnet address (`from`): Direct IP across the
/// tailnet. A relayed or hole-punched connection arrives on the Target's LAN side toward the
/// relay, and a WebSocket one reports the relay's address as its local one
/// (`WsFramedStream::local_addr` returns the remote side), so none of them has a name to sign.
pub fn target_name(arrived_on: IpAddr, from: &str) -> Option<String> {
    let from = ip_in(from)?;
    if !(is_tailnet(arrived_on) && is_tailnet(from)) {
        return None;
    }
    Some(canonical(arrived_on).to_string())
}

/// Every name a Controller may have signed as this Target on this connection: its tailnet
/// address (`target_name`) and, once this connection's key exchange completed (`secured`), its
/// own Machine ID (`own_id`, ticket 07). `secured` is defense in depth, not proof of who the
/// Controller is: a Controller signs a Machine ID only over a stream it verified against the
/// baked server key (`signed_target`), so only this Target can read that signature.
pub fn target_names(arrived_on: IpAddr, from: &str, own_id: &str, secured: bool) -> Vec<String> {
    let mut names: Vec<String> = target_name(arrived_on, from).into_iter().collect();
    if secured && crate::client::boring_is_machine_id(own_id) {
        names.push(own_id.to_owned());
    }
    names
}

/// The Controller's key, proven for this login on this Target. None means the login can't
/// skip the click and won't be remembered.
pub fn login_key(
    lr: &LoginRequest,
    challenge: &str,
    arrived_on: IpAddr,
    from: &str,
    own_id: &str,
    secured: bool,
) -> Option<Key> {
    target_names(arrived_on, from, own_id, secured)
        .iter()
        .find_map(|target| proven_key(&lr.my_id, &lr.boring_controller_pk, &lr.boring_login_sig, challenge, target))
}

pub fn decide(
    controller: &str,
    key: Option<&Key>,
    password: Password,
    trusted: &Trusted,
    at_target: AtTarget,
) -> Decision {
    if password == Password::Right && key.map_or(false, |k| trusted.contains(controller, k)) {
        return Decision::Allow;
    }
    match at_target {
        AtTarget::NotAsked => Decision::Ask,
        AtTarget::Approved => Decision::Allow,
    }
}

/// Someone at the Target accepted a Controller: the list to save. Remembered only with a
/// proven key, when its password checked out, `remember` (no other session is open, see
/// `on_accept`) and the ID isn't on the list already: a trusted ID showing another key could be
/// someone claiming it, so the stored key stays until Remove.
pub fn accepted(
    trusted: &Trusted,
    controller: &str,
    key: Option<&Key>,
    password: Password,
    remember: bool,
) -> Trusted {
    let mut next = trusted.clone();
    if let Some(key) = key {
        if password == Password::Right && remember && !trusted.has_id(controller) {
            next.add(controller, key);
        }
    }
    next
}

/// A `Data::Options` write from the UI. The trusted list stays the daemon's, since the UI
/// sends its whole option map from a cache up to ~1 s old and would wipe a fresh approval.
/// `REMOVE_OPTION` drops IDs from it (allowed during a session: removing only tightens).
/// Returns the IDs removed, whose sessions the caller closes.
pub fn take_options(incoming: &mut HashMap<String, String>, current: &HashMap<String, String>) -> Vec<String> {
    let remove = incoming.remove(REMOVE_OPTION).unwrap_or_default();
    let mut list = Trusted::parse(current.get(TRUSTED_OPTION).map(String::as_str).unwrap_or(""));
    let mut removed = Vec::new();
    for id in remove.split(',').map(str::trim) {
        if list.has_id(id) {
            list.remove(id);
            removed.push(id.to_owned());
        }
    }
    match list.to_option() {
        v if v.is_empty() => incoming.remove(TRUSTED_OPTION),
        v => incoming.insert(TRUSTED_OPTION.to_owned(), v),
    };
    removed
}

// --- Controller side --------------------------------------------------------------------

/// Tailnet names this Controller resolved, and the address it connected to for each.
static DIALED: Mutex<Vec<(String, IpAddr)>> = Mutex::new(Vec::new());

/// A tailnet name resolved to `ip` (`boring_tailnet_addr` in `client.rs`): its login signs `ip`.
pub fn note_dialed(peer: &str, ip: IpAddr) {
    let mut dialed = DIALED.lock().unwrap();
    dialed.retain(|(p, _)| p != peer);
    if dialed.len() >= 64 {
        dialed.remove(0);
    }
    dialed.push((peer.to_owned(), canonical(ip)));
}

/// The tailnet address this Controller connected to (dialed as an address, or a tailnet name
/// `note_dialed` resolved). None for anything else: someone else can answer at a LAN or NAT
/// address on another network.
pub fn dialed_target(peer: &str) -> Option<String> {
    let ip = match ip_in(peer) {
        Some(ip) => ip,
        None => DIALED.lock().unwrap().iter().find(|(p, _)| p == peer)?.1,
    };
    is_tailnet(ip).then(|| ip.to_string())
}

/// The key a connection checks the Hosted servers' word with is the baked server key ("" means
/// the built-in one). `Client::start` refuses a Machine ID with any other key (ticket 07).
pub fn baked_key(key: &str) -> bool {
    key.is_empty() || key == hbb_common::config::RS_PUB_KEY
}

/// What this Controller signs as the Target: a tailnet address it connected to
/// (`dialed_target`), or `peer`'s Machine ID when the stream carrying this login is keyed
/// (`secured`, ticket 07). On a Machine-ID connection, a keyed stream means `secure_connection`
/// checked the Hosted servers' word on the Target's key under the baked key (`baked_key`) and
/// the Target signed this key exchange with that key; upstream's plaintext fallback leaves it
/// unkeyed. None for anything else, so that login goes unsigned and clicks.
pub fn signed_target(peer: &str, secured: bool) -> Option<String> {
    dialed_target(peer).or_else(|| (secured && crate::client::boring_is_machine_id(peer)).then(|| peer.to_owned()))
}

// --- ticket 08: a saved Machine ID's tailnet-first connection ---------------------------

/// Streams `boring_tailnet_first` (client.rs) connected Direct IP to a saved Machine ID's
/// tailnet address, by the stream's local address (unique while it is open), with the address
/// each reached. Per connection: never shared by a session's other connections.
static TAILNET_STREAMS: Mutex<Vec<(SocketAddr, IpAddr)>> = Mutex::new(Vec::new());

/// The stream whose local end is `local` reached `reached`, a tailnet address.
pub fn note_tailnet_stream(local: SocketAddr, reached: IpAddr) {
    if !is_tailnet(reached) {
        return;
    }
    let mut streams = TAILNET_STREAMS.lock().unwrap();
    streams.retain(|(l, _)| *l != local);
    if streams.len() >= 64 {
        streams.remove(0);
    }
    streams.push((local, canonical(reached)));
}

/// This stream is a saved Machine ID's tailnet-first connection: Direct IP across the tailnet
/// (WireGuard), like a typed tailnet address. Not a Hosted connection that failed to verify.
pub fn is_tailnet_stream(local: SocketAddr) -> bool {
    TAILNET_STREAMS.lock().unwrap().iter().any(|(l, _)| *l == local)
}

/// The tailnet address this stream reached, taken when its login is sent: that login signs it.
pub fn take_tailnet_stream(local: SocketAddr) -> Option<IpAddr> {
    let mut streams = TAILNET_STREAMS.lock().unwrap();
    let i = streams.iter().position(|(l, _)| *l == local)?;
    Some(streams.remove(i).1)
}

/// What a Machine ID's login signs on its tailnet-first stream (`reached`, from
/// `take_tailnet_stream`): the tailnet address that stream connected to, as for a typed one.
/// None for anything else.
pub fn reached_target(peer: &str, reached: Option<IpAddr>) -> Option<String> {
    reached
        .filter(|ip| is_tailnet(*ip) && crate::client::boring_is_machine_id(peer))
        .map(|ip| canonical(ip).to_string())
}

/// Sign this login with the Controller's own key pair, for the Target's trusted list. Left
/// unsigned (the Target then asks) for a Target it can't bind (`signed_target`, or ticket 08's
/// `reached_target`), a challenge no Target makes, or no key pair. `secured`: the stream this
/// login goes out on is keyed; `reached`: the tailnet address that stream connected to, if it
/// is a tailnet-first one. On
/// desktop it takes the key pair the service made and never makes one: a key made by this UI
/// process could differ from the service's or race it. Mobile runs both sides in one process.
pub fn sign_login(lr: &mut LoginRequest, challenge: &str, secured: bool, reached: Option<IpAddr>) {
    let Some(target) = signed_target(&lr.username, secured).or_else(|| reached_target(&lr.username, reached)) else {
        return;
    };
    if login_message(challenge, &target, &lr.my_id).is_none() {
        return;
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let pair = Some(Config::get_key_pair());
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let pair = Config::get_existing_key_pair();
    let Some((sk, pk)) = pair else {
        return;
    };
    if let Some(sig) = signature(challenge, &target, &lr.my_id, &sk) {
        lr.boring_controller_pk = pk.into();
        lr.boring_login_sig = sig.into();
    }
}

// --- Target wiring ----------------------------------------------------------------------

#[cfg(not(target_os = "ios"))]
struct Waiting {
    conn_id: i32,
    controller: String,
    key: Option<Key>,
    password: Password,
}

#[cfg(not(target_os = "ios"))]
static PENDING: Mutex<Vec<Waiting>> = Mutex::new(Vec::new());

#[cfg(not(target_os = "ios"))]
fn save(trusted: &Trusted) {
    Config::set_option(TRUSTED_OPTION.to_owned(), trusted.to_option());
}

/// The trusted list. Entries without a key (the ID-only list from before trust binding) are
/// dropped, and the list saved once without them.
#[cfg(not(target_os = "ios"))]
fn load() -> Trusted {
    let stored = Config::get_option(TRUSTED_OPTION);
    let trusted = Trusted::parse(&stored);
    if trusted.to_option() != stored {
        hbb_common::throttled_log!(
            std::time::Duration::from_secs(60),
            warn,
            "trusted Controllers: entries without a key dropped, they need approving again"
        );
        save(&trusted);
    }
    trusted
}

/// A login whose password checked out (`Right`), or one on a Target with no password
/// (`NotSet`), with the Controller's key if it proved one (`login_key`). Allow (trusted) or Ask
/// (now waiting on the prompt).
#[cfg(not(target_os = "ios"))]
pub fn on_login(conn_id: i32, controller: &str, password: Password, key: Option<Key>) -> Decision {
    forget(conn_id);
    let decision = decide(controller, key.as_ref(), password, &load(), AtTarget::NotAsked);
    if decision == Decision::Ask {
        PENDING.lock().unwrap().push(Waiting {
            conn_id,
            controller: controller.to_owned(),
            key,
            password,
        });
        let shown = if storable(controller) { controller } else { "(unreadable ID)" };
        hbb_common::throttled_log!(
            std::time::Duration::from_secs(60),
            info,
            "Controller {shown}: waiting for approval on this computer"
        );
    }
    decision
}

/// The Target's Accept for `conn_id`. True only for a connection waiting on the prompt after
/// `on_login` on this login. A checked password and a proven key also remember the Controller,
/// unless another session is open: the click could then come from a Controller driving this
/// computer.
#[cfg(not(target_os = "ios"))]
pub fn on_accept(conn_id: i32) -> bool {
    let Some(w) = take(conn_id) else {
        log::warn!("accept ignored for conn {conn_id}: not waiting on approval");
        return false;
    };
    let trusted = load();
    let remember = crate::password_lock::authed_sessions() == 0;
    let next = accepted(&trusted, &w.controller, w.key.as_ref(), w.password, remember);
    if matches!(w.key, Some(k) if trusted.has_id(&w.controller) && !trusted.contains(&w.controller, &k)) {
        hbb_common::throttled_log!(
            std::time::Duration::from_secs(60),
            warn,
            "Controller {}: not its trusted key; let in on the click, not remembered (Remove it to approve a new key)",
            w.controller
        );
    }
    if next != trusted {
        save(&next);
        log::info!("Controller {} approved and trusted", w.controller);
    }
    true
}

#[cfg(not(target_os = "ios"))]
fn take(conn_id: i32) -> Option<Waiting> {
    let mut pending = PENDING.lock().unwrap();
    let i = pending.iter().position(|w| w.conn_id == conn_id)?;
    Some(pending.remove(i))
}

/// A new login attempt or a closed connection voids the wait. True if it was waiting.
#[cfg(not(target_os = "ios"))]
pub fn forget(conn_id: i32) -> bool {
    take(conn_id).is_some()
}

/// Close the sessions of Controllers just removed from the list (spec story 15).
#[cfg(not(target_os = "ios"))]
pub fn close_removed(removed: &[String]) {
    for id in removed {
        log::info!("Controller {id} removed from the trusted list: closing its sessions");
        crate::server::close_controller(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::{protobuf::Message as _, rendezvous_proto::IdPk};
    use std::net::Ipv4Addr;

    const NEW: &str = "123456789";
    const KNOWN: &str = "987654321";
    const CHALLENGE: &str = "k3m9xz";
    /// The Target's tailnet address, and the Controller's, on a Direct IP login.
    const TARGET: &str = "100.101.102.103";
    const TARGET_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(100, 101, 102, 103));
    const FROM: &str = "100.70.0.9";
    /// The Target's Machine ID on the Hosted servers (ticket 07).
    const MACHINE_ID: &str = "555666777";

    struct Controller {
        id: &'static str,
        pk: Key,
        sk: sign::SecretKey,
    }

    fn controller(id: &'static str) -> Controller {
        let (pk, sk) = sign::gen_keypair();
        Controller { id, pk: pk.0, sk }
    }

    impl Controller {
        /// The LoginRequest this Controller sends after dialing `dialed` (unsigned where
        /// `dialed_target` has nothing to bind, as `sign_login` does).
        fn login(&self, challenge: &str, dialed: &str) -> LoginRequest {
            self.login_over(challenge, dialed, false)
        }

        /// The same, sent over a stream that is keyed (`secured`) or not.
        fn login_over(&self, challenge: &str, dialed: &str, secured: bool) -> LoginRequest {
            let mut lr = LoginRequest {
                my_id: self.id.to_owned(),
                username: dialed.to_owned(),
                ..Default::default()
            };
            if let Some(target) = signed_target(dialed, secured) {
                let sig = signature(challenge, &target, self.id, &self.sk.0).unwrap();
                lr.boring_controller_pk = self.pk.to_vec().into();
                lr.boring_login_sig = sig.into();
            }
            lr
        }
    }

    fn trusted(entries: &[(&str, &Key)]) -> Trusted {
        let mut t = Trusted::default();
        for (id, key) in entries {
            t.add(id, key);
        }
        t
    }

    /// What the Target decides for this login arriving on `arrived_on` from `from`, before
    /// anyone clicks, on a connection that isn't keyed to the Target (Direct IP).
    fn decides_on(lr: &LoginRequest, challenge: &str, list: &Trusted, arrived_on: IpAddr, from: &str) -> Decision {
        hosted_decides(lr, challenge, list, arrived_on, from, TARGET_ID_UNSECURED)
    }

    /// No Machine ID name on a connection whose key exchange didn't complete.
    const TARGET_ID_UNSECURED: (&str, bool) = (MACHINE_ID, false);

    /// The same, for a Target whose Machine ID is `own.0`, `own.1` saying whether this
    /// connection's key exchange with its signed identity completed.
    fn hosted_decides(
        lr: &LoginRequest,
        challenge: &str,
        list: &Trusted,
        arrived_on: IpAddr,
        from: &str,
        own: (&str, bool),
    ) -> Decision {
        let key = login_key(lr, challenge, arrived_on, from, own.0, own.1);
        decide(&lr.my_id, key.as_ref(), Password::Right, list, AtTarget::NotAsked)
    }

    /// A Machine-ID login: punched or relayed through the Hosted servers, so it arrives on the
    /// Target's LAN side from a public address, on a connection keyed to the Target.
    fn machine_id_decides(lr: &LoginRequest, challenge: &str, list: &Trusted) -> Decision {
        let lan: IpAddr = "192.168.1.20".parse().unwrap();
        hosted_decides(lr, challenge, list, lan, "203.0.113.7", (MACHINE_ID, true))
    }

    /// The same, for Direct IP across the tailnet.
    fn target_decides(lr: &LoginRequest, challenge: &str, list: &Trusted) -> Decision {
        decides_on(lr, challenge, list, TARGET_IP, FROM)
    }

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    // --- trust binding ---

    #[test]
    fn valid_signature_with_the_stored_key_is_trusted() {
        let c = controller(KNOWN);
        let list = trusted(&[(KNOWN, &c.pk)]);
        assert_eq!(target_decides(&c.login(CHALLENGE, TARGET), CHALLENGE, &list), Decision::Allow);
    }

    #[test]
    fn right_id_with_another_key_asks() {
        // Someone with the password claims a trusted Controller's ID, signing with their own key.
        let real = controller(KNOWN);
        let impostor = controller(KNOWN);
        let list = trusted(&[(KNOWN, &real.pk)]);
        assert_eq!(target_decides(&impostor.login(CHALLENGE, TARGET), CHALLENGE, &list), Decision::Ask);
    }

    #[test]
    fn stored_key_presented_without_its_signature_asks() {
        let real = controller(KNOWN);
        let impostor = controller(KNOWN);
        let mut lr = impostor.login(CHALLENGE, TARGET);
        lr.boring_controller_pk = real.pk.to_vec().into(); // the public key isn't secret either
        let list = trusted(&[(KNOWN, &real.pk)]);
        assert_eq!(target_decides(&lr, CHALLENGE, &list), Decision::Ask);
    }

    #[test]
    fn missing_signature_asks() {
        // A 1.7 Controller: right ID, nothing signed.
        let c = controller(KNOWN);
        let list = trusted(&[(KNOWN, &c.pk)]);
        let lr = LoginRequest {
            my_id: KNOWN.to_owned(),
            username: TARGET.to_owned(),
            ..Default::default()
        };
        assert_eq!(target_decides(&lr, CHALLENGE, &list), Decision::Ask);
    }

    #[test]
    fn signature_over_another_challenge_asks() {
        let c = controller(KNOWN);
        let list = trusted(&[(KNOWN, &c.pk)]);
        assert_eq!(target_decides(&c.login("other7", TARGET), CHALLENGE, &list), Decision::Ask);
    }

    #[test]
    fn signature_made_for_another_target_asks() {
        // Another Target the Controller logged in to passes its signature on to this one.
        let c = controller(KNOWN);
        let list = trusted(&[(KNOWN, &c.pk)]);
        for elsewhere in ["100.101.102.104", "fd7a:115c:a1e0::9"] {
            let lr = c.login(CHALLENGE, elsewhere);
            assert!(!lr.boring_login_sig.is_empty(), "{elsewhere}: a tailnet address is signed");
            assert_eq!(target_decides(&lr, CHALLENGE, &list), Decision::Ask, "{elsewhere}");
        }
    }

    #[test]
    fn signature_for_another_controller_id_asks() {
        let c = controller(KNOWN);
        let mut lr = c.login(CHALLENGE, TARGET);
        lr.my_id = NEW.to_owned();
        let list = trusted(&[(KNOWN, &c.pk), (NEW, &c.pk)]);
        assert_eq!(target_decides(&lr, CHALLENGE, &list), Decision::Ask);
    }

    #[test]
    fn relay_punched_or_lan_arrival_asks() {
        // review M1: an attacker answering at 192.168.1.5 on the Controller's network, logging in
        // to the Target by relay or punch, so the Target's arrival address is its own 192.168.1.5.
        let c = controller(KNOWN);
        let list = trusted(&[(KNOWN, &c.pk)]);
        let lan: IpAddr = "192.168.1.5".parse().unwrap();
        // The Controller doesn't sign a LAN address at all...
        assert!(c.login(CHALLENGE, "192.168.1.5").boring_login_sig.is_empty());
        // ...and even a signature over one is never a name of this Target.
        let mut lr = c.login(CHALLENGE, TARGET);
        lr.boring_login_sig = signature(CHALLENGE, "192.168.1.5", KNOWN, &c.sk.0).unwrap().into();
        assert_eq!(decides_on(&lr, CHALLENGE, &list, lan, "203.0.113.7"), Decision::Ask);
        assert_eq!(decides_on(&lr, CHALLENGE, &list, lan, FROM), Decision::Ask);
        // A tailnet arrival from a non-tailnet peer (relay, public rendezvous address) has no name.
        let ok = c.login(CHALLENGE, TARGET);
        assert_eq!(decides_on(&ok, CHALLENGE, &list, TARGET_IP, "203.0.113.7"), Decision::Ask);
        assert_eq!(decides_on(&ok, CHALLENGE, &list, TARGET_IP, "not an address"), Decision::Ask);
        // WebSocket's local_addr is the relay's address: a public one, never a tailnet one.
        assert_eq!(decides_on(&ok, CHALLENGE, &list, "203.0.113.1".parse().unwrap(), FROM), Decision::Ask);
    }

    #[test]
    fn machine_id_logins_on_an_unverified_session_are_not_signed() {
        let c = controller(KNOWN);
        assert!(c.login(CHALLENGE, MACHINE_ID).boring_login_sig.is_empty());
        assert_eq!(dialed_target(MACHINE_ID), None);
        assert_eq!(signed_target(MACHINE_ID, false), None);
    }

    // --- Machine ID through the Hosted servers (ticket 07) ---

    #[test]
    fn only_the_baked_server_key_counts() {
        // "" is what a connection without a configured key checks with: the built-in one.
        assert!(baked_key(""));
        assert!(baked_key(hbb_common::config::RS_PUB_KEY));
        // Another server's key (id@server?key=, a config or IPC key that isn't ours) never does.
        assert!(!baked_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    }

    #[test]
    fn a_machine_id_is_signed_only_over_a_keyed_stream() {
        assert_eq!(signed_target(MACHINE_ID, true), Some(MACHINE_ID.to_owned()));
        // Upstream's plaintext fallback leaves the stream unkeyed: never signed.
        assert_eq!(signed_target(MACHINE_ID, false), None);
        // A keyed stream never makes an address, a name or id@server a Machine ID.
        for peer in ["192.168.1.5", "studio.tail1.ts.net", "555666777@rs.example.com", "", "55 66"] {
            assert_eq!(signed_target(peer, true), None, "{peer:?}");
        }
        // A tailnet address is still signed as before, keyed or not.
        assert_eq!(signed_target(TARGET, true), Some(TARGET.to_owned()));
    }

    #[test]
    fn machine_id_login_on_a_verified_session_is_trusted() {
        let c = controller(KNOWN);
        let list = trusted(&[(KNOWN, &c.pk)]);
        let lr = c.login_over(CHALLENGE, MACHINE_ID, true);
        assert!(!lr.boring_login_sig.is_empty());
        assert_eq!(machine_id_decides(&lr, CHALLENGE, &list), Decision::Allow);
    }

    #[test]
    fn machine_id_name_needs_a_keyed_connection_on_the_target() {
        // A connection whose key exchange didn't complete could be anyone's: no Machine ID name.
        let c = controller(KNOWN);
        let list = trusted(&[(KNOWN, &c.pk)]);
        let lr = c.login_over(CHALLENGE, MACHINE_ID, true);
        let lan: IpAddr = "192.168.1.20".parse().unwrap();
        assert_eq!(hosted_decides(&lr, CHALLENGE, &list, lan, "203.0.113.7", (MACHINE_ID, false)), Decision::Ask);
    }

    #[test]
    fn machine_id_signature_for_another_target_asks() {
        // Signed for 555666777, presented to a Target whose Machine ID is another one.
        let c = controller(KNOWN);
        let list = trusted(&[(KNOWN, &c.pk)]);
        let lr = c.login_over(CHALLENGE, MACHINE_ID, true);
        let lan: IpAddr = "192.168.1.20".parse().unwrap();
        assert_eq!(hosted_decides(&lr, CHALLENGE, &list, lan, "203.0.113.7", ("111222333", true)), Decision::Ask);
        // ...or over another challenge.
        let other = c.login_over("other7", MACHINE_ID, true);
        assert_eq!(machine_id_decides(&other, CHALLENGE, &list), Decision::Ask);
    }

    #[test]
    fn an_unverified_machine_id_login_asks_even_from_a_trusted_controller() {
        let c = controller(KNOWN);
        let list = trusted(&[(KNOWN, &c.pk)]);
        assert_eq!(machine_id_decides(&c.login(CHALLENGE, MACHINE_ID), CHALLENGE, &list), Decision::Ask);
    }

    #[test]
    fn a_target_without_a_machine_id_has_no_id_name() {
        let lan: IpAddr = "192.168.1.20".parse().unwrap();
        assert!(target_names(lan, "203.0.113.7", "", true).is_empty());
        assert_eq!(target_names(lan, "203.0.113.7", MACHINE_ID, true), [MACHINE_ID]);
        assert_eq!(target_names(TARGET_IP, FROM, MACHINE_ID, false), [TARGET]);
        assert_eq!(target_names(TARGET_IP, FROM, MACHINE_ID, true), [TARGET, MACHINE_ID]);
    }

    #[test]
    fn tailnet_login_on_a_keyed_connection_still_binds_its_address() {
        let c = controller(KNOWN);
        let list = trusted(&[(KNOWN, &c.pk)]);
        let lr = c.login(CHALLENGE, TARGET);
        assert_eq!(hosted_decides(&lr, CHALLENGE, &list, TARGET_IP, FROM, (MACHINE_ID, true)), Decision::Allow);
    }

    #[test]
    fn direct_ip_login_is_bound_to_the_address_it_arrived_on() {
        let c = controller(KNOWN);
        let list = trusted(&[(KNOWN, &c.pk)]);
        for dialed in [TARGET, "100.101.102.103:21118"] {
            let lr = c.login(CHALLENGE, dialed);
            assert_eq!(target_decides(&lr, CHALLENGE, &list), Decision::Allow, "{dialed}");
        }
        // The dual-stack listener sees IPv4 as ::ffff:100.x, on both ends.
        let mapped = IpAddr::V6(Ipv4Addr::new(100, 101, 102, 103).to_ipv6_mapped());
        let key = login_key(&c.login(CHALLENGE, TARGET), CHALLENGE, mapped, "::ffff:100.70.0.9", MACHINE_ID, false);
        assert_eq!(key, Some(c.pk));
    }

    #[test]
    fn tailnet_name_signs_the_address_it_resolved_to() {
        let c = controller(KNOWN);
        let list = trusted(&[(KNOWN, &c.pk)]);
        note_dialed("studio-test.tail1.ts.net:21118", TARGET_IP);
        let lr = c.login(CHALLENGE, "studio-test.tail1.ts.net:21118");
        assert_eq!(target_decides(&lr, CHALLENGE, &list), Decision::Allow);
        // A name this Controller never resolved (or typed differently) isn't signed.
        assert!(c.login(CHALLENGE, "never-dialed.tail1.ts.net:21118").boring_login_sig.is_empty());
    }

    #[test]
    fn saved_machine_id_reached_on_its_tailnet_address_signs_that_address() {
        // Ticket 08: the login sent over a tailnet-first stream signs the address it reached.
        let c = controller(KNOWN);
        let list = trusted(&[(KNOWN, &c.pk)]);
        let target = reached_target(MACHINE_ID, Some(TARGET_IP)).unwrap();
        assert_eq!(target, TARGET);
        let lr = LoginRequest {
            my_id: KNOWN.to_owned(),
            username: MACHINE_ID.to_owned(),
            boring_controller_pk: c.pk.to_vec().into(),
            boring_login_sig: signature(CHALLENGE, &target, KNOWN, &c.sk.0).unwrap().into(),
            ..Default::default()
        };
        assert_eq!(decides_on(&lr, CHALLENGE, &list, TARGET_IP, FROM), Decision::Allow);
        // Relayed or punched (not arriving on the tailnet address), it binds nothing: a click.
        let lan: IpAddr = "192.168.1.20".parse().unwrap();
        assert_eq!(decides_on(&lr, CHALLENGE, &list, lan, "203.0.113.7"), Decision::Ask);
        // Never a non-tailnet address, never for a typed name, never without a tailnet-first stream.
        assert_eq!(reached_target(MACHINE_ID, Some(lan)), None);
        assert_eq!(reached_target("studio.tail1.ts.net", Some(TARGET_IP)), None);
        assert_eq!(reached_target(MACHINE_ID, None), None);
    }

    #[test]
    fn a_tailnet_first_stream_is_known_by_its_own_local_address_and_signed_once() {
        let mine: SocketAddr = "100.70.0.9:50001".parse().unwrap();
        let other: SocketAddr = "100.70.0.9:50002".parse().unwrap();
        note_tailnet_stream(mine, TARGET_IP);
        assert!(is_tailnet_stream(mine));
        assert!(!is_tailnet_stream(other));
        assert_eq!(take_tailnet_stream(other), None);
        assert_eq!(take_tailnet_stream(mine), Some(TARGET_IP));
        assert_eq!(take_tailnet_stream(mine), None);
        // A non-tailnet address is never recorded.
        note_tailnet_stream(other, "192.168.1.20".parse().unwrap());
        assert!(!is_tailnet_stream(other));
    }

    #[test]
    fn controller_signs_no_challenge_a_target_does_not_make() {
        let c = controller(KNOWN);
        let long = "a".repeat(65);
        for odd in ["", "has space", "\u{8}\u{1}", long.as_str()] {
            assert!(signature(odd, TARGET, KNOWN, &c.sk.0).is_none(), "{odd:?}");
        }
        assert!(signature(CHALLENGE, TARGET, KNOWN, &c.sk.0).is_some());
    }

    #[test]
    fn a_login_it_cant_bind_or_built_before_the_challenge_is_left_unsigned() {
        // Returns before the key pair is read.
        for (challenge, dialed, secured) in [
            ("", TARGET, false),
            (CHALLENGE, "192.168.1.5", true),
            (CHALLENGE, MACHINE_ID, false),
            ("", MACHINE_ID, true),
        ] {
            let mut lr = LoginRequest {
                my_id: KNOWN.to_owned(),
                username: dialed.to_owned(),
                ..Default::default()
            };
            sign_login(&mut lr, challenge, secured);
            assert!(lr.boring_login_sig.is_empty() && lr.boring_controller_pk.is_empty(), "{dialed}");
        }
    }

    #[test]
    fn a_signed_login_is_never_a_signed_id() {
        let m = login_message(CHALLENGE, TARGET, KNOWN).unwrap();
        assert!(IdPk::parse_from_bytes(&m).is_err());
    }

    #[test]
    fn migration_drops_id_only_entries() {
        let c = controller(KNOWN);
        let stored = format!("111111111, 222222222 ,{KNOWN}:{},333333333:abcd", hex(&c.pk));
        let t = Trusted::parse(&stored);
        assert_eq!(t.ids(), [KNOWN]);
        assert_eq!(t.to_option(), format!("{KNOWN}:{}", hex(&c.pk)));
        assert!(!Trusted::parse("111111111").has_id("111111111"));
    }

    // --- the policy ---

    #[test]
    fn unknown_controller_right_password_waits_for_a_click() {
        let c = controller(NEW);
        let known = controller(KNOWN);
        let list = trusted(&[(KNOWN, &known.pk)]);
        assert_eq!(decide(NEW, Some(&c.pk), Password::Right, &list, AtTarget::NotAsked), Decision::Ask);
    }

    #[test]
    fn unknown_controller_approved_is_allowed_and_remembered_with_its_key() {
        let c = controller(NEW);
        let known = controller(KNOWN);
        let list = trusted(&[(KNOWN, &known.pk)]);
        assert_eq!(decide(NEW, Some(&c.pk), Password::Right, &list, AtTarget::Approved), Decision::Allow);
        let next = accepted(&list, NEW, Some(&c.pk), Password::Right, true);
        // Saved and read back the way the daemon does it, as after a restart or an Update.
        let reloaded = Trusted::parse(&next.to_option());
        assert_eq!(decide(NEW, Some(&c.pk), Password::Right, &reloaded, AtTarget::NotAsked), Decision::Allow);
        assert!(reloaded.contains(KNOWN, &known.pk));
    }

    #[test]
    fn approval_without_a_signature_is_not_remembered() {
        // A 1.7 Controller gets in on the click, and gets a click every time.
        let next = accepted(&Trusted::default(), NEW, None, Password::Right, true);
        assert!(next.ids().is_empty());
    }

    #[test]
    fn approving_a_trusted_id_with_another_key_keeps_the_stored_one() {
        // review S1: the prompt shows a familiar ID; the click lets this session in, nothing more.
        let real = controller(KNOWN);
        let claimant = controller(KNOWN);
        let list = trusted(&[(KNOWN, &real.pk)]);
        assert_eq!(decide(KNOWN, Some(&claimant.pk), Password::Right, &list, AtTarget::Approved), Decision::Allow);
        let next = accepted(&list, KNOWN, Some(&claimant.pk), Password::Right, true);
        assert_eq!(next, list);
        // A reinstalled Controller is approved once Remove has dropped its old entry.
        let mut removed = list.clone();
        removed.remove(KNOWN);
        let next = accepted(&removed, KNOWN, Some(&claimant.pk), Password::Right, true);
        assert!(next.contains(KNOWN, &claimant.pk) && !next.contains(KNOWN, &real.pk));
    }

    #[test]
    fn approval_during_another_session_is_not_remembered() {
        let c = controller(NEW);
        let next = accepted(&Trusted::default(), NEW, Some(&c.pk), Password::Right, false);
        assert_eq!(decide(NEW, Some(&c.pk), Password::Right, &next, AtTarget::NotAsked), Decision::Ask);
    }

    #[test]
    fn removed_controller_is_asked_again() {
        let (k, n) = (controller(KNOWN), controller(NEW));
        let mut t = trusted(&[(KNOWN, &k.pk), (NEW, &n.pk)]);
        t.remove(KNOWN);
        let reloaded = Trusted::parse(&t.to_option());
        assert_eq!(decide(KNOWN, Some(&k.pk), Password::Right, &reloaded, AtTarget::NotAsked), Decision::Ask);
        assert_eq!(decide(NEW, Some(&n.pk), Password::Right, &reloaded, AtTarget::NotAsked), Decision::Allow);
    }

    #[test]
    fn no_password_on_target_always_asks() {
        // Unattended access needs a Permanent password, trusted Controller or not.
        let k = controller(KNOWN);
        let t = trusted(&[(KNOWN, &k.pk)]);
        assert_eq!(decide(KNOWN, Some(&k.pk), Password::NotSet, &t, AtTarget::NotAsked), Decision::Ask);
        assert_eq!(decide(NEW, None, Password::NotSet, &t, AtTarget::NotAsked), Decision::Ask);
    }

    #[test]
    fn no_password_on_target_someone_approves_is_allowed_but_not_remembered() {
        let c = controller(NEW);
        let none = Trusted::default();
        assert_eq!(decide(NEW, Some(&c.pk), Password::NotSet, &none, AtTarget::Approved), Decision::Allow);
        let next = accepted(&none, NEW, Some(&c.pk), Password::NotSet, true);
        assert!(next.ids().is_empty());
        // Once a password is set it still takes a click the first time.
        assert_eq!(decide(NEW, Some(&c.pk), Password::Right, &next, AtTarget::NotAsked), Decision::Ask);
    }

    #[test]
    fn odd_ids_are_never_trusted_or_remembered() {
        let c = controller(NEW);
        for id in ["", "1,2", "12 34", "a\nb", "1:2"] {
            let next = accepted(&Trusted::default(), id, Some(&c.pk), Password::Right, true);
            assert!(next.ids().is_empty(), "{id:?}");
            assert_eq!(decide(id, Some(&c.pk), Password::Right, &next, AtTarget::NotAsked), Decision::Ask);
        }
    }

    #[test]
    fn parse_ignores_blanks_duplicates_and_bad_keys() {
        let k = controller(KNOWN);
        let good = format!("{KNOWN}:{}", hex(&k.pk));
        let upper = format!("{NEW}:{}", hex(&k.pk).to_uppercase());
        let t = Trusted::parse(&format!(" {good}, ,{good},{upper},abc:12"));
        assert_eq!(t.ids(), [KNOWN]);
        assert_eq!(Trusted::parse("").ids().len(), 0);
    }

    #[test]
    fn ui_copy_of_the_list_is_never_taken() {
        let (a, b) = (controller("111111111"), controller("222222222"));
        let stored = trusted(&[("111111111", &a.pk), ("222222222", &b.pk)]).to_option();
        let current = map(&[(TRUSTED_OPTION, stored.as_str())]);
        // A stale UI map missing a fresh approval, one with an entry added by hand, an empty one.
        let only_a = trusted(&[("111111111", &a.pk)]).to_option();
        let added = format!("{stored},666666666:{}", hex(&a.pk));
        for stale in [only_a.as_str(), added.as_str(), ""] {
            let mut incoming = map(&[(TRUSTED_OPTION, stale), ("theme", "dark")]);
            assert!(take_options(&mut incoming, &current).is_empty());
            assert_eq!(incoming.get(TRUSTED_OPTION), Some(&stored));
            assert_eq!(incoming.get("theme").map(String::as_str), Some("dark"));
        }
    }

    #[test]
    fn remove_drops_only_listed_ids_and_reports_them() {
        let (a, b) = (controller("111111111"), controller("222222222"));
        let stored = trusted(&[("111111111", &a.pk), ("222222222", &b.pk)]).to_option();
        let current = map(&[(TRUSTED_OPTION, stored.as_str())]);
        let mut incoming = map(&[(REMOVE_OPTION, "222222222,999999999")]);
        assert_eq!(take_options(&mut incoming, &current), ["222222222".to_owned()]);
        assert_eq!(incoming.get(TRUSTED_OPTION), Some(&trusted(&[("111111111", &a.pk)]).to_option()));
        assert_eq!(incoming.get(REMOVE_OPTION), None);
        let mut incoming = map(&[(REMOVE_OPTION, "111111111,222222222")]);
        take_options(&mut incoming, &current);
        assert_eq!(incoming.get(TRUSTED_OPTION), None);
    }

    #[test]
    fn accept_without_a_waiting_login_is_ignored() {
        assert!(!on_accept(-42));
    }

    #[test]
    fn new_login_attempt_voids_the_wait() {
        PENDING.lock().unwrap().push(Waiting {
            conn_id: -7,
            controller: NEW.to_owned(),
            key: None,
            password: Password::Right,
        });
        assert!(forget(-7));
        assert!(!forget(-7));
        assert!(!on_accept(-7));
    }
}
