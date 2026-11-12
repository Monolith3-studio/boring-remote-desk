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
//! "The Target it dialed" (`dialed_target` on the Controller, `target_names` here) is the
//! Target's Machine ID, or for Direct IP the IP address the Controller connected to (a tailnet
//! name counts as the address it resolved to), which has to be the address the connection
//! arrived on here. So a Target that a Controller logs in to can't pass that signature on to
//! another Target.
//!
//! A Controller without a signature (1.7 and older, stock RustDesk) gets a click every time and
//! is never remembered. The list used to hold IDs only; `load` drops those entries once, so each
//! of those Controllers needs one more click.
//!
//! Known limits: a Controller's identity is its key file (the key pair in its config). Whoever
//! copies that file and has the password gets in with no click, as that Controller; Remove ends
//! it. Reinstalling or wiping a Controller's config makes a new key, so it needs approving
//! again. Two networks can reuse one private address: a Controller tricked into dialing an
//! attacker at the same address its trusted Target receives on, at the moment the attacker
//! logs in to that Target, would have its signature relayed.
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

/// What a Controller may have signed as this Target: its Machine ID, and the IP the connection
/// arrived on (Direct IP).
pub fn target_names(my_id: &str, arrived_on: IpAddr) -> Vec<String> {
    let mut names = vec![my_id.to_owned()];
    let ip = canonical(arrived_on);
    if !ip.is_unspecified() && !ip.is_loopback() {
        names.push(ip.to_string());
    }
    names.retain(|n| !n.is_empty());
    names
}

/// The Controller's key, proven for this login on this Target. None means the login can't
/// skip the click and won't be remembered.
pub fn login_key(lr: &LoginRequest, challenge: &str, my_id: &str, arrived_on: IpAddr) -> Option<Key> {
    target_names(my_id, arrived_on).iter().find_map(|target| {
        proven_key(&lr.my_id, &lr.boring_controller_pk, &lr.boring_login_sig, challenge, target)
    })
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
/// proven key, when its password checked out and `remember` (no other session is open, see
/// `on_accept`).
pub fn accepted(
    trusted: &Trusted,
    controller: &str,
    key: Option<&Key>,
    password: Password,
    remember: bool,
) -> Trusted {
    let mut next = trusted.clone();
    if let Some(key) = key {
        if password == Password::Right && remember {
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

/// What this Controller signs as the Target: for Direct IP the IP it connected to (dialed as an
/// address, or a tailnet name `note_dialed` resolved), else the Machine ID it dialed.
pub fn dialed_target(peer: &str) -> String {
    if let Some(ip) = ip_in(peer) {
        return ip.to_string();
    }
    let dialed = DIALED.lock().unwrap();
    match dialed.iter().find(|(p, _)| p == peer) {
        Some((_, ip)) => ip.to_string(),
        None => peer.to_owned(),
    }
}

/// Sign this login with the Controller's own key pair, for the Target's trusted list. Left
/// unsigned without a key pair or for a challenge no Target makes (the Target then asks); the
/// key pair isn't touched then (a login built before any `Hash`, or in a test).
pub fn sign_login(lr: &mut LoginRequest, challenge: &str) {
    let target = dialed_target(&lr.username);
    if login_message(challenge, &target, &lr.my_id).is_none() {
        return;
    }
    let (sk, pk) = Config::get_key_pair();
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
        log::info!("trusted Controllers: entries without a key dropped, they need approving again");
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    const NEW: &str = "123456789";
    const KNOWN: &str = "987654321";
    const TARGET: &str = "555666777";
    const CHALLENGE: &str = "k3m9xz";
    const TAILNET_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(100, 101, 102, 103));

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
        /// The LoginRequest this Controller sends after dialing `dialed`.
        fn login(&self, challenge: &str, dialed: &str) -> LoginRequest {
            let mut lr = LoginRequest {
                my_id: self.id.to_owned(),
                username: dialed.to_owned(),
                ..Default::default()
            };
            let sig = signature(challenge, &dialed_target(dialed), self.id, &self.sk.0).unwrap();
            lr.boring_controller_pk = self.pk.to_vec().into();
            lr.boring_login_sig = sig.into();
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

    /// What the Target decides for this login, before anyone clicks.
    fn target_decides(lr: &LoginRequest, challenge: &str, list: &Trusted) -> Decision {
        let key = login_key(lr, challenge, TARGET, TAILNET_IP);
        decide(&lr.my_id, key.as_ref(), Password::Right, list, AtTarget::NotAsked)
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
        for elsewhere in ["111222333", "100.101.102.104", "fd7a:115c:a1e0::9"] {
            let lr = c.login(CHALLENGE, elsewhere);
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
    fn direct_ip_login_is_bound_to_the_address_it_arrived_on() {
        let c = controller(KNOWN);
        let list = trusted(&[(KNOWN, &c.pk)]);
        for dialed in ["100.101.102.103", "100.101.102.103:21118"] {
            let lr = c.login(CHALLENGE, dialed);
            assert_eq!(target_decides(&lr, CHALLENGE, &list), Decision::Allow, "{dialed}");
        }
        // The dual-stack listener sees an IPv4 peer as ::ffff:100.x.
        let mapped = IpAddr::V6(Ipv4Addr::new(100, 101, 102, 103).to_ipv6_mapped());
        let key = login_key(&c.login(CHALLENGE, "100.101.102.103"), CHALLENGE, TARGET, mapped);
        assert_eq!(key, Some(c.pk));
    }

    #[test]
    fn tailnet_name_signs_the_address_it_resolved_to() {
        let c = controller(KNOWN);
        let list = trusted(&[(KNOWN, &c.pk)]);
        note_dialed("studio-test.tail1.ts.net:21118", TAILNET_IP);
        let lr = c.login(CHALLENGE, "studio-test.tail1.ts.net:21118");
        assert_eq!(target_decides(&lr, CHALLENGE, &list), Decision::Allow);
        // A name this Controller never resolved signs the name, which no Target answers to.
        let lr = c.login(CHALLENGE, "never-dialed.tail1.ts.net:21118");
        assert_eq!(target_decides(&lr, CHALLENGE, &list), Decision::Ask);
    }

    #[test]
    fn an_unspecified_or_loopback_arrival_address_is_never_a_target_name() {
        let any = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        assert_eq!(target_names(TARGET, any), [TARGET.to_owned()]);
        assert_eq!(target_names(TARGET, IpAddr::V4(Ipv4Addr::LOCALHOST)), [TARGET.to_owned()]);
        assert_eq!(target_names("", TAILNET_IP), ["100.101.102.103".to_owned()]);
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
    fn a_login_built_before_the_challenge_is_left_unsigned() {
        let mut lr = LoginRequest {
            my_id: KNOWN.to_owned(),
            username: TARGET.to_owned(),
            ..Default::default()
        };
        sign_login(&mut lr, "");
        assert!(lr.boring_login_sig.is_empty() && lr.boring_controller_pk.is_empty());
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
    fn approving_again_with_a_new_key_replaces_the_old_one() {
        let old = controller(KNOWN);
        let reinstalled = controller(KNOWN);
        let next = accepted(&trusted(&[(KNOWN, &old.pk)]), KNOWN, Some(&reinstalled.pk), Password::Right, true);
        assert!(next.contains(KNOWN, &reinstalled.pk));
        assert!(!next.contains(KNOWN, &old.pk));
        assert_eq!(next.ids(), [KNOWN]);
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
