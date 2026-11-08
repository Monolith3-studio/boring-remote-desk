//! LAN trust (v1.7 ticket 04, ADRs 0002, 0005).
//!
//! A Controller that a Target has let in once over an encrypted Direct Link carries a random
//! per-Controller token the Target issued it; presenting that token is the only thing that
//! skips the approval prompt or the Unattended Password. Self-reported id, name or hwid never
//! does. The exchange happens right after `direct_link::secure`, so the token only ever travels
//! inside the already-encrypted stream:
//!
//! 1. Controller → Target: the token it holds for this Target ID, or nothing.
//! 2. Target → Controller: nothing if that token is Trusted; otherwise a fresh token. The fresh
//!    one is worth nothing until someone here approves the session or the Unattended Password
//!    is right ([`Admission::approve`]); only then is it stored (hashed) as Trusted.
//!
//! "Always ask for password" (a switch per Trusted Controller in Settings, off by default):
//! that Controller's token stops being enough. It gets in by this Mac's Unattended Password and
//! nothing else, every connect: not a click here, not a one-time code, not a recent session,
//! whatever the approve mode (connection.rs, rebrand T04_ALWAYS_ASK and its gate). It stays
//! Trusted and keeps its token, so switching off gives back the silent way in. Only Settings on
//! this Mac changes the switch; nothing a Controller sends does.

use crate::message_proto::{message, Message, PublicKey};
use hbb_common::{
    bail,
    config::{Config, LocalConfig},
    password_security::{decrypt_str_or_original, encrypt_str_or_original},
    protobuf::Message as _,
    serde_json,
    sodiumoxide::{crypto::hash::sha256, randombytes::randombytes, utils::memcmp},
    ResultType, Stream,
};
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

/// Target side (server Config): the Trusted Controllers, as hashes of the tokens issued to them.
pub const TRUSTED_OPTION: &str = "boring-trusted-controllers";
/// Controller side (LocalConfig): the token each Target issued this Mac, by Target ID.
pub const TOKENS_OPTION: &str = "boring-trust-tokens";

const TAG: &[u8] = b"boring-trust-1";
const TOKEN_LEN: usize = 32; // 256 bits
const ENC: &str = "00";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// `json` as `T`; an unset option ("") is the default quietly, a corrupt one is the default and a
/// log line (throttled: the Target reads its list on every Direct Link a peer opens).
pub(crate) fn parse_or_default<T: Default + serde::de::DeserializeOwned>(json: &str, what: &str) -> T {
    match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => {
            if !json.trim().is_empty() {
                hbb_common::throttled_log!(std::time::Duration::from_secs(60), warn, "{} unreadable, using none: {}", what, e);
            }
            T::default()
        }
    }
}

fn digest(token: &[u8]) -> Vec<u8> {
    sha256::hash(token).0.to_vec()
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// One Trusted Controller as the Target keeps it. `key` is the hash of its token, never the token.
/// A removed one stays as a hidden entry (`removed`) so that when it comes back with that token
/// this Mac knows it was removed and asks, whatever password it brings (device check A2 step 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedController {
    pub key: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub added: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub removed: bool,
    /// "Always ask for password". Absent (every 1.7.0 entry) is off, and off is never written, so
    /// a list with none switched on is byte for byte what 1.7.0 wrote and reads.
    #[serde(default, skip_serializing_if = "is_false")]
    pub always_ask: bool,
}

/// The Target's Trusted Controllers (Settings → Advanced → Trusted Controllers lists and removes).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trusted(Vec<TrustedController>);

impl Trusted {
    /// Unreadable JSON counts as no Trusted Controllers (everyone is asked again), and says so.
    pub fn parse(json: &str) -> Self {
        Trusted(parse_or_default(json, "Trusted Controllers"))
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.0).unwrap_or_default()
    }

    pub fn load() -> Self {
        Self::parse(&Config::get_option(TRUSTED_OPTION))
    }

    pub fn save(&self) {
        Config::set_option(TRUSTED_OPTION.to_owned(), self.to_json());
    }

    /// The Trusted Controllers Settings lists: removed ones are not.
    pub fn list(&self) -> Vec<&TrustedController> {
        self.0.iter().filter(|t| !t.removed).collect()
    }

    /// Who holds `token`, if anyone, removed or not (the caller looks at `removed`). Only a
    /// full-length token can match, and every entry is compared in constant time.
    pub fn check(&self, token: &[u8]) -> Option<&TrustedController> {
        if token.len() != TOKEN_LEN {
            return None;
        }
        let d = digest(token);
        let mut hit = None;
        for t in &self.0 {
            let ok = unhex(&t.key).map_or(false, |k| k.len() == d.len() && memcmp(&k, &d));
            if ok && hit.is_none() {
                hit = Some(t);
            }
        }
        hit
    }

    fn add(&mut self, key: &[u8], name: &str) {
        let key = hex(key);
        // A Controller that dropped its token (Forget, a reinstall) comes back as a stranger. If
        // it uses the name of one switched to always ask, it is stored switched on too. A name is
        // self-reported, so it never lets anyone in (ADR 0005); here it can only take away.
        let always_ask = !name.is_empty() && self.0.iter().any(|t| t.always_ask && t.name == name);
        self.0.retain(|t| t.key != key);
        self.0.push(TrustedController { key, name: name.to_owned(), added: now(), removed: false, always_ask });
    }

    /// Settings' "Always ask for password" for the listed Controller with `key` (a removed one has
    /// no switch). flutter/lib/desktop/kit/trust.dart `setAlwaysAsk` does the same to the option
    /// JSON, over ipc to the service, as Remove does.
    pub fn set_always_ask(&mut self, key: &str, on: bool) -> bool {
        match self.0.iter_mut().find(|t| t.key == key && !t.removed) {
            Some(t) => {
                t.always_ask = on;
                true
            }
            None => false,
        }
    }

    /// Removing an entry revokes its token: the next connect from that Controller is asked on
    /// this Mac, and only Allow here trusts it again (not the Unattended Password).
    /// flutter/lib/desktop/kit/trust.dart `removeTrusted` does the same to the option JSON.
    pub fn remove(&mut self, key: &str) -> bool {
        match self.0.iter_mut().find(|t| t.key == key && !t.removed) {
            Some(t) => {
                t.removed = true;
                true
            }
            None => false,
        }
    }

    /// Allow on this Mac for a removed Controller: its token is Trusted again (still always ask,
    /// if it was).
    fn reinstate(&mut self, key: &str, name: &str) -> bool {
        match self.0.iter_mut().find(|t| t.key == key) {
            Some(t) => {
                t.removed = false;
                t.name = name.to_owned();
                t.added = now();
                true
            }
            None => false,
        }
    }
}

/// How a Direct Link session got in (src/server/connection.rs maps its sign-in to this).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignIn {
    /// Someone clicked Allow on this Mac.
    Allowed,
    /// The Unattended Password.
    UnattendedPassword,
    /// Anything else, such as the one-time code: in for this session, asked again next time.
    ThisSessionOnly,
}

/// What the Target learned in the exchange: already Trusted, Trusted but always asked for the
/// password (its name), removed from Trusted Controllers (its key), or the hash of the token it
/// just issued, waiting for approval.
#[derive(Debug, Clone, Default)]
pub struct Admission {
    trusted: Option<String>,
    pending: Option<Vec<u8>>,
    removed: Option<String>,
    always_ask: Option<String>,
    /// Set by connection.rs only, once this session's Unattended Password checked out.
    password_right: bool,
}

/// The `platform_additions` key a Target adds to its `PeerInfo` when it let in an always-ask
/// Controller (connection.rs, rebrand T04_ALWAYS_ASK_MARK). A Boring Remote Controller then keeps
/// no password for it (client.rs, T04_ALWAYS_ASK_FORGET), so the next connect asks. Any other
/// Controller ignores the key; the protocol is unchanged. Telling it is a courtesy, not the lock:
/// the lock is the Target asking every time.
pub const ALWAYS_ASK_MARKER: &str = "boring_always_ask";

/// Whether the Target's `platform_additions` JSON says it always asks this Controller.
pub fn asks_every_time(platform_additions: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(platform_additions)
        .ok()
        .and_then(|v| v.get(ALWAYS_ASK_MARKER).and_then(|m| m.as_bool()))
        .unwrap_or(false)
}

/// Hex characters of a Trusted Controllers key the ask carries (64 bits).
pub const KEY_PREFIX_LEN: usize = 16;

/// What the ask shows and what Settings matches a waiting ask on (audit H1): new, removed or
/// trusted; the start of its Trusted Controllers key (the removed entry's, or the one Allow would
/// store); its address. Never the name alone: the Controller picks that itself. Rides the
/// connection window's `Data::Login` (src/ipc.rs) and its client JSON, flattened.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AskInfo {
    #[serde(default)]
    pub boring_trust: String,
    #[serde(default)]
    pub boring_key: String,
    #[serde(default)]
    pub boring_ip: String,
}

impl Admission {
    /// For the ask: "trusted", "removed" or "new", and the key prefix (empty when trusted, or
    /// when no exchange ran).
    pub fn ask_info(&self, ip: &str) -> AskInfo {
        let prefix = |k: &str| k.get(..KEY_PREFIX_LEN).unwrap_or(k).to_owned();
        let (trust, key) = if self.trusted.is_some() || self.always_ask.is_some() {
            ("trusted", String::new())
        } else if let Some(k) = &self.removed {
            ("removed", prefix(k))
        } else {
            ("new", self.pending.as_deref().map(|d| prefix(&hex(d))).unwrap_or_default())
        };
        AskInfo { boring_trust: trust.to_owned(), boring_key: key, boring_ip: ip.to_owned() }
    }

    /// Presented a token this Mac issued and still trusts.
    pub fn is_trusted(&self) -> bool {
        self.trusted.is_some()
    }

    /// Presented a token this Mac issued and then removed: the session waits for Allow here,
    /// whatever password it brings (src/server/connection.rs, rebrand T04_TRUSTED_SKIP).
    pub fn must_ask(&self) -> bool {
        self.removed.is_some()
    }

    /// Presented a token this Mac trusts, switched to always ask: it gets in by the Unattended
    /// Password and nothing else (src/server/connection.rs, rebrand T04_ALWAYS_ASK).
    pub fn always_ask(&self) -> bool {
        self.always_ask.is_some()
    }

    /// connection.rs: this session gave this Mac's Unattended Password (not a one-time code).
    pub fn unattended_password_right(&mut self) {
        self.password_right = true;
    }

    /// The last word before any sign-in lets this session in (rebrand T04_ALWAYS_ASK_GATE): no for
    /// an always-ask Controller that has not given the Unattended Password, whatever got it this
    /// far (a click, switch sides, a sign-in path upstream adds later). Yes for everyone else.
    pub fn may_let_in(&self) -> bool {
        self.always_ask.is_none() || self.password_right
    }

    /// The session got in. If someone clicked Allow here or the Unattended Password was right,
    /// the token just issued becomes Trusted under `name`; any other sign-in leaves it worthless.
    pub fn approve(&mut self, how: SignIn, name: &str) {
        if self.trusted.is_some() {
            hbb_common::log::info!("Direct Link: Trusted Controller {:?} came straight in", name);
            return;
        }
        if self.always_ask.is_some() {
            hbb_common::log::info!("Direct Link: Trusted Controller {:?} gave the Unattended Password (always ask)", name);
            return;
        }
        let was_removed = self.removed.is_some();
        let mut t = Trusted::load();
        let stored = self.approve_into(&mut t, how, name);
        if stored {
            t.save();
        }
        hbb_common::log::info!(
            "Direct Link: {:?} got in by {:?}{}; Trusted now: {}",
            name,
            how,
            if was_removed { " after being removed" } else { "" },
            stored
        );
    }

    fn approve_into(&mut self, t: &mut Trusted, how: SignIn, name: &str) -> bool {
        // Always ask: its entry stays exactly as Settings left it, and no token is issued, so no
        // sign-in can make it come in silently again.
        if self.always_ask.is_some() {
            return false;
        }
        // A removed Controller is Trusted again only by Allow here, never by a password.
        if let Some(key) = self.removed.as_ref() {
            if how != SignIn::Allowed {
                return false;
            }
            let ok = t.reinstate(key, name);
            self.removed = None;
            return ok;
        }
        match self.pending.take() {
            Some(key) if how != SignIn::ThisSessionOnly => {
                t.add(&key, name);
                true
            }
            _ => false,
        }
    }
}

fn frame(token: &[u8]) -> Message {
    let mut m = Message::new();
    m.set_public_key(PublicKey {
        asymmetric_value: TAG.to_vec().into(),
        symmetric_value: token.to_vec().into(),
        ..Default::default()
    });
    m
}

async fn read(stream: &mut Stream, ms: u64) -> ResultType<Vec<u8>> {
    let bytes = match hbb_common::timeout(ms, stream.next()).await {
        Ok(Some(Ok(bytes))) => bytes,
        _ => bail!("no trust exchange"),
    };
    match Message::parse_from_bytes(&bytes)?.union {
        Some(message::Union::PublicKey(pk)) if &pk.asymmetric_value[..] == TAG => Ok(pk.symmetric_value.to_vec()),
        _ => bail!("no trust exchange"),
    }
}

/// Target side, right after the encrypted handshake.
pub async fn answer(stream: &mut Stream, trusted: &Trusted, ms: u64) -> ResultType<Admission> {
    if !stream.is_secured() {
        bail!("trust exchange needs an encrypted Direct Link");
    }
    let token = read(stream, ms).await?;
    match trusted.check(&token) {
        Some(t) if !t.removed && t.always_ask => {
            // Still Trusted, so no fresh token: it keeps this one, and this one keeps asking.
            stream.send(&frame(&[])).await?;
            Ok(Admission { always_ask: Some(t.name.clone()), ..Default::default() })
        }
        Some(t) if !t.removed => {
            stream.send(&frame(&[])).await?;
            Ok(Admission { trusted: Some(t.name.clone()), ..Default::default() })
        }
        Some(t) => {
            // Removed: no fresh token, so the Controller keeps presenting this one and stays
            // known as removed until someone clicks Allow here.
            hbb_common::log::info!("Direct Link: removed Controller {:?} is back; asking on this Mac", t.name);
            stream.send(&frame(&[])).await?;
            Ok(Admission { removed: Some(t.key.clone()), ..Default::default() })
        }
        None => {
            let fresh = randombytes(TOKEN_LEN);
            stream.send(&frame(&fresh)).await?;
            Ok(Admission { pending: Some(digest(&fresh)), ..Default::default() })
        }
    }
}

/// Controller side: present `token` (if any). Returns the fresh token the Target issued, if it
/// issued one; it counts only once the Target approves this session.
pub async fn present(stream: &mut Stream, token: Option<&[u8]>, ms: u64) -> ResultType<Option<Vec<u8>>> {
    if !stream.is_secured() {
        bail!("trust exchange needs an encrypted Direct Link");
    }
    stream.send(&frame(token.unwrap_or_default())).await?;
    let got = read(stream, ms).await?;
    Ok(if got.len() == TOKEN_LEN { Some(got) } else { None })
}

/// The tokens Targets issued this Controller, by Target ID (encrypted at rest).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tokens(HashMap<String, String>);

impl Tokens {
    pub fn parse(json: &str) -> Self {
        Tokens(parse_or_default(json, "trust tokens"))
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.0).unwrap_or_default()
    }

    pub fn load() -> Self {
        Self::parse(&LocalConfig::get_option(TOKENS_OPTION))
    }

    pub fn save(&self) {
        LocalConfig::set_option(TOKENS_OPTION.to_owned(), self.to_json());
    }

    pub fn get(&self, target: &str) -> Option<Vec<u8>> {
        let (h, _, _) = decrypt_str_or_original(self.0.get(target)?, ENC);
        unhex(&h).filter(|t| t.len() == TOKEN_LEN)
    }

    pub fn set(&mut self, target: &str, token: &[u8]) {
        self.0.insert(target.to_owned(), encrypt_str_or_original(&hex(token), ENC, 128));
    }

    pub fn forget(&mut self, target: &str) {
        self.0.remove(target);
    }
}

/// Controller side, called by `direct_link::handshake` once the stream is keyed to `target`.
pub async fn present_for(stream: &mut Stream, target: &str, ms: u64) -> ResultType<()> {
    let mut tokens = Tokens::load();
    if let Some(fresh) = present(stream, tokens.get(target).as_deref(), ms).await? {
        tokens.set(target, &fresh);
        tokens.save();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn keyed_pair() -> (Stream, Stream) {
        let l = hbb_common::tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let c = hbb_common::tokio::net::TcpStream::connect(addr).await.unwrap();
        let (srv, _) = l.accept().await.unwrap();
        let (mut ctl, mut tgt) = (Stream::from(c, addr), Stream::from(srv, addr));
        let key = hbb_common::sodiumoxide::crypto::secretbox::gen_key();
        ctl.set_key(key.clone());
        tgt.set_key(key);
        (ctl, tgt)
    }

    /// One connect: the Controller presents what it holds, the Target answers from `trusted`.
    async fn connect(trusted: &Trusted, holding: Option<Vec<u8>>) -> (Admission, Option<Vec<u8>>) {
        let (mut ctl, mut tgt) = keyed_pair().await;
        let c = tokio::spawn(async move { present(&mut ctl, holding.as_deref(), 2_000).await.unwrap() });
        let a = answer(&mut tgt, trusted, 2_000).await.unwrap();
        (a, c.await.unwrap())
    }

    #[tokio::test]
    async fn an_unknown_controller_is_not_trusted() {
        let (a, issued) = connect(&Trusted::default(), None).await;
        assert!(!a.is_trusted());
        assert_eq!(issued.map(|t| t.len()), Some(32)); // issued, but worth nothing yet
    }

    #[tokio::test]
    async fn approval_stores_trusted_and_the_second_connect_skips_the_prompt() {
        let mut trusted = Trusted::default();
        let (mut a, issued) = connect(&trusted, None).await;
        let token = issued.unwrap();
        // Not approved yet: presenting the issued token is still a stranger.
        let (b, _) = connect(&trusted, Some(token.clone())).await;
        assert!(!b.is_trusted());
        assert!(a.approve_into(&mut trusted, SignIn::Allowed, "Edit Bay 2"));
        assert!(!a.approve_into(&mut trusted, SignIn::Allowed, "again"), "one approval stores one token");
        let trusted = Trusted::parse(&trusted.to_json());
        assert_eq!(trusted.list().len(), 1);
        assert_eq!(trusted.list()[0].name, "Edit Bay 2");
        assert!(!trusted.to_json().contains(&hex(&token)), "the Target stores only a hash");
        let (second, reissued) = connect(&trusted, Some(token)).await;
        assert!(second.is_trusted());
        assert_eq!(reissued, None);
    }

    #[tokio::test]
    async fn a_one_time_code_lets_a_controller_in_for_that_session_only() {
        let mut trusted = Trusted::default();
        let (mut a, issued) = connect(&trusted, None).await;
        assert!(!a.approve_into(&mut trusted, SignIn::ThisSessionOnly, "Edit Bay 2"));
        assert!(trusted.list().is_empty());
        let (next, _) = connect(&trusted, issued).await;
        assert!(!next.is_trusted(), "asked again next time");
    }

    #[tokio::test]
    async fn removing_a_trusted_controller_revokes_its_token() {
        let mut trusted = Trusted::default();
        let (mut a, issued) = connect(&trusted, None).await;
        a.approve_into(&mut trusted, SignIn::UnattendedPassword, "Stage Left");
        let key = trusted.list()[0].key.clone();
        assert!(trusted.remove(&key));
        let (again, _) = connect(&trusted, issued).await;
        assert!(!again.is_trusted());
    }

    /// Device check A2 step 5: Remove, then the same Controller connects again. It must be asked
    /// on this Mac; the Unattended Password (typed or remembered on the Controller) must not
    /// quietly make it Trusted again. Only Allow here does.
    #[tokio::test]
    async fn a_removed_controller_is_asked_again_and_the_password_does_not_undo_remove() {
        let mut trusted = Trusted::default();
        let (mut a, issued) = connect(&trusted, None).await;
        a.approve_into(&mut trusted, SignIn::Allowed, "Sam M Studio");
        let key = trusted.list()[0].key.clone();
        assert!(trusted.remove(&key));
        assert!(trusted.list().is_empty(), "Settings no longer lists it");
        let mut trusted = Trusted::parse(&trusted.to_json());

        // It comes back with the token it holds.
        let (mut back, reissued) = connect(&trusted, issued.clone()).await;
        assert!(!back.is_trusted());
        assert!(back.must_ask(), "a removed Controller is asked here, password or not");
        assert!(!back.approve_into(&mut trusted, SignIn::UnattendedPassword, "Sam M Studio"),
                "the Unattended Password does not undo Remove");
        assert!(!back.approve_into(&mut trusted, SignIn::ThisSessionOnly, "Sam M Studio"));
        assert!(trusted.list().is_empty());

        // Still removed next time, whatever token it now holds.
        let holding = reissued.or(issued);
        let (mut again, kept) = connect(&trusted, holding.clone()).await;
        assert!(again.must_ask());
        assert!(!again.approve_into(&mut trusted, SignIn::UnattendedPassword, "Sam M Studio"));

        // Allow on this Mac trusts it again, and the next connect skips the ask.
        let holding = kept.or(holding);
        assert!(again.approve_into(&mut trusted, SignIn::Allowed, "Sam M Studio"));
        assert_eq!(trusted.list().len(), 1);
        let (fourth, _) = connect(&trusted, holding).await;
        assert!(fourth.is_trusted());
        assert!(!fourth.must_ask());
    }

    /// Audit H1: the ask says new or removed, with the key Settings matches a waiting ask on.
    #[tokio::test]
    async fn the_ask_says_new_removed_or_trusted_with_the_key_settings_matches_on() {
        let mut trusted = Trusted::default();
        let (mut a, issued) = connect(&trusted, None).await;
        let ask = a.ask_info("192.168.1.20");
        assert_eq!((ask.boring_trust.as_str(), ask.boring_ip.as_str()), ("new", "192.168.1.20"));
        assert_eq!(ask.boring_key.len(), KEY_PREFIX_LEN);
        a.approve_into(&mut trusted, SignIn::Allowed, "Edit Bay 2");
        let key = trusted.list()[0].key.clone();
        assert!(key.starts_with(&ask.boring_key), "the stored key is the one the ask named");

        let (b, _) = connect(&trusted, issued.clone()).await;
        assert_eq!(b.ask_info("").boring_trust, "trusted");

        trusted.remove(&key);
        let (c, _) = connect(&trusted, issued).await;
        let ask = c.ask_info("192.168.1.20");
        assert_eq!(ask.boring_trust, "removed");
        assert_eq!(ask.boring_key, key[..KEY_PREFIX_LEN]);

        // A stranger using the removed one's name is new, with a key of its own.
        let (d, _) = connect(&trusted, None).await;
        let ask = d.ask_info("192.168.1.66");
        assert_eq!(ask.boring_trust, "new");
        assert!(!key.starts_with(&ask.boring_key));
        assert_eq!(Admission::default().ask_info("").boring_trust, "new", "no exchange is never shown as known");
    }

    #[tokio::test]
    async fn an_unknown_controller_is_not_forced_to_the_ask() {
        // ADR 0005 unchanged for strangers: the Unattended Password still works and trusts.
        let mut trusted = Trusted::default();
        let (mut a, _) = connect(&trusted, None).await;
        assert!(!a.must_ask());
        assert!(a.approve_into(&mut trusted, SignIn::UnattendedPassword, "Stage Left"));
    }

    #[tokio::test]
    async fn a_wrong_or_blank_token_is_never_trusted() {
        let mut trusted = Trusted::default();
        let (mut a, _) = connect(&trusted, None).await;
        a.approve_into(&mut trusted, SignIn::Allowed, "Edit Bay 2");
        for t in [vec![], vec![0u8; 32], vec![1u8; 31], randombytes(32)] {
            assert!(trusted.check(&t).is_none(), "{:?}", t);
        }
        // A list someone pasted a hash of the blank token into still refuses the blank token.
        let blank = Trusted::parse(&format!(r#"[{{"key":"{}","name":"x"}}]"#, hex(&digest(&[]))));
        assert!(blank.check(&[]).is_none());
    }

    #[tokio::test]
    async fn self_reported_id_name_or_hwid_alone_never_grants_entry() {
        // The Target trusts "Edit Bay 2" (id 123456789). A stranger that says it is that Mac,
        // by name or by id, but has no token, is a stranger.
        let mut trusted = Trusted::default();
        let (mut a, _) = connect(&trusted, None).await;
        a.approve_into(&mut trusted, SignIn::Allowed, "Edit Bay 2");
        for claim in ["Edit Bay 2", "123456789", "hwid-of-edit-bay-2"] {
            let (b, _) = connect(&trusted, Some(claim.as_bytes().to_vec())).await;
            assert!(!b.is_trusted(), "{}", claim);
        }
        let (b, _) = connect(&trusted, None).await;
        assert!(!b.is_trusted());
    }

    #[tokio::test]
    async fn no_exchange_on_a_plaintext_stream() {
        let l = hbb_common::tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let c = hbb_common::tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut ctl = Stream::from(c, addr);
        assert!(present(&mut ctl, None, 100).await.is_err());
    }

    /// What 1.7.0 wrote: no `always_ask` anywhere. It loads as before and saves byte for byte.
    const TRUST_FILE_1_7_0: &str = r#"[{"key":"aa11","name":"Edit Bay 2","added":1761955200},{"key":"bb22","name":"Stage Left","added":1761955300,"removed":true}]"#;

    #[test]
    fn a_1_7_0_trust_file_loads_unchanged() {
        let t = Trusted::parse(TRUST_FILE_1_7_0);
        assert_eq!(t.list().len(), 1);
        assert!(t.0.iter().all(|c| !c.always_ask), "off unless switched on");
        assert_eq!(t.to_json(), TRUST_FILE_1_7_0, "off is not written, so 1.7.0 reads it back as it was");
    }

    /// Trusted, then "Always ask for password" switched on in Settings.
    async fn always_ask_controller() -> (Trusted, Vec<u8>, String) {
        let mut trusted = Trusted::default();
        let (mut a, issued) = connect(&trusted, None).await;
        a.approve_into(&mut trusted, SignIn::Allowed, "Edit Bay 2");
        let key = trusted.list()[0].key.clone();
        assert!(trusted.set_always_ask(&key, true));
        (Trusted::parse(&trusted.to_json()), issued.unwrap(), key)
    }

    #[tokio::test]
    async fn always_ask_takes_away_the_silent_way_in_and_off_gives_it_back() {
        let (mut trusted, token, key) = always_ask_controller().await;
        assert!(trusted.to_json().contains(r#""always_ask":true"#));
        assert_eq!(trusted.list().len(), 1, "it stays on the Trusted list");

        let (a, reissued) = connect(&trusted, Some(token.clone())).await;
        assert!(!a.is_trusted(), "its token alone no longer gets it in");
        assert!(a.always_ask());
        assert!(!a.must_ask(), "not removed: no ask here, it needs the password");
        assert_eq!(reissued, None, "no fresh token: it keeps this one, and this one keeps asking");
        assert_eq!(a.ask_info("192.168.1.20").boring_trust, "trusted", "never shown as a new computer");

        assert!(trusted.set_always_ask(&key, false));
        let (b, _) = connect(&trusted, Some(token)).await;
        assert!(b.is_trusted(), "off: in without asking again, as before");
        assert!(!b.always_ask());
        assert!(!trusted.to_json().contains("always_ask"), "off is not written");
    }

    #[tokio::test]
    async fn only_the_unattended_password_lets_an_always_ask_controller_in() {
        let (trusted, token, _) = always_ask_controller().await;
        let (mut a, _) = connect(&trusted, Some(token)).await;
        assert!(!a.may_let_in(), "a click here, a one-time code or a recent session is not enough");
        a.unattended_password_right();
        assert!(a.may_let_in());

        // Not always-ask: may_let_in never stands in the way of the usual sign-ins.
        assert!(Admission::default().may_let_in());
        let (b, _) = connect(&Trusted::default(), None).await;
        assert!(b.may_let_in());
    }

    #[tokio::test]
    async fn signing_in_never_changes_an_always_ask_entry_or_issues_a_token() {
        let (trusted, token, _) = always_ask_controller().await;
        let before = trusted.to_json();
        for how in [SignIn::UnattendedPassword, SignIn::Allowed, SignIn::ThisSessionOnly] {
            let mut t = trusted.clone();
            let (mut a, reissued) = connect(&t, Some(token.clone())).await;
            a.unattended_password_right();
            assert!(!a.approve_into(&mut t, how, "Renamed"), "{:?}", how);
            assert_eq!(t.to_json(), before, "{:?}: nothing stored, nothing switched off", how);
            assert_eq!(reissued, None);
        }
    }

    #[tokio::test]
    async fn dropping_its_token_and_coming_back_by_name_stays_always_ask() {
        // Forget on the Controller, or a reinstall: it comes back with no token, as a stranger. A
        // name is self-reported, so it can only take the silent way in away, never grant it.
        let (mut trusted, _, _) = always_ask_controller().await;
        let (mut back, _) = connect(&trusted, None).await;
        assert!(!back.always_ask() && !back.is_trusted());
        assert!(back.approve_into(&mut trusted, SignIn::UnattendedPassword, "Edit Bay 2"));
        assert_eq!(trusted.list().len(), 2);
        assert!(trusted.list().iter().all(|c| c.always_ask), "the new entry is switched on too");

        let (mut other, _) = connect(&trusted, None).await;
        assert!(other.approve_into(&mut trusted, SignIn::UnattendedPassword, "Stage Left"));
        assert!(!trusted.list().iter().find(|c| c.name == "Stage Left").unwrap().always_ask);
        let (mut nameless, _) = connect(&trusted, None).await;
        assert!(nameless.approve_into(&mut trusted, SignIn::Allowed, ""));
        assert!(!trusted.list().iter().find(|c| c.name.is_empty()).unwrap().always_ask);
    }

    #[tokio::test]
    async fn remove_then_allow_keeps_always_ask() {
        let (mut trusted, token, key) = always_ask_controller().await;
        assert!(trusted.remove(&key));
        assert!(!trusted.set_always_ask(&key, false), "a removed one has no switch");
        let (mut back, _) = connect(&trusted, Some(token.clone())).await;
        assert!(back.must_ask() && !back.always_ask(), "removed wins: it waits for Allow here");
        assert!(back.approve_into(&mut trusted, SignIn::Allowed, "Edit Bay 2"));
        let (again, _) = connect(&trusted, Some(token)).await;
        assert!(again.always_ask(), "Allow trusts it again, still asking for the password");
        assert!(!trusted.set_always_ask("not-a-key", true));
    }

    #[test]
    fn the_target_tells_the_controller_not_to_keep_its_password() {
        assert!(asks_every_time(r#"{"boring_remote":"1.7.1","boring_always_ask":true}"#));
        for no in ["", "junk", "{}", r#"{"boring_always_ask":false}"#, r#"{"boring_always_ask":"true"}"#,
                   r#"{"boring_remote":"1.7.0","is_installed":true}"#] {
            assert!(!asks_every_time(no), "{}", no);
        }
    }

    #[test]
    fn the_controller_keeps_one_token_per_target_and_forgets_it() {
        let mut tokens = Tokens::default();
        let t = randombytes(32);
        tokens.set("123456789", &t);
        let mut tokens = Tokens::parse(&tokens.to_json());
        assert_eq!(tokens.get("123456789"), Some(t));
        assert_eq!(tokens.get("987654321"), None);
        tokens.forget("123456789");
        assert_eq!(tokens.get("123456789"), None);
    }
}
