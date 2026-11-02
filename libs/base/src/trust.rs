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
        self.0.retain(|t| t.key != key);
        self.0.push(TrustedController { key, name: name.to_owned(), added: now(), removed: false });
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

    /// Allow on this Mac for a removed Controller: its token is Trusted again.
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

/// What the Target learned in the exchange: already Trusted, removed from Trusted Controllers
/// (its key), or the hash of the token it just issued, waiting for approval.
#[derive(Debug, Clone, Default)]
pub struct Admission {
    trusted: Option<String>,
    pending: Option<Vec<u8>>,
    removed: Option<String>,
}

impl Admission {
    /// Presented a token this Mac issued and still trusts.
    pub fn is_trusted(&self) -> bool {
        self.trusted.is_some()
    }

    /// Presented a token this Mac issued and then removed: the session waits for Allow here,
    /// whatever password it brings (src/server/connection.rs, rebrand T04_TRUSTED_SKIP).
    pub fn must_ask(&self) -> bool {
        self.removed.is_some()
    }

    /// The session got in. If someone clicked Allow here or the Unattended Password was right,
    /// the token just issued becomes Trusted under `name`; any other sign-in leaves it worthless.
    pub fn approve(&mut self, how: SignIn, name: &str) {
        if self.trusted.is_some() {
            hbb_common::log::info!("Direct Link: Trusted Controller {:?} came straight in", name);
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
        a.approve_into(&mut trusted, SignIn::Allowed, "Jason M Studio");
        let key = trusted.list()[0].key.clone();
        assert!(trusted.remove(&key));
        assert!(trusted.list().is_empty(), "Settings no longer lists it");
        let mut trusted = Trusted::parse(&trusted.to_json());

        // It comes back with the token it holds.
        let (mut back, reissued) = connect(&trusted, issued.clone()).await;
        assert!(!back.is_trusted());
        assert!(back.must_ask(), "a removed Controller is asked here, password or not");
        assert!(!back.approve_into(&mut trusted, SignIn::UnattendedPassword, "Jason M Studio"),
                "the Unattended Password does not undo Remove");
        assert!(!back.approve_into(&mut trusted, SignIn::ThisSessionOnly, "Jason M Studio"));
        assert!(trusted.list().is_empty());

        // Still removed next time, whatever token it now holds.
        let holding = reissued.or(issued);
        let (mut again, kept) = connect(&trusted, holding.clone()).await;
        assert!(again.must_ask());
        assert!(!again.approve_into(&mut trusted, SignIn::UnattendedPassword, "Jason M Studio"));

        // Allow on this Mac trusts it again, and the next connect skips the ask.
        let holding = kept.or(holding);
        assert!(again.approve_into(&mut trusted, SignIn::Allowed, "Jason M Studio"));
        assert_eq!(trusted.list().len(), 1);
        let (fourth, _) = connect(&trusted, holding).await;
        assert!(fourth.is_trusted());
        assert!(!fourth.must_ask());
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
