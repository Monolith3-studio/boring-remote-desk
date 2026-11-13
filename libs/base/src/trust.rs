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
//!
//! 1.8.0 (Hosted servers, ADR 0005; ticket 06, trust binding option B), on the same one list:
//!
//! - The Controller's own key. A 1.8 Controller signs each login with its persistent Ed25519 key
//!   (the one it signs its ID with as a Target) over [`login_message`]: this connection's
//!   challenge, the Target's Machine ID and its own ID. It signs only over a stream whose Target
//!   it verified (a Direct Link pinned to that Machine ID, or the Hosted servers' word under the
//!   baked server key); the Target takes its own Machine ID as the signed name only on a keyed
//!   stream (src/trust_policy.rs). Allow stores that key (`pk`) with the entry, next to the token
//!   when there is one. On the Hosted path there is no token exchange: the key is what finds the
//!   entry ([`Admission::prove`]). A Machine ID, name or hwid alone never does.
//! - A new Controller needs Allow on this computer even with the right Unattended Password
//!   (spec stories 13 and 16): the password alone no longer stores or lets in a stranger. Allow
//!   stores it only when its password checked out and no other session is open (the click could
//!   come from a Controller driving this computer). No password set here: Allow lets it in for
//!   that session only.
//! - A Trusted Controller found by its key still gives the Unattended Password (Hosted is open to
//!   anyone who has a Machine ID); one found by its token on a Direct Link comes in silently, as
//!   in 1.7.
//! - Remove ends that Controller's live sessions. While any session is open, Settings can only
//!   tighten the list (Remove, Always ask on), never loosen it ([`edit_in_session`]).

use crate::message_proto::{message, Message, PublicKey};
use hbb_common::{
    bail,
    config::{compute_permanent_password_h1, decode_permanent_password_h1_from_storage, Config, LocalConfig},
    password_security::{decrypt_str_or_original, encrypt_str_or_original, symmetric_crypt},
    protobuf::Message as _,
    serde_json,
    sodiumoxide::{base64, crypto::hash::sha256, crypto::sign, randombytes::randombytes, utils::memcmp},
    ResultType, Stream,
};
use serde_derive::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    convert::TryInto,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

/// Target side (server Config): the Trusted Controllers, as hashes of the tokens issued to them.
pub const TRUSTED_OPTION: &str = "boring-trusted-controllers";
/// Controller side (LocalConfig): the token each Target issued this Mac, by Target ID.
pub const TOKENS_OPTION: &str = "boring-trust-tokens";
/// Target side: "New computers always ask for password" ("Y" on; unset off, as 1.7.0).
pub const NEW_ALWAYS_ASK_OPTION: &str = "boring-new-computers-always-ask";
/// The ipc config name Settings' Remove, Allow and "Always ask for password" go through to the
/// service (src/ipc.rs, rebrand T04_EDIT_IPC): one locked read-modify-write there ([`edit`]).
pub const EDIT_CONFIG: &str = "boring-trust-edit";

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

/// What the pre-port 1.8.0 build wrote to the same option: `id:hex-key`, comma separated (never
/// released). Read as no Trusted Controllers, so each of those Controllers is asked once more.
fn is_pre_port_list(raw: &str) -> bool {
    let raw = raw.trim();
    !raw.starts_with('[')
        && raw.split(',').all(|e| {
            let (id, key) = e.split_once(':').unwrap_or((e, ""));
            !id.is_empty()
                && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                && (key.is_empty() || key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()))
        })
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
    /// 1.8: the Controller's own Ed25519 public key (hex), proven by its signed login when it was
    /// let in. Absent on every 1.7 entry and never written empty, so a 1.7 list saves unchanged.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pk: String,
}

/// `key` of an entry stored with no token (let in over the Hosted path, where there is no token
/// exchange): this prefix plus its `pk`. Never hex, so no token can ever match it ([`Trusted::check`]).
pub const PK_KEY_PREFIX: &str = "pk:";

/// The Target's Trusted Controllers (Settings → Advanced → Trusted Controllers lists and removes).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trusted {
    list: Vec<TrustedController>,
    /// "New computers always ask for password": a Controller stored from now on starts switched on.
    pub new_always_ask: bool,
}

impl Trusted {
    /// Unreadable JSON counts as no Trusted Controllers (everyone is asked again), and says so.
    pub fn parse(json: &str) -> Self {
        Trusted { list: parse_or_default(json, "Trusted Controllers"), ..Default::default() }
    }

    /// For writing: unset is an empty list, unreadable is None, so it is never written over
    /// (a list rebuilt from nothing would drop every entry's switch).
    pub fn parse_strict(json: &str) -> Option<Self> {
        if json.trim().is_empty() || is_pre_port_list(json) {
            return Some(Self::default());
        }
        serde_json::from_str(json).ok().map(|list| Trusted { list, ..Default::default() })
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.list).unwrap_or_default()
    }

    pub fn load() -> Self {
        Trusted { new_always_ask: Config::get_option(NEW_ALWAYS_ASK_OPTION) == "Y", ..Self::parse(&Config::get_option(TRUSTED_OPTION)) }
    }

    pub fn save(&self) {
        Config::set_option(TRUSTED_OPTION.to_owned(), self.to_json());
    }

    /// The Trusted Controllers Settings lists: removed ones are not.
    pub fn list(&self) -> Vec<&TrustedController> {
        self.list.iter().filter(|t| !t.removed).collect()
    }

    /// Who holds `token`, if anyone, removed or not (the caller looks at `removed`). Only a
    /// full-length token can match, and every entry is compared in constant time.
    pub fn check(&self, token: &[u8]) -> Option<&TrustedController> {
        if token.len() != TOKEN_LEN {
            return None;
        }
        let d = digest(token);
        let mut hit = None;
        for t in &self.list {
            let ok = unhex(&t.key).map_or(false, |k| k.len() == d.len() && memcmp(&k, &d));
            if ok && hit.is_none() {
                hit = Some(t);
            }
        }
        hit
    }

    fn add(&mut self, key: &str, name: &str, pk: &str) {
        let key = key.to_owned();
        // A Controller that dropped its token (Forget, a reinstall) comes back as a stranger. If
        // it uses the name of one switched to always ask, it is stored switched on too. A name is
        // self-reported, so it never lets anyone in (ADR 0005); here it can only take away. With
        // "New computers always ask for password" on, every new one starts switched on.
        let always_ask =
            self.new_always_ask || !name.is_empty() && self.list.iter().any(|t| t.always_ask && t.name == name);
        self.list.retain(|t| t.key != key);
        self.list.push(TrustedController { key, name: name.to_owned(), added: now(), removed: false, always_ask, pk: pk.to_owned() });
    }

    /// The entry holding the Controller key `pk` (hex), removed or not. One key, one entry.
    pub fn by_pk(&self, pk: &str) -> Option<&TrustedController> {
        if pk.len() != 64 {
            return None;
        }
        self.list.iter().find(|c| c.pk == pk)
    }

    /// A 1.7 entry (token only) whose Controller now proved its own key: store the key with it,
    /// once. Never over another key, and never a key another entry already holds.
    fn bind_pk(&mut self, key: &str, pk: &str) -> bool {
        if pk.len() != 64 || self.list.iter().any(|c| c.pk == pk) {
            return false;
        }
        match self.list.iter_mut().find(|c| c.key == key && c.pk.is_empty()) {
            Some(c) => {
                c.pk = pk.to_owned();
                true
            }
            None => false,
        }
    }

    /// Settings' "Always ask for password" for the listed Controller with `key` (a removed one has
    /// no switch). Settings reaches it through [`edit`], never by writing the option itself.
    pub fn set_always_ask(&mut self, key: &str, on: bool) -> bool {
        match self.list.iter_mut().find(|t| t.key == key && !t.removed) {
            Some(t) => {
                t.always_ask = on;
                true
            }
            None => false,
        }
    }

    /// Removing an entry revokes its token: the next connect from that Controller is asked on
    /// this Mac, and only Allow here trusts it again (not the Unattended Password). Settings'
    /// Remove reaches it through [`edit`].
    pub fn remove(&mut self, key: &str) -> bool {
        match self.list.iter_mut().find(|t| t.key == key && !t.removed) {
            Some(t) => {
                t.removed = true;
                true
            }
            None => false,
        }
    }

    /// Reset password's "Also remove every Trusted Controller": all of them, as Remove does.
    pub fn remove_all(&mut self) -> bool {
        let mut any = false;
        for t in self.list.iter_mut().filter(|t| !t.removed) {
            t.removed = true;
            any = true;
        }
        any
    }

    /// Allow on this Mac for a removed Controller: its token is Trusted again (still always ask,
    /// if it was).
    fn reinstate(&mut self, key: &str, name: &str) -> bool {
        match self.list.iter_mut().find(|t| t.key == key) {
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
/// just issued, waiting for approval. 1.8: and what the Controller's proven key found
/// ([`Admission::prove`]), whether this login waits on Allow here, and what Allow may store.
#[derive(Debug, Clone, Default)]
pub struct Admission {
    trusted: Option<String>,
    pending: Option<Vec<u8>>,
    removed: Option<String>,
    always_ask: Option<String>,
    /// Set by connection.rs only, once this session's Unattended Password checked out.
    password_right: bool,
    /// Its Trusted Controllers key, once known (Trusted, or stored at approve): what Settings'
    /// switch is matched on while the session runs ([`Admission::lost_trust`]).
    key: Option<String>,
    /// The [`EDITS`] count this session last looked at.
    seen_edits: u64,
    /// This sign-in stored it switched on (review M-new): it stays, see [`Admission::approve_into`].
    stays: bool,
    /// 1.8: the Controller key this login proved (hex), and the entry it found with no token.
    pk: Option<String>,
    by_key: Option<ByKey>,
    /// 1.8: waiting on Allow here; `true` when the Unattended Password checked out first.
    waiting: Option<bool>,
    /// 1.8, set when Allow lands ([`Admission::take_wait`]): Allow may store a new Controller (its
    /// password was right and no other session is open) / may trust a removed one again.
    may_remember: bool,
    may_reinstate: bool,
}

/// 1.8: what a proven Controller key found on the list, when no token said who this is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ByKey {
    /// Listed: in with the Unattended Password, no Allow needed. Its name and key.
    Trusted(String, String),
    /// Listed, "Always ask for password": the Unattended Password and nothing else.
    AlwaysAsk(String, String),
    /// Removed: waits for Allow here, whatever password it brings. Its key.
    Removed(String),
}

/// Settings edits saved so far in this process; a live session looks at the list again only
/// when this moves (connection.rs once a second, rebrand T04_ALWAYS_ASK_KICK).
static EDITS: AtomicU64 = AtomicU64::new(0);
/// One read-modify-write of the Trusted list at a time: sign-ins storing a Controller and
/// Settings' edits, both in the service ([`edit_list`]).
static EDIT_LOCK: Mutex<()> = Mutex::new(());

/// What an always-ask Controller is told when something other than the Unattended Password
/// tried to let it in (connection.rs, rebrand T04_ALWAYS_ASK_GATE).
pub const ASKS_EVERY_TIME: &str = "This computer asks for its Unattended Password every time.";
/// What it is told when this Mac has no Unattended Password it could give (none set, or turned
/// off): it cannot get in until someone here sets one or switches always ask off.
pub const NO_UNATTENDED_PASSWORD: &str = "This computer asks for its Unattended Password, and none is set on it.";

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
    /// when no exchange ran and no key was proven).
    pub fn ask_info(&self, ip: &str) -> AskInfo {
        let prefix = |k: &str| k.get(..KEY_PREFIX_LEN).unwrap_or(k).to_owned();
        let (trust, key) = if self.trusted.is_some() || self.always_ask() || self.skips_click() {
            ("trusted", String::new())
        } else if let Some(k) = self.removed_key() {
            ("removed", prefix(k))
        } else if let Some(d) = self.pending.as_deref() {
            ("new", prefix(&hex(d)))
        } else {
            ("new", self.pk.as_deref().map(|pk| prefix(&format!("{PK_KEY_PREFIX}{pk}"))).unwrap_or_default())
        };
        AskInfo { boring_trust: trust.to_owned(), boring_key: key, boring_ip: ip.to_owned() }
    }

    /// Presented a token this Mac issued and still trusts.
    pub fn is_trusted(&self) -> bool {
        self.trusted.is_some()
    }

    /// Presented a token this Mac issued and then removed (a Direct Link): the session waits for
    /// Allow here, whatever password it brings (src/server/connection.rs, rebrand T04_TRUSTED_SKIP).
    /// 1.8: one that proved the key of a removed entry instead (the Hosted path has no token) is not
    /// waved to Allow: it gives the Unattended Password first, as a new one does, and only Allow
    /// after it trusts it again ([`Admission::approve_into`]).
    pub fn must_ask(&self) -> bool {
        self.removed.is_some()
    }

    fn removed_key(&self) -> Option<&str> {
        match &self.by_key {
            Some(ByKey::Removed(k)) if self.removed.is_none() => Some(k),
            _ => self.removed.as_deref(),
        }
    }

    /// Presented a token this Mac trusts, switched to always ask, or (1.8) proved such an entry's
    /// key: it gets in by the Unattended Password and nothing else (src/server/connection.rs,
    /// rebrand T04_ALWAYS_ASK).
    pub fn always_ask(&self) -> bool {
        self.always_ask.is_some() || matches!(self.by_key, Some(ByKey::AlwaysAsk(..)))
    }

    /// 1.8: a Trusted Controller found by its proven key (no token): once its Unattended Password
    /// checks out it is in with no Allow here (rebrand TRUST_GATE). Never for a key alone.
    pub fn skips_click(&self) -> bool {
        matches!(self.by_key, Some(ByKey::Trusted(..)))
    }

    /// 1.8, on each login request: `pk` is the Controller key this login proved (src/trust_policy.rs
    /// `login_key`, None for no or a bad signature). With no token deciding who this is, the key
    /// finds its entry: listed, always ask, or removed. A token's verdict always stands; the key
    /// only rides along with it, to be stored once ([`Admission::approve`]).
    pub fn prove(&mut self, pk: Option<[u8; 32]>, t: &Trusted) {
        self.pk = pk.map(|k| hex(&k));
        self.by_key = None;
        if self.trusted.is_some() || self.always_ask.is_some() || self.removed.is_some() {
            return;
        }
        let Some(c) = self.pk.as_deref().and_then(|pk| t.by_pk(pk)) else { return };
        self.by_key = Some(if c.removed {
            ByKey::Removed(c.key.clone())
        } else if c.always_ask {
            ByKey::AlwaysAsk(c.name.clone(), c.key.clone())
        } else {
            ByKey::Trusted(c.name.clone(), c.key.clone())
        });
    }

    /// The Trusted Controllers key this session is matched on while it runs: its token's entry,
    /// the one its key found, or the one Allow just stored.
    fn session_key(&self) -> Option<&str> {
        self.key.as_deref().or(match &self.by_key {
            Some(ByKey::Trusted(_, k)) | Some(ByKey::AlwaysAsk(_, k)) => Some(k.as_str()),
            _ => None,
        })
    }

    /// connection.rs: this session gave this Mac's Unattended Password (not a one-time code).
    pub fn unattended_password_right(&mut self) {
        self.password_right = true;
    }

    /// 1.8: this login now waits on Allow here (`password_right`: its Unattended Password checked
    /// out first, so Allow may store it). connection.rs (rebrand) at every ask it shows.
    pub fn wait_for_allow(&mut self, password_right: bool) {
        self.waiting = Some(password_right);
    }

    /// 1.8: whether this connection is waiting on Allow (a new login request on it then ends it,
    /// so a click can't land on a different login than the one the ask showed).
    pub fn waiting(&self) -> bool {
        self.waiting.is_some()
    }

    /// 1.8: Allow landed (the connection window's Authorize). True only for a login that waits
    /// on it; it stops waiting. `others`: authorised sessions open right now. With another one
    /// open the click could come from a Controller driving this computer, so it lets this one in
    /// but stores nothing.
    pub fn take_wait(&mut self, others: usize) -> bool {
        match self.waiting.take() {
            Some(password_right) => {
                self.may_remember = password_right && others == 0;
                self.may_reinstate = others == 0;
                true
            }
            None => false,
        }
    }

    /// The last word before any sign-in lets this session in (rebrand T04_ALWAYS_ASK_GATE): no for
    /// an always-ask Controller that has not given the Unattended Password, whatever got it this
    /// far (a click, switch sides, a sign-in path upstream adds later). Yes for everyone else.
    pub fn may_let_in(&self) -> bool {
        !self.always_ask() || self.password_right
    }

    /// connection.rs, once a second while the session runs (rebrand T04_ALWAYS_ASK_KICK): true
    /// once Settings switched this Controller to always ask after it got in without the
    /// Unattended Password, or (1.8) removed it, so the session ends now. Reads the list only
    /// after an edit.
    pub fn lost_trust(&mut self) -> bool {
        let edits = EDITS.load(Ordering::Acquire);
        if self.session_key().is_none() || edits == self.seen_edits {
            return false;
        }
        self.seen_edits = edits;
        self.lost_trust_in(&Trusted::load())
    }

    fn lost_trust_in(&self, t: &Trusted) -> bool {
        let Some(key) = self.session_key() else { return false };
        t.list.iter().any(|c| c.key == key && (c.removed || !self.password_right && !self.stays && c.always_ask))
    }

    /// What `how` may store (1.8): a new Controller, or one found removed by its key, only by Allow
    /// after its Unattended Password checked out, with no other session open; one whose token says
    /// removed (a Direct Link, 1.7) by Allow with no other session open. Anything else lets this
    /// session in and stores nothing.
    fn effective(&self, how: SignIn) -> SignIn {
        let ok = if self.must_ask() { self.may_reinstate } else { self.may_remember };
        if how == SignIn::Allowed && !ok {
            SignIn::ThisSessionOnly
        } else {
            how
        }
    }

    /// The session got in. If someone clicked Allow here (after the right password, 1.8), the
    /// token just issued and the key just proven become Trusted under `name`; any other sign-in
    /// leaves them worthless. A token-trusted Controller that proved its key gets it stored.
    pub fn approve(&mut self, how: SignIn, name: &str) {
        if self.trusted.is_some() {
            if let (Some(key), Some(pk)) = (self.key.clone(), self.pk.clone()) {
                if let Ok(true) = edit_list(|t| {
                    let bound = t.bind_pk(&key, &pk);
                    Ok((bound, bound))
                }) {
                    hbb_common::log::info!("Direct Link: Trusted Controller {:?} proved its own key; stored", name);
                }
            }
            hbb_common::log::info!("Direct Link: Trusted Controller {:?} came straight in", name);
            return;
        }
        if self.always_ask() {
            hbb_common::log::info!("Trusted Controller {:?} gave the Unattended Password (always ask)", name);
            return;
        }
        if self.skips_click() {
            hbb_common::log::info!("Trusted Controller {:?} proved its key and gave the Unattended Password", name);
            return;
        }
        let was_removed = self.removed_key().is_some();
        let how = self.effective(how);
        // Under the edit lock, on the list as it is now; an unreadable list is not written over,
        // so this one stays out of it (asked again next time) and the log says why.
        let stored = match edit_list(|t| {
            let stored = self.approve_into(t, how, name);
            Ok((stored, stored))
        }) {
            Ok(stored) => stored,
            Err(e) => {
                hbb_common::log::warn!("{:?} not stored as Trusted: {}", name, e);
                false
            }
        };
        hbb_common::log::info!(
            "{:?} got in by {:?}{}; Trusted now: {}",
            name,
            how,
            if was_removed { " after being removed" } else { "" },
            stored
        );
    }

    fn approve_into(&mut self, t: &mut Trusted, how: SignIn, name: &str) -> bool {
        // Always ask: its entry stays exactly as Settings left it, and no token is issued, so no
        // sign-in can make it come in silently again.
        if self.always_ask() {
            return false;
        }
        // A removed Controller is Trusted again only by Allow here, never by a password.
        if let Some(key) = self.removed_key().map(str::to_owned) {
            if how != SignIn::Allowed {
                return false;
            }
            let ok = t.reinstate(&key, name);
            if let Some(pk) = self.pk.as_deref() {
                t.bind_pk(&key, pk);
            }
            self.removed = None;
            self.by_key = None;
            self.key = Some(key);
            self.stored_as_always_ask(t, name);
            return ok;
        }
        // 1.8: only Allow here stores a new Controller; the password alone lets nobody new in.
        if how != SignIn::Allowed {
            self.pending = None;
            return false;
        }
        let pk = self.pk.clone().filter(|pk| t.by_pk(pk).is_none()).unwrap_or_default();
        let key = match self.pending.take() {
            Some(d) => hex(&d),
            None if !pk.is_empty() => format!("{PK_KEY_PREFIX}{pk}"),
            None => return false,
        };
        t.add(&key, name, &pk);
        self.key = Some(key);
        self.stored_as_always_ask(t, name);
        true
    }

    /// Stored switched on by this very sign-in (New computers always ask, the name of one switched
    /// on, or Allow on a removed one that was on). Someone here let it in, by Allow or the
    /// password, and the switch went on with it, not after: this session stays (no lost_trust
    /// kick). Allow by a click here still creates an always-ask entry; it is never silent, since
    /// the next connect needs the password. And the Controller is told now to keep no password
    /// (ALWAYS_ASK_MARKER rides this session's PeerInfo, built after this runs).
    fn stored_as_always_ask(&mut self, t: &Trusted, name: &str) {
        let key = self.key.as_deref();
        if t.list.iter().any(|c| Some(c.key.as_str()) == key && !c.removed && c.always_ask) {
            self.always_ask = Some(name.to_owned());
            self.stays = true;
        }
    }
}

/// What Settings asks the service to change (kit/trust.dart `trustEdit`, over ipc [`EDIT_CONFIG`]).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Edit {
    Remove { key: String },
    /// 1.8: Reset password's "Also remove every Trusted Controller".
    RemoveAll,
    Allow { key: String },
    /// On needs this Mac's Unattended Password, typed by whoever is at this Mac (H1, see [`edit`]).
    AlwaysAsk {
        key: String,
        on: bool,
        #[serde(default)]
        password: String,
    },
}

// What Settings shows when an edit did not happen. Plain words; nothing was changed in any of them.
pub const UNREADABLE: &str = "The Trusted list on this computer can't be read, so nothing was changed.";
pub const NOT_ON_LIST: &str = "That computer isn't on the Trusted list any more.";
pub const NEED_PASSWORD: &str = "Type this computer's Unattended Password to turn this on.";
pub const WRONG_PASSWORD: &str = "That isn't this computer's Unattended Password.";
pub const NO_PASSWORD_SET: &str = "Set an Unattended Password on this computer first.";
pub const SALT_FAILED: &str = "The Unattended Password couldn't be updated, so nothing was changed.";
pub const NO_SERVICE: &str = "Boring Remote's background service didn't answer, so nothing was changed.";
/// 1.8: a change that lets more in (Allow, Always ask off) while someone is connected: the click
/// could be theirs (they drive this computer's screen).
pub const IN_SESSION: &str = "Someone is connected to this computer right now. Try again after they disconnect.";

/// `edit` applied to the list as stored now (`raw`): the new list, and whether turning always
/// ask on means the password's salt has to turn over first. Nothing here is saved. `sessions`:
/// authorised sessions open right now; with any open, only edits that let fewer in go through.
fn plan_edit(raw: &str, edit: &Edit, sessions: usize) -> Result<(Trusted, bool), &'static str> {
    let mut t = Trusted::parse_strict(raw).ok_or(UNREADABLE)?;
    let listed = |t: &Trusted, key: &str| t.list.iter().any(|c| c.key == key && !c.removed);
    let rotate = match edit {
        Edit::Remove { key } => {
            if !t.remove(key) {
                return Err(NOT_ON_LIST);
            }
            false
        }
        Edit::RemoveAll => {
            t.remove_all();
            false
        }
        Edit::Allow { .. } if sessions > 0 => return Err(IN_SESSION),
        Edit::Allow { key } => {
            let name = t.list.iter().find(|c| c.key == *key && c.removed).map(|c| c.name.clone());
            match name {
                Some(name) => t.reinstate(key, &name),
                None => return Err(NOT_ON_LIST),
            };
            false
        }
        Edit::AlwaysAsk { key, on, password } => {
            if !listed(&t, key) {
                return Err(NOT_ON_LIST);
            }
            let was = t.list.iter().any(|c| c.key == *key && c.always_ask);
            if !*on && was && sessions > 0 {
                return Err(IN_SESSION);
            }
            if *on && !was && password.is_empty() {
                return Err(NEED_PASSWORD);
            }
            t.set_always_ask(key, *on);
            *on && !was
        }
    };
    Ok((t, rotate))
}

/// Whether `typed` is the Unattended Password stored as `stored` (its salted hash) under `salt`.
fn password_is(stored: Option<[u8; 32]>, salt: &str, typed: &str) -> bool {
    match stored {
        Some(h1) if !typed.is_empty() => memcmp(&compute_permanent_password_h1(typed, salt), &h1),
        _ => false,
    }
}

/// H1: a Controller that saved the Unattended Password saved its salted hash, and sends that
/// hash again without anyone typing. This Mac keeps only the same hash, so it cannot tell typed
/// from saved. Turning always ask on therefore turns the salt over: the person at this Mac
/// types the password, it is checked, and stored again under a fresh salt. Every hash any
/// Controller saved (this one's and everyone else's) stops matching, so each has to type it
/// once more. A failure puts the old salt and hash back.
fn rotate_salt(password: &str) -> Result<(), &'static str> {
    if Config::is_disable_change_permanent_password() {
        return Err(SALT_FAILED);
    }
    let (storage, salt) = Config::get_local_permanent_password_storage_and_salt();
    if storage.is_empty() {
        return Err(NO_PASSWORD_SET);
    }
    if !password_is(decode_permanent_password_h1_from_storage(&storage), &salt, password) {
        return Err(WRONG_PASSWORD);
    }
    // The new salt and its hash go in one write: a crash before it leaves the old pair, which
    // still works; after it, the new one. Never a moment with no Unattended Password.
    let fresh = Config::get_auto_password(32);
    let new_storage = resalted(password, &fresh).ok_or(SALT_FAILED)?;
    match Config::set_permanent_password_storage_for_sync(&new_storage, &fresh) {
        Ok(true) => Ok(()),
        _ => {
            hbb_common::log::error!("always ask: salt not turned over");
            Err(SALT_FAILED)
        }
    }
}

/// The Unattended Password's storage under `salt`, in hbb_common's current form ("01" + the
/// encrypted "00" + base64 hash), read back through hbb_common's own decoder before it is
/// trusted: if that form ever changes upstream, this is None and nothing is written.
fn resalted(password: &str, salt: &str) -> Option<String> {
    let h1 = compute_permanent_password_h1(password, salt);
    let hashed = format!("00{}", base64::encode(h1, base64::Variant::Original));
    let sealed = symmetric_crypt(hashed.as_bytes(), true).ok()?;
    let storage = format!("01{}", base64::encode(sealed, base64::Variant::Original));
    (decode_permanent_password_h1_from_storage(&storage) == Some(h1)).then_some(storage)
}

/// The one way the Trusted list is changed: under [`EDIT_LOCK`], on the list as the service
/// holds it now (the only writer: [`keep_live`] stops the settings window's stale copy), never
/// over an unreadable one. `f` returns its result and whether to save.
fn edit_list<R>(f: impl FnOnce(&mut Trusted) -> Result<(R, bool), &'static str>) -> Result<R, &'static str> {
    let _lock = EDIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let raw = Config::get_option(TRUSTED_OPTION);
    let mut t = Trusted::parse_strict(&raw).ok_or(UNREADABLE)?;
    t.new_always_ask = Config::get_option(NEW_ALWAYS_ASK_OPTION) == "Y";
    let (r, save) = f(&mut t)?;
    if save {
        t.save();
        EDITS.fetch_add(1, Ordering::AcqRel);
    }
    Ok(r)
}

/// The service's answer to Settings' edit `request` (JSON [`Edit`]) with no session open (the
/// one-process mobile path).
pub fn edit(request: &str) -> String {
    edit_in_session(request, 0)
}

/// The service's answer to Settings' edit `request` (JSON [`Edit`]): `{"ok":true}`, or
/// `{"ok":false,"error":...}` with nothing changed. src/ipc.rs calls it with the authorised
/// sessions open now (rebrand T04_EDIT_IPC): while any is, only edits that let fewer in apply.
pub fn edit_in_session(request: &str, sessions: usize) -> String {
    let result = match serde_json::from_str::<Edit>(request) {
        Err(_) => Err(UNREADABLE),
        Ok(edit) => edit_list(|t| {
            let (planned, rotate) = plan_edit(&t.to_json(), &edit, sessions)?;
            if rotate {
                if let Edit::AlwaysAsk { password, .. } = &edit {
                    rotate_salt(password)?;
                }
            }
            let changed = planned.list != t.list;
            t.list = planned.list;
            Ok(((), changed))
        }),
    };
    match result {
        Ok(()) => serde_json::json!({ "ok": true }).to_string(),
        Err(e) => {
            hbb_common::log::warn!("Trusted list edit refused: {}", e);
            serde_json::json!({ "ok": false, "error": e }).to_string()
        }
    }
}

/// src/ipc.rs, before it stores a whole options map the settings window sent (rebrand
/// T04_KEEP_LIST): the Trusted list in it is that window's copy, up to a second old, so the
/// service's own is kept. Only [`edit_list`] changes it.
pub fn keep_trusted_list(mut options: HashMap<String, String>) -> HashMap<String, String> {
    keep_live(&mut options, &Config::get_option(TRUSTED_OPTION));
    options
}

fn keep_live(options: &mut HashMap<String, String>, live: &str) {
    if live.is_empty() {
        options.remove(TRUSTED_OPTION);
    } else {
        options.insert(TRUSTED_OPTION.to_owned(), live.to_owned());
    }
}

// --- 1.8: the Controller's signed login (ticket 06, trust binding option B) -----------------

/// Leads every signed login. The leading zero byte is never a valid protobuf tag, so a signed
/// login can't be read as a `SignedId` (`IdPk`), which the same key signs as a Target.
const LOGIN_DOMAIN: &[u8] = b"\0boring-remote trusted Controller login v1\0";

/// The bytes a Controller signs: the domain, then the Target's challenge, the Target's Machine ID
/// and its own ID, each length-prefixed. None for a challenge no Target makes (they are short
/// alphanumeric strings): the Target picks the challenge, so the Controller signs nothing else.
pub fn login_message(challenge: &str, target: &str, controller: &str) -> Option<Vec<u8>> {
    let challenge_ok =
        !challenge.is_empty() && challenge.len() <= 64 && challenge.bytes().all(|b| b.is_ascii_alphanumeric());
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
pub fn login_signature(challenge: &str, target: &str, controller: &str, sk: &[u8]) -> Option<Vec<u8>> {
    let sk = sign::SecretKey(sk.try_into().ok()?);
    Some(sign::sign(&login_message(challenge, target, controller)?, &sk))
}

/// The pure verifier: `pk`, if `sig` is its signature over this login (`challenge`, `target`,
/// `controller`). None for no signature (a 1.7 Controller), a bad one, or one made for another
/// challenge, Target or Controller ID.
pub fn proven_key(controller: &str, pk: &[u8], sig: &[u8], challenge: &str, target: &str) -> Option<[u8; 32]> {
    let key: [u8; 32] = pk.try_into().ok()?;
    let want = login_message(challenge, target, controller)?;
    let signed = sign::verify(sig, &sign::PublicKey(key)).ok()?;
    (signed == want).then_some(key)
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
            Ok(Admission { always_ask: Some(t.name.clone()), key: Some(t.key.clone()), ..Default::default() })
        }
        Some(t) if !t.removed => {
            stream.send(&frame(&[])).await?;
            Ok(Admission { trusted: Some(t.name.clone()), key: Some(t.key.clone()), ..Default::default() })
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
        a.approve_into(&mut trusted, SignIn::Allowed, "Stage Left");
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
    async fn the_password_alone_never_stores_a_new_controller() {
        // 1.8 (spec stories 13, 16): a stranger with the right Unattended Password still needs
        // Allow here; the password lets nobody new in and stores nothing.
        let mut trusted = Trusted::default();
        let (mut a, issued) = connect(&trusted, None).await;
        assert!(!a.must_ask() && !a.skips_click());
        assert!(!a.approve_into(&mut trusted, SignIn::UnattendedPassword, "Stage Left"));
        assert!(trusted.list().is_empty());
        let (b, _) = connect(&trusted, issued).await;
        assert!(!b.is_trusted(), "its token is worth nothing");
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
        assert!(t.list.iter().all(|c| !c.always_ask), "off unless switched on");
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
        assert!(back.approve_into(&mut trusted, SignIn::Allowed, "Edit Bay 2"));
        assert_eq!(trusted.list().len(), 2);
        assert!(trusted.list().iter().all(|c| c.always_ask), "the new entry is switched on too");

        let (mut other, _) = connect(&trusted, None).await;
        assert!(other.approve_into(&mut trusted, SignIn::Allowed, "Stage Left"));
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

    #[tokio::test]
    async fn new_computers_always_ask_when_this_mac_says_so() {
        // Forget + rename on a Controller, then the password: a new entry. With the host-wide
        // switch on it starts asking; off (the default) it comes in silently next time, as 1.7.0.
        let mut trusted = Trusted { new_always_ask: true, ..Default::default() };
        let (mut a, _) = connect(&trusted, None).await;
        assert!(a.approve_into(&mut trusted, SignIn::Allowed, "Renamed Laptop"));
        assert!(trusted.list()[0].always_ask);
        let mut trusted = Trusted::default();
        let (mut b, _) = connect(&trusted, None).await;
        assert!(b.approve_into(&mut trusted, SignIn::Allowed, "Edit Bay 2"));
        assert!(!trusted.list()[0].always_ask);
    }

    fn always_ask(key: &str, on: bool, password: &str) -> Edit {
        Edit::AlwaysAsk { key: key.into(), on, password: password.into() }
    }

    #[test]
    fn settings_edits_apply_to_the_list_as_it_is_now() {
        let raw = TRUST_FILE_1_7_0; // aa11 listed, bb22 removed
        let (t, rotate) = plan_edit(raw, &always_ask("aa11", true, "pw"), 0).unwrap();
        assert!(rotate, "on: the salt turns over, so every saved password stops working");
        assert!(t.list()[0].always_ask);
        let (again, rotate) = plan_edit(&t.to_json(), &always_ask("aa11", true, "pw"), 0).unwrap();
        assert!(!rotate && again == t, "already on: nothing to do");
        let (t, rotate) = plan_edit(&t.to_json(), &always_ask("aa11", false, ""), 0).unwrap();
        assert!(!rotate);
        assert_eq!(t.to_json(), TRUST_FILE_1_7_0, "off: back to what 1.7.0 wrote");
        assert_eq!(plan_edit(raw, &always_ask("aa11", true, ""), 0).unwrap_err(), NEED_PASSWORD);
        assert_eq!(plan_edit(raw, &always_ask("bb22", true, "pw"), 0).unwrap_err(), NOT_ON_LIST, "removed: no switch");
        assert_eq!(plan_edit(raw, &always_ask("cc33", false, ""), 0).unwrap_err(), NOT_ON_LIST);

        let (t, _) = plan_edit(raw, &Edit::Remove { key: "aa11".into() }, 0).unwrap();
        assert!(t.list().is_empty());
        assert!(t.list.iter().find(|c| c.key == "aa11").unwrap().removed, "kept, hidden (A2 step 5)");
        assert_eq!(plan_edit(raw, &Edit::Remove { key: "bb22".into() }, 0).unwrap_err(), NOT_ON_LIST);
        let (t, _) = plan_edit(raw, &Edit::Allow { key: "bb22".into() }, 0).unwrap();
        assert_eq!(t.list().iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["Edit Bay 2", "Stage Left"]);
        assert_eq!(plan_edit(raw, &Edit::Allow { key: "aa11".into() }, 0).unwrap_err(), NOT_ON_LIST);

        // What Settings sends (kit/trust.dart trustEdit).
        let sent = r#"{"op":"always_ask","key":"aa11","on":true,"password":"pw"}"#;
        assert_eq!(serde_json::from_str::<Edit>(sent).unwrap(), always_ask("aa11", true, "pw"));
        assert_eq!(serde_json::from_str::<Edit>(r#"{"op":"remove","key":"aa11"}"#).unwrap(), Edit::Remove { key: "aa11".into() });
    }

    #[test]
    fn an_unreadable_list_is_never_written_over() {
        for bad in ["not json", "{}", r#"[{"key":1}]"#] {
            assert_eq!(Trusted::parse_strict(bad), None, "{}", bad);
            assert_eq!(plan_edit(bad, &Edit::Remove { key: "aa11".into() }, 0).unwrap_err(), UNREADABLE, "{}", bad);
            assert_eq!(plan_edit(bad, &always_ask("aa11", false, ""), 0).unwrap_err(), UNREADABLE, "{}", bad);
        }
        assert_eq!(Trusted::parse_strict(""), Some(Trusted::default()), "unset is an empty list");
        assert_eq!(plan_edit("", &Edit::Remove { key: "aa11".into() }, 0).unwrap_err(), NOT_ON_LIST);
    }

    #[test]
    fn only_the_unattended_password_itself_turns_always_ask_on() {
        let stored = compute_permanent_password_h1("Studio-pass-1", "salt-a");
        assert!(password_is(Some(stored), "salt-a", "Studio-pass-1"));
        for (h1, salt, typed) in [(Some(stored), "salt-a", "studio-pass-1"), (Some(stored), "salt-b", "Studio-pass-1"),
                                  (None, "salt-a", "Studio-pass-1"), (Some(stored), "salt-a", "")] {
            assert!(!password_is(h1, salt, typed), "{} {}", salt, typed);
        }
        // What a Controller saves is this same salted hash. A new salt, same password: what it
        // saved no longer matches, so it has to be typed again (H1).
        assert_ne!(compute_permanent_password_h1("Studio-pass-1", "salt-b"), stored);
    }

    #[tokio::test]
    async fn switching_on_ends_a_session_that_came_in_without_the_password() {
        let (mut trusted, token, key) = always_ask_controller().await;
        trusted.set_always_ask(&key, false);
        let (silent, _) = connect(&trusted, Some(token.clone())).await;
        assert!(silent.is_trusted() && !silent.lost_trust_in(&trusted));
        trusted.set_always_ask(&key, true);
        assert!(silent.lost_trust_in(&trusted), "in silently, then switched on: ended");
        let (mut asked, _) = connect(&trusted, Some(token)).await;
        asked.unattended_password_right();
        assert!(!asked.lost_trust_in(&trusted), "gave the password: stays");

        // A stranger let in and stored, then switched on in Settings while still connected.
        let mut t = Trusted::default();
        let (mut s, _) = connect(&t, None).await;
        assert!(s.approve_into(&mut t, SignIn::Allowed, "Stage Left"));
        let k = t.list()[0].key.clone();
        assert!(!s.lost_trust_in(&t));
        t.set_always_ask(&k, true);
        assert!(s.lost_trust_in(&t));
        assert!(!Admission::default().lost_trust_in(&t), "no token: nothing to match");
    }

    #[test]
    fn a_whole_options_write_from_the_settings_window_never_carries_the_trusted_list() {
        let ui = |v: &str| HashMap::from([(TRUSTED_OPTION.to_owned(), v.to_owned()), ("x".to_owned(), "1".to_owned())]);
        let mut sent = ui("[]");
        keep_live(&mut sent, TRUST_FILE_1_7_0);
        assert_eq!(sent[TRUSTED_OPTION], TRUST_FILE_1_7_0, "the window's stale copy is ignored");
        assert_eq!(sent["x"], "1");
        let mut sent = ui(TRUST_FILE_1_7_0);
        keep_live(&mut sent, "");
        assert!(!sent.contains_key(TRUSTED_OPTION));
    }

    /// Review M-new: stored as always ask by this very sign-in (New computers always ask, the
    /// name of one switched on, or Allow on a removed one that was on). That session stays: it was
    /// let in here by Allow or the password, and the switch went on with it, not after. It also
    /// tells the Controller to keep no password, so the next connect has to type it.
    #[tokio::test]
    async fn a_session_stored_as_always_ask_stays_and_its_controller_keeps_no_password() {
        for how in [SignIn::Allowed] {
            let mut t = Trusted { new_always_ask: true, ..Default::default() };
            let (mut a, _) = connect(&t, None).await;
            assert!(!a.always_ask(), "{:?}", how);
            assert!(a.approve_into(&mut t, how, "Renamed Laptop"));
            assert!(t.list()[0].always_ask);
            assert!(a.always_ask(), "{:?}: PeerInfo carries the marker", how);
            assert!(!a.lost_trust_in(&t), "{:?}: not ended a second after it got in", how);
        }
        // By name.
        let (mut t, _, _) = always_ask_controller().await;
        let (mut back, _) = connect(&t, None).await;
        assert!(back.approve_into(&mut t, SignIn::Allowed, "Edit Bay 2"));
        assert!(back.always_ask() && !back.lost_trust_in(&t));
        // Allow on a removed one that was on.
        let (mut t, token, key) = always_ask_controller().await;
        t.remove(&key);
        let (mut removed, _) = connect(&t, Some(token)).await;
        assert!(removed.approve_into(&mut t, SignIn::Allowed, "Edit Bay 2"));
        assert!(removed.always_ask() && !removed.lost_trust_in(&t));
        // Stored switched off: nothing changes.
        let mut t = Trusted::default();
        let (mut plain, _) = connect(&t, None).await;
        plain.approve_into(&mut t, SignIn::Allowed, "Stage Left");
        assert!(!plain.always_ask());
    }

    #[test]
    fn the_salt_and_its_hash_are_written_together() {
        // Review Low: one write of the new pair, built and read back before anything is stored.
        let storage = resalted("Studio-pass-1", "salt-b").unwrap();
        assert_eq!(decode_permanent_password_h1_from_storage(&storage),
                   Some(compute_permanent_password_h1("Studio-pass-1", "salt-b")));
        assert!(password_is(decode_permanent_password_h1_from_storage(&storage), "salt-b", "Studio-pass-1"));
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

    // --- 1.8: the Controller's own key on the same Trusted list (ticket 06, option B) -------

    fn keypair() -> (Vec<u8>, [u8; 32]) {
        let (pk, sk) = sign::gen_keypair();
        (sk.0.to_vec(), pk.0)
    }

    /// A login as a 1.8 Controller signs it: this challenge, the Target's Machine ID, its own ID.
    fn signed(sk: &[u8], pk: &[u8; 32], challenge: &str, target: &str, me: &str) -> Option<[u8; 32]> {
        let sig = login_signature(challenge, target, me, sk).unwrap();
        proven_key(me, pk, &sig, challenge, target)
    }

    #[test]
    fn a_signed_login_proves_its_key_only_for_this_challenge_target_and_controller() {
        let (sk, pk) = keypair();
        let sig = login_signature("Ab3dE9", "123456789", "987654321", &sk).unwrap();
        assert_eq!(proven_key("987654321", &pk, &sig, "Ab3dE9", "123456789"), Some(pk));
        for (me, ch, target) in [("111", "Ab3dE9", "123456789"), ("987654321", "Zz9", "123456789"),
                                 ("987654321", "Ab3dE9", "555555555")] {
            assert_eq!(proven_key(me, &pk, &sig, ch, target), None, "{} {} {}", me, ch, target);
        }
        let (_, other) = keypair();
        assert_eq!(proven_key("987654321", &other, &sig, "Ab3dE9", "123456789"), None, "another key");
        assert_eq!(proven_key("987654321", &pk, b"", "Ab3dE9", "123456789"), None, "no signature (1.7)");
        assert_eq!(login_message("", "1", "2"), None);
        assert_eq!(login_message("no spaces", "1", "2"), None, "a challenge no Target makes");
        // Never readable as a SignedId: a zero byte leads it.
        assert_eq!(login_message("a", "b", "c").unwrap()[0], 0);
    }

    #[tokio::test]
    async fn hosted_new_controller_is_stored_by_its_key_on_allow_and_found_by_it_next_time() {
        let (sk, pk) = keypair();
        let mut t = Trusted::default();
        let mut a = Admission::default(); // Hosted: no token exchange
        a.prove(signed(&sk, &pk, "c1", "123", "9"), &t);
        assert!(!a.skips_click() && !a.must_ask() && !a.always_ask());
        assert_eq!(a.ask_info("").boring_key, format!("{PK_KEY_PREFIX}{}", hex(&pk))[..KEY_PREFIX_LEN]);
        assert!(a.approve_into(&mut t, SignIn::Allowed, "Laptop"));
        let c = &t.list()[0];
        assert_eq!((c.key.as_str(), c.pk.as_str()), (format!("{PK_KEY_PREFIX}{}", hex(&pk)).as_str(), hex(&pk).as_str()));
        assert!(t.check(&[0u8; 32]).is_none() && unhex(&c.key).is_none(), "no token matches a key entry");

        let t = Trusted::parse(&t.to_json());
        let mut b = Admission::default();
        b.prove(signed(&sk, &pk, "c2", "123", "9"), &t);
        assert!(b.skips_click(), "its key, proven again: no Allow needed once the password checks out");
        assert!(!b.is_trusted(), "never the silent token way in");
        assert_eq!(b.ask_info("").boring_trust, "trusted");
        // Another Controller claiming the same ID with its own key is a stranger.
        let (sk2, pk2) = keypair();
        let mut c = Admission::default();
        c.prove(signed(&sk2, &pk2, "c3", "123", "9"), &t);
        assert!(!c.skips_click());
        // No signature, or none at all: a stranger.
        let mut d = Admission::default();
        d.prove(None, &t);
        assert!(!d.skips_click());
    }

    #[tokio::test]
    async fn allow_stores_only_after_the_right_password_with_no_other_session_open() {
        let (sk, pk) = keypair();
        for (password_right, others, stored) in [(true, 0, true), (false, 0, false), (true, 1, false)] {
            let mut a = Admission::default();
            a.prove(signed(&sk, &pk, "c1", "123", "9"), &Trusted::default());
            a.wait_for_allow(password_right);
            assert!(a.waiting());
            assert!(a.take_wait(others));
            assert!(!a.waiting() && !a.take_wait(others), "one Allow per ask");
            let mut t = Trusted::default();
            assert_eq!(a.approve_into(&mut t, a.effective(SignIn::Allowed), "Laptop"), stored,
                       "password {} others {}", password_right, others);
            assert_eq!(t.list().len(), stored as usize);
        }
        // Allow that nothing waits on is no Allow.
        assert!(!Admission::default().take_wait(0));
    }

    #[tokio::test]
    async fn a_proven_key_finds_always_ask_and_removed_entries_too() {
        let (sk, pk) = keypair();
        let mut t = Trusted::default();
        let mut a = Admission::default();
        a.prove(signed(&sk, &pk, "c", "1", "9"), &t);
        a.approve_into(&mut t, SignIn::Allowed, "Laptop");
        let key = t.list()[0].key.clone();
        t.set_always_ask(&key, true);
        let mut b = Admission::default();
        b.prove(signed(&sk, &pk, "c", "1", "9"), &t);
        assert!(b.always_ask() && !b.skips_click() && !b.may_let_in());
        b.unattended_password_right();
        assert!(b.may_let_in());
        assert!(!b.approve_into(&mut t.clone(), SignIn::Allowed, "x"), "always ask: nothing stored");

        t.set_always_ask(&key, false);
        t.remove(&key);
        let mut c = Admission::default();
        c.prove(signed(&sk, &pk, "c", "1", "9"), &t);
        assert!(!c.must_ask() && !c.skips_click(), "found by key: the password first, then Allow");
        assert_eq!(c.ask_info("").boring_trust, "removed");
        assert!(!c.approve_into(&mut t, SignIn::UnattendedPassword, "Laptop"), "the password does not undo Remove");
        c.wait_for_allow(true);
        c.take_wait(1);
        assert_eq!(c.effective(SignIn::Allowed), SignIn::ThisSessionOnly, "another session open: not reinstated");
        c.wait_for_allow(true);
        c.take_wait(0);
        assert!(c.approve_into(&mut t, c.effective(SignIn::Allowed), "Laptop"));
        assert_eq!(t.list().len(), 1);
    }

    #[tokio::test]
    async fn a_token_decides_and_its_controller_key_is_stored_with_it_once() {
        let (sk, pk) = keypair();
        let mut trusted = Trusted::default();
        let (mut a, issued) = connect(&trusted, None).await;
        a.prove(signed(&sk, &pk, "c", "1", "9"), &trusted);
        assert!(a.approve_into(&mut trusted, SignIn::Allowed, "Edit Bay 2"));
        assert_eq!(trusted.list()[0].pk, hex(&pk), "Allow over a Direct Link stores token and key together");

        // A 1.7 entry (token only): the token decides; the key it proves is stored once.
        let mut t17 = Trusted::default();
        let (mut b, token) = connect(&t17, None).await;
        b.approve_into(&mut t17, SignIn::Allowed, "Old Mac");
        assert!(t17.list()[0].pk.is_empty());
        let key = t17.list()[0].key.clone();
        let (mut c, _) = connect(&t17, token.clone()).await;
        c.prove(signed(&sk, &pk, "c", "1", "9"), &t17);
        assert!(c.is_trusted() && !c.skips_click(), "the token's verdict stands");
        assert!(t17.bind_pk(&key, &hex(&pk)));
        let (_, pk2) = keypair();
        assert!(!t17.bind_pk(&key, &hex(&pk2)), "never over another key");
        assert!(!trusted.bind_pk(&trusted.list()[0].key.clone(), &hex(&pk)), "already stored");
        let _ = issued;
    }

    #[tokio::test]
    async fn remove_ends_that_controllers_session() {
        let (sk, pk) = keypair();
        let mut t = Trusted::default();
        let mut a = Admission::default();
        a.prove(signed(&sk, &pk, "c", "1", "9"), &t);
        a.approve_into(&mut t, SignIn::Allowed, "Laptop");
        let key = t.list()[0].key.clone();
        let mut b = Admission::default();
        b.prove(signed(&sk, &pk, "c", "1", "9"), &t);
        b.unattended_password_right();
        assert!(!b.lost_trust_in(&t));
        t.remove(&key);
        assert!(b.lost_trust_in(&t), "removed while connected, password or not: ended");
        assert!(a.lost_trust_in(&t), "the session that was just stored too");
    }

    #[test]
    fn while_someone_is_connected_settings_only_tightens_the_list() {
        let raw = TRUST_FILE_1_7_0; // aa11 listed, bb22 removed
        assert_eq!(plan_edit(raw, &Edit::Allow { key: "bb22".into() }, 1).unwrap_err(), IN_SESSION);
        assert!(plan_edit(raw, &Edit::Remove { key: "aa11".into() }, 1).is_ok());
        assert!(plan_edit(raw, &always_ask("aa11", true, "pw"), 1).is_ok());
        let (on, _) = plan_edit(raw, &always_ask("aa11", true, "pw"), 0).unwrap();
        assert_eq!(plan_edit(&on.to_json(), &always_ask("aa11", false, ""), 1).unwrap_err(), IN_SESSION);
        let (all, _) = plan_edit(raw, &Edit::RemoveAll, 1).unwrap();
        assert!(all.list().is_empty());
        assert_eq!(serde_json::from_str::<Edit>(r#"{"op":"remove_all"}"#).unwrap(), Edit::RemoveAll);
    }

    #[test]
    fn a_1_7_list_with_keys_reads_in_1_7_and_the_pre_port_list_is_asked_again() {
        // What 1.8 writes for a token entry with its key: 1.7.1 ignores the unknown field.
        let with_pk = r#"[{"key":"aa11","name":"Edit Bay 2","added":1761955200,"pk":"00"}]"#;
        assert_eq!(Trusted::parse(with_pk).list()[0].pk, "00");
        assert_eq!(Trusted::parse(TRUST_FILE_1_7_0).to_json(), TRUST_FILE_1_7_0, "no key: nothing written");
        let pre = format!("123456789:{},987654321", "ab".repeat(32));
        assert_eq!(Trusted::parse_strict(&pre), Some(Trusted::default()));
        assert_eq!(Trusted::parse_strict("not json"), None, "anything else stays unreadable");
    }
}
