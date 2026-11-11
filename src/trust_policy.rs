//! Trusted Controllers (ticket 06, spec slice 4).
//!
//! The Target keeps a list of approved Controller Machine IDs. A Controller not on it needs a
//! click on the Target's existing accept prompt, even with the right password. Approved →
//! remembered. Nobody answers the prompt → the connection times out (`LOGIN_GRACE` in
//! `server/connection.rs`).
//!
//! Known limit: the Machine ID is what the Controller reports about itself in `LoginRequest`
//! (`lr.my_id`), and Machine IDs are not secret. Someone holding the password and a trusted
//! ID can claim that ID and skip the click. The list stops casual use of a leaked password
//! from an unknown machine; it is not spoof resistance. Binding trust to something the
//! Controller proves needs a protocol change (see the trust-binding design note).
//!
//! No Permanent password set on the Target (a 1.7 Target before setup): no unattended access,
//! but someone at the Target can still click Accept, so tailnet access keeps working while
//! setup is pending (spec slice 4). That approval is not remembered.
//!
//! Every Ask counts against the IP's login failure budget in `server/connection.rs`, so the
//! prompt can't be raised without limit. A new login on a connection already waiting on the
//! prompt closes it, so the click can't land on a different login than the one shown.
use hbb_common::{config::Config, log};
use std::{collections::HashMap, sync::Mutex};

/// Config option holding the trusted Controller IDs, comma separated. Written only by the
/// daemon (`on_accept`, `take_options`); the UI's copy of it is never taken.
pub const TRUSTED_OPTION: &str = "boring-trusted-controllers";
/// Option the Settings list sends to remove IDs (comma separated). Never stored.
pub const REMOVE_OPTION: &str = "boring-trusted-controllers-remove";

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
pub struct Trusted(Vec<String>);

/// RustDesk IDs are digits or a custom `[A-Za-z0-9_-]` name. Anything else (empty, commas,
/// spaces) is never trusted, remembered or logged.
fn storable(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Trusted {
    pub fn parse(option: &str) -> Self {
        let mut t = Trusted::default();
        for id in option.split(',') {
            t.add(id.trim());
        }
        t
    }

    pub fn to_option(&self) -> String {
        self.0.join(",")
    }

    pub fn contains(&self, id: &str) -> bool {
        storable(id) && self.0.iter().any(|t| t == id)
    }

    pub fn add(&mut self, id: &str) {
        if storable(id) && !self.contains(id) {
            self.0.push(id.to_owned());
        }
    }

    pub fn remove(&mut self, id: &str) {
        self.0.retain(|t| t != id);
    }

    #[cfg(test)]
    pub fn ids(&self) -> &[String] {
        &self.0
    }
}

pub fn decide(controller: &str, password: Password, trusted: &Trusted, at_target: AtTarget) -> Decision {
    if password == Password::Right && trusted.contains(controller) {
        return Decision::Allow;
    }
    match at_target {
        AtTarget::NotAsked => Decision::Ask,
        AtTarget::Approved => Decision::Allow,
    }
}

/// Someone at the Target accepted a Controller: the list to save. Remembered only when its
/// password checked out and `remember` (no other session is open, see `on_accept`).
pub fn accepted(trusted: &Trusted, controller: &str, password: Password, remember: bool) -> Trusted {
    let mut next = trusted.clone();
    if password == Password::Right && remember {
        next.add(controller);
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
        if list.contains(id) {
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

// --- wiring -----------------------------------------------------------------------------

struct Waiting {
    conn_id: i32,
    controller: String,
    password: Password,
}

static PENDING: Mutex<Vec<Waiting>> = Mutex::new(Vec::new());

fn load() -> Trusted {
    Trusted::parse(&Config::get_option(TRUSTED_OPTION))
}

/// A login whose password checked out (`Right`), or one on a Target with no password
/// (`NotSet`). Allow (trusted) or Ask (now waiting on the prompt).
pub fn on_login(conn_id: i32, controller: &str, password: Password) -> Decision {
    forget(conn_id);
    let decision = decide(controller, password, &load(), AtTarget::NotAsked);
    if decision == Decision::Ask {
        PENDING.lock().unwrap().push(Waiting {
            conn_id,
            controller: controller.to_owned(),
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
/// `on_login` on this login. A checked password also remembers the Controller, unless another
/// session is open: the click could then come from a Controller driving this computer.
pub fn on_accept(conn_id: i32) -> bool {
    let Some(w) = take(conn_id) else {
        log::warn!("accept ignored for conn {conn_id}: not waiting on approval");
        return false;
    };
    let trusted = load();
    let remember = crate::password_lock::authed_sessions() == 0;
    let next = accepted(&trusted, &w.controller, w.password, remember);
    if next != trusted {
        Config::set_option(TRUSTED_OPTION.to_owned(), next.to_option());
        log::info!("Controller {} approved and trusted", w.controller);
    }
    true
}

fn take(conn_id: i32) -> Option<Waiting> {
    let mut pending = PENDING.lock().unwrap();
    let i = pending.iter().position(|w| w.conn_id == conn_id)?;
    Some(pending.remove(i))
}

/// A new login attempt or a closed connection voids the wait. True if it was waiting.
pub fn forget(conn_id: i32) -> bool {
    take(conn_id).is_some()
}

/// Close the sessions of Controllers just removed from the list (spec story 15).
pub fn close_removed(removed: &[String]) {
    for id in removed {
        log::info!("Controller {id} removed from the trusted list: closing its sessions");
        crate::server::close_controller(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NEW: &str = "123456789";
    const KNOWN: &str = "987654321";

    fn trusted(ids: &[&str]) -> Trusted {
        let mut t = Trusted::default();
        for id in ids {
            t.add(id);
        }
        t
    }

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn unknown_controller_right_password_waits_for_a_click() {
        let t = trusted(&[KNOWN]);
        assert_eq!(decide(NEW, Password::Right, &t, AtTarget::NotAsked), Decision::Ask);
    }

    #[test]
    fn unknown_controller_approved_is_allowed_and_remembered() {
        let t = trusted(&[KNOWN]);
        assert_eq!(decide(NEW, Password::Right, &t, AtTarget::Approved), Decision::Allow);
        let next = accepted(&t, NEW, Password::Right, true);
        // Saved and read back the way the daemon does it, as after a restart or an Update.
        let reloaded = Trusted::parse(&next.to_option());
        assert_eq!(decide(NEW, Password::Right, &reloaded, AtTarget::NotAsked), Decision::Allow);
        assert!(reloaded.contains(KNOWN));
    }

    #[test]
    fn approval_during_another_session_is_not_remembered() {
        let next = accepted(&trusted(&[KNOWN]), NEW, Password::Right, false);
        assert_eq!(decide(NEW, Password::Right, &next, AtTarget::NotAsked), Decision::Ask);
    }

    #[test]
    fn trusted_controller_right_password_is_allowed_without_a_prompt() {
        let t = trusted(&[KNOWN]);
        assert_eq!(decide(KNOWN, Password::Right, &t, AtTarget::NotAsked), Decision::Allow);
    }

    #[test]
    fn removed_controller_is_asked_again() {
        let mut t = trusted(&[KNOWN, NEW]);
        t.remove(KNOWN);
        let reloaded = Trusted::parse(&t.to_option());
        assert_eq!(decide(KNOWN, Password::Right, &reloaded, AtTarget::NotAsked), Decision::Ask);
        assert_eq!(decide(NEW, Password::Right, &reloaded, AtTarget::NotAsked), Decision::Allow);
    }

    #[test]
    fn no_password_on_target_always_asks() {
        // Unattended access needs a Permanent password, trusted Controller or not.
        let t = trusted(&[KNOWN]);
        for id in [KNOWN, NEW] {
            assert_eq!(decide(id, Password::NotSet, &t, AtTarget::NotAsked), Decision::Ask, "{id}");
        }
    }

    #[test]
    fn no_password_on_target_someone_approves_is_allowed_but_not_remembered() {
        assert_eq!(decide(NEW, Password::NotSet, &Trusted::default(), AtTarget::Approved), Decision::Allow);
        let next = accepted(&Trusted::default(), NEW, Password::NotSet, true);
        assert!(next.ids().is_empty());
        // Once a password is set it still takes a click the first time.
        assert_eq!(decide(NEW, Password::Right, &next, AtTarget::NotAsked), Decision::Ask);
    }

    #[test]
    fn odd_ids_are_never_trusted_or_remembered() {
        for id in ["", "1,2", "12 34", "a\nb"] {
            let next = accepted(&Trusted::default(), id, Password::Right, true);
            assert!(next.ids().is_empty(), "{id:?}");
            assert_eq!(decide(id, Password::Right, &next, AtTarget::NotAsked), Decision::Ask);
        }
    }

    #[test]
    fn a_list_smuggling_extra_ids_through_one_id_cant_happen() {
        let next = accepted(&Trusted::default(), "111111111,222222222", Password::Right, true);
        assert!(!next.contains("111111111") && !next.contains("222222222"));
    }

    #[test]
    fn parse_ignores_blanks_and_duplicates() {
        let t = Trusted::parse(" 1, ,1,abc-def ,");
        assert_eq!(t.ids(), ["1".to_owned(), "abc-def".to_owned()]);
        assert_eq!(Trusted::parse("").ids().len(), 0);
    }

    #[test]
    fn ui_copy_of_the_list_is_never_taken() {
        // A stale UI map missing a fresh approval, one with an ID added by hand, an empty one.
        let current = map(&[(TRUSTED_OPTION, "111111111,222222222")]);
        for stale in ["111111111", "111111111,222222222,666666666", ""] {
            let mut incoming = map(&[(TRUSTED_OPTION, stale), ("theme", "dark")]);
            assert!(take_options(&mut incoming, &current).is_empty());
            assert_eq!(incoming.get(TRUSTED_OPTION).map(String::as_str), Some("111111111,222222222"));
            assert_eq!(incoming.get("theme").map(String::as_str), Some("dark"));
        }
    }

    #[test]
    fn remove_drops_only_listed_ids_and_reports_them() {
        let current = map(&[(TRUSTED_OPTION, "111111111,222222222")]);
        let mut incoming = map(&[(REMOVE_OPTION, "222222222,999999999")]);
        assert_eq!(take_options(&mut incoming, &current), ["222222222".to_owned()]);
        assert_eq!(incoming.get(TRUSTED_OPTION).map(String::as_str), Some("111111111"));
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
            password: Password::Right,
        });
        assert!(forget(-7));
        assert!(!forget(-7));
        assert!(!on_accept(-7));
    }
}
