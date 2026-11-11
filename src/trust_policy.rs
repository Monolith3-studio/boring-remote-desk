//! Trusted Controllers (ticket 06, spec slice 4).
//!
//! A stolen Permanent password alone isn't enough: the Target keeps a list of approved
//! Controller Machine IDs. A Controller not on it needs a click on the Target's existing
//! accept prompt, even with the right password. Approved → remembered. Nobody answers the
//! prompt → the connection times out and is refused. A wrong password is refused always.
//!
//! No Permanent password set on the Target (a 1.7 Target before setup): no unattended access,
//! but someone at the Target can still click Accept, so tailnet access keeps working while
//! setup is pending (spec slice 4). That approval is not remembered: trust means "the password
//! is enough without a click", and with no password there is nothing for it to stand on.
//!
//! `decide` and `Trusted` are pure. `on_login`, `on_accept` and `forget` are the thin
//! wiring into `server/connection.rs`; they hold which connections are waiting on the
//! prompt with a password that already checked out.
//!
//! The list lives in the daemon's config options under `TRUSTED_OPTION`, so it survives
//! restarts and Updates. `password_lock::SECURITY_OPTIONS` names it, so a remote session
//! can't add itself (or anyone) to it.
use hbb_common::config::Config;
use hbb_common::log;
use std::sync::Mutex;

/// Config option holding the trusted Controller IDs, comma separated.
pub const TRUSTED_OPTION: &str = "boring-trusted-controllers";

/// The password result, which carries whether the Target has a Permanent password at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Password {
    /// The Target has a Permanent password and the Controller gave it.
    Right,
    /// The Target has one and the Controller didn't give it.
    Wrong,
    /// The Target has no Permanent password: nothing to check, no unattended access.
    NotSet,
}

/// Someone at the Target: the accept prompt, answered or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtTarget {
    /// The prompt hasn't been shown for this login yet.
    NotAsked,
    /// Someone clicked Accept.
    Approved,
    /// Nobody answered before the timeout, or they said no.
    NoAnswer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Show the Target's accept prompt and wait.
    Ask,
    Refuse,
}

/// The approved Controller Machine IDs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trusted(Vec<String>);

/// A Machine ID we can store: RustDesk IDs are digits or a custom `[A-Za-z0-9_-]` name.
/// Anything else (empty, commas, spaces) is never trusted and never remembered.
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

    pub fn ids(&self) -> &[String] {
        &self.0
    }
}

pub fn decide(controller: &str, password: Password, trusted: &Trusted, at_target: AtTarget) -> Decision {
    if password == Password::Wrong {
        return Decision::Refuse;
    }
    if password == Password::Right && trusted.contains(controller) {
        return Decision::Allow;
    }
    match at_target {
        AtTarget::NotAsked => Decision::Ask,
        AtTarget::Approved => Decision::Allow,
        AtTarget::NoAnswer => Decision::Refuse,
    }
}

/// Someone at the Target accepted a Controller: the decision and the list to save. Remembered
/// only when its password checked out; a no-password approval lets in this login alone.
pub fn accepted(trusted: &Trusted, controller: &str, password: Password) -> (Decision, Trusted) {
    let decision = decide(controller, password, trusted, AtTarget::Approved);
    let mut next = trusted.clone();
    if decision == Decision::Allow && password == Password::Right {
        next.add(controller);
    }
    (decision, next)
}

// --- wiring -----------------------------------------------------------------------------

/// Connections waiting on the accept prompt: (conn id, Controller ID, password result). Only
/// `Right` (checked out) and `NotSet` (Target has none) are ever here.
static PENDING: Mutex<Vec<(i32, String, Password)>> = Mutex::new(Vec::new());

fn load() -> Trusted {
    Trusted::parse(&Config::get_option(TRUSTED_OPTION))
}

/// A login whose password checked out (`Right`), or one on a Target with no password
/// (`NotSet`). Allow (trusted), Ask (now waiting on the prompt), or Refuse (`Wrong`).
pub fn on_login(conn_id: i32, controller: &str, password: Password) -> Decision {
    forget(conn_id);
    let decision = decide(controller, password, &load(), AtTarget::NotAsked);
    if decision == Decision::Ask {
        PENDING.lock().unwrap().push((conn_id, controller.to_owned(), password));
        log::info!("Controller {controller}: waiting for approval on this computer");
    }
    decision
}

/// The Target's Accept for `conn_id`. True only for a connection waiting on the prompt after
/// `on_login` on this login; a checked password also remembers the Controller. False means
/// ignore the click.
pub fn on_accept(conn_id: i32) -> bool {
    let (controller, password) = {
        let mut pending = PENDING.lock().unwrap();
        let Some(i) = pending.iter().position(|(c, _, _)| *c == conn_id) else {
            log::warn!("accept ignored for conn {conn_id}: not waiting on approval");
            return false;
        };
        let (_, controller, password) = pending.remove(i);
        (controller, password)
    };
    let trusted = load();
    let (decision, next) = accepted(&trusted, &controller, password);
    if decision != Decision::Allow {
        return false;
    }
    if next != trusted {
        Config::set_option(TRUSTED_OPTION.to_owned(), next.to_option());
        log::info!("Controller {controller} approved and trusted");
    }
    true
}

/// A new login attempt or a closed connection: whatever it was waiting on is void.
pub fn forget(conn_id: i32) {
    PENDING.lock().unwrap().retain(|(c, _, _)| *c != conn_id);
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

    #[test]
    fn unknown_controller_right_password_nobody_at_target_is_refused() {
        let t = trusted(&[KNOWN]);
        assert_eq!(decide(NEW, Password::Right, &t, AtTarget::NotAsked), Decision::Ask);
        assert_eq!(decide(NEW, Password::Right, &t, AtTarget::NoAnswer), Decision::Refuse);
    }

    #[test]
    fn unknown_controller_approved_is_allowed_and_remembered() {
        let t = trusted(&[KNOWN]);
        let (decision, next) = accepted(&t, NEW, Password::Right);
        assert_eq!(decision, Decision::Allow);
        // Saved and read back the way the daemon does it, as after a restart or an Update.
        let reloaded = Trusted::parse(&next.to_option());
        assert_eq!(decide(NEW, Password::Right, &reloaded, AtTarget::NotAsked), Decision::Allow);
        assert!(reloaded.contains(KNOWN));
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
    fn wrong_password_is_refused_always() {
        let t = trusted(&[KNOWN]);
        for id in [KNOWN, NEW] {
            for at in [AtTarget::NotAsked, AtTarget::Approved, AtTarget::NoAnswer] {
                assert_eq!(decide(id, Password::Wrong, &t, at), Decision::Refuse, "{id} {at:?}");
            }
        }
    }

    #[test]
    fn no_password_on_target_nobody_at_target_is_refused() {
        // Unattended access needs a Permanent password, trusted Controller or not.
        let t = trusted(&[KNOWN]);
        for id in [KNOWN, NEW] {
            assert_eq!(decide(id, Password::NotSet, &t, AtTarget::NotAsked), Decision::Ask, "{id}");
            assert_eq!(decide(id, Password::NotSet, &t, AtTarget::NoAnswer), Decision::Refuse, "{id}");
        }
    }

    #[test]
    fn no_password_on_target_someone_approves_is_allowed_but_not_remembered() {
        let (decision, next) = accepted(&Trusted::default(), NEW, Password::NotSet);
        assert_eq!(decision, Decision::Allow);
        assert!(next.ids().is_empty());
        assert_eq!(decide(NEW, Password::NotSet, &next, AtTarget::NotAsked), Decision::Ask);
        // Once a password is set it still takes a click the first time.
        assert_eq!(decide(NEW, Password::Right, &next, AtTarget::NotAsked), Decision::Ask);
    }

    #[test]
    fn approving_a_wrong_password_does_nothing() {
        let (decision, next) = accepted(&Trusted::default(), NEW, Password::Wrong);
        assert_eq!(decision, Decision::Refuse);
        assert!(next.ids().is_empty());
    }

    #[test]
    fn odd_ids_are_never_trusted_or_remembered() {
        for id in ["", "1,2", "12 34", "a\nb"] {
            let (decision, next) = accepted(&Trusted::default(), id, Password::Right);
            assert_eq!(decision, Decision::Allow, "{id:?}"); // this one approved login only
            assert!(next.ids().is_empty(), "{id:?}");
            assert_eq!(decide(id, Password::Right, &next, AtTarget::NotAsked), Decision::Ask);
        }
    }

    #[test]
    fn a_list_smuggling_extra_ids_through_one_id_cant_happen() {
        // "1,2" is not stored, so neither 1 nor 2 becomes trusted by approving it.
        let (_, next) = accepted(&Trusted::default(), "111111111,222222222", Password::Right);
        assert!(!next.contains("111111111") && !next.contains("222222222"));
    }

    #[test]
    fn parse_ignores_blanks_and_duplicates() {
        let t = Trusted::parse(" 1, ,1,abc-def ,");
        assert_eq!(t.ids(), ["1".to_owned(), "abc-def".to_owned()]);
        assert_eq!(Trusted::parse("").ids().len(), 0);
    }

    #[test]
    fn accept_without_a_checked_password_is_ignored() {
        // No on_login waiting on this connection: the click does nothing.
        assert!(!on_accept(-42));
    }

    #[test]
    fn new_login_attempt_voids_the_wait() {
        PENDING.lock().unwrap().push((-7, NEW.to_owned(), Password::Right));
        forget(-7);
        assert!(!on_accept(-7));
    }
}
