//! Permanent-password-only access (ticket 05).
//!
//! - `generate`: a strong permanent password from the OS RNG. The UI shows it once, at
//!   generate/reset; the daemon stores only its salted hash, so it is never readable again.
//! - `refuse_login`: no permanent password set (or the lock gone) means the login is refused,
//!   not handed to click-to-accept.
//! - `config_write_allowed` / `guard_options`: while any authorised remote session exists, the
//!   daemon refuses password and PIN writes and keeps the security options as they were, so a
//!   Controller driving the Target's Settings window can't loosen them.
//!
//! The decisions are pure; `generate_and_set` and `authed_sessions` are the thin wiring.
use hbb_common::log;
use hbb_common::rand::{rngs::OsRng, Rng};
use std::collections::HashMap;

/// No 0/O, 1/l/I: safe to read aloud or copy by hand.
pub const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
/// 20 chars of a 57-symbol alphabet: about 116 bits.
pub const LEN: usize = 20;
/// The only verification method this build accepts (locked in OVERWRITE_SETTINGS).
pub const PERMANENT_ONLY: &str = "use-permanent-password";
/// Login error when the Target has no permanent password.
pub const NO_PASSWORD_ERROR: &str = "No password is set on this computer";

/// Config writes (IPC `Data::Config`) refused during a remote session.
pub const PROTECTED_CONFIG: &[&str] = &["permanent-password", "salt", "unlock-pin"];

/// Options (IPC `Data::Options`) a remote session can't change. Locked ones are here too,
/// in case a lock is ever dropped.
pub const SECURITY_OPTIONS: &[&str] = &[
    "verification-method",
    "temporary-password-length",
    "allow-numeric-one-time-password",
    "approve-mode",
    "access-mode",
    "allow-remote-config-modification",
    "whitelist",
    "direct-server",
    "allow-only-conn-window-open",
    "2fa",
    "enable-trusted-devices",
    "disable-change-permanent-password",
    "disable-unlock-pin",
    "enable-keyboard",
    "enable-clipboard",
    "enable-file-transfer",
    "enable-audio",
    "enable-camera",
    "enable-terminal",
    "enable-tunnel",
    "enable-remote-restart",
    "enable-record-session",
    "enable-block-input",
    "enable-remote-printer",
];

pub fn generate_with<R: Rng>(rng: &mut R) -> String {
    (0..LEN)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

pub fn generate() -> String {
    generate_with(&mut OsRng)
}

/// True when the login must be refused outright.
pub fn refuse_login(verification_method: &str, has_permanent_password: bool) -> bool {
    verification_method != PERMANENT_ONLY || !has_permanent_password
}

pub fn config_write_allowed(name: &str, remote_sessions: usize) -> bool {
    remote_sessions == 0 || !PROTECTED_CONFIG.contains(&name)
}

/// `incoming` with every security option put back to its `current` value (or removed, if
/// unset) while a remote session exists. Other options pass through.
pub fn guard_options(
    mut incoming: HashMap<String, String>,
    current: &HashMap<String, String>,
    remote_sessions: usize,
) -> HashMap<String, String> {
    if remote_sessions == 0 {
        return incoming;
    }
    for key in SECURITY_OPTIONS {
        match current.get(*key) {
            Some(v) => incoming.insert(key.to_string(), v.clone()),
            None => incoming.remove(*key),
        };
    }
    incoming
}

/// Authorised connections of any kind (remote, file transfer, terminal, port forward).
pub fn authed_sessions() -> usize {
    crate::server::AUTHED_CONNS.lock().unwrap().len()
}

/// Generate, hand to the daemon, and return the password once for the UI to show.
/// Empty if the daemon refused it. The password is never logged.
pub fn generate_and_set() -> String {
    let pw = generate();
    if crate::ui_interface::set_permanent_password_with_result(pw.clone()) {
        pw
    } else {
        log::warn!("generated permanent password refused by the daemon");
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::rand::{rngs::StdRng, SeedableRng};
    use std::collections::HashSet;

    #[test]
    fn generated_password_is_long_and_unambiguous() {
        for _ in 0..200 {
            let pw = generate();
            assert_eq!(pw.chars().count(), LEN);
            assert!(LEN >= 16);
            assert!(pw.bytes().all(|b| ALPHABET.contains(&b)), "{pw}");
            assert!(!pw.contains(['0', 'O', '1', 'l', 'I']), "{pw}");
        }
    }

    #[test]
    fn generated_passwords_differ() {
        let all: HashSet<String> = (0..1000).map(|_| generate()).collect();
        assert_eq!(all.len(), 1000);
    }

    #[test]
    fn every_symbol_can_appear() {
        let mut rng = StdRng::seed_from_u64(5);
        let seen: HashSet<u8> = (0..500).flat_map(|_| generate_with(&mut rng).into_bytes()).collect();
        assert_eq!(seen.len(), ALPHABET.len());
    }

    #[test]
    fn alphabet_has_no_duplicates() {
        let set: HashSet<&u8> = ALPHABET.iter().collect();
        assert_eq!(set.len(), ALPHABET.len());
    }

    #[test]
    fn login_refused_without_a_permanent_password() {
        assert!(refuse_login(PERMANENT_ONLY, false));
        assert!(!refuse_login(PERMANENT_ONLY, true));
    }

    #[test]
    fn login_refused_if_the_permanent_only_lock_is_gone() {
        for m in ["", "use-temporary-password", "use-both-passwords"] {
            assert!(refuse_login(m, true), "{m}");
        }
    }

    #[test]
    fn password_pin_and_salt_writes_refused_during_a_session() {
        for k in PROTECTED_CONFIG {
            assert!(!config_write_allowed(k, 1), "{k}");
            assert!(config_write_allowed(k, 0), "{k}");
        }
        assert!(config_write_allowed("voice-call-input", 3));
        assert!(config_write_allowed("id", 1));
    }

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn security_options_kept_during_a_session() {
        let current = map(&[("approve-mode", "password"), ("theme", "dark")]);
        let incoming = map(&[
            ("approve-mode", "click"),
            ("access-mode", "full"),
            ("enable-keyboard", "Y"),
            ("theme", "light"),
        ]);
        let out = guard_options(incoming, &current, 1);
        assert_eq!(out.get("approve-mode").map(String::as_str), Some("password"));
        assert_eq!(out.get("access-mode"), None);
        assert_eq!(out.get("enable-keyboard"), None);
        assert_eq!(out.get("theme").map(String::as_str), Some("light"));
    }

    #[test]
    fn security_option_removal_ignored_during_a_session() {
        let current = map(&[("allow-remote-config-modification", "N")]);
        let out = guard_options(HashMap::new(), &current, 2);
        assert_eq!(out.get("allow-remote-config-modification").map(String::as_str), Some("N"));
    }

    #[test]
    fn options_pass_through_with_no_session() {
        let incoming = map(&[("approve-mode", "click"), ("theme", "light")]);
        assert_eq!(guard_options(incoming.clone(), &HashMap::new(), 0), incoming);
    }
}
