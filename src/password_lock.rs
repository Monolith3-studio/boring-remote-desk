//! Permanent-password-only access (ticket 05).
//!
//! - `generate`: a strong permanent password from the OS RNG. The UI shows it once, at
//!   generate/reset; the daemon stores only its salted hash, so it is never readable again.
//! - `refuse_login`: the permanent-only lock gone means every login is refused. No permanent
//!   password set means no unattended access, only a click on the Target
//!   (`trust_policy::Password::NotSet`, ticket 06).
//! - `config_write_allowed` / `guard_options`: while any authorised remote session exists, the
//!   daemon refuses password, salt and PIN writes, keeps the security options as they were and
//!   refuses a whole-config sync (`Data::SyncConfig`), so a Controller driving the Target's
//!   Settings window can't loosen them. Out of scope: a Controller that runs its own code as
//!   the logged-in user can talk to the daemon directly; nothing here stops that.
//!
//! - `hosted_servers` / `hosted_on`: a Target registers with the Hosted servers only once it has a
//!   password this app generated (ticket 09). The daemon sets `GENERATED_OPTION` together with
//!   that password (`set_generated`, IPC `GENERATED_CONFIG`); any other password write clears it,
//!   no Options write can set it, and no remote session can send `GENERATED_CONFIG`. A 1.7.x typed
//!   password keeps the tailnet only. Direct IP is a separate listener and keeps working.
//!
//! The decisions are pure; `generate_and_set` and `authed_sessions` are the thin wiring.
use base::config::keys;
use hbb_common::{
    config::Config,
    log,
    rand::{rngs::OsRng, Rng},
};
#[cfg(not(target_os = "android"))]
use hbb_common::tokio;
use std::collections::HashMap;

/// No 0/O, 1/l/I: safe to read aloud or copy by hand.
pub const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
/// 20 chars of a 57-symbol alphabet: about 116 bits.
pub const LEN: usize = 20;
/// The only verification method this build accepts (locked in OVERWRITE_SETTINGS).
pub const PERMANENT_ONLY: &str = "use-permanent-password";
/// Login error if the permanent-only lock is ever gone.
pub const LOCK_GONE_ERROR: &str = "Connection not allowed";

/// Config writes (IPC `Data::Config`) refused during a remote session.
pub const PROTECTED_CONFIG: &[&str] = &["permanent-password", GENERATED_CONFIG, "salt", "unlock-pin"];

/// IPC `Data::Config` name: set this generated password and mark it generated (ticket 09).
pub const GENERATED_CONFIG: &str = "boring-generated-password";
/// The daemon's marker: "Y" while the permanent password is one this app generated.
pub const GENERATED_OPTION: &str = "boring-password-generated";

/// Options (IPC `Data::Options`) a remote session can't change. Locked ones are here too,
/// in case a lock is ever dropped.
pub const SECURITY_OPTIONS: &[&str] = &[
    keys::OPTION_VERIFICATION_METHOD,
    keys::OPTION_TEMPORARY_PASSWORD_LENGTH,
    keys::OPTION_ALLOW_NUMERNIC_ONE_TIME_PASSWORD,
    keys::OPTION_APPROVE_MODE,
    keys::OPTION_ACCESS_MODE,
    keys::OPTION_ALLOW_REMOTE_CONFIG_MODIFICATION,
    keys::OPTION_WHITELIST,
    keys::OPTION_DIRECT_SERVER,
    keys::OPTION_ALLOW_ONLY_CONN_WINDOW_OPEN,
    "2fa",
    keys::OPTION_ENABLE_TRUSTED_DEVICES,
    keys::OPTION_DISABLE_CHANGE_PERMANENT_PASSWORD,
    keys::OPTION_DISABLE_UNLOCK_PIN,
    keys::OPTION_ENABLE_KEYBOARD,
    keys::OPTION_ENABLE_CLIPBOARD,
    keys::OPTION_ENABLE_FILE_TRANSFER,
    keys::OPTION_ENABLE_AUDIO,
    keys::OPTION_ENABLE_CAMERA,
    keys::OPTION_ENABLE_TERMINAL,
    keys::OPTION_ENABLE_TUNNEL,
    keys::OPTION_ENABLE_REMOTE_RESTART,
    keys::OPTION_ENABLE_RECORD_SESSION,
    keys::OPTION_ENABLE_BLOCK_INPUT,
    keys::OPTION_ENABLE_REMOTE_PRINTER,
    "allow-hide-cm",
    crate::trust_policy::TRUSTED_OPTION,
];

pub fn generate_with<R: Rng>(rng: &mut R) -> String {
    (0..LEN)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

pub fn generate() -> String {
    generate_with(&mut OsRng)
}

/// True when the login must be refused outright: the permanent-only lock is gone.
pub fn refuse_login(verification_method: &str) -> bool {
    verification_method != PERMANENT_ONLY
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
    pin_option(&mut incoming, current, GENERATED_OPTION);
    if remote_sessions == 0 {
        return incoming;
    }
    for key in SECURITY_OPTIONS {
        pin_option(&mut incoming, current, key);
    }
    incoming
}

fn pin_option(incoming: &mut HashMap<String, String>, current: &HashMap<String, String>, key: &str) {
    match current.get(key) {
        Some(v) => incoming.insert(key.to_string(), v.clone()),
        None => incoming.remove(key),
    };
}

/// True when this Target may register with the Hosted servers: its password is app-generated.
pub fn hosted_ready(marker: &str, has_password: bool) -> bool {
    marker == "Y" && has_password
}

pub fn hosted_on() -> bool {
    hosted_ready(&Config::get_option(GENERATED_OPTION), Config::has_permanent_password())
}

/// Whether the daemon takes `password` as a generated one: the generator's shape, changes allowed,
/// no remote session open.
pub fn generated_write_allowed(password: &str, remote_sessions: usize, change_disabled: bool) -> bool {
    !change_disabled
        && config_write_allowed(GENERATED_CONFIG, remote_sessions)
        && password.len() == LEN
        && password.bytes().all(|b| ALPHABET.contains(&b))
}

/// Daemon side of `GENERATED_CONFIG`: the password and its marker, together.
pub fn set_generated(password: &str) -> bool {
    if !generated_write_allowed(
        password,
        authed_sessions(),
        Config::is_disable_change_permanent_password(),
    ) {
        return false;
    }
    if !Config::set_permanent_password(password) {
        return false;
    }
    Config::set_option(GENERATED_OPTION.to_owned(), "Y".to_owned());
    true
}

/// Any other password write (typed, removed, reset by hand): Hosted off until Generate.
pub fn clear_generated() {
    Config::set_option(GENERATED_OPTION.to_owned(), String::new());
}

/// The rendezvous servers to register with: none until `hosted_on`.
pub fn hosted_servers(servers: Vec<String>, password_set: bool) -> Vec<String> {
    if password_set {
        servers
    } else {
        Vec::new()
    }
}

/// Authorised connections of any kind (remote, file transfer, terminal, port forward).
pub fn authed_sessions() -> usize {
    crate::server::AUTHED_CONNS.lock().unwrap().len()
}

/// Generate, hand to the daemon, and return the password once for the UI to show.
/// Empty if the daemon refused it. The password is never logged.
pub fn generate_and_set() -> String {
    let pw = generate();
    if send_generated(pw.clone()) {
        pw
    } else {
        log::warn!("generated permanent password refused by the daemon");
        String::new()
    }
}

/// Hands a generated password to the daemon as `GENERATED_CONFIG` and waits for its ACK.
#[cfg(not(target_os = "android"))]
fn send_generated(pw: String) -> bool {
    match send_generated_async(pw) {
        Ok(ok) => {
            if ok {
                if let Err(e) = crate::ipc::sync_permanent_password_storage_from_daemon() {
                    log::warn!("permanent password storage sync after generate: {e}");
                }
            }
            ok
        }
        Err(e) => {
            log::warn!("generated permanent password: IPC: {e}");
            false
        }
    }
}

#[cfg(not(target_os = "android"))]
#[tokio::main(flavor = "current_thread")]
async fn send_generated_async(pw: String) -> hbb_common::ResultType<bool> {
    let mut c = crate::ipc::connect(1_000, "").await?;
    c.send(&crate::ipc::Data::Config((GENERATED_CONFIG.to_owned(), Some(pw)))).await?;
    if let Some(crate::ipc::Data::Config((name, Some(v)))) = c.next_timeout(1_000).await? {
        return Ok(name == GENERATED_CONFIG && v.trim() == "Y");
    }
    Ok(false)
}

#[cfg(target_os = "android")]
fn send_generated(pw: String) -> bool {
    set_generated(&pw)
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
    fn login_not_refused_outright_with_the_lock_in_place() {
        // No password set is not refused here: it goes to the click (trust_policy, ticket 06).
        assert!(!refuse_login(PERMANENT_ONLY));
    }

    #[test]
    fn login_refused_if_the_permanent_only_lock_is_gone() {
        for m in ["", "use-temporary-password", "use-both-passwords"] {
            assert!(refuse_login(m), "{m}");
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
    fn trusted_controllers_kept_during_a_session() {
        let key = crate::trust_policy::TRUSTED_OPTION;
        let current = map(&[(key, "111111111")]);
        let incoming = map(&[(key, "111111111,666666666")]);
        let out = guard_options(incoming, &current, 1);
        assert_eq!(out.get(key).map(String::as_str), Some("111111111"));
        // ...and can't be emptied either; with no session the local user can change it.
        assert_eq!(guard_options(HashMap::new(), &current, 1).get(key).map(String::as_str), Some("111111111"));
        assert_eq!(guard_options(HashMap::new(), &current, 0).get(key), None);
    }

    #[test]
    fn options_pass_through_with_no_session() {
        let incoming = map(&[("approve-mode", "click"), ("theme", "light")]);
        assert_eq!(guard_options(incoming.clone(), &HashMap::new(), 0), incoming);
    }

    #[test]
    fn no_password_registers_with_no_server() {
        let hosted = vec!["rs.theboringremote.com".to_owned()];
        assert!(hosted_servers(hosted, false).is_empty());
    }

    #[test]
    fn a_password_registers_with_the_hosted_servers() {
        let hosted = vec!["rs.theboringremote.com".to_owned()];
        assert_eq!(hosted_servers(hosted.clone(), true), hosted);
    }

    #[test]
    fn hosted_needs_the_generated_marker_and_a_password() {
        assert!(hosted_ready("Y", true));
        assert!(!hosted_ready("", true), "a 1.7.x typed password keeps Hosted off");
        assert!(!hosted_ready("Y", false), "marker left behind with no password");
        assert!(!hosted_ready("N", true));
    }

    #[test]
    fn daemon_marks_only_a_generator_shaped_password_with_no_session() {
        let pw = generate();
        assert!(generated_write_allowed(&pw, 0, false));
        assert!(!generated_write_allowed(&pw, 1, false), "remote session open");
        assert!(!generated_write_allowed(&pw, 0, true), "changes disabled");
        assert!(!generated_write_allowed("hunter2", 0, false));
        assert!(!generated_write_allowed("ABCDEFGHJKLMNPQRSTU0", 0, false), "0 is not in the alphabet");
        assert!(!generated_write_allowed(&format!("{pw}A"), 0, false));
    }

    #[test]
    fn generated_password_write_refused_during_a_session() {
        assert!(PROTECTED_CONFIG.contains(&GENERATED_CONFIG));
        assert!(!config_write_allowed(GENERATED_CONFIG, 1));
    }

    #[test]
    fn options_write_never_sets_or_clears_the_marker() {
        let none = HashMap::new();
        let forged = map(&[(GENERATED_OPTION, "Y"), ("theme", "dark")]);
        let out = guard_options(forged, &none, 0);
        assert_eq!(out.get(GENERATED_OPTION), None);
        assert_eq!(out.get("theme").map(String::as_str), Some("dark"));
        let current = map(&[(GENERATED_OPTION, "Y")]);
        let out = guard_options(HashMap::new(), &current, 0);
        assert_eq!(out.get(GENERATED_OPTION).map(String::as_str), Some("Y"));
    }
}
