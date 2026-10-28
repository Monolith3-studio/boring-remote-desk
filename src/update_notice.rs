//! Update notice (ADR 0003): read one public version file, say whether it is
//! newer than this build and whether this build is below the file's Minimum
//! version. The file counts only when its `.sig` verifies against one of the two
//! embedded keys (ADR 0004). Nothing here downloads or installs.
//! Contract: the-boring-remote/docs/version-file.md.
use hbb_common::base64::{self, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use std::time::Duration;

pub const VERSION_URL: &str = "https://boringlabs.online/downloads/the-boring-remote-version.json";
/// Settings switch (local option). Anything but "N" means on.
pub const KEY_ENABLED: &str = "boring-update-check";
/// Unix seconds of the last attempt, success or not.
pub const KEY_LAST_TRY: &str = "boring-update-last-try";
/// Remote `version` from the last good fetch.
pub const KEY_LAST_GOOD: &str = "boring-update-last-good";
/// Remote `min_version` from the last good fetch ("" when the file had none).
pub const KEY_LAST_MIN: &str = "boring-update-last-min";
/// `package_sha256` / `package_sig` from the last good (signed) fetch, for Install update.
pub const KEY_LAST_PKG_SHA: &str = "boring-update-last-pkg-sha256";
pub const KEY_LAST_PKG_SIG: &str = "boring-update-last-pkg-sig";
const GATE_SECS: u64 = 24 * 60 * 60;
/// The one source of the update public keys ({current, backup}, base64 raw ed25519).
const PUBKEYS_JSON: &str = include_str!("../boring/update-pubkeys.json");

/// What the banner needs: the newer version, and whether this build is below the Minimum version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub version: String,
    pub below_min: bool,
}

pub fn sig_url() -> String {
    format!("{VERSION_URL}.sig")
}

/// [current, backup] from `boring/update-pubkeys.json`. Panics on a malformed file:
/// it is compiled in, and the unit test pins both values.
pub fn embedded_keys() -> Vec<VerifyingKey> {
    let v: serde_json::Value = serde_json::from_str(PUBKEYS_JSON).expect("update-pubkeys.json");
    ["current", "backup"]
        .iter()
        .map(|k| {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(v[*k].as_str().expect("pubkey string"))
                .expect("pubkey base64");
            VerifyingKey::from_bytes(&raw.try_into().expect("32-byte pubkey")).expect("ed25519 pubkey")
        })
        .collect()
}

/// The HTTP body as a String with exactly the bytes that came off the wire, so the
/// signature is checked over the same bytes the JSON is parsed from. Not UTF-8 → Err.
pub fn body_text(bytes: Vec<u8>) -> Result<String, String> {
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

/// True when `sig_b64` is a valid signature over the exact bytes of `body` by any of `keys`.
fn verified(keys: &[VerifyingKey], body: &str, sig_b64: &str) -> bool {
    verify_bytes(keys, body.as_bytes(), sig_b64)
}

/// True when `sig_b64` is a valid signature over `bytes` by any of `keys`.
pub fn verify_bytes(keys: &[VerifyingKey], bytes: &[u8], sig_b64: &str) -> bool {
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(sig_b64.trim()) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&raw) else {
        return false;
    };
    keys.iter().any(|k| k.verify_strict(bytes, &sig).is_ok())
}

pub trait Fetch {
    /// GET `url` with the given User-Agent; Ok((status, body)) or Err on any transport failure.
    fn get(&self, url: &str, user_agent: &str, timeout: Duration) -> Result<(u16, String), String>;
}

pub trait Store {
    fn get(&self, key: &str) -> String;
    fn set(&mut self, key: &str, value: String);
}

/// Strict `X.Y.Z`: three runs of ASCII digits, nothing else.
pub fn parse_semver(s: &str) -> Option<(u64, u64, u64)> {
    let mut it = s.split('.');
    let mut next = || {
        let p = it.next()?;
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        p.parse::<u64>().ok()
    };
    let v = (next()?, next()?, next()?);
    it.next().is_none().then_some(v)
}

/// (version, min_version or "") from a version file; None if either is not strict X.Y.Z.
fn remote_versions(body: &str) -> Option<(String, String)> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let s = v.get("version")?.as_str()?;
    parse_semver(s)?;
    let min = match v.get("min_version") {
        None => String::new(),
        Some(m) => {
            let m = m.as_str()?;
            parse_semver(m)?;
            m.to_owned()
        }
    };
    Some((s.to_owned(), min))
}

/// (package_sha256, package_sig), "" for either that is missing.
fn package_fields(body: &str) -> (String, String) {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let f = |k: &str| v.get(k).and_then(|s| s.as_str()).unwrap_or("").to_owned();
    (f("package_sha256"), f("package_sig"))
}

/// The package to install, from the last good signed fetch; None when it had no package details.
pub fn release(store: &dyn Store) -> Option<crate::update_install::Release> {
    let r = crate::update_install::Release {
        version: store.get(KEY_LAST_GOOD),
        package_sha256: store.get(KEY_LAST_PKG_SHA),
        package_sig: store.get(KEY_LAST_PKG_SIG),
    };
    (parse_semver(&r.version).is_some() && !r.package_sha256.is_empty() && !r.package_sig.is_empty()).then_some(r)
}

fn newer_than(remote: &str, running: &str) -> bool {
    match (parse_semver(remote), parse_semver(running)) {
        (Some(r), Some(l)) => r > l,
        _ => false,
    }
}

/// Returns the notice when the remote version is strictly newer than `running`.
/// Fetches at most once per 24 h (the try is stamped before the request, so a
/// failure also waits a day); a clock set back past the stamp counts as due.
/// A failed, unusable or unsigned fetch keeps the last good answer.
pub fn check(fetch: &dyn Fetch, store: &mut dyn Store, now: u64, running: &str) -> Option<Notice> {
    check_with(&embedded_keys(), fetch, store, now, running)
}

/// `check` against the given keys (tests pass throwaway ones).
pub fn check_with(
    keys: &[VerifyingKey],
    fetch: &dyn Fetch,
    store: &mut dyn Store,
    now: u64,
    running: &str,
) -> Option<Notice> {
    if store.get(KEY_ENABLED) == "N" {
        return None;
    }
    let due = match store.get(KEY_LAST_TRY).parse::<u64>() {
        Ok(last) => now < last || now - last >= GATE_SECS,
        Err(_) => true,
    };
    if due {
        store.set(KEY_LAST_TRY, now.to_string());
        let ua = format!("BoringRemote/{running}");
        let t = Duration::from_secs(10);
        if let Ok((200, body)) = fetch.get(VERSION_URL, &ua, t) {
            if let Some((v, min)) = remote_versions(&body) {
                if let Ok((200, sig)) = fetch.get(&sig_url(), &ua, t) {
                    if verified(keys, &body, &sig) {
                        let (sha, psig) = package_fields(&body);
                        store.set(KEY_LAST_GOOD, v);
                        store.set(KEY_LAST_MIN, min);
                        store.set(KEY_LAST_PKG_SHA, sha);
                        store.set(KEY_LAST_PKG_SIG, psig);
                    }
                }
            }
        }
    }
    let good = store.get(KEY_LAST_GOOD);
    newer_than(&good, running).then(|| Notice {
        below_min: newer_than(&store.get(KEY_LAST_MIN), running),
        version: good,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn body_text_keeps_the_exact_signed_bytes() {
        let bom = b"\xEF\xBB\xBF{\"version\":\"1.0.0\"}".to_vec();
        assert_eq!(super::body_text(bom.clone()).unwrap().as_bytes(), &bom[..]);
        assert!(super::body_text(b"{\"v\":\"\xFF\"}".to_vec()).is_err());
    }

    use super::*;
    use hbb_common::base64::{self, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    use std::cell::RefCell;
    use std::collections::HashMap;

    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
    // Throwaway test keys: fixed seeds, never the release keys.
    fn current() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32])
    }
    fn backup() -> SigningKey {
        SigningKey::from_bytes(&[2u8; 32])
    }
    fn stranger() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }
    fn keys() -> Vec<VerifyingKey> {
        vec![current().verifying_key(), backup().verifying_key()]
    }
    fn sign(k: &SigningKey, body: &str) -> String {
        B64.encode(k.sign(body.as_bytes()).to_bytes())
    }

    /// Serves the version file and its `.sig` by URL.
    struct Fake {
        replies: HashMap<String, Result<(u16, String), String>>,
        calls: RefCell<Vec<(String, String, Duration)>>,
    }
    impl Fake {
        fn raw(body: Result<(u16, String), String>, sig: Result<(u16, String), String>) -> Self {
            let mut replies = HashMap::new();
            replies.insert(VERSION_URL.to_owned(), body);
            replies.insert(sig_url(), sig);
            Fake { replies, calls: RefCell::new(vec![]) }
        }
        fn signed_by(k: &SigningKey, body: &str) -> Self {
            Self::raw(Ok((200, body.into())), Ok((200, sign(k, body))))
        }
        fn ok(body: &str) -> Self {
            Self::signed_by(&current(), body)
        }
        fn err(e: &str) -> Self {
            Self::raw(Err(e.into()), Err(e.into()))
        }
        /// Number of version-file fetches.
        fn n(&self) -> usize {
            self.calls.borrow().iter().filter(|c| c.0 == VERSION_URL).count()
        }
    }
    impl Fetch for Fake {
        fn get(&self, url: &str, ua: &str, t: Duration) -> Result<(u16, String), String> {
            self.calls.borrow_mut().push((url.into(), ua.into(), t));
            self.replies.get(url).cloned().unwrap_or(Ok((404, String::new())))
        }
    }
    #[derive(Default)]
    struct Mem(HashMap<String, String>);
    impl Store for Mem {
        fn get(&self, k: &str) -> String {
            self.0.get(k).cloned().unwrap_or_default()
        }
        fn set(&mut self, k: &str, v: String) {
            self.0.insert(k.into(), v);
        }
    }
    fn body(v: &str) -> String {
        format!(r#"{{"version":"{v}","sha256":"x","url":"u","extra":1}}"#)
    }
    fn body_min(v: &str, min: &str) -> String {
        format!(r#"{{"version":"{v}","sha256":"x","url":"u","min_version":"{min}"}}"#)
    }
    fn notice(v: &str, below_min: bool) -> Option<Notice> {
        Some(Notice { version: v.into(), below_min })
    }
    const NOW: u64 = 1_800_000_000;
    fn run(f: &Fake, s: &mut Mem, now: u64, running: &str) -> Option<Notice> {
        check_with(&keys(), f, s, now, running)
    }

    // --- signature (ticket 10) ---
    #[test]
    fn good_sig_from_current_key_is_accepted() {
        assert_eq!(run(&Fake::ok(&body("1.6.0")), &mut Mem::default(), NOW, "1.5.0"), notice("1.6.0", false));
    }
    #[test]
    fn sig_from_backup_key_is_accepted() {
        let f = Fake::signed_by(&backup(), &body("1.6.0"));
        assert_eq!(run(&f, &mut Mem::default(), NOW, "1.5.0"), notice("1.6.0", false));
    }
    #[test]
    fn sig_from_an_unknown_key_is_rejected() {
        let f = Fake::signed_by(&stranger(), &body("1.6.0"));
        assert_eq!(run(&f, &mut Mem::default(), NOW, "1.5.0"), None);
    }
    #[test]
    fn garbage_or_missing_sig_is_rejected() {
        for sig in [Ok((200, "not base64!".into())), Ok((200, B64.encode([0u8; 10]))),
                    Ok((200, String::new())), Ok((404, sign(&current(), &body("1.6.0")))),
                    Err("timeout".into())] {
            let f = Fake::raw(Ok((200, body("1.6.0"))), sig.clone());
            assert_eq!(run(&f, &mut Mem::default(), NOW, "1.5.0"), None, "{sig:?}");
        }
    }
    #[test]
    fn tampered_file_is_rejected() {
        let good = body_min("1.6.0", "1.5.0");
        let evil = body_min("1.6.0", "9.0.0");
        let f = Fake::raw(Ok((200, evil)), Ok((200, sign(&current(), &good))));
        assert_eq!(run(&f, &mut Mem::default(), NOW, "1.5.0"), None);
    }
    #[test]
    fn sig_with_trailing_newline_is_accepted() {
        let b = body("1.6.0");
        let f = Fake::raw(Ok((200, b.clone())), Ok((200, format!("{}\n", sign(&current(), &b)))));
        assert_eq!(run(&f, &mut Mem::default(), NOW, "1.5.0"), notice("1.6.0", false));
    }
    #[test]
    fn bad_sig_keeps_last_good_answer_including_below_min() {
        let mut s = Mem::default();
        run(&Fake::ok(&body_min("1.6.0", "1.6.0")), &mut s, NOW, "1.5.0");
        let evil = Fake::signed_by(&stranger(), &body_min("1.7.0", "1.0.0"));
        assert_eq!(run(&evil, &mut s, NOW + GATE_SECS, "1.5.0"), notice("1.6.0", true));
    }
    #[test]
    fn sig_is_fetched_from_the_version_url_plus_dot_sig() {
        assert_eq!(sig_url(), format!("{VERSION_URL}.sig"));
        let f = Fake::ok(&body("1.6.0"));
        run(&f, &mut Mem::default(), NOW, "1.5.0");
        let c = f.calls.borrow();
        assert!(c.iter().any(|c| c.0 == sig_url() && c.1 == "BoringRemote/1.5.0" && c.2 == Duration::from_secs(10)));
    }
    #[test]
    fn embedded_keys_are_both_release_keys() {
        let k = embedded_keys();
        assert_eq!(k.len(), 2);
        assert_eq!(B64.encode(k[0].to_bytes()), "sJyFBUc4U5I42j4FvNuafMRd4s2rdqQNiQPTfUU8q3o=");
        assert_eq!(B64.encode(k[1].to_bytes()), "fUGKPveLBQfyeExmew6ttY+xlFygkFC02liG1adqZnk=");
    }

    // --- package details for Install update (ticket 12) ---
    #[test]
    fn signed_package_details_are_kept_for_install() {
        let mut s = Mem::default();
        assert_eq!(release(&s), None);
        let b = r#"{"version":"1.6.0","package_sha256":"ab12","package_sig":"c2ln"}"#;
        run(&Fake::ok(b), &mut s, NOW, "1.5.0");
        let r = release(&s).unwrap();
        assert_eq!((r.version.as_str(), r.package_sha256.as_str(), r.package_sig.as_str()), ("1.6.0", "ab12", "c2ln"));
        // An unsigned file never replaces them.
        let evil = r#"{"version":"1.7.0","package_sha256":"ff","package_sig":"eA=="}"#;
        run(&Fake::signed_by(&stranger(), evil), &mut s, NOW + GATE_SECS, "1.5.0");
        assert_eq!(release(&s).unwrap().package_sha256, "ab12");
        // A signed file with no package (CI output before signing) clears them.
        run(&Fake::ok(&body("1.6.1")), &mut s, NOW + 2 * GATE_SECS, "1.5.0");
        assert_eq!(release(&s), None);
    }

    // --- Minimum version (ticket 10) ---
    #[test]
    fn below_min_is_reported() {
        let f = Fake::ok(&body_min("1.7.0", "1.6.0"));
        assert_eq!(run(&f, &mut Mem::default(), NOW, "1.5.9"), notice("1.7.0", true));
    }
    #[test]
    fn at_or_above_min_is_not_below_min() {
        for running in ["1.6.0", "1.6.5"] {
            let f = Fake::ok(&body_min("1.7.0", "1.6.0"));
            assert_eq!(run(&f, &mut Mem::default(), NOW, running), notice("1.7.0", false), "{running}");
        }
    }
    #[test]
    fn min_is_judged_against_the_running_version_from_the_store() {
        let mut s = Mem::default();
        run(&Fake::ok(&body_min("1.7.0", "1.6.0")), &mut s, NOW, "1.5.0");
        assert_eq!(run(&Fake::ok("x"), &mut s, NOW + 5, "1.6.1"), notice("1.7.0", false));
    }
    #[test]
    fn non_strict_min_rejects_the_file() {
        let f = Fake::ok(&body_min("1.7.0", "1.6"));
        assert_eq!(run(&f, &mut Mem::default(), NOW, "1.5.0"), None);
    }

    // --- carried over from ADR 0003 ---
    #[test]
    fn newer_is_reported() {
        assert_eq!(run(&Fake::ok(&body("1.6.0")), &mut Mem::default(), NOW, "1.5.0"), notice("1.6.0", false));
    }
    #[test]
    fn semver_compares_numerically() {
        let f = Fake::ok(&body("1.10.0"));
        assert_eq!(run(&f, &mut Mem::default(), NOW, "1.9.9"), notice("1.10.0", false));
    }
    #[test]
    fn equal_and_older_report_nothing() {
        for v in ["1.5.0", "1.4.9", "0.9.0"] {
            assert_eq!(run(&Fake::ok(&body(v)), &mut Mem::default(), NOW, "1.5.0"), None, "{v}");
        }
    }
    #[test]
    fn non_strict_versions_report_nothing() {
        for v in ["1.5", "v1.6.0", "1.6.0-beta", "1.6.0.1", "", "1.x.0", " 1.6.0", "-1.6.0"] {
            assert_eq!(run(&Fake::ok(&body(v)), &mut Mem::default(), NOW, "1.5.0"), None, "{v:?}");
        }
    }
    #[test]
    fn bad_json_and_missing_version_report_nothing() {
        for b in ["not json", "{}", r#"{"version":5}"#, ""] {
            assert_eq!(run(&Fake::ok(b), &mut Mem::default(), NOW, "1.5.0"), None, "{b:?}");
        }
    }
    #[test]
    fn non_200_reports_nothing() {
        let b = body("9.0.0");
        let f = Fake::raw(Ok((404, b.clone())), Ok((200, sign(&current(), &b))));
        assert_eq!(run(&f, &mut Mem::default(), NOW, "1.5.0"), None);
    }
    #[test]
    fn request_carries_only_the_user_agent_and_a_10s_timeout() {
        let f = Fake::ok(&body("1.6.0"));
        run(&f, &mut Mem::default(), NOW, "1.5.0");
        let c = f.calls.borrow();
        assert_eq!(c[0].0, VERSION_URL);
        assert_eq!(c[0].1, "BoringRemote/1.5.0");
        assert_eq!(c[0].2, Duration::from_secs(10));
    }
    #[test]
    fn failed_fetch_keeps_last_good_answer_and_records_the_try() {
        let mut s = Mem::default();
        run(&Fake::ok(&body("1.6.0")), &mut s, NOW, "1.5.0");
        let bad = Fake::err("timeout");
        let later = NOW + GATE_SECS;
        assert_eq!(run(&bad, &mut s, later, "1.5.0"), notice("1.6.0", false));
        assert_eq!(bad.n(), 1);
        assert_eq!(s.get(KEY_LAST_TRY), later.to_string());
    }
    #[test]
    fn gate_blocks_a_second_fetch_inside_24h_but_still_answers() {
        let mut s = Mem::default();
        run(&Fake::ok(&body("1.6.0")), &mut s, NOW, "1.5.0");
        let f = Fake::ok(&body("1.7.0"));
        assert_eq!(run(&f, &mut s, NOW + GATE_SECS - 1, "1.5.0"), notice("1.6.0", false));
        assert_eq!(f.n(), 0);
        assert_eq!(run(&f, &mut s, NOW + GATE_SECS, "1.5.0"), notice("1.7.0", false));
        assert_eq!(f.n(), 1);
    }
    #[test]
    fn failed_try_also_starts_the_gate() {
        let mut s = Mem::default();
        let bad = Fake::err("down");
        run(&bad, &mut s, NOW, "1.5.0");
        run(&bad, &mut s, NOW + 60, "1.5.0");
        assert_eq!(bad.n(), 1);
    }
    #[test]
    fn clock_set_backwards_counts_as_due() {
        let mut s = Mem::default();
        run(&Fake::ok(&body("1.6.0")), &mut s, NOW, "1.5.0");
        let f = Fake::ok(&body("1.6.0"));
        run(&f, &mut s, NOW - 5, "1.5.0");
        assert_eq!(f.n(), 1);
    }
    #[test]
    fn switch_off_means_no_fetch_and_no_notice() {
        let mut s = Mem::default();
        run(&Fake::ok(&body("1.6.0")), &mut s, NOW, "1.5.0");
        s.set(KEY_ENABLED, "N".into());
        let f = Fake::ok(&body("1.7.0"));
        assert_eq!(run(&f, &mut s, NOW + 10 * GATE_SECS, "1.5.0"), None);
        assert_eq!(f.calls.borrow().len(), 0);
    }
    #[test]
    fn stored_answer_is_judged_against_the_running_version() {
        let mut s = Mem::default();
        run(&Fake::ok(&body("1.6.0")), &mut s, NOW, "1.5.0");
        assert_eq!(run(&Fake::ok("x"), &mut s, NOW + 5, "1.6.0"), None);
    }
    #[test]
    fn unparseable_running_version_reports_nothing() {
        assert_eq!(run(&Fake::ok(&body("9.0.0")), &mut Mem::default(), NOW, "dev"), None);
    }
}
