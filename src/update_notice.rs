//! Update notice (ADR 0003): read one public version file, say whether it is
//! newer than this build. Notice only: nothing here downloads or installs.
//! Contract: the-boring-remote/docs/version-file.md.
use std::time::Duration;

pub const VERSION_URL: &str = "https://boringlabs.online/downloads/the-boring-remote-version.json";
/// Settings switch (local option). Anything but "N" means on.
pub const KEY_ENABLED: &str = "boring-update-check";
/// Unix seconds of the last attempt, success or not.
pub const KEY_LAST_TRY: &str = "boring-update-last-try";
/// Remote `version` from the last good fetch.
pub const KEY_LAST_GOOD: &str = "boring-update-last-good";
const GATE_SECS: u64 = 24 * 60 * 60;

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

fn remote_version(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let s = v.get("version")?.as_str()?;
    parse_semver(s).map(|_| s.to_owned())
}

fn newer_than(remote: &str, running: &str) -> bool {
    match (parse_semver(remote), parse_semver(running)) {
        (Some(r), Some(l)) => r > l,
        _ => false,
    }
}

/// Returns the remote version when it is strictly newer than `running`.
/// Fetches at most once per 24 h (the try is stamped before the request, so a
/// failure also waits a day); a clock set back past the stamp counts as due.
/// A failed or unusable fetch keeps the last good answer.
pub fn check(fetch: &dyn Fetch, store: &mut dyn Store, now: u64, running: &str) -> Option<String> {
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
        if let Ok((200, body)) = fetch.get(VERSION_URL, &ua, Duration::from_secs(10)) {
            if let Some(v) = remote_version(&body) {
                store.set(KEY_LAST_GOOD, v);
            }
        }
    }
    let good = store.get(KEY_LAST_GOOD);
    newer_than(&good, running).then_some(good)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    struct Fake {
        reply: Result<(u16, String), String>,
        calls: RefCell<Vec<(String, String, Duration)>>,
    }
    impl Fake {
        fn ok(body: &str) -> Self {
            Fake { reply: Ok((200, body.into())), calls: RefCell::new(vec![]) }
        }
        fn n(&self) -> usize {
            self.calls.borrow().len()
        }
    }
    impl Fetch for Fake {
        fn get(&self, url: &str, ua: &str, t: Duration) -> Result<(u16, String), String> {
            self.calls.borrow_mut().push((url.into(), ua.into(), t));
            self.reply.clone()
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
    const NOW: u64 = 1_800_000_000;

    #[test]
    fn newer_is_reported() {
        let f = Fake::ok(&body("1.6.0"));
        let mut s = Mem::default();
        assert_eq!(check(&f, &mut s, NOW, "1.5.0"), Some("1.6.0".into()));
    }
    #[test]
    fn semver_compares_numerically() {
        let f = Fake::ok(&body("1.10.0"));
        assert_eq!(check(&f, &mut Mem::default(), NOW, "1.9.9"), Some("1.10.0".into()));
    }
    #[test]
    fn equal_and_older_report_nothing() {
        for v in ["1.5.0", "1.4.9", "0.9.0"] {
            let f = Fake::ok(&body(v));
            assert_eq!(check(&f, &mut Mem::default(), NOW, "1.5.0"), None, "{v}");
        }
    }
    #[test]
    fn non_strict_versions_report_nothing() {
        for v in ["1.5", "v1.6.0", "1.6.0-beta", "1.6.0.1", "", "1.x.0", " 1.6.0", "-1.6.0"] {
            let f = Fake::ok(&body(v));
            assert_eq!(check(&f, &mut Mem::default(), NOW, "1.5.0"), None, "{v:?}");
        }
    }
    #[test]
    fn bad_json_and_missing_version_report_nothing() {
        for b in ["not json", "{}", r#"{"version":5}"#, ""] {
            let f = Fake::ok(b);
            assert_eq!(check(&f, &mut Mem::default(), NOW, "1.5.0"), None, "{b:?}");
        }
    }
    #[test]
    fn non_200_reports_nothing() {
        let f = Fake { reply: Ok((404, body("9.0.0"))), calls: RefCell::new(vec![]) };
        assert_eq!(check(&f, &mut Mem::default(), NOW, "1.5.0"), None);
    }
    #[test]
    fn request_carries_only_the_user_agent_and_a_10s_timeout() {
        let f = Fake::ok(&body("1.6.0"));
        check(&f, &mut Mem::default(), NOW, "1.5.0");
        let c = f.calls.borrow();
        assert_eq!(c[0].0, VERSION_URL);
        assert_eq!(c[0].1, "BoringRemote/1.5.0");
        assert_eq!(c[0].2, Duration::from_secs(10));
    }
    #[test]
    fn failed_fetch_keeps_last_good_answer_and_records_the_try() {
        let mut s = Mem::default();
        check(&Fake::ok(&body("1.6.0")), &mut s, NOW, "1.5.0");
        let bad = Fake { reply: Err("timeout".into()), calls: RefCell::new(vec![]) };
        let later = NOW + GATE_SECS;
        assert_eq!(check(&bad, &mut s, later, "1.5.0"), Some("1.6.0".into()));
        assert_eq!(bad.n(), 1);
        assert_eq!(s.get(KEY_LAST_TRY), later.to_string());
    }
    #[test]
    fn gate_blocks_a_second_fetch_inside_24h_but_still_answers() {
        let mut s = Mem::default();
        check(&Fake::ok(&body("1.6.0")), &mut s, NOW, "1.5.0");
        let f = Fake::ok(&body("1.7.0"));
        assert_eq!(check(&f, &mut s, NOW + GATE_SECS - 1, "1.5.0"), Some("1.6.0".into()));
        assert_eq!(f.n(), 0);
        assert_eq!(check(&f, &mut s, NOW + GATE_SECS, "1.5.0"), Some("1.7.0".into()));
        assert_eq!(f.n(), 1);
    }
    #[test]
    fn failed_try_also_starts_the_gate() {
        let mut s = Mem::default();
        let bad = Fake { reply: Err("down".into()), calls: RefCell::new(vec![]) };
        check(&bad, &mut s, NOW, "1.5.0");
        check(&bad, &mut s, NOW + 60, "1.5.0");
        assert_eq!(bad.n(), 1);
    }
    #[test]
    fn clock_set_backwards_counts_as_due() {
        let mut s = Mem::default();
        check(&Fake::ok(&body("1.6.0")), &mut s, NOW, "1.5.0");
        let f = Fake::ok(&body("1.6.0"));
        check(&f, &mut s, NOW - 5, "1.5.0");
        assert_eq!(f.n(), 1);
    }
    #[test]
    fn switch_off_means_no_fetch_and_no_notice() {
        let mut s = Mem::default();
        check(&Fake::ok(&body("1.6.0")), &mut s, NOW, "1.5.0");
        s.set(KEY_ENABLED, "N".into());
        let f = Fake::ok(&body("1.7.0"));
        assert_eq!(check(&f, &mut s, NOW + 10 * GATE_SECS, "1.5.0"), None);
        assert_eq!(f.n(), 0);
    }
    #[test]
    fn stored_answer_is_judged_against_the_running_version() {
        let mut s = Mem::default();
        check(&Fake::ok(&body("1.6.0")), &mut s, NOW, "1.5.0");
        let f = Fake::ok("x");
        assert_eq!(check(&f, &mut s, NOW + 5, "1.6.0"), None);
    }
    #[test]
    fn unparseable_running_version_reports_nothing() {
        assert_eq!(check(&Fake::ok(&body("9.0.0")), &mut Mem::default(), NOW, "dev"), None);
    }
}
