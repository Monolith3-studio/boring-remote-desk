//! Install update (ADR 0004, spec slice 5): with a License key, fetch the Update
//! package from fulfillment, check it, and hand it to the root install script.
//! Nothing here touches /Applications: every failure before the handoff leaves
//! the install as it was. The script re-verifies the sig itself (slice 6).
use crate::update_notice::verify_bytes;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Whole-download budget. The fetcher gets it as its timeout; the clock enforces it too.
pub const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// What the signed version file says about the package to install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    pub package_sha256: String,
    pub package_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallError {
    NoKey,
    /// Someone is connected; the banner says "Finish your session to update".
    LiveSession,
    /// No signed package details from the last good check.
    NoRelease,
    Download(String),
    Timeout,
    Sha256,
    Signature,
    Script(String),
}

impl InstallError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoKey => "no-key",
            Self::LiveSession => "live-session",
            Self::NoRelease => "no-release",
            Self::Download(_) => "download",
            Self::Timeout => "timeout",
            Self::Sha256 => "sha256",
            Self::Signature => "signature",
            Self::Script(_) => "script",
        }
    }
}

pub trait Fetcher {
    /// POST JSON `body` to `url`, writing the response body to `dest`. Ok(status) or Err on transport failure.
    fn post_to_file(&self, url: &str, body: &str, dest: &Path, timeout: Duration) -> Result<u16, String>;
}
pub trait Clock {
    /// Monotonic seconds.
    fn now(&self) -> u64;
}
pub trait SessionCount {
    fn live(&self) -> usize;
}
pub trait Runner {
    /// Run the root install script on the checked package. Returns once the script is done.
    fn run(&self, package: &Path, sig: &str, version: &str) -> Result<(), String>;
}

pub struct Deps<'a> {
    pub fetcher: &'a dyn Fetcher,
    pub clock: &'a dyn Clock,
    pub sessions: &'a dyn SessionCount,
    pub runner: &'a dyn Runner,
    pub keys: &'a [VerifyingKey],
    /// Fresh private temp dir; the package lands here.
    pub temp_dir: &'a Path,
}

pub fn package_path(temp_dir: &Path, version: &str) -> PathBuf {
    temp_dir.join(format!("BoringRemote-{version}-macos-arm64.app.tar.xz"))
}

/// Refuse during a live session, download, check sha256 and sig, then hand off.
pub fn install(d: &Deps, url: &str, key: &str, release: Option<&Release>) -> Result<(), InstallError> {
    let key = key.trim();
    if key.is_empty() {
        return Err(InstallError::NoKey);
    }
    if d.sessions.live() > 0 {
        return Err(InstallError::LiveSession);
    }
    let r = release.ok_or(InstallError::NoRelease)?;
    let dest = package_path(d.temp_dir, &r.version);
    let res = download_and_check(d, url, key, r, &dest);
    if res.is_err() {
        let _ = std::fs::remove_file(&dest);
    }
    res?;
    d.runner.run(&dest, &r.package_sig, &r.version).map_err(InstallError::Script)
}

fn download_and_check(d: &Deps, url: &str, key: &str, r: &Release, dest: &Path) -> Result<(), InstallError> {
    let body = serde_json::json!({"license_key": key, "version": r.version}).to_string();
    let start = d.clock.now();
    let status = d
        .fetcher
        .post_to_file(url, &body, dest, DOWNLOAD_TIMEOUT)
        .map_err(InstallError::Download)?;
    if d.clock.now().saturating_sub(start) > DOWNLOAD_TIMEOUT.as_secs() {
        return Err(InstallError::Timeout);
    }
    if status != 200 {
        return Err(InstallError::Download(format!("HTTP {status}")));
    }
    let bytes = std::fs::read(dest).map_err(|e| InstallError::Download(e.to_string()))?;
    if !hex::encode(Sha256::digest(&bytes)).eq_ignore_ascii_case(r.package_sha256.trim()) {
        return Err(InstallError::Sha256);
    }
    if !verify_bytes(d.keys, &bytes, &r.package_sig) {
        return Err(InstallError::Signature);
    }
    Ok(())
}

/// `--boring-verify-package <file> <sig>`: the script's own sig check, against the embedded keys.
pub fn verify_cli(args: &[String]) -> i32 {
    match args {
        [file, sig] => match std::fs::read(file) {
            Ok(b) if verify_bytes(&crate::update_notice::embedded_keys(), &b, sig) => 0,
            _ => 1,
        },
        _ => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use hbb_common::base64::{self, Engine as _};
    use std::cell::{Cell, RefCell};

    const URL: &str = "https://fulfillment.test/update";
    const PKG: &[u8] = b"pretend tar.xz bytes";

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32])
    }
    fn release_for(bytes: &[u8], k: &SigningKey) -> Release {
        Release {
            version: "1.6.0".into(),
            package_sha256: hex::encode(Sha256::digest(bytes)),
            package_sig: base64::engine::general_purpose::STANDARD.encode(k.sign(bytes).to_bytes()),
        }
    }

    struct Fetch<'c> {
        status: Result<u16, String>,
        bytes: Vec<u8>,
        sent: RefCell<Vec<(String, String, Duration)>>,
        clock_jump: u64,
        clock: Option<&'c FakeClock>,
    }
    impl Fetch<'_> {
        fn ok(bytes: &[u8]) -> Self {
            Fetch { status: Ok(200), bytes: bytes.to_vec(), sent: RefCell::new(vec![]), clock_jump: 0, clock: None }
        }
    }
    impl Fetcher for Fetch<'_> {
        fn post_to_file(&self, url: &str, body: &str, dest: &Path, t: Duration) -> Result<u16, String> {
            self.sent.borrow_mut().push((url.into(), body.into(), t));
            if let Some(c) = self.clock {
                c.0.set(c.0.get() + self.clock_jump);
            }
            std::fs::write(dest, &self.bytes).unwrap();
            self.status.clone()
        }
    }
    struct FakeClock(Cell<u64>);
    impl Clock for FakeClock {
        fn now(&self) -> u64 {
            self.0.get()
        }
    }
    struct Sessions(usize);
    impl SessionCount for Sessions {
        fn live(&self) -> usize {
            self.0
        }
    }
    #[derive(Default)]
    struct Run {
        calls: RefCell<Vec<(PathBuf, String, String, Vec<u8>)>>,
    }
    impl Runner for Run {
        fn run(&self, p: &Path, sig: &str, v: &str) -> Result<(), String> {
            self.calls.borrow_mut().push((p.into(), sig.into(), v.into(), std::fs::read(p).unwrap()));
            Ok(())
        }
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("t12-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn go(name: &str, f: &Fetch, clock: &FakeClock, live: usize, r: Option<&Release>, key: &str) -> (Result<(), InstallError>, Run, PathBuf) {
        let run = Run::default();
        let dir = tmp(name);
        let keys = [signer().verifying_key(), SigningKey::from_bytes(&[2u8; 32]).verifying_key()];
        let d = Deps { fetcher: f, clock, sessions: &Sessions(live), runner: &run, keys: &keys, temp_dir: &dir };
        (install(&d, URL, key, r), run, dir)
    }
    fn clock() -> FakeClock {
        FakeClock(Cell::new(1000))
    }

    #[test]
    fn good_package_is_handed_to_the_script() {
        let r = release_for(PKG, &signer());
        let f = Fetch::ok(PKG);
        let (res, run, dir) = go("good", &f, &clock(), 0, Some(&r), " KEY-1 ");
        assert_eq!(res, Ok(()));
        let c = run.calls.borrow();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].0, dir.join("BoringRemote-1.6.0-macos-arm64.app.tar.xz"));
        assert_eq!((c[0].1.as_str(), c[0].2.as_str(), c[0].3.as_slice()), (r.package_sig.as_str(), "1.6.0", PKG));
        let (url, body, t) = f.sent.borrow()[0].clone();
        assert_eq!((url.as_str(), t), (URL, Duration::from_secs(600)));
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v, serde_json::json!({"license_key": "KEY-1", "version": "1.6.0"}));
    }

    #[test]
    fn live_session_blocks_before_any_download() {
        let r = release_for(PKG, &signer());
        let f = Fetch::ok(PKG);
        let (res, run, _) = go("live", &f, &clock(), 1, Some(&r), "K");
        assert_eq!(res, Err(InstallError::LiveSession));
        assert!(f.sent.borrow().is_empty());
        assert!(run.calls.borrow().is_empty());
    }

    #[test]
    fn no_key_or_no_release_does_nothing() {
        let r = release_for(PKG, &signer());
        let f = Fetch::ok(PKG);
        assert_eq!(go("nokey", &f, &clock(), 0, Some(&r), "  ").0, Err(InstallError::NoKey));
        assert_eq!(go("norel", &f, &clock(), 0, None, "K").0, Err(InstallError::NoRelease));
        assert!(f.sent.borrow().is_empty());
    }

    #[test]
    fn sha_mismatch_means_no_handoff_and_no_leftover_file() {
        let r = release_for(PKG, &signer());
        let (res, run, dir) = go("sha", &Fetch::ok(b"tampered bytes"), &clock(), 0, Some(&r), "K");
        assert_eq!(res, Err(InstallError::Sha256));
        assert!(run.calls.borrow().is_empty());
        assert_eq!(std::fs::read_dir(dir).unwrap().count(), 0);
    }

    #[test]
    fn bad_sig_means_no_handoff() {
        // Right sha, but signed by a key the app does not carry.
        let r = release_for(PKG, &SigningKey::from_bytes(&[3u8; 32]));
        let (res, run, _) = go("sig", &Fetch::ok(PKG), &clock(), 0, Some(&r), "K");
        assert_eq!(res, Err(InstallError::Signature));
        assert!(run.calls.borrow().is_empty());
        let mut junk = release_for(PKG, &signer());
        junk.package_sig = "not base64!".into();
        assert_eq!(go("sig2", &Fetch::ok(PKG), &clock(), 0, Some(&junk), "K").0, Err(InstallError::Signature));
    }

    #[test]
    fn backup_key_sig_is_accepted() {
        let r = release_for(PKG, &SigningKey::from_bytes(&[2u8; 32]));
        assert_eq!(go("backup", &Fetch::ok(PKG), &clock(), 0, Some(&r), "K").0, Ok(()));
    }

    #[test]
    fn timeout_leaves_install_untouched() {
        let r = release_for(PKG, &signer());
        let c = clock();
        let mut f = Fetch::ok(PKG);
        f.clock = Some(&c);
        f.clock_jump = DOWNLOAD_TIMEOUT.as_secs() + 1;
        let (res, run, dir) = go("timeout", &f, &c, 0, Some(&r), "K");
        assert_eq!(res, Err(InstallError::Timeout));
        assert!(run.calls.borrow().is_empty());
        assert_eq!(std::fs::read_dir(dir).unwrap().count(), 0);
    }

    #[test]
    fn transport_error_and_non_200_mean_no_handoff() {
        let r = release_for(PKG, &signer());
        let mut f = Fetch::ok(PKG);
        f.status = Err("timed out".into());
        let (res, run, _) = go("err", &f, &clock(), 0, Some(&r), "K");
        assert_eq!(res, Err(InstallError::Download("timed out".into())));
        assert!(run.calls.borrow().is_empty());
        let mut f = Fetch::ok(br#"{"error":"revoked"}"#);
        f.status = Ok(403);
        assert_eq!(go("403", &f, &clock(), 0, Some(&r), "K").0, Err(InstallError::Download("HTTP 403".into())));
    }

    #[test]
    fn script_failure_is_surfaced() {
        struct Bad;
        impl Runner for Bad {
            fn run(&self, _: &Path, _: &str, _: &str) -> Result<(), String> {
                Err("User canceled.".into())
            }
        }
        let r = release_for(PKG, &signer());
        let dir = tmp("script");
        let keys = [signer().verifying_key()];
        let f = Fetch::ok(PKG);
        let d = Deps { fetcher: &f, clock: &clock(), sessions: &Sessions(0), runner: &Bad, keys: &keys, temp_dir: &dir };
        assert_eq!(install(&d, URL, "K", Some(&r)), Err(InstallError::Script("User canceled.".into())));
    }
}
