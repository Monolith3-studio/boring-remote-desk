//! Real wiring for `update_install`: HTTP download, monotonic clock, live
//! session count, and the root install script through osascript. Blocking:
//! call off the UI thread.
use crate::update_install::{install, Clock, Deps, Fetcher, InstallError, Runner, SessionCount};
use hbb_common::config::LocalConfig;
use std::path::Path;
use std::time::{Duration, Instant};

struct Http;
impl Fetcher for Http {
    fn post_to_file(&self, url: &str, body: &str, dest: &Path, timeout: Duration) -> Result<u16, String> {
        let client = crate::hbbs_http::create_http_client_with_url_strict(url).map_err(|e| e.to_string())?;
        let mut r = client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::USER_AGENT, format!("BoringRemote/{}", crate::VERSION))
            .body(body.to_owned())
            .timeout(timeout)
            .send()
            .map_err(|e| e.to_string())?;
        let mut f = std::fs::File::create(dest).map_err(|e| e.to_string())?;
        r.copy_to(&mut f).map_err(|e| e.to_string())?;
        Ok(r.status().as_u16())
    }
}

struct Mono(Instant);
impl Clock for Mono {
    fn now(&self) -> u64 {
        self.0.elapsed().as_secs()
    }
}

struct Live;
impl SessionCount for Live {
    fn live(&self) -> usize {
        crate::ui_cm_interface::get_clients_length()
    }
}

/// One admin prompt naming Boring Remote and the version; argv is quoted, never spliced.
const OSA: &str = r#"on run argv
  do shell script (quoted form of item 1 of argv) & " " & (quoted form of item 2 of argv) & " " & (quoted form of item 3 of argv) & " " & (quoted form of item 4 of argv) with prompt ("Boring Remote needs your password to install version " & (item 4 of argv) & ".") with administrator privileges
end run"#;

struct Osascript;
impl Runner for Osascript {
    fn run(&self, package: &Path, sig: &str, version: &str) -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let script = exe
            .parent()
            .and_then(|m| m.parent())
            .map(|c| c.join("Resources/boring-install-update.sh"))
            .ok_or("no bundle")?;
        let out = std::process::Command::new("osascript")
            .arg("-e")
            .arg(OSA)
            .arg(&script)
            .arg(package)
            .arg(sig)
            .arg(version)
            .output()
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
        }
    }
}

struct Local;
impl crate::update_notice::Store for Local {
    fn get(&self, key: &str) -> String {
        LocalConfig::get_option(key)
    }
    fn set(&mut self, key: &str, value: String) {
        LocalConfig::set_option(key.to_owned(), value);
    }
}

/// "ok" or an `InstallError::as_str()` word.
pub fn install_now() -> String {
    let key = LocalConfig::get_option(crate::license_key::KEY_OPTION);
    let release = crate::update_notice::release(&Local);
    let dir = std::env::temp_dir().join(format!("boring-update-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        log::error!("install update: temp dir: {e}");
        return InstallError::Download(e.to_string()).as_str().into();
    }
    let keys = crate::update_notice::embedded_keys();
    let d = Deps {
        fetcher: &Http,
        clock: &Mono(Instant::now()),
        sessions: &Live,
        runner: &Osascript,
        keys: &keys,
        temp_dir: &dir,
    };
    let res = install(&d, crate::license_key::UPDATE_ENDPOINT, &key, release.as_ref());
    let _ = std::fs::remove_dir_all(&dir);
    match res {
        Ok(()) => "ok".into(),
        Err(e) => {
            log::warn!("install update: {e:?}");
            e.as_str().into()
        }
    }
}

