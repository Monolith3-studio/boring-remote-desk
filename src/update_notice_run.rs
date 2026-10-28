//! Real HTTP + local-config wiring for `update_notice`. Blocking: call off the UI thread.
use crate::update_notice::{check, Fetch, Store};
use hbb_common::config::LocalConfig;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Http;
impl Fetch for Http {
    fn get(&self, url: &str, user_agent: &str, timeout: Duration) -> Result<(u16, String), String> {
        let client = crate::hbbs_http::create_http_client_with_url_strict(url).map_err(|e| e.to_string())?;
        let r = client
            .get(url)
            .header(reqwest::header::USER_AGENT, user_agent)
            .timeout(timeout)
            .send()
            .map_err(|e| e.to_string())?;
        let status = r.status().as_u16();
        Ok((status, r.text().map_err(|e| e.to_string())?))
    }
}

struct Local;
impl Store for Local {
    fn get(&self, key: &str) -> String {
        LocalConfig::get_option(key)
    }
    fn set(&mut self, key: &str, value: String) {
        LocalConfig::set_option(key.to_owned(), value);
    }
}

/// The root service answers on its IPC socket (half of "healthy", spec slice 7).
#[cfg(target_os = "macos")]
fn service_responds() -> bool {
    hbb_common::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map(|rt| rt.block_on(crate::ipc::connect_service(1000)).is_ok())
        .unwrap_or(false)
}
#[cfg(not(target_os = "macos"))]
fn service_responds() -> bool {
    false
}

/// `{"version":"X.Y.Z","below_min":bool}` if a newer signed version is out, else None.
/// `{"failed":"X.Y.Z","running":"A.B.C"}` once after an update was rolled back.
/// Called by the home banner, so the main window is up.
pub fn check_now() -> Option<String> {
    let dir = std::path::Path::new(crate::update_rollback::SUPPORT_DIR);
    let pending = dir.join("update-pending").exists();
    if let Some(to) = crate::update_rollback::on_launch(dir, crate::VERSION, pending && service_responds()) {
        return Some(serde_json::json!({"failed": to, "running": crate::VERSION}).to_string());
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let n = check(&Http, &mut Local, now, crate::VERSION)?;
    Some(serde_json::json!({"version": n.version, "below_min": n.below_min}).to_string())
}
