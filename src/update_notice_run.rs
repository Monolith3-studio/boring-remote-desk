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

/// The newer version string if one is out, else None.
pub fn check_now() -> Option<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    check(&Http, &mut Local, now, crate::VERSION)
}
