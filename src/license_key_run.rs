//! Real HTTP + local-config wiring for `license_key`. Blocking: call off the UI thread.
use crate::license_key::{check, Post, KEY_OPTION};
use hbb_common::config::LocalConfig;
use std::time::Duration;

struct Http;
impl Post for Http {
    fn post_json(&self, url: &str, body: &str, timeout: Duration) -> Result<(u16, String), String> {
        let client = crate::hbbs_http::create_http_client_with_url_strict(url).map_err(|e| e.to_string())?;
        let r = client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::USER_AGENT, format!("BoringRemote/{}", crate::VERSION))
            .body(body.to_owned())
            .timeout(timeout)
            .send()
            .map_err(|e| e.to_string())?;
        let status = r.status().as_u16();
        Ok((status, r.text().map_err(|e| e.to_string())?))
    }
}

/// Stores `key` (trimmed) in `boring-license-key`, then checks it with fulfillment.
pub fn set_and_check(key: &str) -> String {
    let key = key.trim();
    LocalConfig::set_option(KEY_OPTION.to_owned(), key.to_owned());
    check(&Http, key).as_str().to_owned()
}

/// Activate link (ticket 14): parse `boringremote://activate?key=…`, then store + check
/// like the Settings field. Anything else → `rejected`, nothing stored. Key never logged.
pub fn activate_link(url: &str) -> String {
    match crate::activate_link::parse(url) {
        Some(key) => set_and_check(&key),
        None => "rejected".to_owned(),
    }
}
