//! License key (spec slice 5): stored in local option `boring-license-key`,
//! checked against fulfillment `POST /update {license_key, check:true}`.
use std::time::Duration;

pub const KEY_OPTION: &str = "boring-license-key";
pub const UPDATE_ENDPOINT: &str = "https://store-fulfillment.boringstories.workers.dev/update";

pub trait Post {
    /// POST JSON `body` to `url`; Ok((status, body)) or Err on any transport failure.
    fn post_json(&self, url: &str, body: &str, timeout: Duration) -> Result<(u16, String), String>;
}

/// One word for the Settings field: "valid", "revoked", "refunded", "unknown"
/// (fulfillment has no such key), "busy" (rate limited), "network" (no usable
/// answer, so the key's state is not known), or "none" (blank key, no request).
pub fn check(post: &dyn Post, key: &str) -> &'static str {
    let key = key.trim();
    if key.is_empty() {
        return "none";
    }
    let body = serde_json::json!({"license_key": key, "check": true}).to_string();
    let (status, text) = match post.post_json(UPDATE_ENDPOINT, &body, Duration::from_secs(10)) {
        Ok(r) => r,
        Err(_) => return "network",
    };
    if status == 429 {
        return "busy";
    }
    let Some(v) = (status == 200).then(|| serde_json::from_str::<serde_json::Value>(&text).ok()).flatten() else {
        return "network";
    };
    match (v.get("valid").and_then(|b| b.as_bool()), v.get("reason").and_then(|r| r.as_str())) {
        (Some(true), _) => "valid",
        (Some(false), Some("revoked")) => "revoked",
        (Some(false), Some("refunded")) => "refunded",
        (Some(false), _) => "unknown",
        _ => "network",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Fake {
        reply: Result<(u16, String), String>,
        sent: RefCell<Vec<(String, String)>>,
    }
    fn fake(reply: Result<(u16, &str), &str>) -> Fake {
        Fake {
            reply: reply.map(|(s, b)| (s, b.to_owned())).map_err(|e| e.to_owned()),
            sent: RefCell::new(vec![]),
        }
    }
    impl Post for Fake {
        fn post_json(&self, url: &str, body: &str, _t: Duration) -> Result<(u16, String), String> {
            self.sent.borrow_mut().push((url.to_owned(), body.to_owned()));
            self.reply.clone()
        }
    }

    #[test]
    fn valid_key() {
        let f = fake(Ok((200, r#"{"valid":true,"reason":null}"#)));
        assert_eq!(check(&f, "ABC-123"), "valid");
        let (url, body) = f.sent.borrow()[0].clone();
        assert_eq!(url, "https://store-fulfillment.boringstories.workers.dev/update");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v, serde_json::json!({"license_key": "ABC-123", "check": true}));
    }

    #[test]
    fn revoked_refunded_unknown() {
        for (reason, want) in [("revoked", "revoked"), ("refunded", "refunded"), ("not found", "unknown")] {
            let body = format!(r#"{{"valid":false,"reason":"{reason}"}}"#);
            assert_eq!(check(&fake(Ok((200, &body))), "k"), want);
        }
    }

    #[test]
    fn network_failures_are_not_invalid() {
        assert_eq!(check(&fake(Err("dns")), "k"), "network");
        assert_eq!(check(&fake(Ok((500, "oops"))), "k"), "network");
        assert_eq!(check(&fake(Ok((200, "<html>"))), "k"), "network");
        assert_eq!(check(&fake(Ok((429, r#"{"reason":"too many requests"}"#))), "k"), "busy");
    }

    #[test]
    fn empty_key_never_hits_network() {
        let f = fake(Ok((200, r#"{"valid":true,"reason":null}"#)));
        assert_eq!(check(&f, "  "), "none");
        assert!(f.sent.borrow().is_empty());
    }
}
