//! License key (spec slice 5): stored in local option `boring-license-key`,
//! checked against fulfillment `POST /update {license_key, check:true}`.
use std::time::Duration;

pub const KEY_OPTION: &str = "boring-license-key";
pub const UPDATE_ENDPOINT: &str = "https://store-fulfillment.boringstories.workers.dev/update";

pub trait Post {
    fn post_json(&self, url: &str, body: &str, timeout: Duration) -> Result<(u16, String), String>;
}

/// The Settings field's word for a key. `Unknown`: fulfillment has no such key.
/// `Network`: no usable answer, so the key's state is not known. `None`: blank key, no request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    Valid,
    Revoked,
    Refunded,
    Unknown,
    Busy,
    Network,
    None,
}

impl KeyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Revoked => "revoked",
            Self::Refunded => "refunded",
            Self::Unknown => "unknown",
            Self::Busy => "busy",
            Self::Network => "network",
            Self::None => "none",
        }
    }
}

pub fn check(post: &dyn Post, key: &str) -> KeyStatus {
    let key = key.trim();
    if key.is_empty() {
        return KeyStatus::None;
    }
    let body = serde_json::json!({"license_key": key, "check": true}).to_string();
    let (status, text) = match post.post_json(UPDATE_ENDPOINT, &body, Duration::from_secs(10)) {
        Ok(r) => r,
        Err(_) => return KeyStatus::Network,
    };
    if status == 429 {
        return KeyStatus::Busy;
    }
    let Some(v) = (status == 200).then(|| serde_json::from_str::<serde_json::Value>(&text).ok()).flatten() else {
        return KeyStatus::Network;
    };
    match (v.get("valid").and_then(|b| b.as_bool()), v.get("reason").and_then(|r| r.as_str())) {
        (Some(true), _) => KeyStatus::Valid,
        (Some(false), Some("revoked")) => KeyStatus::Revoked,
        (Some(false), Some("refunded")) => KeyStatus::Refunded,
        (Some(false), _) => KeyStatus::Unknown,
        _ => KeyStatus::Network,
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
        assert_eq!(check(&f, "ABC-123").as_str(), "valid");
        let (url, body) = f.sent.borrow()[0].clone();
        assert_eq!(url, "https://store-fulfillment.boringstories.workers.dev/update");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v, serde_json::json!({"license_key": "ABC-123", "check": true}));
    }

    #[test]
    fn revoked_refunded_unknown() {
        for (reason, want) in [("revoked", "revoked"), ("refunded", "refunded"), ("not found", "unknown")] {
            let body = format!(r#"{{"valid":false,"reason":"{reason}"}}"#);
            assert_eq!(check(&fake(Ok((200, &body))), "k").as_str(), want);
        }
    }

    #[test]
    fn network_failures_are_not_invalid() {
        assert_eq!(check(&fake(Err("dns")), "k").as_str(), "network");
        assert_eq!(check(&fake(Ok((500, "oops"))), "k").as_str(), "network");
        assert_eq!(check(&fake(Ok((200, "<html>"))), "k").as_str(), "network");
        assert_eq!(check(&fake(Ok((429, r#"{"reason":"too many requests"}"#))), "k").as_str(), "busy");
    }

    #[test]
    fn empty_key_never_hits_network() {
        let f = fake(Ok((200, r#"{"valid":true,"reason":null}"#)));
        assert_eq!(check(&f, "  ").as_str(), "none");
        assert!(f.sent.borrow().is_empty());
    }
}
