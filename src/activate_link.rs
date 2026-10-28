//! One-click activate link (ticket 14): `boringremote://activate?key=<License key>`.
//! Rides upstream's URL-scheme plumbing (scheme renamed by boring/rebrand.py).
//! The key is never logged.

const SCHEME: &str = "boringremote://";

/// The License key from an activate link, or None for anything else: another host,
/// a path, a missing/empty key, extra params, or a key outside `[A-Za-z0-9-]{8,64}`.
pub fn parse(url: &str) -> Option<String> {
    let url = url.trim();
    let rest = url.get(..SCHEME.len()).filter(|s| s.eq_ignore_ascii_case(SCHEME)).map(|_| &url[SCHEME.len()..])?;
    let (host, query) = rest.split_once('?')?;
    if !host.eq_ignore_ascii_case("activate") && !host.eq_ignore_ascii_case("activate/") {
        return None;
    }
    let key = query.strip_prefix("key=")?.trim();
    let sane = (8..=64).contains(&key.len()) && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    sane.then(|| key.to_owned())
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn good_link_gives_the_key() {
        assert_eq!(parse("boringremote://activate?key=BLL-AB12-CD34-EF56").as_deref(), Some("BLL-AB12-CD34-EF56"));
    }

    #[test]
    fn trailing_slash_and_case_are_fine() {
        assert_eq!(parse(" BoringRemote://activate/?key=BLL-AB12-CD34-EF56\n").as_deref(), Some("BLL-AB12-CD34-EF56"));
    }

    #[test]
    fn wrong_host_or_scheme_is_rejected() {
        for u in ["boringremote://connect?key=BLL-AB12-CD34-EF56", "boringremote://activatex?key=BLL-AB12-CD34-EF56",
                  "rustdesk://activate?key=BLL-AB12-CD34-EF56", "https://activate?key=BLL-AB12-CD34-EF56",
                  "boringremote://activate/extra?key=BLL-AB12-CD34-EF56", "boringremote://evil@activate?key=BLL-AB12-CD34-EF56"] {
            assert_eq!(parse(u), None, "{u}");
        }
    }

    #[test]
    fn missing_or_empty_key_is_rejected() {
        for u in ["boringremote://activate", "boringremote://activate?", "boringremote://activate?key=",
                  "boringremote://activate?license=BLL-AB12-CD34-EF56", "boringremote://activate?key=short"] {
            assert_eq!(parse(u), None, "{u}");
        }
    }

    #[test]
    fn extra_junk_is_rejected() {
        for u in ["boringremote://activate?key=BLL-AB12-CD34-EF56&x=1", "boringremote://activate?key=BLL-AB12-CD34-EF56#frag",
                  "boringremote://activate?x=1&key=BLL-AB12-CD34-EF56", "boringremote://activate?key=BLL-AB12-CD34-EF56&key=OTHER-KEY1"] {
            assert_eq!(parse(u), None, "{u}");
        }
    }

    #[test]
    fn injection_ish_keys_are_rejected() {
        let long = "A".repeat(65);
        for k in ["BLL-AB12%0Arm -rf", "BLL-AB12;rm -rf /", "BLL-AB12\"},{\"x", "../../etc/passwd", "BLL-AB12 CD34",
                  "BLL-ÄB12-CD34-EF56", long.as_str()] {
            assert_eq!(parse(&format!("boringremote://activate?key={k}")), None, "{k}");
        }
    }
}
