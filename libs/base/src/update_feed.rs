//! The signed version file (ADR 0003/0004/0007), read per platform. Pure: no network, no keys.
//!
//! Mac reads the top-level keys every 1.6.x client already reads. Windows (v1.7 ticket 12) reads
//! the `windows` entry the release workflow adds; a file without one offers Windows nothing.
//! `min_version` is top level and shared. Shape:
//! `{"version","sha256","url","package_sha256","package_sig","min_version",
//!   "windows":{"version","url","sha256","sig"}}`

/// Where Windows packages may come from. The file is signed, but the URL is pinned anyway.
pub const WINDOWS_DOWNLOADS: &str = "https://boringlabs.online/downloads/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Mac,
    Windows,
}

/// The platform this build reads the file as. Anything but Windows reads the Mac keys.
#[cfg(target_os = "windows")]
pub const THIS: Platform = Platform::Windows;
#[cfg(not(target_os = "windows"))]
pub const THIS: Platform = Platform::Mac;

/// One platform's release from the version file. Missing package fields are "".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    /// "" when the file has none.
    pub min_version: String,
    /// Windows: the MSI to download. Mac: "" (the package comes from fulfillment).
    pub url: String,
    pub package_sha256: String,
    pub package_sig: String,
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
    if it.next().is_none() {
        Some(v)
    } else {
        None
    }
}

/// True only when both are strict X.Y.Z and `remote` is strictly newer, compared as numbers.
pub fn newer(remote: &str, running: &str) -> bool {
    match (parse_semver(remote), parse_semver(running)) {
        (Some(r), Some(l)) => r > l,
        _ => false,
    }
}

/// `platform`'s release from the version file, or None if the file offers it nothing usable:
/// not JSON, a version or min_version that is not strict X.Y.Z, or (Windows) no `windows`
/// entry, or one whose URL is not under [`WINDOWS_DOWNLOADS`] or whose sha256 is not 64 hex.
pub fn release_for(body: &str, platform: Platform) -> Option<Release> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let min_version = match v.get("min_version") {
        None => String::new(),
        Some(m) => {
            let m = m.as_str()?;
            parse_semver(m)?;
            m.to_owned()
        }
    };
    let s = |o: &serde_json::Value, k: &str| o.get(k).and_then(|x| x.as_str()).unwrap_or("").to_owned();
    match platform {
        Platform::Mac => {
            let version = v.get("version")?.as_str()?;
            parse_semver(version)?;
            Some(Release {
                version: version.to_owned(),
                min_version,
                url: String::new(),
                package_sha256: s(&v, "package_sha256"),
                package_sig: s(&v, "package_sig"),
            })
        }
        Platform::Windows => {
            let w = v.get("windows")?;
            let version = w.get("version")?.as_str()?;
            parse_semver(version)?;
            let url = s(w, "url");
            let name = url.strip_prefix(WINDOWS_DOWNLOADS)?;
            if name.is_empty() || name.contains('/') || !name.ends_with(".msi") {
                return None;
            }
            let sha = s(w, "sha256");
            if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            Some(Release {
                version: version.to_owned(),
                min_version,
                url,
                package_sha256: sha,
                package_sig: s(w, "sig"),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12";

    fn both() -> String {
        format!(
            r#"{{"version":"1.7.0","sha256":"d","url":"https://boringlabs.online/downloads/BoringRemote-1.7.0-macos-arm64.dmg","package_sha256":"m","package_sig":"ms","min_version":"1.5.0","windows":{{"version":"1.7.0","url":"https://boringlabs.online/downloads/BoringRemote-1.7.0-windows-x64.msi","sha256":"{SHA}","sig":"ws"}}}}"#
        )
    }

    #[test]
    fn mac_reads_the_top_level_keys_as_before() {
        let r = release_for(&both(), Platform::Mac).unwrap();
        assert_eq!(
            r,
            Release {
                version: "1.7.0".into(),
                min_version: "1.5.0".into(),
                url: "".into(),
                package_sha256: "m".into(),
                package_sig: "ms".into(),
            }
        );
    }

    #[test]
    fn windows_reads_its_own_entry_and_the_shared_min_version() {
        let r = release_for(&both(), Platform::Windows).unwrap();
        assert_eq!(
            r,
            Release {
                version: "1.7.0".into(),
                min_version: "1.5.0".into(),
                url: "https://boringlabs.online/downloads/BoringRemote-1.7.0-windows-x64.msi".into(),
                package_sha256: SHA.into(),
                package_sig: "ws".into(),
            }
        );
    }

    #[test]
    fn a_1_6_file_offers_windows_nothing_and_mac_everything() {
        let old = r#"{"version":"1.6.4","sha256":"d","url":"u","package_sha256":"m","package_sig":"","min_version":"1.5.0"}"#;
        assert_eq!(release_for(old, Platform::Windows), None);
        let mac = release_for(old, Platform::Mac).unwrap();
        assert_eq!((mac.version.as_str(), mac.package_sig.as_str()), ("1.6.4", ""));
    }

    #[test]
    fn mac_keeps_tolerating_extra_keys_and_missing_package_fields() {
        let r = release_for(r#"{"version":"1.2.3","extra":1}"#, Platform::Mac).unwrap();
        assert_eq!((r.min_version.as_str(), r.package_sha256.as_str()), ("", ""));
    }

    #[test]
    fn bad_versions_are_refused_on_both() {
        for bad in [r#"{"version":"1.7"}"#, r#"{"version":"v1.7.0"}"#, r#"{"version":"1.7.0","min_version":"1.5"}"#, "not json"] {
            assert_eq!(release_for(bad, Platform::Mac), None, "{bad}");
        }
        let w = both().replace(r#""windows":{"version":"1.7.0""#, r#""windows":{"version":"1.7.0-rc1""#);
        assert_eq!(release_for(&w, Platform::Windows), None);
    }

    #[test]
    fn windows_refuses_a_url_off_our_downloads_or_not_an_msi() {
        for url in [
            "https://evil.example/BoringRemote.msi",
            "http://boringlabs.online/downloads/BoringRemote-1.7.0-windows-x64.msi",
            "https://boringlabs.online/downloads/sub/BoringRemote.msi",
            "https://boringlabs.online/downloads/BoringRemote-1.7.0-windows-x64.exe",
            "https://boringlabs.online/downloads/",
        ] {
            let body = both().replace("https://boringlabs.online/downloads/BoringRemote-1.7.0-windows-x64.msi", url);
            assert_eq!(release_for(&body, Platform::Windows), None, "{url}");
        }
    }

    #[test]
    fn windows_refuses_a_sha256_that_is_not_64_hex() {
        for sha in ["", "abc", &SHA[1..], SHA.replace('a', "z").as_str()] {
            let body = both().replace(SHA, sha);
            assert_eq!(release_for(&body, Platform::Windows), None, "{sha}");
        }
    }

    #[test]
    fn newer_compares_numbers_not_text() {
        assert!(newer("1.10.0", "1.9.9"));
        assert!(newer("1.7.0", "1.6.4"));
        assert!(newer("2.0.0", "1.99.99"));
        assert!(!newer("1.7.0", "1.7.0"));
        assert!(!newer("1.6.4", "1.7.0"));
        assert!(!newer("1.7", "1.6.0"));
        assert!(!newer("1.7.0", "junk"));
    }

    #[test]
    fn this_build_reads_its_own_platform() {
        assert_eq!(THIS, if cfg!(target_os = "windows") { Platform::Windows } else { Platform::Mac });
    }
}
