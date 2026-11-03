//! Save a support file (v1.7 ticket 20) and crash files.
//!
//! One zip on the Desktop, "Boring Remote support <date>.zip": the last three days of logs from
//! every Boring Remote process (client, server, cm, service), any crash files, redacted config
//! and an info.txt the caller fills (version, OS, displays, codecs, Access rows). Nothing leaves
//! the computer; there is no upload yet. Secrets never go in: passwords, salts, the key pair,
//! trust tokens and pinned keys are removed by name, and IDs are hashed, in config and logs alike.
//!
//! A Rust panic writes crash-<time>.txt with a backtrace into that process's log folder. The next
//! launch sees it (or a macOS / Windows crash report newer than the last one shown) and offers
//! the support file once.

use hbb_common::{
    chrono::{DateTime, Datelike, Local, Timelike},
    config::{Config, LocalConfig},
    log,
    serde_json::{self, Value as Json},
    sha2::{Digest, Sha256},
    toml::{self, Value},
    ResultType,
};
use std::{
    convert::TryFrom,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// LocalConfig: the newest crash (seconds since 1970) the notice already offered.
pub const SEEN_OPTION: &str = "boring-crash-seen";
pub const KEEP_DAYS: u64 = 3;
pub const ZIP_PREFIX: &str = "Boring Remote support";
pub const CRASH_PREFIX: &str = "crash-";
const REMOVED: &str = "(removed)";
/// Values dropped by key name, wherever they sit in a config file. The key stays, so the file
/// still shows the setting exists.
pub const SECRET_KEYS: &[&str] = &[
    "password",
    "salt",
    "key_pair",
    "enc_id",
    "trusted_devices",
    "boring-trust-tokens",
    "boring-license-key",
];
/// Key names that mean a secret whatever else they say ("access_token", "permanent-password").
const SECRET_WORDS: &[&str] = &["password", "token", "secret", "salt", "private"];
/// Logs past this (newest first) are left out, so the zip stays a size people can send.
const MAX_LOG_BYTES: u64 = 200 * 1024 * 1024;

/// "id-" and the first 10 hex of the ID's SHA-256: the same ID reads the same everywhere in the
/// file, so a support reader can follow it without seeing it.
pub fn hash_id(id: &str) -> String {
    let d = Sha256::digest(id.trim().as_bytes());
    let h: String = d.iter().map(|b| format!("{:02x}", b)).collect();
    format!("id-{}", &h[..10])
}

fn is_secret(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    SECRET_KEYS.contains(&k.as_str()) || SECRET_WORDS.iter().any(|w| k.contains(w))
}

/// A JSON-valued option with secrets inside: keep its shape and names, drop the secrets.
/// boring-trusted-controllers: [{key, name, ...}] keeps name. boring-direct-link-known:
/// {id: {pk, lan, tailscale}} hashes the ID and drops pk.
fn redact_json_option(key: &str, value: &str) -> Option<String> {
    let mut v: Json = serde_json::from_str(value).ok()?;
    match key {
        "boring-trusted-controllers" => {
            for c in v.as_array_mut()? {
                if let Some(o) = c.as_object_mut() {
                    if o.contains_key("key") {
                        o.insert("key".into(), Json::String(REMOVED.into()));
                    }
                }
            }
        }
        "boring-direct-link-known" => {
            let o = v.as_object()?;
            let mut out = serde_json::Map::new();
            for (id, t) in o {
                let mut t = t.clone();
                if let Some(t) = t.as_object_mut() {
                    if t.contains_key("pk") {
                        t.insert("pk".into(), Json::String(REMOVED.into()));
                    }
                }
                out.insert(hash_id(id), t);
            }
            v = Json::Object(out);
        }
        _ => return None,
    }
    serde_json::to_string(&v).ok()
}

fn redact_value(key: &str, v: &mut Value) {
    if is_secret(key) {
        *v = Value::String(REMOVED.into());
        return;
    }
    if key == "id" {
        if let Value::String(s) = v {
            if !s.is_empty() {
                *s = hash_id(s);
            }
        }
        return;
    }
    match v {
        Value::Table(t) => {
            for (k, v) in t.iter_mut() {
                redact_value(k, v);
            }
        }
        Value::Array(a) => {
            for v in a.iter_mut() {
                redact_value("", v);
            }
        }
        Value::String(s) => {
            if let Some(r) = redact_json_option(key, s) {
                *s = r;
            } else if key == "boring-trusted-controllers" || key == "boring-direct-link-known" {
                *s = REMOVED.into(); // unreadable: say nothing rather than guess
            }
        }
        _ => {}
    }
}

/// A config file with every secret removed and IDs hashed. A file that does not parse is left
/// out entirely rather than copied raw.
pub fn redact_toml(text: &str) -> String {
    match text.parse::<Value>() {
        Ok(mut v) => {
            redact_value("", &mut v);
            toml::to_string(&v).unwrap_or_else(|_| "# could not write this file out\n".into())
        }
        Err(_) => "# could not read this file, so it was left out\n".into(),
    }
}

/// Log text with each of `ids` replaced by its hash (ignores IDs too short to be one).
pub fn scrub_ids(text: &str, ids: &[String]) -> String {
    let mut out = text.to_owned();
    for id in ids.iter().map(|s| s.trim()).filter(|s| s.len() >= 6) {
        out = out.replace(id, &hash_id(id));
    }
    out
}

// --- zip (stored, no compression: stdlib only, readable by Finder and Explorer) ------------

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (!(crc & 1)).wrapping_add(1));
        }
    }
    !crc
}

fn dos_time(t: SystemTime) -> (u16, u16) {
    let d: DateTime<Local> = t.into();
    if d.year() < 1980 {
        return (0, (1 << 5) | 1);
    }
    let time = ((d.hour() as u16) << 11) | ((d.minute() as u16) << 5) | (d.second() as u16 / 2);
    let date = (((d.year() - 1980) as u16) << 9) | ((d.month() as u16) << 5) | d.day() as u16;
    (time, date)
}

struct Entry {
    name: String,
    crc: u32,
    size: u32,
    offset: u32,
    time: (u16, u16),
}

pub struct Zip<W: Write> {
    out: W,
    at: u64,
    entries: Vec<Entry>,
}

impl<W: Write> Zip<W> {
    pub fn new(out: W) -> Self {
        Zip { out, at: 0, entries: Vec::new() }
    }

    fn put(&mut self, b: &[u8]) -> io::Result<()> {
        self.out.write_all(b)?;
        self.at += b.len() as u64;
        Ok(())
    }

    pub fn add(&mut self, name: &str, data: &[u8], modified: SystemTime) -> io::Result<()> {
        let too_big = || io::Error::new(io::ErrorKind::Other, "support file over 4 GB");
        let size = u32::try_from(data.len()).map_err(|_| too_big())?;
        let offset = u32::try_from(self.at).map_err(|_| too_big())?;
        let e = Entry { name: name.to_owned(), crc: crc32(data), size, offset, time: dos_time(modified) };
        let mut h = Vec::with_capacity(30 + name.len());
        h.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        h.extend_from_slice(&20u16.to_le_bytes()); // version needed
        h.extend_from_slice(&0x0800u16.to_le_bytes()); // names are UTF-8
        h.extend_from_slice(&0u16.to_le_bytes()); // stored
        h.extend_from_slice(&e.time.0.to_le_bytes());
        h.extend_from_slice(&e.time.1.to_le_bytes());
        h.extend_from_slice(&e.crc.to_le_bytes());
        h.extend_from_slice(&size.to_le_bytes());
        h.extend_from_slice(&size.to_le_bytes());
        h.extend_from_slice(&(name.len() as u16).to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        h.extend_from_slice(name.as_bytes());
        self.put(&h)?;
        self.put(data)?;
        self.entries.push(e);
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<W> {
        let start = self.at;
        let mut cd = Vec::new();
        for e in &self.entries {
            cd.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            cd.extend_from_slice(&20u16.to_le_bytes()); // made by
            cd.extend_from_slice(&20u16.to_le_bytes()); // needed
            cd.extend_from_slice(&0x0800u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&e.time.0.to_le_bytes());
            cd.extend_from_slice(&e.time.1.to_le_bytes());
            cd.extend_from_slice(&e.crc.to_le_bytes());
            cd.extend_from_slice(&e.size.to_le_bytes());
            cd.extend_from_slice(&e.size.to_le_bytes());
            cd.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&[0; 12]); // extra, comment, disk, internal and external attrs
            cd.extend_from_slice(&e.offset.to_le_bytes());
            cd.extend_from_slice(e.name.as_bytes());
        }
        self.put(&cd)?;
        let n = self.entries.len() as u16;
        let mut end = Vec::with_capacity(22);
        end.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        end.extend_from_slice(&[0; 4]);
        end.extend_from_slice(&n.to_le_bytes());
        end.extend_from_slice(&n.to_le_bytes());
        end.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        end.extend_from_slice(&(start as u32).to_le_bytes());
        end.extend_from_slice(&0u16.to_le_bytes());
        self.put(&end)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

// --- what goes in --------------------------------------------------------------------

/// Where this computer keeps what the support file reads. Each folder has a label that becomes
/// its folder in the zip.
#[derive(Debug, Clone, Default)]
pub struct Sources {
    pub logs: Vec<(String, PathBuf)>,
    pub config: Vec<(String, PathBuf)>,
    /// Folders of native crash reports, and the file-name start that marks ours.
    pub crash_reports: Vec<(PathBuf, String)>,
    /// IDs to hash wherever they show up in a log.
    pub ids: Vec<String>,
}

impl Sources {
    /// This computer's: Mac ~/Library/Logs/BoringRemote and ~/Library/Preferences/<org>.BoringRemote;
    /// Windows %APPDATA%\BoringRemote\{log,config} and the service's under LocalService.
    pub fn here() -> Self {
        let app = hbb_common::config::APP_NAME.read().map(|s| s.clone()).unwrap_or_default();
        let mut s = Sources::default();
        s.logs.push(("logs".into(), Config::log_path()));
        if let Some(dir) = Config::file().parent() {
            s.config.push(("config".into(), dir.to_path_buf()));
        }
        #[cfg(windows)]
        {
            let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
            let svc = PathBuf::from(root).join("ServiceProfiles\\LocalService\\AppData\\Roaming").join(&app);
            s.logs.push(("logs-service".into(), svc.join("log")));
            s.config.push(("config-service".into(), svc.join("config")));
            if let Ok(local) = std::env::var("LOCALAPPDATA") {
                s.crash_reports.push((PathBuf::from(local).join("CrashDumps"), app.clone()));
            }
        }
        #[cfg(target_os = "macos")]
        if let Some(home) = hbb_common::directories_next::BaseDirs::new() {
            s.crash_reports.push((home.home_dir().join("Library/Logs/DiagnosticReports"), app.clone()));
        }
        s.ids = vec![Config::get_id()];
        s
    }
}

fn modified(p: &Path) -> Option<SystemTime> {
    fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// Files under `dir` (two folders deep) changed since `since`, newest first.
fn recent_files(dir: &Path, since: SystemTime) -> Vec<(PathBuf, SystemTime)> {
    fn walk(dir: &Path, depth: u8, since: SystemTime, out: &mut Vec<(PathBuf, SystemTime)>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() && depth > 0 {
                walk(&p, depth - 1, since, out);
            } else if ft.is_file() {
                if let Some(m) = modified(&p).filter(|m| *m >= since) {
                    out.push((p, m));
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, 2, since, &mut out);
    out.sort_by(|a, b| b.1.cmp(&a.1));
    out
}

fn zip_name(label: &str, root: &Path, p: &Path) -> String {
    let rel = p.strip_prefix(root).unwrap_or(p);
    let rel: Vec<String> = rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    format!("{}/{}", label, rel.join("/"))
}

fn is_crash_file(p: &Path) -> bool {
    p.file_name().map_or(false, |n| {
        let n = n.to_string_lossy();
        n.starts_with(CRASH_PREFIX) && n.ends_with(".txt")
    })
}

fn native_reports(s: &Sources, since: SystemTime) -> Vec<(PathBuf, SystemTime)> {
    let mut out = Vec::new();
    for (dir, prefix) in &s.crash_reports {
        let Ok(rd) = fs::read_dir(dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if !e.file_name().to_string_lossy().starts_with(prefix.as_str()) {
                continue;
            }
            if let Some(m) = modified(&p).filter(|m| *m >= since) {
                out.push((p, m));
            }
        }
    }
    out
}

/// Write the support file for `s` into `out`. `info` is info.txt, as the caller wrote it.
pub fn write_zip<W: Write>(s: &Sources, info: &str, now: SystemTime, out: W) -> io::Result<W> {
    let since = now.checked_sub(Duration::from_secs(KEEP_DAYS * 86400)).unwrap_or(UNIX_EPOCH);
    let mut zip = Zip::new(out);
    zip.add("info.txt", info.as_bytes(), now)?;
    let mut budget = MAX_LOG_BYTES;
    let mut skipped = 0;
    for (label, root) in &s.logs {
        for (p, m) in recent_files(root, since) {
            let Ok(data) = fs::read(&p) else { continue };
            if (data.len() as u64) > budget && !is_crash_file(&p) {
                skipped += 1;
                continue;
            }
            budget = budget.saturating_sub(data.len() as u64);
            let text = scrub_ids(&String::from_utf8_lossy(&data), &s.ids);
            zip.add(&zip_name(label, root, &p), text.as_bytes(), m)?;
        }
    }
    for (label, root) in &s.config {
        let Ok(rd) = fs::read_dir(root) else { continue };
        let mut files: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| {
            p.is_file() && p.extension().map_or(false, |x| x == "toml")
        }).collect();
        files.sort();
        for p in files {
            let Ok(text) = fs::read_to_string(&p) else { continue };
            let m = modified(&p).unwrap_or(now);
            zip.add(&zip_name(label, root, &p), redact_toml(&text).as_bytes(), m)?;
        }
    }
    for (p, m) in native_reports(s, since) {
        let Ok(data) = fs::read(&p) else { continue };
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        zip.add(&format!("crash-reports/{}", name), &data, m)?;
    }
    if skipped > 0 {
        let note = format!("{} older log files were left out to keep this file small.\n", skipped);
        zip.add("left-out.txt", note.as_bytes(), now)?;
    }
    zip.finish()
}

/// "Boring Remote support 2026-11-03.zip", then "... 2026-11-03 (2).zip" if that is taken.
pub fn zip_path(dir: &Path, now: SystemTime) -> PathBuf {
    let date = DateTime::<Local>::from(now).format("%Y-%m-%d").to_string();
    let mut p = dir.join(format!("{} {}.zip", ZIP_PREFIX, date));
    let mut n = 2;
    while p.exists() {
        p = dir.join(format!("{} {} ({}).zip", ZIP_PREFIX, date, n));
        n += 1;
    }
    p
}

/// info.txt: what the caller knows (version, displays, codecs, Access rows) under a header
/// this module fills (when, OS).
pub fn info_text(now: SystemTime, rows: &[(&str, String)]) -> String {
    use hbb_common::sysinfo::System;
    let when = DateTime::<Local>::from(now).format("%Y-%m-%d %H:%M:%S %z");
    let os = System::new().long_os_version().unwrap_or_default();
    let mut out = format!(
        "Boring Remote support file\nMade: {}\nOS: {} ({} {})\n",
        when,
        os,
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    for (k, v) in rows {
        out.push_str(&format!("\n{}:\n{}\n", k, v.trim_end()));
    }
    out
}

fn desktop() -> PathBuf {
    hbb_common::directories_next::UserDirs::new()
        .and_then(|u| u.desktop_dir().map(Path::to_path_buf))
        .unwrap_or_else(Config::get_home)
}

/// Save the support file on the Desktop. Returns where it went.
pub fn save(rows: &[(&str, String)]) -> ResultType<PathBuf> {
    let now = SystemTime::now();
    let path = zip_path(&desktop(), now);
    let file = io::BufWriter::new(fs::File::create(&path)?);
    if let Err(e) = write_zip(&Sources::here(), &info_text(now, rows), now, file) {
        fs::remove_file(&path).ok();
        return Err(e.into());
    }
    log::info!("support file saved: {}", path.display());
    Ok(path)
}

// --- crashes -------------------------------------------------------------------------

pub fn crash_file_name(when: SystemTime) -> String {
    format!("{}{}.txt", CRASH_PREFIX, DateTime::<Local>::from(when).format("%Y-%m-%d-%H%M%S"))
}

pub fn crash_text(when: SystemTime, version: &str, thread: &str, message: &str, location: &str, backtrace: &str) -> String {
    format!(
        "Boring Remote closed unexpectedly.\nWhen: {}\nVersion: {}\nOS: {} {}\nThread: {}\nPanic: {}\nAt: {}\n\nBacktrace:\n{}\n",
        DateTime::<Local>::from(when).format("%Y-%m-%d %H:%M:%S %z"),
        version,
        std::env::consts::OS,
        std::env::consts::ARCH,
        thread,
        message,
        location,
        backtrace
    )
}

/// Every panic in this process writes a crash file into `dir`, then runs the hook it replaced.
pub fn install_panic_hook_in(dir: PathBuf, version: &str) {
    let version = version.to_owned();
    let before = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let when = SystemTime::now();
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_default();
        let location = info.location().map(|l| l.to_string()).unwrap_or_default();
        let thread = std::thread::current().name().unwrap_or("unnamed").to_owned();
        let bt = std::backtrace::Backtrace::force_capture().to_string();
        let text = crash_text(when, &version, &thread, &message, &location, &bt);
        fs::create_dir_all(&dir).ok();
        match fs::write(dir.join(crash_file_name(when)), text) {
            Ok(()) => log::error!("panic at {}: {} (crash file written)", location, message),
            Err(e) => log::error!("panic at {}: {} (crash file not written: {})", location, message, e),
        }
        before(info);
    }));
}

/// The startup hook: crash files go next to this process's log (`log_name` as init_log names it).
/// Once per process; a second call does nothing.
pub fn install_panic_hook(log_name: &str, version: &str) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let mut dir = Config::log_path();
        if !log_name.is_empty() {
            dir.push(log_name);
        }
        install_panic_hook_in(dir, version);
    });
}

fn secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// The newest crash (ours or a native report) in the last three days, in seconds since 1970.
pub fn newest_crash(s: &Sources, now: SystemTime) -> Option<u64> {
    let since = now.checked_sub(Duration::from_secs(KEEP_DAYS * 86400)).unwrap_or(UNIX_EPOCH);
    let ours = s.logs.iter().flat_map(|(_, root)| recent_files(root, since)).filter(|(p, _)| is_crash_file(p));
    ours.chain(native_reports(s, since)).map(|(_, m)| secs(m)).max()
}

/// True when there is a crash newer than the one the notice last offered (`seen`, "" for none).
pub fn should_offer(newest: Option<u64>, seen: &str) -> bool {
    newest.map_or(false, |n| n > seen.trim().parse::<u64>().unwrap_or(0))
}

/// Home's notice: did Boring Remote close unexpectedly since the notice last showed?
pub fn crash_to_offer() -> bool {
    should_offer(newest_crash(&Sources::here(), SystemTime::now()), &LocalConfig::get_option(SEEN_OPTION))
}

/// The notice was answered (saved or dismissed): don't offer these crashes again.
pub fn crash_offered() {
    if let Some(n) = newest_crash(&Sources::here(), SystemTime::now()) {
        LocalConfig::set_option(SEEN_OPTION.to_owned(), n.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "123456789";

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("boring-support-{}-{}", name, std::process::id()));
        fs::remove_dir_all(&d).ok();
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// The entries of a stored zip, read back through the central directory, each CRC checked.
    fn unzip(b: &[u8]) -> Vec<(String, Vec<u8>)> {
        let u16_at = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]) as usize;
        let u32_at = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) as usize;
        let end = b.len() - 22;
        assert_eq!(u32_at(end), 0x0605_4b50, "end of central directory");
        let (n, mut at) = (u16_at(end + 10), u32_at(end + 16));
        let mut out = Vec::new();
        for _ in 0..n {
            assert_eq!(u32_at(at), 0x0201_4b50);
            let (crc, size, nlen, off) = (u32_at(at + 16), u32_at(at + 20), u16_at(at + 28), u32_at(at + 42));
            let name = String::from_utf8(b[at + 46..at + 46 + nlen].to_vec()).unwrap();
            assert_eq!(u32_at(off), 0x0403_4b50);
            let data_at = off + 30 + u16_at(off + 26) + u16_at(off + 28);
            let data = b[data_at..data_at + size].to_vec();
            assert_eq!(crc32(&data) as usize, crc, "crc of {}", name);
            out.push((name, data));
            at += 46 + nlen;
        }
        out
    }

    fn get<'a>(z: &'a [(String, Vec<u8>)], name: &str) -> &'a str {
        let e = z.iter().find(|(n, _)| n == name).unwrap_or_else(|| panic!("{} missing", name));
        std::str::from_utf8(&e.1).unwrap()
    }

    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn ids_hash_the_same_every_time_and_hide_the_id() {
        let h = hash_id(ID);
        assert_eq!(h, hash_id(ID));
        assert!(h.starts_with("id-") && h.len() == 13, "{}", h);
        assert!(!h.contains(ID));
        assert_ne!(h, hash_id("987654321"));
    }

    #[test]
    fn config_secrets_are_removed_by_name_and_the_id_hashed() {
        let text = format!(
            "id = '{ID}'\nenc_id = 'enc'\npassword = 'hunter2'\nsalt = 'pepper'\nkey_pair = [[1, 2, 3], [4, 5]]\n\
             trusted_devices = 'devs'\n\n[options]\nboring-device-name = 'Front Desk'\n\
             boring-trust-tokens = '{{\"{ID}\":\"00tok\"}}'\nboring-license-key = 'LK-1'\naccess_token = 'tok'\n\
             boring-trusted-controllers = '[{{\"key\":\"hashhash\",\"name\":\"Studio Mac\",\"added\":5}}]'\n\
             boring-direct-link-known = '{{\"{ID}\":{{\"pk\":\"abcdef\",\"lan\":\"10.0.0.2:21118\",\"tailscale\":\"\"}}}}'\n"
        );
        let out = redact_toml(&text);
        for secret in ["hunter2", "pepper", "enc'", "devs", "00tok", "LK-1", "'tok'", "hashhash", "abcdef", ID, "[1, 2, 3]"] {
            assert!(!out.contains(secret), "{} left in:\n{}", secret, out);
        }
        for kept in ["password", "salt", "key_pair", "enc_id", "trusted_devices", "boring-trust-tokens",
                     "Front Desk", "Studio Mac", "10.0.0.2:21118", &hash_id(ID)] {
            assert!(out.contains(kept), "{} missing:\n{}", kept, out);
        }
    }

    #[test]
    fn a_config_file_that_does_not_parse_is_left_out_not_copied() {
        let out = redact_toml("password = 'hunter2\nnot toml");
        assert!(!out.contains("hunter2"));
    }

    #[test]
    fn logs_hash_this_computers_id() {
        let out = scrub_ids(&format!("connected as {ID}, peer {ID}"), &[ID.into(), "".into()]);
        assert!(!out.contains(ID));
        assert_eq!(out.matches(&hash_id(ID)).count(), 2);
    }

    #[test]
    fn the_zip_has_info_recent_logs_from_every_process_redacted_config_and_crash_files() {
        let d = tmp("zip");
        let logs = d.join("Logs");
        for sub in ["", "server", "cm", "flutter_ffi"] {
            fs::create_dir_all(logs.join(sub)).unwrap();
            fs::write(logs.join(sub).join("BoringRemote_rCURRENT.log"), format!("{} log, id {ID}", sub)).unwrap();
        }
        fs::write(logs.join("server").join("crash-2026-11-03-101500.txt"), "Backtrace:\n main").unwrap();
        let old = logs.join("cm").join("BoringRemote_r2026-10-01.log");
        fs::write(&old, "old").unwrap();
        let conf = d.join("Prefs");
        fs::create_dir_all(conf.join("peers")).unwrap();
        fs::write(conf.join("BoringRemote.toml"), format!("id = '{ID}'\npassword = 'hunter2'\n")).unwrap();
        fs::write(conf.join("peers").join("x.toml"), "password = 'peerpw'").unwrap();
        let reports = d.join("DiagnosticReports");
        fs::create_dir_all(&reports).unwrap();
        fs::write(reports.join("BoringRemote-2026-11-03.ips"), "native").unwrap();
        fs::write(reports.join("Safari-2026-11-03.ips"), "not ours").unwrap();
        let s = Sources {
            logs: vec![("logs".into(), logs.clone())],
            config: vec![("config".into(), conf)],
            crash_reports: vec![(reports, "BoringRemote".into())],
            ids: vec![ID.into()],
        };
        // "now" is ten days after the old log was last written
        let now = modified(&old).unwrap() + Duration::from_secs(10 * 86400);
        for p in recent_files(&logs, UNIX_EPOCH) {
            if p.0 != old {
                fs::File::options().write(true).open(&p.0).unwrap().set_modified(now - Duration::from_secs(60)).unwrap();
            }
        }
        fs::File::options().write(true).open(d.join("DiagnosticReports/BoringRemote-2026-11-03.ips")).unwrap()
            .set_modified(now - Duration::from_secs(60)).unwrap();
        let z = unzip(&write_zip(&s, "Version: 1.7.0\n", now, Vec::new()).unwrap());
        let names: Vec<&str> = z.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(get(&z, "info.txt"), "Version: 1.7.0\n");
        for n in ["logs/BoringRemote_rCURRENT.log", "logs/server/BoringRemote_rCURRENT.log",
                  "logs/cm/BoringRemote_rCURRENT.log", "logs/flutter_ffi/BoringRemote_rCURRENT.log",
                  "logs/server/crash-2026-11-03-101500.txt", "config/BoringRemote.toml",
                  "crash-reports/BoringRemote-2026-11-03.ips"] {
            assert!(names.contains(&n), "{} missing from {:?}", n, names);
        }
        assert!(!names.iter().any(|n| n.contains("2026-10-01") || n.contains("Safari") || n.contains("peers")), "{:?}", names);
        let all: String = z.iter().map(|(_, b)| String::from_utf8_lossy(b).into_owned()).collect();
        for secret in [ID, "hunter2", "peerpw"] {
            assert!(!all.contains(secret), "{} in the zip", secret);
        }
        assert!(get(&z, "logs/server/BoringRemote_rCURRENT.log").contains(&hash_id(ID)));
        if Path::new("/usr/bin/unzip").exists() {
            let f = d.join("t.zip");
            fs::write(&f, write_zip(&s, "x", now, Vec::new()).unwrap()).unwrap();
            let r = std::process::Command::new("/usr/bin/unzip").arg("-t").arg(&f).output().unwrap();
            assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stdout));
        }
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn the_file_is_named_for_the_day_and_never_overwrites_one() {
        let d = tmp("name");
        let now = SystemTime::now();
        let date = DateTime::<Local>::from(now).format("%Y-%m-%d").to_string();
        let first = zip_path(&d, now);
        assert_eq!(first.file_name().unwrap().to_string_lossy(), format!("Boring Remote support {}.zip", date));
        fs::write(&first, "").unwrap();
        assert_eq!(zip_path(&d, now).file_name().unwrap().to_string_lossy(),
                   format!("Boring Remote support {} (2).zip", date));
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn info_names_the_os_then_each_row() {
        let t = info_text(SystemTime::now(), &[("Version", "1.7.0".into()), ("Access", "Screen Recording: yes".into())]);
        assert!(t.starts_with("Boring Remote support file\n"));
        assert!(t.contains(&format!("OS: ")) && t.contains(std::env::consts::OS));
        assert!(t.contains("\nVersion:\n1.7.0\n") && t.contains("\nAccess:\nScreen Recording: yes\n"), "{}", t);
    }

    #[test]
    fn a_panic_writes_a_crash_file_with_a_backtrace() {
        let d = tmp("panic");
        install_panic_hook_in(d.clone(), "1.7.0-test");
        let r = std::thread::Builder::new()
            .name("boring-test".into())
            .spawn(|| panic!("boom {}", 7))
            .unwrap()
            .join();
        let _ = std::panic::take_hook(); // back to the default for the other tests
        assert!(r.is_err());
        // only this panic's file: another test failing meanwhile writes its own here too
        let files: Vec<PathBuf> = fs::read_dir(&d).unwrap().flatten().map(|e| e.path())
            .filter(|p| fs::read_to_string(p).map_or(false, |t| t.contains("boom 7"))).collect();
        assert_eq!(files.len(), 1, "{:?}", files);
        assert!(is_crash_file(&files[0]), "{:?}", files[0]);
        let text = fs::read_to_string(&files[0]).unwrap();
        for want in ["Boring Remote closed unexpectedly.", "Version: 1.7.0-test", "Thread: boring-test",
                     "Panic: boom 7", "support.rs", "Backtrace:\n"] {
            assert!(text.contains(want), "{} missing:\n{}", want, text);
        }
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_crash_is_offered_once_and_only_recent_ones() {
        let d = tmp("offer");
        let now = SystemTime::now();
        let s = Sources { logs: vec![("logs".into(), d.clone())], ..Default::default() };
        assert_eq!(newest_crash(&s, now), None);
        fs::write(d.join("BoringRemote_rCURRENT.log"), "not a crash").unwrap();
        assert_eq!(newest_crash(&s, now), None);
        fs::create_dir_all(d.join("server")).unwrap();
        fs::write(d.join("server").join(crash_file_name(now)), "x").unwrap();
        let n = newest_crash(&s, now);
        assert!(n.is_some());
        assert!(should_offer(n, ""));
        assert!(!should_offer(n, &n.unwrap().to_string()));
        assert!(should_offer(n, &(n.unwrap() - 1).to_string()));
        assert!(!should_offer(None, ""));
        // four days later the same crash is too old to bring up
        assert_eq!(newest_crash(&s, now + Duration::from_secs(4 * 86400)), None);
        fs::remove_dir_all(&d).ok();
    }
}
