//! boring-remote (v1.7 t30): a file transfer proves every file. The sender hashes what it reads, the
//! receiver reads the `.download` back from disk after write and flush, and only a match gets the
//! real name. Hooks into upstream (fs.rs, connection.rs, io_loop.rs, ui_cm_interface.rs, ipc.rs) are
//! patches in boring/rebrand.py.
//!
//! BLAKE3, not XXH3-128: both outrun the link, but BLAKE3 is a cryptographic hash, so "these match"
//! holds against anything, not just random damage, and `b3sum` can check the verify log years later
//! with no code of ours.
//!
//! Protocol files stay upstream's. Everything here rides in `Misc::plugin_request`, an upstream
//! message nothing in the app uses, with our id and JSON inside. A Target says it can in
//! `platform_additions` ([`MARKER`]); a Controller that sees that says [`Wire::Hello`]; neither side
//! sends anything else until then, so an old peer never sees one of these.

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    io::Read,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    time::SystemTime,
};

use crate::{
    fs::{self, TransferJob},
    message_proto::*,
};
use hbb_common::config::Config;
use serde_derive::{Deserialize, Serialize};

/// Added to the Target's `platform_additions`.
pub const MARKER: &str = "boring_verified_files";
/// `PluginRequest.id` of everything here.
pub const WIRE_ID: &str = "boring_verify";
/// What the job says when the other side can't prove anything.
pub const OLD_PEER_WORDS: &str = "Not verified: the other computer needs the latest Boring Remote";
const NO_ANSWER_WORDS: &str = "Not verified: the other computer never confirmed the copy";

/// A file's extended attributes past this travel no further than a line in the job's report. A
/// frame holds about 1 GiB, and this all goes through memory.
const XATTRS_MAX: usize = 64 * 1024 * 1024;
/// Names the job spells out. The verify log has all of them.
const NAMES_SHOWN: usize = 5;
const CHUNK: usize = 4 * 1024 * 1024;
/// Chunks read and not yet hashed.
const READ_AHEAD: usize = 4;

pub fn this_os() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "other"
    }
}

/// PeerInfo's platform name, in this module's words.
pub fn os_from_platform(platform: &str) -> String {
    match platform {
        "Windows" => "windows",
        "Mac OS" => "macos",
        _ => "other",
    }
    .to_string()
}

pub fn peer_says_verified(platform_additions: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(platform_additions)
        .map_or(false, |v| v.get(MARKER).and_then(|k| k.as_bool()) == Some(true))
}

// --- what goes on the wire ------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct Meta {
    pub mode: Option<u32>,
    pub modified: Option<(i64, u32)>,
    pub created: Option<(i64, u32)>,
    /// (name, hex of the value)
    pub xattrs: Vec<(String, String)>,
    /// What the sender couldn't read, for the job's list.
    pub unread: Vec<String>,
    pub windows_hidden: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DirEntry {
    pub path: String,
    pub meta: Meta,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinkEntry {
    pub path: String,
    pub target: String,
    pub to_dir: bool,
    pub modified: Option<(i64, u32)>,
}

/// A name and why, for anything a job couldn't do.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Listed {
    pub name: String,
    pub why: String,
}

impl Listed {
    fn new(name: impl Into<String>, why: impl Into<String>) -> Self {
        Self { name: name.into(), why: why.into() }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum SealKind {
    /// Its bytes were just sent.
    Sent,
    /// Not sent: already there, or the person said to keep what's there. Compare what's there.
    Skipped,
    /// From before a job's resume. Compare what's there, resend if it's wrong.
    Resumed,
    /// The sender gave up on it: `why`.
    Failed,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Seal {
    pub id: i32,
    pub file_num: i32,
    pub kind: SealKind,
    pub size: u64,
    pub hash: String,
    pub meta: Meta,
    pub why: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Wire {
    Hello { os: String },
    /// Connection to its CM: this new read job's peer can verify.
    StartRead { id: i32, os: String },
    /// First thing in a job. What a file list can't carry.
    Manifest {
        id: i32,
        os: String,
        dirs: Vec<DirEntry>,
        links: Vec<LinkEntry>,
        listed: Vec<Listed>,
    },
    Seal(Seal),
    Verdict { id: i32, file_num: i32, ok: bool, why: String, size: u64, hash: String },
    Report { id: i32, report: Report },
}

impl Wire {
    pub fn job_id(&self) -> Option<i32> {
        match self {
            Wire::Hello { .. } => None,
            Wire::StartRead { id, .. }
            | Wire::Manifest { id, .. }
            | Wire::Verdict { id, .. }
            | Wire::Report { id, .. } => Some(*id),
            Wire::Seal(s) => Some(s.id),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn from_json(s: &[u8]) -> Option<Self> {
        serde_json::from_slice(s).ok()
    }

    pub fn to_message(&self) -> Message {
        let mut misc = Misc::new();
        misc.set_plugin_request(PluginRequest {
            id: WIRE_ID.to_string(),
            content: self.to_json().into_bytes().into(),
            ..Default::default()
        });
        let mut msg = Message::new();
        msg.set_misc(misc);
        msg
    }
}

// --- what the job says ----------------------------------------------------------------------

/// One job's outcome. The receiver writes it, since it's the one that read the files back.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct Report {
    pub files: usize,
    pub verified: usize,
    pub bytes: u64,
    pub folders: usize,
    pub failed: Vec<Listed>,
    pub skipped: Vec<Listed>,
    /// Links, folders and unreadable things that didn't come across.
    pub not_copied: Vec<Listed>,
    /// Came across, but without this.
    pub not_kept: Vec<Listed>,
}

fn size_words(bytes: u64) -> String {
    let b = bytes as f64;
    if b >= 1e12 {
        format!("{:.1} TB", b / 1e12)
    } else if b >= 1e9 {
        format!("{:.1} GB", b / 1e9)
    } else if b >= 1e6 {
        format!("{:.1} MB", b / 1e6)
    } else if b >= 1e3 {
        format!("{:.0} KB", b / 1e3)
    } else {
        format!("{} bytes", bytes)
    }
}

fn files_words(n: usize) -> String {
    format!("{} file{}", n, if n == 1 { "" } else { "s" })
}

fn names_words(items: &[Listed]) -> String {
    let mut out: Vec<String> = items
        .iter()
        .take(NAMES_SHOWN)
        .map(|i| if i.why.is_empty() { i.name.clone() } else { format!("{} ({})", i.name, i.why) })
        .collect();
    if items.len() > NAMES_SHOWN {
        out.push(format!("and {} more, all in the verify log", items.len() - NAMES_SHOWN));
    }
    out.join(", ")
}

impl Report {
    /// The only way to the word Verified: every file on the list passed.
    pub fn all_passed(&self) -> bool {
        self.failed.is_empty() && self.skipped.is_empty() && self.verified == self.files
    }

    pub fn words(&self) -> String {
        let mut out = if self.all_passed() {
            if self.files == 0 {
                format!("Verified: {} folder{}", self.folders, if self.folders == 1 { "" } else { "s" })
            } else {
                format!("Verified: {}, {}", files_words(self.files), size_words(self.bytes))
            }
        } else {
            let mut parts = Vec::new();
            if !self.failed.is_empty() {
                parts.push(format!(
                    "{} of {} failed: {}",
                    self.failed.len(),
                    files_words(self.files),
                    names_words(&self.failed)
                ));
            }
            if !self.skipped.is_empty() {
                parts.push(format!(
                    "{} of {} skipped: {}",
                    self.skipped.len(),
                    files_words(self.files),
                    names_words(&self.skipped)
                ));
            }
            let mut s = format!("Not verified: {}", parts.join(". "));
            s.push_str(&format!(". {} proved, {}", self.verified, size_words(self.bytes)));
            s
        };
        if !self.not_copied.is_empty() {
            out.push_str(&format!(". Not copied: {}", names_words(&self.not_copied)));
        }
        if !self.not_kept.is_empty() {
            out.push_str(&format!(". Couldn't keep: {}", names_words(&self.not_kept)));
        }
        out
    }
}

/// What the Controller's job says. `report` is the receiver's, from whichever side that was.
pub fn job_words(report: Option<&Report>, peer_can_verify: bool) -> String {
    match report {
        Some(r) => r.words(),
        None if peer_can_verify => NO_ANSWER_WORDS.to_string(),
        None => OLD_PEER_WORDS.to_string(),
    }
}

// --- the verify log -------------------------------------------------------------------------

lazy_static::lazy_static! {
    static ref LOG_OVERRIDE: Mutex<Option<PathBuf>> = Mutex::new(None);
    static ref LOG_LOCK: Mutex<()> = Mutex::new(());
}

/// For a bench or a test, so it doesn't write into the app's log folder.
pub fn set_log_path(path: PathBuf) {
    *LOG_OVERRIDE.lock().unwrap() = Some(path);
}

pub fn log_path() -> PathBuf {
    if let Some(p) = LOG_OVERRIDE.lock().unwrap().clone() {
        return p;
    }
    Config::log_path().join("verify.log")
}

/// One line per file, tab-separated: when, what happened, size, hash, path, why.
fn log_line(status: &str, size: u64, hash: &str, path: &str, why: &str) {
    use std::io::Write;
    let line = format!(
        "{}\t{}\t{}\tblake3:{}\t{}\t{}\n",
        hbb_common::chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
        status,
        size,
        hash,
        path.replace(['\t', '\n'], " "),
        why.replace(['\t', '\n'], " ")
    );
    let _guard = LOG_LOCK.lock().unwrap();
    let path = log_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    match std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        Ok(mut f) => {
            if let Err(err) = f.write_all(line.as_bytes()) {
                log::error!("verify log {:?}: {}", path, err);
            }
        }
        Err(err) => log::error!("verify log {:?}: {}", path, err),
    }
}

// --- metadata -------------------------------------------------------------------------------

fn to_parts(t: std::io::Result<SystemTime>) -> Option<(i64, u32)> {
    let t = t.ok()?;
    match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => Some((d.as_secs() as i64, d.subsec_nanos())),
        Err(e) => {
            let d = e.duration();
            // Before 1970: whole seconds round towards the past, nanos stay positive.
            let (s, n) = (d.as_secs() as i64, d.subsec_nanos());
            Some(if n == 0 { (-s, 0) } else { (-s - 1, 1_000_000_000 - n) })
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(target_os = "macos")]
mod mac {
    use super::*;
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    /// Quarantine stays behind, as the ticket asks. Provenance is the system's own record of which
    /// app wrote a file: it isn't content, and it can't be set.
    pub const LEFT_BEHIND: &[&str] = &["com.apple.quarantine", "com.apple.provenance"];

    fn c_path(path: &Path) -> Option<CString> {
        CString::new(path.as_os_str().as_bytes()).ok()
    }

    pub fn read_xattrs(path: &Path, meta: &mut Meta) {
        let Some(p) = c_path(path) else { return };
        let len = unsafe { libc::listxattr(p.as_ptr(), std::ptr::null_mut(), 0, libc::XATTR_NOFOLLOW) };
        if len <= 0 {
            return;
        }
        let mut names = vec![0u8; len as usize];
        let len = unsafe {
            libc::listxattr(p.as_ptr(), names.as_mut_ptr() as *mut _, names.len(), libc::XATTR_NOFOLLOW)
        };
        if len <= 0 {
            return;
        }
        let mut total = 0;
        for name in names[..len as usize].split(|b| *b == 0).filter(|n| !n.is_empty()) {
            let text = String::from_utf8_lossy(name).to_string();
            if LEFT_BEHIND.contains(&text.as_str()) {
                continue;
            }
            let Ok(c_name) = CString::new(name) else { continue };
            let got = unsafe {
                libc::getxattr(p.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0, 0, libc::XATTR_NOFOLLOW)
            };
            if got < 0 {
                meta.unread.push(text);
                continue;
            }
            total += got as usize;
            if total > XATTRS_MAX {
                meta.unread.push(text);
                continue;
            }
            let mut value = vec![0u8; got as usize];
            let got = unsafe {
                libc::getxattr(
                    p.as_ptr(),
                    c_name.as_ptr(),
                    value.as_mut_ptr() as *mut _,
                    value.len(),
                    0,
                    libc::XATTR_NOFOLLOW,
                )
            };
            if got < 0 {
                meta.unread.push(text);
                continue;
            }
            value.truncate(got as usize);
            meta.xattrs.push((text, super::hex(&value)));
        }
    }

    /// Writes each one and reads it back. Returns the names that didn't stick.
    pub fn write_xattrs(path: &Path, xattrs: &[(String, String)]) -> Vec<String> {
        let mut failed = Vec::new();
        let Some(p) = c_path(path) else {
            return xattrs.iter().map(|x| x.0.clone()).collect();
        };
        for (name, value) in xattrs {
            if LEFT_BEHIND.contains(&name.as_str()) {
                continue;
            }
            let (Ok(c_name), Some(value)) = (CString::new(name.as_str()), unhex(value)) else {
                failed.push(name.clone());
                continue;
            };
            let res = unsafe {
                libc::setxattr(p.as_ptr(), c_name.as_ptr(), value.as_ptr() as *const _, value.len(), 0, 0)
            };
            let mut back = vec![0u8; value.len()];
            let got = unsafe {
                libc::getxattr(p.as_ptr(), c_name.as_ptr(), back.as_mut_ptr() as *mut _, back.len(), 0, 0)
            };
            if res != 0 || got != value.len() as isize || back != value {
                failed.push(name.clone());
            }
        }
        failed
    }

    /// `setattrlist` is the only way to the created date.
    pub fn set_created(path: &Path, created: (i64, u32)) -> bool {
        let Some(p) = c_path(path) else { return false };
        let mut attrs: libc::attrlist = unsafe { std::mem::zeroed() };
        attrs.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
        attrs.commonattr = libc::ATTR_CMN_CRTIME;
        let mut time = libc::timespec { tv_sec: created.0 as _, tv_nsec: created.1 as _ };
        let res = unsafe {
            libc::setattrlist(
                p.as_ptr(),
                &mut attrs as *mut _ as *mut _,
                &mut time as *mut _ as *mut _,
                std::mem::size_of::<libc::timespec>(),
                libc::FSOPT_NOFOLLOW as _,
            )
        };
        res == 0
    }

    /// Reads from the disk, not the system's copy of what was just written: `msync` drops the
    /// cached pages and `F_NOCACHE` keeps this read from adding them back.
    pub fn drop_cached(file: &std::fs::File) {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        let len = file.metadata().map_or(0, |m| m.len()) as usize;
        unsafe {
            if len > 0 {
                let map = libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ, libc::MAP_SHARED, fd, 0);
                if map != libc::MAP_FAILED {
                    libc::msync(map, len, libc::MS_SYNC | libc::MS_INVALIDATE);
                    libc::munmap(map, len);
                }
            }
            libc::fcntl(fd, libc::F_NOCACHE, 1);
        }
    }
}

#[cfg(windows)]
mod win {
    use std::{
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
        path::Path,
    };

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    pub const FILE_FLAG_NO_BUFFERING: u32 = 0x2000_0000;

    /// 100 ns ticks since 1601, which is what Windows keeps a date in.
    pub fn set_created(path: &Path, created: (i64, u32)) -> bool {
        let Ok(f) = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
        else {
            return false;
        };
        let ticks = ((created.0 + 11_644_473_600) as u64) * 10_000_000 + (created.1 as u64) / 100;
        let time = winapi::shared::minwindef::FILETIME {
            dwLowDateTime: ticks as u32,
            dwHighDateTime: (ticks >> 32) as u32,
        };
        unsafe {
            winapi::um::fileapi::SetFileTime(
                f.as_raw_handle() as _,
                &time,
                std::ptr::null(),
                std::ptr::null(),
            ) != 0
        }
    }
}

/// What a file or folder is like, apart from its bytes.
pub fn capture_meta(path: &Path) -> Meta {
    let mut meta = Meta::default();
    let Ok(m) = std::fs::symlink_metadata(path) else {
        return meta;
    };
    meta.modified = to_parts(m.modified());
    meta.created = to_parts(m.created());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.mode = Some(m.permissions().mode() & 0o7777);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        meta.windows_hidden = m.file_attributes() & 0x2 != 0;
    }
    #[cfg(target_os = "macos")]
    mac::read_xattrs(path, &mut meta);
    meta
}

/// Before the real name: extended attributes and permissions, in that order, since a read-only
/// mode would stop the attributes. Returns what didn't stick.
fn apply_contents_meta(path: &Path, meta: &Meta, peer_os: &str) -> Vec<String> {
    let mut lost: Vec<String> = meta.unread.iter().map(|x| format!("attribute {} (couldn't read it)", x)).collect();
    #[cfg(target_os = "macos")]
    for name in mac::write_xattrs(path, &meta.xattrs) {
        lost.push(format!("attribute {}", name));
    }
    #[cfg(not(target_os = "macos"))]
    if !meta.xattrs.is_empty() {
        lost.push("Finder tags, comments and other Mac attributes".to_string());
    }
    #[cfg(unix)]
    if let Some(mode) = meta.mode {
        use std::os::unix::fs::PermissionsExt;
        // Setuid and friends don't cross machines: they'd run as someone they were never given to.
        if mode & 0o7000 != 0 {
            lost.push("setuid, setgid or sticky bit".to_string());
        }
        if std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o777)).is_err() {
            lost.push("permissions".to_string());
        }
    }
    #[cfg(unix)]
    if meta.windows_hidden {
        lost.push("Windows hidden flag".to_string());
    }
    #[cfg(windows)]
    if peer_os != "windows" && meta.mode.is_some() {
        lost.push("permissions".to_string());
    }
    let _ = (path, peer_os);
    lost
}

/// Last of all, since writing inside a folder or renaming moves a date.
fn apply_times(path: &Path, meta: &Meta) -> Vec<String> {
    let mut lost = Vec::new();
    if let Some((s, n)) = meta.modified {
        if filetime::set_file_mtime(path, filetime::FileTime::from_unix_time(s, n)).is_err() {
            lost.push("modified date".to_string());
        }
    }
    #[cfg(target_os = "macos")]
    if let Some(created) = meta.created {
        if !mac::set_created(path, created) {
            lost.push("created date".to_string());
        }
    }
    #[cfg(windows)]
    if let Some(created) = meta.created {
        if !win::set_created(path, created) {
            lost.push("created date".to_string());
        }
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    let _ = meta.created;
    lost
}

// --- names and listing ----------------------------------------------------------------------

/// Why Windows wouldn't take this relative name, if it wouldn't. Reported, never rewritten.
pub fn illegal_on_windows(name: &str) -> Option<String> {
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1",
        "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    for part in name.split('/').filter(|p| !p.is_empty()) {
        if part.chars().any(|c| "<>:\"|?*\\".contains(c) || (c as u32) < 32) {
            return Some("this name isn't allowed on Windows".to_string());
        }
        if part.ends_with('.') || part.ends_with(' ') {
            return Some("Windows doesn't allow a name ending in a dot or a space".to_string());
        }
        let stem = part.split('.').next().unwrap_or(part).to_ascii_uppercase();
        if RESERVED.contains(&stem.as_str()) {
            return Some("this name is reserved on Windows".to_string());
        }
    }
    None
}

fn rel_string(rel: &Path) -> String {
    rel.to_string_lossy().replace('\\', "/")
}

/// Everything a file list can't carry, from one walk of the source.
#[derive(Default, Debug)]
pub struct Walk {
    pub dirs: Vec<DirEntry>,
    pub links: Vec<LinkEntry>,
    pub listed: Vec<Listed>,
    /// Names on the file list that aren't regular files. Reading a fifo would hang.
    pub not_files: HashMap<String, String>,
}

fn walk_dir(path: &Path, rel: &Path, out: &mut Walk) {
    out.dirs.push(DirEntry { path: rel_string(rel), meta: capture_meta(path) });
    let entries = match std::fs::read_dir(path) {
        Ok(e) => e,
        Err(err) => {
            let shown = if rel.as_os_str().is_empty() { path.to_string_lossy().to_string() } else { rel_string(rel) };
            out.listed.push(Listed::new(shown, format!("couldn't read this folder: {}", err)));
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(err) => {
                out.listed.push(Listed::new(rel_string(rel), format!("couldn't read this folder: {}", err)));
                continue;
            }
        };
        let name = entry.file_name();
        let child = path.join(&name);
        let child_rel = rel.join(&name);
        if name.to_str().is_none() {
            // The engine's list drops these, since names travel as text.
            out.listed.push(Listed::new(child_rel.to_string_lossy(), "this name isn't valid text"));
            continue;
        }
        let meta = match std::fs::symlink_metadata(&child) {
            Ok(m) => m,
            Err(err) => {
                out.listed.push(Listed::new(rel_string(&child_rel), format!("couldn't read it: {}", err)));
                continue;
            }
        };
        let kind = meta.file_type();
        if kind.is_symlink() {
            match std::fs::read_link(&child) {
                Ok(target) => out.links.push(LinkEntry {
                    path: rel_string(&child_rel),
                    target: target.to_string_lossy().to_string(),
                    to_dir: child.is_dir(),
                    modified: to_parts(meta.modified()),
                }),
                Err(err) => out.listed.push(Listed::new(rel_string(&child_rel), format!("couldn't read this link: {}", err))),
            }
        } else if kind.is_dir() {
            walk_dir(&child, &child_rel, out);
        } else if !kind.is_file() {
            out.not_files.insert(rel_string(&child_rel), "not a regular file".to_string());
        }
    }
}

pub fn walk(root: &Path) -> Walk {
    let mut out = Walk::default();
    if root.is_dir() {
        walk_dir(root, Path::new(""), &mut out);
    } else if let Ok(m) = std::fs::metadata(root) {
        if !m.is_file() {
            out.not_files.insert(String::new(), "not a regular file".to_string());
        }
    }
    out
}

// --- free space -----------------------------------------------------------------------------

fn free_space(path: &Path) -> Option<u64> {
    let mut at = Some(path);
    while let Some(p) = at {
        if p.exists() {
            return free_space_at(p);
        }
        at = p.parent();
    }
    None
}

#[cfg(unix)]
fn free_space_at(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    Some(s.f_bavail as u64 * s.f_frsize as u64)
}

#[cfg(windows)]
fn free_space_at(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut free: winapi::shared::ntdef::ULARGE_INTEGER = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        winapi::um::fileapi::GetDiskFreeSpaceExW(wide.as_ptr(), &mut free, std::ptr::null_mut(), std::ptr::null_mut())
    };
    if ok == 0 {
        return None;
    }
    Some(unsafe { *free.QuadPart() })
}

#[cfg(not(any(unix, windows)))]
fn free_space_at(_path: &Path) -> Option<u64> {
    None
}

/// The message if `need` bytes won't fit. An unknown answer doesn't stop a job.
pub fn room_for(dest: &Path, need: u64) -> Result<(), String> {
    match free_space(dest) {
        Some(free) if free < need => Err(format!(
            "Not enough room: this needs {} and {} is free",
            size_words(need),
            size_words(free)
        )),
        _ => Ok(()),
    }
}

/// Before a write job starts. What's already in a `.download` from an interrupted run doesn't count.
pub fn check_room(job: &TransferJob) -> Result<(), String> {
    let fs::DataSource::FilePath(base) = &job.data_source else {
        return Ok(());
    };
    let partial: u64 = job
        .files()
        .iter()
        .map(|f| {
            let path = TransferJob::join(base, &f.name);
            std::fs::metadata(format!("{}.download", path.to_string_lossy())).map_or(0, |m| m.len())
        })
        .sum();
    room_for(base, job.total_size().saturating_sub(partial))
}

// --- reading a file back --------------------------------------------------------------------

/// Read back from the disk. This thread reads and another hashes, since the two together are the
/// slowest part of a job: 411 MiB/s on one thread on the T9, against 678 for its read alone. Every
/// read checks `cancel`.
pub fn hash_from_disk(path: &Path, cancel: &AtomicBool) -> std::io::Result<(u64, String)> {
    let mut file = open_for_read_back(path)?;
    let (full_tx, full_rx) = mpsc::sync_channel::<(Vec<u8>, usize, usize)>(READ_AHEAD);
    let (empty_tx, empty_rx) = mpsc::channel::<(Vec<u8>, usize)>();
    for _ in 0..READ_AHEAD + 1 {
        // Windows' unbuffered read takes an address on a sector boundary.
        let raw = vec![0u8; CHUNK + 4096];
        let start = raw.as_ptr().align_offset(4096);
        empty_tx.send((raw, start)).ok();
    }
    std::thread::scope(|scope| {
        let hashing = scope.spawn(move || {
            let mut hasher = blake3::Hasher::new();
            let mut size = 0u64;
            while let Ok((raw, start, n)) = full_rx.recv() {
                hasher.update(&raw[start..start + n]);
                size += n as u64;
                empty_tx.send((raw, start)).ok();
            }
            (size, hasher.finalize().to_hex().to_string())
        });
        let mut failed = None;
        while let Ok((mut raw, start)) = empty_rx.recv() {
            if cancel.load(Ordering::Relaxed) {
                failed = Some(std::io::Error::new(std::io::ErrorKind::Interrupted, "cancelled"));
                break;
            }
            let n = match read_retrying(&mut file, &mut raw[start..start + CHUNK]) {
                Ok(n) => n,
                Err(err) => {
                    failed = Some(err);
                    break;
                }
            };
            if n == 0 {
                break;
            }
            if full_tx.send((raw, start, n)).is_err() {
                break;
            }
        }
        drop(full_tx);
        let done = hashing.join().map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "the hash stopped"))?;
        match failed {
            Some(err) => Err(err),
            None => Ok(done),
        }
    })
}

fn read_retrying(file: &mut std::fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        match file.read(buf) {
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            res => return res,
        }
    }
}

#[cfg(target_os = "macos")]
fn open_for_read_back(path: &Path) -> std::io::Result<std::fs::File> {
    let file = std::fs::File::open(path)?;
    mac::drop_cached(&file);
    Ok(file)
}

#[cfg(windows)]
fn open_for_read_back(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().read(true).custom_flags(win::FILE_FLAG_NO_BUFFERING).open(path)
}

#[cfg(not(any(target_os = "macos", windows)))]
fn open_for_read_back(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

#[cfg(test)]
lazy_static::lazy_static! {
    /// Runs between the write and the read-back: (path, attempt).
    static ref BEFORE_READ_BACK: Mutex<Option<Arc<dyn Fn(&Path, u32) + Send + Sync>>> = Mutex::new(None);
}

// --- the sender -----------------------------------------------------------------------------

enum Hashing {
    Bytes(Vec<u8>),
    Reset,
    Finish { id: i32, file_num: i32, meta: Meta },
    FromDisk { id: i32, file_num: i32, path: PathBuf, kind: SealKind, meta: Meta },
}

type Queue = Arc<Mutex<VecDeque<Message>>>;

fn hashing_thread(rx: mpsc::Receiver<Hashing>, out: Queue, cancel: Arc<AtomicBool>) {
    let mut hasher = blake3::Hasher::new();
    let mut size = 0u64;
    let push = |seal: Seal| out.lock().unwrap().push_back(Wire::Seal(seal).to_message());
    while let Ok(msg) = rx.recv() {
        match msg {
            Hashing::Bytes(b) => {
                hasher.update(&b);
                size += b.len() as u64;
            }
            Hashing::Reset => {
                hasher = blake3::Hasher::new();
                size = 0;
            }
            Hashing::Finish { id, file_num, meta } => {
                let hash = hasher.finalize().to_hex().to_string();
                push(Seal { id, file_num, kind: SealKind::Sent, size, hash, meta, why: String::new() });
                hasher = blake3::Hasher::new();
                size = 0;
            }
            Hashing::FromDisk { id, file_num, path, kind, meta } => {
                let seal = match hash_from_disk(&path, &cancel) {
                    Ok((size, hash)) => Seal { id, file_num, kind, size, hash, meta, why: String::new() },
                    Err(err) => Seal {
                        id,
                        file_num,
                        kind: SealKind::Failed,
                        size: 0,
                        hash: String::new(),
                        meta,
                        why: format!("couldn't read the original: {}", err),
                    },
                };
                push(seal);
            }
        }
    }
}

struct Sending {
    id: i32,
    tx: mpsc::SyncSender<Hashing>,
    out: Queue,
    /// Sealed, no verdict yet: the path and how it was sealed.
    waiting: HashMap<i32, (PathBuf, SealKind)>,
    resends: VecDeque<i32>,
    tried: HashSet<i32>,
    /// Files that never get read, and why.
    refused: HashMap<i32, String>,
    resending: bool,
    /// The stream moved, so what went through the hasher isn't the whole file.
    partial: bool,
    cancel: Arc<AtomicBool>,
}

struct Receiving {
    id: i32,
    peer_os: String,
    tx: mpsc::Sender<Task>,
    closed: HashSet<i32>,
    seals: HashMap<i32, Seal>,
    dirs: Vec<DirEntry>,
    links: Vec<LinkEntry>,
    listed: Vec<Listed>,
    results: Arc<Mutex<Results>>,
    /// Bytes the job has counted for a file that's coming again.
    rewinds: HashMap<i32, u64>,
    cancel: Arc<AtomicBool>,
}

/// A TransferJob's verification. Off for an old peer, for printers and for memory jobs.
#[derive(Default)]
pub enum JobVerify {
    #[default]
    Off,
    Send(Box<Sending>),
    Receive(Box<Receiving>),
}

impl std::fmt::Debug for JobVerify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            JobVerify::Off => "Off",
            JobVerify::Send(_) => "Send",
            JobVerify::Receive(_) => "Receive",
        })
    }
}

impl Drop for JobVerify {
    fn drop(&mut self) {
        match self {
            JobVerify::Send(s) => s.cancel.store(true, Ordering::Relaxed),
            JobVerify::Receive(r) => {
                // Done has already been handled if there's nothing left to check, so this only
                // ever stops work that a cancel made pointless.
                r.cancel.store(true, Ordering::Relaxed)
            }
            JobVerify::Off => {}
        }
    }
}

impl JobVerify {
    #[inline]
    pub fn sending(&self) -> bool {
        matches!(self, JobVerify::Send(_))
    }

    #[inline]
    pub fn receiving(&self) -> bool {
        matches!(self, JobVerify::Receive(_))
    }

    #[inline]
    pub fn active(&self) -> bool {
        !matches!(self, JobVerify::Off)
    }

    /// What the file read. Hashed on another thread, so the loop that sends isn't the one hashing.
    #[inline]
    pub fn sent_bytes(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if let JobVerify::Send(s) = self {
            s.tx.send(Hashing::Bytes(bytes.to_vec())).ok();
        }
    }

    /// The stream moved, for a resume. The hash at the end comes from the whole file on disk.
    pub fn stream_moved(&mut self) {
        if let JobVerify::Send(s) = self {
            s.partial = true;
        }
    }

    /// The file's last block has gone. Returns the file_num the job goes on with.
    pub fn sent_eof(&mut self, file_num: i32, path: &Path, next: i32, len: i32) -> i32 {
        let JobVerify::Send(s) = self else { return next };
        let meta = capture_meta(path);
        if s.partial {
            s.tx.send(Hashing::Reset).ok();
            s.tx.send(Hashing::FromDisk { id: s.id, file_num, path: path.to_path_buf(), kind: SealKind::Sent, meta }).ok();
        } else {
            s.tx.send(Hashing::Finish { id: s.id, file_num, meta }).ok();
        }
        s.partial = false;
        s.waiting.insert(file_num, (path.to_path_buf(), SealKind::Sent));
        if s.resending {
            s.resending = false;
            return len;
        }
        next
    }

    /// A read or open failed. Returns the file_num the job goes on with.
    pub fn read_failed(&mut self, file_num: i32, path: &Path, err: &str, next: i32, len: i32) -> i32 {
        let JobVerify::Send(s) = self else { return next };
        log::warn!("job {}: reading {:?} failed: {}", s.id, path, err);
        s.tx.send(Hashing::Reset).ok();
        s.partial = false;
        if s.tried.insert(file_num) {
            s.resends.push_back(file_num);
        } else {
            s.give_up(file_num, path, &format!("couldn't read the original: {}", err));
        }
        if s.resending {
            s.resending = false;
            return len;
        }
        next
    }

    /// Skipped by the overwrite question. The receiver compares what's there.
    pub fn skipped(&mut self, file_num: i32, path: &Path) {
        if let JobVerify::Send(s) = self {
            s.partial = false;
            s.tx.send(Hashing::Reset).ok();
            s.tx.send(Hashing::FromDisk {
                id: s.id,
                file_num,
                path: path.to_path_buf(),
                kind: SealKind::Skipped,
                meta: capture_meta(path),
            })
            .ok();
            s.waiting.insert(file_num, (path.to_path_buf(), SealKind::Skipped));
        }
    }

    /// Whether this file is on the list of what never gets read.
    pub fn refuse(&mut self, file_num: i32, path: &Path) -> bool {
        if let JobVerify::Send(s) = self {
            if let Some(why) = s.refused.remove(&file_num) {
                s.give_up(file_num, path, &why);
                return true;
            }
        }
        false
    }

    pub fn next_resend(&mut self) -> Option<i32> {
        match self {
            JobVerify::Send(s) => s.resends.pop_front(),
            _ => None,
        }
    }

    pub fn resend_started(&mut self) {
        if let JobVerify::Send(s) = self {
            s.resending = true;
            s.partial = false;
            s.tx.send(Hashing::Reset).ok();
        }
    }

    pub fn resend_failed(&mut self, file_num: i32, path: &Path, err: &str) {
        if let JobVerify::Send(s) = self {
            s.give_up(file_num, path, &format!("couldn't read the original: {}", err));
        }
    }

    /// Done goes only once there's nothing left to send or hear about.
    pub fn holds_done(&self, file_num: i32, len: i32) -> bool {
        let JobVerify::Send(s) = self else { return false };
        file_num < len
            || s.resending
            || !s.resends.is_empty()
            || !s.waiting.is_empty()
            || !s.out.lock().unwrap().is_empty()
    }

    pub fn take_outgoing(&mut self) -> Vec<Message> {
        match self {
            JobVerify::Send(s) => s.out.lock().unwrap().drain(..).collect(),
            _ => Vec::new(),
        }
    }

    /// Bytes the receiver's job shouldn't count twice, once per resend.
    pub fn rewind(&mut self, file_num: i32) -> u64 {
        match self {
            JobVerify::Receive(r) => r.rewinds.remove(&file_num).unwrap_or(0),
            _ => 0,
        }
    }

    pub fn write_failed(&mut self, file_num: i32, err: &str) {
        if let JobVerify::Receive(r) = self {
            // The read-back finds it, and the sender resends.
            log::warn!("job {}: writing file {} failed: {}", r.id, file_num, err);
        }
    }
}

impl Sending {
    fn give_up(&mut self, file_num: i32, path: &Path, why: &str) {
        log_line("failed", 0, "", &path.to_string_lossy(), why);
        self.out.lock().unwrap().push_back(
            Wire::Seal(Seal {
                id: self.id,
                file_num,
                kind: SealKind::Failed,
                size: 0,
                hash: String::new(),
                meta: Meta::default(),
                why: why.to_string(),
            })
            .to_message(),
        );
    }

    fn on_verdict(&mut self, file_num: i32, ok: bool, why: &str, size: u64, hash: &str) {
        let Some((path, kind)) = self.waiting.remove(&file_num) else {
            return;
        };
        if ok {
            log_line("sent", size, hash, &path.to_string_lossy(), "");
            return;
        }
        log::warn!("job {}: {:?} came back wrong: {}", self.id, path, why);
        // Once, then it's named in the job. A file the person chose to keep stays as it is.
        if kind != SealKind::Skipped && self.tried.insert(file_num) {
            self.resends.push_back(file_num);
        }
    }
}

/// Turns on a read job whose peer can verify: lists what a file list can't carry, and queues that
/// before any of its blocks. Safe to call on every tick.
pub fn enable_send(job: &mut TransferJob, peer_os: &str) {
    if job.boring.active() || job.r#type != fs::JobType::Generic || job.is_last_job {
        return;
    }
    let fs::DataSource::FilePath(root) = &job.data_source else {
        return;
    };
    let root = root.clone();
    let mut walked = walk(&root);
    let mut refused = HashMap::new();
    for (i, f) in job.files().iter().enumerate() {
        let name = f.name.replace('\\', "/");
        let shown = shown_name(&root, &f.name);
        let why = walked.not_files.remove(&name).or_else(|| {
            if peer_os == "windows" {
                illegal_on_windows(if name.is_empty() { &shown } else { &name })
            } else {
                None
            }
        });
        if let Some(why) = why {
            refused.insert(i as i32, why);
        }
    }
    let mut listed = std::mem::take(&mut walked.listed);
    for (name, why) in walked.not_files.drain() {
        listed.push(Listed::new(name, why));
    }
    if peer_os == "windows" {
        walked.dirs.retain(|d| match illegal_on_windows(&d.path) {
            Some(why) => {
                listed.push(Listed::new(d.path.clone(), why));
                false
            }
            None => true,
        });
        walked.links.retain(|l| match illegal_on_windows(&l.path) {
            Some(why) => {
                listed.push(Listed::new(l.path.clone(), why));
                false
            }
            None => true,
        });
    }
    let out: Queue = Default::default();
    out.lock().unwrap().push_back(
        Wire::Manifest {
            id: job.id,
            os: this_os().to_string(),
            dirs: walked.dirs,
            links: walked.links,
            listed,
        }
        .to_message(),
    );
    // 16 MiB in hand. A hasher that far behind holds up reading, not memory.
    let (tx, rx) = mpsc::sync_channel(128);
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let (out, cancel) = (out.clone(), cancel.clone());
        std::thread::spawn(move || hashing_thread(rx, out, cancel));
    }
    let mut sending = Sending {
        id: job.id,
        tx,
        out,
        waiting: HashMap::new(),
        resends: VecDeque::new(),
        tried: HashSet::new(),
        refused,
        resending: false,
        partial: false,
        cancel,
    };
    // A resumed job: what went before is compared too, this run having no memory of it.
    for i in 0..job.file_num.min(job.files().len() as i32) {
        if sending.refused.contains_key(&i) {
            continue;
        }
        let path = TransferJob::join(&root, &job.files()[i as usize].name);
        sending
            .tx
            .send(Hashing::FromDisk {
                id: job.id,
                file_num: i,
                path: path.clone(),
                kind: SealKind::Resumed,
                meta: capture_meta(&path),
            })
            .ok();
        sending.waiting.insert(i, (path, SealKind::Resumed));
    }
    job.boring = JobVerify::Send(Box::new(sending));
}

/// [`enable_send`] for a job list, once the peer is known. Printer and paused jobs wait.
pub fn enable_sends(jobs: &mut [TransferJob], peer_os: Option<&str>) {
    if let Some(os) = peer_os {
        for job in jobs.iter_mut() {
            enable_send(job, os);
        }
    }
}

fn shown_name(root: &Path, name: &str) -> String {
    if name.is_empty() {
        root.file_name().map_or(String::new(), |n| n.to_string_lossy().to_string())
    } else {
        name.replace('\\', "/")
    }
}

// --- the receiver ---------------------------------------------------------------------------

/// How a verdict gets back to the sender: the Controller's loop, or the CM's IPC to its connection.
pub type Outbox = Arc<dyn Fn(Message) + Send + Sync>;

enum Outcome {
    Passed,
    Bad(String),
    SkipDiffers,
}

#[derive(Default, Debug)]
struct Results {
    /// (shown name, size, what happened). The latest word on a file replaces the one before.
    files: BTreeMap<i32, FileResult>,
    not_kept: Vec<Listed>,
}

#[derive(Debug)]
struct FileResult {
    name: String,
    size: u64,
    state: FileState,
}

#[derive(Debug, PartialEq)]
enum FileState {
    Verified,
    Failed(String),
    Skipped(String),
}

struct Task {
    file_num: i32,
    name: String,
    path: PathBuf,
    seal: Seal,
}

fn receive_thread(
    rx: mpsc::Receiver<Task>,
    results: Arc<Mutex<Results>>,
    outbox: Outbox,
    peer_os: String,
    cancel: Arc<AtomicBool>,
) {
    let mut attempts: HashMap<i32, u32> = HashMap::new();
    while let Ok(task) = rx.recv() {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        let attempt = attempts.entry(task.file_num).or_insert(0);
        *attempt += 1;
        let attempt = *attempt;
        let (id, file_num) = (task.seal.id, task.file_num);
        let outcome = check_one(&task, attempt, &peer_os, &results, &cancel);
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        let (state, ok, why) = match outcome {
            Outcome::Passed => (FileState::Verified, true, String::new()),
            Outcome::Bad(why) => (FileState::Failed(why.clone()), false, why),
            Outcome::SkipDiffers => {
                let why = "already there, and not the same as the original".to_string();
                (FileState::Skipped(why.clone()), false, why)
            }
        };
        results.lock().unwrap().files.insert(
            file_num,
            FileResult { name: task.name.clone(), size: task.seal.size, state },
        );
        let (size, hash) = (task.seal.size, task.seal.hash);
        outbox(Wire::Verdict { id, file_num, ok, why, size, hash }.to_message());
    }
}

fn check_one(
    task: &Task,
    attempt: u32,
    peer_os: &str,
    results: &Arc<Mutex<Results>>,
    cancel: &AtomicBool,
) -> Outcome {
    let shown = task.path.to_string_lossy().to_string();
    let seal = &task.seal;
    if seal.kind != SealKind::Sent {
        // Nothing was written: compare what's under the real name.
        return match hash_from_disk(&task.path, cancel) {
            Ok((size, hash)) if size == seal.size && hash == seal.hash => {
                log_line("already there", size, &hash, &shown, "");
                Outcome::Passed
            }
            Ok((size, hash)) => {
                let why = "doesn't match the original";
                log_line("different", size, &hash, &shown, why);
                if seal.kind == SealKind::Skipped {
                    Outcome::SkipDiffers
                } else {
                    Outcome::Bad(why.to_string())
                }
            }
            Err(err) if seal.kind == SealKind::Skipped => {
                log_line("different", 0, "", &shown, &err.to_string());
                Outcome::SkipDiffers
            }
            Err(err) => Outcome::Bad(format!("couldn't read it: {}", err)),
        };
    }
    let download = PathBuf::from(format!("{}.download", shown));
    let shown_download = download.to_string_lossy().to_string();
    #[cfg(test)]
    {
        let hook = BEFORE_READ_BACK.lock().unwrap().clone();
        if let Some(hook) = hook {
            hook(&download, attempt);
        }
    }
    #[cfg(not(test))]
    let _ = attempt;
    // Write access, since Windows won't flush a file opened for reading.
    let flushed = std::fs::OpenOptions::new().read(true).write(true).open(&download).and_then(|f| f.sync_all());
    if let Err(err) = flushed {
        let why = format!("couldn't flush the copy to disk: {}", err);
        log_line("failed", 0, "", &shown_download, &why);
        return Outcome::Bad(why);
    }
    let read = hash_from_disk(&download, cancel);
    let (size, hash) = match read {
        Ok(v) => v,
        Err(err) => {
            let why = format!("couldn't read the copy back: {}", err);
            log_line("failed", 0, "", &shown_download, &why);
            return Outcome::Bad(why);
        }
    };
    if size != seal.size || hash != seal.hash {
        let why = if size != seal.size {
            format!("the copy is {} bytes, the original {}", size, seal.size)
        } else {
            "the copy doesn't match the original".to_string()
        };
        log_line("failed", size, &hash, &shown_download, &why);
        return Outcome::Bad(why);
    }
    let mut lost = apply_contents_meta(&download, &seal.meta, peer_os);
    if let Err(err) = std::fs::rename(&download, &task.path) {
        let why = format!("couldn't give it its name: {}", err);
        log_line("failed", size, &hash, &shown_download, &why);
        return Outcome::Bad(why);
    }
    std::fs::remove_file(format!("{}.digest", shown)).ok();
    lost.extend(apply_times(&task.path, &seal.meta));
    if !lost.is_empty() {
        let mut r = results.lock().unwrap();
        r.not_kept.push(Listed::new(task.name.clone(), lost.join(", ")));
    }
    log_line("verified", size, &hash, &shown, &lost.join(", "));
    Outcome::Passed
}

/// The hook behind every message from the peer, once the job is found.
pub fn on_wire(job: &mut TransferJob, wire: Wire, outbox: Option<&Outbox>) {
    match wire {
        Wire::Manifest { id, os, dirs, links, listed } => {
            let Some(outbox) = outbox else { return };
            if job.boring.active() {
                return;
            }
            let (tx, rx) = mpsc::channel();
            let results: Arc<Mutex<Results>> = Default::default();
            let cancel = Arc::new(AtomicBool::new(false));
            {
                let (results, outbox, os, cancel) = (results.clone(), outbox.clone(), os.clone(), cancel.clone());
                std::thread::spawn(move || receive_thread(rx, results, outbox, os, cancel));
            }
            job.boring = JobVerify::Receive(Box::new(Receiving {
                id,
                peer_os: os,
                tx,
                closed: HashSet::new(),
                seals: HashMap::new(),
                dirs,
                links,
                listed,
                results,
                rewinds: HashMap::new(),
                cancel,
            }));
        }
        Wire::Seal(seal) => on_seal(job, seal, outbox),
        Wire::Verdict { file_num, ok, why, size, hash, .. } => {
            if let JobVerify::Send(s) = &mut job.boring {
                s.on_verdict(file_num, ok, &why, size, &hash);
            }
        }
        Wire::StartRead { os, .. } => enable_send(job, &os),
        Wire::Hello { .. } | Wire::Report { .. } => {}
    }
}

fn job_file(job: &TransferJob, file_num: i32) -> Option<(String, PathBuf)> {
    let fs::DataSource::FilePath(base) = &job.data_source else {
        return None;
    };
    if file_num < 0 {
        return None;
    }
    let entry = job.files().get(file_num as usize)?;
    match fs::join_validated_path(base, &entry.name) {
        Ok(path) => Some((shown_name(base, &entry.name), path)),
        Err(err) => {
            log::error!("job {}: bad name in a seal: {}", job.id, err);
            None
        }
    }
}

fn on_seal(job: &mut TransferJob, seal: Seal, outbox: Option<&Outbox>) {
    let file_num = seal.file_num;
    let found = job_file(job, file_num);
    let JobVerify::Receive(r) = &mut job.boring else {
        return;
    };
    let Some((name, path)) = found else {
        if let Some(outbox) = outbox {
            outbox(
                Wire::Verdict {
                    id: r.id,
                    file_num,
                    ok: false,
                    why: "no such file in this job".to_string(),
                    size: 0,
                    hash: String::new(),
                }
                .to_message(),
            );
        }
        return;
    };
    if seal.kind == SealKind::Failed {
        r.results.lock().unwrap().files.insert(
            file_num,
            FileResult { name, size: 0, state: FileState::Failed(seal.why) },
        );
        return;
    }
    r.seals.insert(file_num, seal);
    queue_if_ready(r, file_num, name, path);
}

fn queue_if_ready(r: &mut Receiving, file_num: i32, name: String, path: PathBuf) {
    let Some(kind) = r.seals.get(&file_num).map(|s| s.kind) else {
        return;
    };
    if kind == SealKind::Sent && !r.closed.remove(&file_num) {
        return;
    }
    let Some(seal) = r.seals.remove(&file_num) else {
        return;
    };
    // If it comes round again, the job's count starts over for it.
    r.rewinds.insert(file_num, seal.size);
    r.tx.send(Task { file_num, name, path, seal }).ok();
}

/// The file's last block is written and the handle is shut.
pub fn file_closed(job: &mut TransferJob, file_num: i32) {
    let found = job_file(job, file_num);
    if let JobVerify::Receive(r) = &mut job.boring {
        r.closed.insert(file_num);
        if let Some((name, path)) = found {
            queue_if_ready(r, file_num, name, path);
        }
    }
}

fn apply_manifest(r: &Receiving, base: &Path) -> (usize, Vec<Listed>, Vec<Listed>) {
    let mut not_copied = r.listed.clone();
    let mut not_kept = Vec::new();
    let peer_os = r.peer_os.as_str();
    let mut folders = 0;
    let mut dirs: Vec<(&DirEntry, PathBuf)> = Vec::new();
    for d in &r.dirs {
        match fs::join_validated_path(&base.to_path_buf(), &d.path) {
            Ok(path) => match std::fs::create_dir_all(&path) {
                Ok(()) => {
                    folders += 1;
                    dirs.push((d, path));
                }
                Err(err) => not_copied.push(Listed::new(d.path.clone(), format!("couldn't make this folder: {}", err))),
            },
            Err(err) => not_copied.push(Listed::new(d.path.clone(), err.to_string())),
        }
    }
    for link in &r.links {
        if let Some(why) = make_link(base, link) {
            not_copied.push(Listed::new(link.path.clone(), why));
        }
    }
    // Deepest first: a folder's date moves whenever something inside it does.
    dirs.sort_by_key(|(_, path)| std::cmp::Reverse(path.components().count()));
    for (d, path) in dirs {
        let mut lost = apply_contents_meta(&path, &d.meta, peer_os);
        lost.extend(apply_times(&path, &d.meta));
        if !lost.is_empty() {
            let name = if d.path.is_empty() {
                base.file_name().map_or(String::new(), |n| n.to_string_lossy().to_string())
            } else {
                d.path.clone()
            };
            not_kept.push(Listed::new(name, lost.join(", ")));
        }
    }
    (folders, not_copied, not_kept)
}

/// Why the link couldn't be made, if it couldn't. A link never goes over something that's there,
/// and a name passing through a link was already refused by `join_validated_path`.
fn make_link(base: &Path, link: &LinkEntry) -> Option<String> {
    let path = match fs::join_validated_path(&base.to_path_buf(), &link.path) {
        Ok(p) => p,
        Err(err) => return Some(err.to_string()),
    };
    if let Ok(m) = std::fs::symlink_metadata(&path) {
        let same = m.file_type().is_symlink()
            && std::fs::read_link(&path).map_or(false, |t| t.to_string_lossy() == link.target);
        return if same { None } else { Some("something else is already there".to_string()) };
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    #[cfg(unix)]
    let res = std::os::unix::fs::symlink(&link.target, &path);
    #[cfg(windows)]
    let res = {
        // Windows spells a link's target its own way, and may not allow links at all.
        let target = link.target.replace('/', "\\");
        if link.to_dir {
            std::os::windows::fs::symlink_dir(&target, &path)
        } else {
            std::os::windows::fs::symlink_file(&target, &path)
        }
    };
    #[cfg(not(any(unix, windows)))]
    let res: std::io::Result<()> = Err(std::io::Error::new(std::io::ErrorKind::Other, "no links here"));
    match res {
        Ok(()) => {
            if let Some((s, n)) = link.modified {
                let t = filetime::FileTime::from_unix_time(s, n);
                filetime::set_symlink_file_times(&path, t, t).ok();
            }
            None
        }
        Err(err) => Some(format!("this link couldn't be made here: {}", err)),
    }
}

/// When Done lands on a receiving job. Everything the sender waited for is settled by then.
pub fn finish(job: &TransferJob) -> Option<Report> {
    let JobVerify::Receive(r) = &job.boring else {
        return None;
    };
    let fs::DataSource::FilePath(base) = &job.data_source else {
        return None;
    };
    let (folders, not_copied, mut not_kept) = apply_manifest(r, base);
    let results = r.results.lock().unwrap();
    let mut report = Report { files: job.files().len(), folders, not_copied, ..Default::default() };
    for (i, f) in job.files().iter().enumerate() {
        match results.files.get(&(i as i32)) {
            Some(FileResult { size, state: FileState::Verified, .. }) => {
                report.verified += 1;
                report.bytes += size;
            }
            Some(FileResult { name, state: FileState::Failed(why), .. }) => {
                let kept = TransferJob::join(base, &f.name);
                let download = format!("{}.download", kept.to_string_lossy());
                let why = if Path::new(&download).exists() {
                    format!("{}; the partial copy is {}", why, download)
                } else {
                    why.clone()
                };
                report.failed.push(Listed::new(name.clone(), why));
            }
            Some(FileResult { name, state: FileState::Skipped(why), .. }) => {
                report.skipped.push(Listed::new(name.clone(), why.clone()));
            }
            // Strict on purpose: no word on a file means it didn't pass.
            None => report.failed.push(Listed::new(shown_name(base, &f.name), "never confirmed")),
        }
    }
    not_kept.extend(results.not_kept.iter().cloned());
    report.not_kept = not_kept;
    for l in report.not_copied.iter() {
        log_line("not copied", 0, "", &l.name, &l.why);
    }
    for l in report.not_kept.iter() {
        log_line("not kept", 0, "", &l.name, &l.why);
    }
    Some(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{DataSource, JobType};
    use hbb_common::{
        protobuf::Message as _,
        sodiumoxide::crypto::secretbox,
        tokio::{self, net::TcpListener, time},
        Stream,
    };
    use std::time::Duration;

    lazy_static::lazy_static! {
        /// The read-back hook is one global, so the tests that use it take turns.
        static ref HOOK_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::new(());
    }

    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Self {
            static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = N.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir().join(format!("file-verify-{}-{tag}-{n}", std::process::id()));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }

        fn file(&self, name: &str, data: &[u8]) -> PathBuf {
            let p = self.0.join(name);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, data).unwrap();
            p
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    fn noise(len: usize, mut s: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + 8);
        while out.len() < len {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            out.extend_from_slice(&s.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes());
        }
        out.truncate(len);
        out
    }

    async fn pair() -> (Stream, Stream) {
        let key = secretbox::gen_key();
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let a = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (b, peer) = l.accept().await.unwrap();
        a.set_nodelay(true).unwrap();
        b.set_nodelay(true).unwrap();
        let (mut sa, mut sb) = (Stream::from(a, addr), Stream::from(b, peer));
        sa.set_key(key.clone());
        sb.set_key(key);
        (sa, sb)
    }

    fn read_job(path: &Path, detect: bool) -> TransferJob {
        TransferJob::new_read(
            1,
            JobType::Generic,
            String::new(),
            DataSource::FilePath(path.to_path_buf()),
            0,
            true,
            false,
            detect,
        )
        .unwrap()
    }

    fn write_job(to: &Path, files: Vec<FileEntry>) -> TransferJob {
        TransferJob::new_write(
            1,
            JobType::Generic,
            String::new(),
            DataSource::FilePath(to.to_path_buf()),
            0,
            true,
            true,
            false,
        )
        .with_files(files)
        .unwrap()
    }

    /// The receiver's select loop, as in io_loop and the CM: writes blocks, answers from a channel.
    async fn receive(mut stream: Stream, mut job: TransferJob) -> Report {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
        let outbox: Outbox = Arc::new(move |m| {
            tx.send(m).ok();
        });
        loop {
            tokio::select! {
                res = stream.next() => {
                    let bytes = res.expect("sender went away before Done").unwrap();
                    match Message::parse_from_bytes(&bytes).unwrap().union {
                        Some(message::Union::FileResponse(fr)) => match fr.union {
                            Some(file_response::Union::Block(b)) => job.write(b).await.unwrap(),
                            Some(file_response::Union::Done(_)) => {
                                job.modify_time();
                                return finish(&job).expect("a verified job has a report");
                            }
                            Some(file_response::Union::Error(e)) => panic!("job failed: {}", e.error),
                            _ => {}
                        },
                        Some(message::Union::Misc(m)) => {
                            if let Some(misc::Union::PluginRequest(p)) = m.union {
                                assert_eq!(p.id, WIRE_ID);
                                on_wire(&mut job, Wire::from_json(&p.content).unwrap(), Some(&outbox));
                            }
                        }
                        _ => {}
                    }
                }
                Some(m) = rx.recv() => stream.send(&m).await.unwrap(),
            }
        }
    }

    /// The sender's: the tick arm and the message arm.
    async fn send(mut stream: Stream, job: TransferJob) -> TransferJob {
        let id = job.id;
        let mut jobs = vec![job];
        enable_sends(&mut jobs, Some(this_os()));
        let mut tick = time::interval(Duration::from_millis(1));
        while !jobs.is_empty() {
            tokio::select! {
                _ = tick.tick() => { crate::file_speed::pump_read_jobs(&mut jobs, &mut stream).await.unwrap(); }
                res = stream.next() => {
                    let bytes = res.expect("receiver went away").unwrap();
                    if let Some(message::Union::Misc(m)) = Message::parse_from_bytes(&bytes).unwrap().union {
                        if let Some(misc::Union::PluginRequest(p)) = m.union {
                            let wire = Wire::from_json(&p.content).unwrap();
                            if let Some(job) = fs::get_job(id, &mut jobs) {
                                on_wire(job, wire, None);
                            }
                        }
                    }
                }
            }
        }
        // Keeps the job's type simple for the caller: nothing is left of it.
        TransferJob::default()
    }

    async fn copy(src: &Path, dst: &Path) -> Report {
        let job = read_job(src, false);
        let (a, b) = pair().await;
        let rx = tokio::spawn(receive(b, write_job(dst, job.files().clone())));
        let tx = tokio::spawn(send(a, job));
        let report = time::timeout(Duration::from_secs(120), rx).await.expect("the job hung").unwrap();
        tx.await.unwrap();
        report
    }

    /// One log for the run, since the path is global and these tests run side by side.
    fn with_log(_dir: &Dir) -> PathBuf {
        let p = std::env::temp_dir().join(format!("file-verify-{}.log", std::process::id()));
        set_log_path(p.clone());
        p
    }

    /// The read-back hook, for files under `to` only: the other tests are running too.
    fn hook(to: &Path, f: impl Fn(&Path, u32) + Send + Sync + 'static) {
        let to = to.to_path_buf();
        *BEFORE_READ_BACK.lock().unwrap() = Some(Arc::new(move |path: &Path, attempt| {
            if path.starts_with(&to) {
                f(path, attempt);
            }
        }));
    }

    #[test]
    fn the_marker_is_read_only_when_it_says_true() {
        assert!(peer_says_verified(r#"{"boring_verified_files":true}"#));
        assert!(!peer_says_verified(r#"{"boring_verified_files":false}"#));
        assert!(!peer_says_verified(r#"{"boring_remote":"1.6.4"}"#));
        assert!(!peer_says_verified(""));
    }

    #[test]
    fn a_wire_message_is_a_plugin_request_and_survives_the_trip() {
        let w = Wire::Verdict { id: 3, file_num: 2, ok: false, why: "x".into(), size: 1, hash: "h".into() };
        let bytes = w.to_message().write_to_bytes().unwrap();
        let Some(message::Union::Misc(m)) = Message::parse_from_bytes(&bytes).unwrap().union else {
            panic!()
        };
        let Some(misc::Union::PluginRequest(p)) = m.union else { panic!() };
        assert_eq!(p.id, WIRE_ID);
        assert!(matches!(
            Wire::from_json(&p.content),
            Some(Wire::Verdict { id: 3, file_num: 2, ok: false, .. })
        ));
        assert!(Wire::from_json(b"{not json").is_none());
    }

    #[test]
    fn verified_appears_only_when_every_file_passed() {
        let ok = Report { files: 2, verified: 2, bytes: 4_300_000_000, ..Default::default() };
        assert_eq!(ok.words(), "Verified: 2 files, 4.3 GB");
        let one = Report { files: 1, verified: 1, bytes: 5, ..Default::default() };
        assert_eq!(one.words(), "Verified: 1 file, 5 bytes");
        let partial = Report {
            files: 12,
            verified: 11,
            bytes: 4_000_000_000,
            failed: vec![Listed::new("A001.MOV", "the copy doesn't match the original")],
            ..Default::default()
        };
        assert_eq!(
            partial.words(),
            "Not verified: 1 of 12 files failed: A001.MOV (the copy doesn't match the original). 11 proved, 4.0 GB"
        );
        let skipped = Report {
            files: 2,
            verified: 1,
            bytes: 1000,
            skipped: vec![Listed::new("b", "already there, and not the same as the original")],
            ..Default::default()
        };
        assert!(skipped.words().starts_with("Not verified: 1 of 2 files skipped: b ("));
        // One missing result, with nothing else said, is still not Verified.
        let missing = Report { files: 2, verified: 1, ..Default::default() };
        assert!(!missing.words().starts_with("Verified"));
        let extras = Report {
            files: 1,
            verified: 1,
            bytes: 1000,
            not_copied: vec![Listed::new("l", "this link couldn't be made here")],
            not_kept: vec![Listed::new("a", "permissions")],
            ..Default::default()
        };
        assert_eq!(
            extras.words(),
            "Verified: 1 file, 1 KB. Not copied: l (this link couldn't be made here). Couldn't keep: a (permissions)"
        );
    }

    #[test]
    fn an_old_peer_is_named_and_never_called_verified() {
        assert_eq!(
            job_words(None, false),
            "Not verified: the other computer needs the latest Boring Remote"
        );
        assert!(job_words(None, true).starts_with("Not verified"));
    }

    #[test]
    fn long_lists_are_cut_and_point_at_the_log() {
        let many: Vec<_> = (0..8).map(|i| Listed::new(format!("f{i}"), "")).collect();
        let r = Report { files: 8, failed: many, ..Default::default() };
        assert_eq!(
            r.words(),
            "Not verified: 8 of 8 files failed: f0, f1, f2, f3, f4, and 3 more, all in the verify log. 0 proved, 0 bytes"
        );
    }

    #[test]
    fn windows_names_are_reported_not_rewritten() {
        assert!(illegal_on_windows("a:b.mov").is_some());
        assert!(illegal_on_windows("dir/que?.mov").is_some());
        assert!(illegal_on_windows("back\\slash").is_some());
        assert!(illegal_on_windows("ends.").is_some());
        assert!(illegal_on_windows("ends /x").is_some());
        assert!(illegal_on_windows("CON").is_some());
        assert!(illegal_on_windows("sub/com1.txt").is_some());
        assert!(illegal_on_windows("A001C002.MOV").is_none());
        assert!(illegal_on_windows(".hidden/console.log").is_none());
    }

    #[test]
    fn no_room_is_refused_with_the_numbers_and_room_passes() {
        let dir = Dir::new("room");
        assert!(room_for(&dir.0, 1).is_ok());
        let err = room_for(&dir.0.join("not/yet/there"), u64::MAX / 2).unwrap_err();
        assert!(err.starts_with("Not enough room: this needs"), "{}", err);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_folder_arrives_whole_and_says_verified() {
        let (src, dst, logs) = (Dir::new("src"), Dir::new("dst"), Dir::new("log"));
        let log = with_log(&logs);
        let big = noise(3 * 1024 * 1024 + 11, 1);
        src.file("big.mov", &big);
        src.file("empty.bin", b"");
        src.file("sub/deep/text.log", &b"same again\n".repeat(50_000));
        src.file(".hidden", b"dot file");
        src.file("sub/.DS_Store", b"finder");
        std::fs::create_dir_all(src.0.join("empty-folder/inner")).unwrap();
        std::fs::create_dir_all(src.0.join(".hidden-folder")).unwrap();
        let to = dst.0.join("copy");
        let report = copy(&src.0, &to).await;
        assert_eq!(report.words(), format!("Verified: 5 files, {}", size_words(big.len() as u64 + 550_000 + 8 + 6)));
        assert!(report.all_passed());
        assert_eq!(std::fs::read(to.join("big.mov")).unwrap(), big);
        assert_eq!(std::fs::read(to.join(".hidden")).unwrap(), b"dot file");
        assert_eq!(std::fs::read(to.join("sub/.DS_Store")).unwrap(), b"finder");
        assert_eq!(std::fs::metadata(to.join("empty.bin")).unwrap().len(), 0);
        assert!(to.join("empty-folder/inner").is_dir());
        assert!(to.join(".hidden-folder").is_dir());
        assert!(!to.join("big.mov.download").exists());
        assert!(!to.join("big.mov.digest").exists());
        let lines = std::fs::read_to_string(log).unwrap();
        let line = lines
            .lines()
            .find(|l| l.contains(&format!("{}", to.join("big.mov").display())) && l.contains("\tverified\t"))
            .expect("the verify log names the file");
        assert!(line.contains(&format!("\t{}\tblake3:{}\t", big.len(), blake3::hash(&big).to_hex())), "{}", line);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_flipped_byte_is_caught_and_resent() {
        let _turn = HOOK_LOCK.lock().await;
        let (src, dst, logs) = (Dir::new("src"), Dir::new("dst"), Dir::new("log"));
        with_log(&logs);
        let data = noise(1024 * 1024 + 5, 2);
        src.file("a.mov", &data);
        src.file("b.mov", &noise(4096, 3));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let to = dst.0.join("copy");
        {
            let seen = seen.clone();
            hook(&to, move |path, attempt| {
                if path.to_string_lossy().contains("a.mov") && attempt == 1 {
                    let mut f = std::fs::read(path).unwrap();
                    f[777_777] ^= 1;
                    std::fs::write(path, f).unwrap();
                }
                seen.lock().unwrap().push((path.to_path_buf(), attempt));
            });
        }
        let report = copy(&src.0, &to).await;
        *BEFORE_READ_BACK.lock().unwrap() = None;
        assert!(report.all_passed(), "{}", report.words());
        assert_eq!(std::fs::read(to.join("a.mov")).unwrap(), data);
        let seen = seen.lock().unwrap();
        let a: Vec<_> = seen.iter().filter(|(p, _)| p.to_string_lossy().contains("a.mov")).collect();
        assert_eq!(a.len(), 2, "caught, then resent once: {:?}", *seen);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_truncated_file_is_caught_and_resent() {
        let _turn = HOOK_LOCK.lock().await;
        let (src, dst, logs) = (Dir::new("src"), Dir::new("dst"), Dir::new("log"));
        with_log(&logs);
        let data = noise(512 * 1024, 4);
        src.file("a.mov", &data);
        let to = dst.0.join("copy");
        hook(&to, |path, attempt| {
            if attempt == 1 {
                let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
                f.set_len(1000).unwrap();
            }
        });
        let report = copy(&src.0, &to).await;
        *BEFORE_READ_BACK.lock().unwrap() = None;
        assert!(report.all_passed(), "{}", report.words());
        assert_eq!(std::fs::read(to.join("a.mov")).unwrap(), data);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn two_failures_name_the_file_keep_the_download_and_finish_the_rest() {
        let _turn = HOOK_LOCK.lock().await;
        let (src, dst, logs) = (Dir::new("src"), Dir::new("dst"), Dir::new("log"));
        let log = with_log(&logs);
        src.file("bad.mov", &noise(300 * 1024, 5));
        let good = noise(300 * 1024, 6);
        src.file("good.mov", &good);
        src.file("zlast.mov", &good);
        let to = dst.0.join("copy");
        hook(&to, |path, _attempt| {
            if path.to_string_lossy().contains("bad.mov") {
                let mut f = std::fs::read(path).unwrap();
                f[0] ^= 0x80;
                std::fs::write(path, f).unwrap();
            }
        });
        let report = copy(&src.0, &to).await;
        *BEFORE_READ_BACK.lock().unwrap() = None;
        assert!(!report.all_passed());
        assert_eq!(report.verified, 2);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].name, "bad.mov");
        let words = report.words();
        assert!(words.starts_with("Not verified: 1 of 3 files failed: bad.mov ("), "{}", words);
        assert!(words.contains(".download"), "{}", words);
        assert!(!to.join("bad.mov").exists(), "a file that failed never gets the real name");
        assert!(to.join("bad.mov.download").exists(), "and the partial copy stays");
        assert_eq!(std::fs::read(to.join("good.mov")).unwrap(), good);
        assert_eq!(std::fs::read(to.join("zlast.mov")).unwrap(), good);
        let lines = std::fs::read_to_string(log).unwrap();
        let wanted = format!("{}", to.join("bad.mov.download").display());
        assert!(lines.lines().any(|l| l.contains("\tfailed\t") && l.contains(&wanted)), "{}", lines);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_file_that_cannot_be_read_is_named_and_the_rest_arrive() {
        let (src, dst, logs) = (Dir::new("src"), Dir::new("dst"), Dir::new("log"));
        with_log(&logs);
        let keep = noise(4096, 7);
        src.file("a-gone.mov", &keep);
        src.file("b.mov", &keep);
        let job = read_job(&src.0, false);
        std::fs::remove_file(src.0.join("a-gone.mov")).unwrap();
        let (a, b) = pair().await;
        let to = dst.0.join("copy");
        let rx = tokio::spawn(receive(b, write_job(&to, job.files().clone())));
        tokio::spawn(send(a, job));
        let report = time::timeout(Duration::from_secs(60), rx).await.unwrap().unwrap();
        assert_eq!(report.verified, 1);
        assert_eq!(report.failed[0].name, "a-gone.mov");
        assert!(report.failed[0].why.contains("couldn't read the original"), "{:?}", report.failed);
        assert_eq!(std::fs::read(to.join("b.mov")).unwrap(), keep);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn links_are_recreated_as_links() {
        let (src, dst, logs) = (Dir::new("src"), Dir::new("dst"), Dir::new("log"));
        with_log(&logs);
        src.file("real/file.txt", b"x");
        std::os::unix::fs::symlink("real/file.txt", src.0.join("to-file")).unwrap();
        std::os::unix::fs::symlink("real", src.0.join("to-dir")).unwrap();
        std::os::unix::fs::symlink("/nowhere/at/all", src.0.join("dangling")).unwrap();
        let to = dst.0.join("copy");
        let report = copy(&src.0, &to).await;
        assert!(report.all_passed(), "{}", report.words());
        assert!(report.not_copied.is_empty(), "{:?}", report.not_copied);
        assert_eq!(std::fs::read_link(to.join("to-file")).unwrap(), Path::new("real/file.txt"));
        assert_eq!(std::fs::read_link(to.join("to-dir")).unwrap(), Path::new("real"));
        assert_eq!(std::fs::read_link(to.join("dangling")).unwrap(), Path::new("/nowhere/at/all"));
        assert!(!to.join("to-dir/file.txt.download").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_link_never_goes_over_something_that_is_there_and_says_so() {
        let dir = Dir::new("link");
        dir.file("taken", b"mine");
        let link = LinkEntry { path: "taken".into(), target: "/etc/passwd".into(), to_dir: false, modified: None };
        assert_eq!(make_link(&dir.0, &link).as_deref(), Some("something else is already there"));
        assert_eq!(std::fs::read(dir.0.join("taken")).unwrap(), b"mine");
        // A name can't climb out either.
        let climbing = LinkEntry { path: "../out".into(), target: "x".into(), to_dir: false, modified: None };
        assert!(make_link(&dir.0, &climbing).is_some());
        assert!(!dir.0.parent().unwrap().join("out").exists());
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_fifo_is_listed_not_read() {
        let (src, dst, logs) = (Dir::new("src"), Dir::new("dst"), Dir::new("log"));
        with_log(&logs);
        src.file("a.txt", b"a");
        let fifo = std::ffi::CString::new(src.0.join("pipe").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        let to = dst.0.join("copy");
        let report = copy(&src.0, &to).await;
        assert!(!report.all_passed());
        assert_eq!(report.failed[0].name, "pipe");
        assert_eq!(report.failed[0].why, "not a regular file");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_folder_it_cannot_read_is_listed() {
        use std::os::unix::fs::PermissionsExt;
        let (src, dst, logs) = (Dir::new("src"), Dir::new("dst"), Dir::new("log"));
        with_log(&logs);
        src.file("a.txt", b"a");
        src.file("locked/b.txt", b"b");
        let locked = src.0.join("locked");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let to = dst.0.join("copy");
        let report = copy(&src.0, &to).await;
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(to.join("locked"), std::fs::Permissions::from_mode(0o755)).ok();
        assert!(report.not_copied.iter().any(|l| l.name == "locked"), "{:?}", report);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_mac_copy_keeps_dates_permissions_and_attributes_but_not_quarantine() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let (src, dst, logs) = (Dir::new("src"), Dir::new("dst"), Dir::new("log"));
        with_log(&logs);
        let p = src.file("sub/card.mov", &noise(200 * 1024, 8));
        let sub = src.0.join("sub");
        let set = |path: &Path, name: &str, value: &[u8]| {
            let (c, n) = (
                std::ffi::CString::new(path.to_str().unwrap()).unwrap(),
                std::ffi::CString::new(name).unwrap(),
            );
            let r = unsafe { libc::setxattr(c.as_ptr(), n.as_ptr(), value.as_ptr() as *const _, value.len(), 0, 0) };
            assert_eq!(r, 0, "setxattr {}", name);
        };
        set(&p, "com.apple.metadata:_kMDItemUserTags", b"bplist-tags");
        set(&p, "com.apple.ResourceFork", &noise(70_000, 9));
        set(&p, "com.example.comment", b"a note");
        set(&p, "com.apple.quarantine", b"0081;00000000;Safari;");
        set(&sub, "com.example.folder", b"folder note");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(mac::set_created(&p, (1_000_000_000, 123_456_000)));
        assert!(mac::set_created(&sub, (1_000_000_100, 0)));
        let modified = filetime::FileTime::from_unix_time(1_500_000_000, 987_654_321);
        filetime::set_file_mtime(&p, modified).unwrap();
        let dir_modified = filetime::FileTime::from_unix_time(1_600_000_000, 111_222_333);
        filetime::set_file_mtime(&sub, dir_modified).unwrap();
        let source = capture_meta(&p);
        assert_eq!(source.xattrs.len(), 3, "quarantine is left behind: {:?}", source.xattrs.iter().map(|x| &x.0).collect::<Vec<_>>());

        let to = dst.0.join("copy");
        let report = copy(&src.0, &to).await;
        assert!(report.all_passed(), "{}", report.words());
        assert!(report.not_kept.is_empty(), "{:?}", report.not_kept);

        let q = to.join("sub/card.mov");
        let copied = capture_meta(&q);
        let sorted = |m: &Meta| {
            let mut x = m.xattrs.clone();
            x.sort();
            x
        };
        assert_eq!(sorted(&copied), sorted(&source));
        assert_eq!(copied.mode, Some(0o640));
        let m = std::fs::metadata(&q).unwrap();
        assert_eq!((m.mtime(), m.mtime_nsec()), (1_500_000_000, 987_654_321), "modified, to the nanosecond");
        assert_eq!(copied.created, Some((1_000_000_000, 123_456_000)));
        let d = capture_meta(&to.join("sub"));
        assert_eq!(d.modified, Some((1_600_000_000, 111_222_333)), "folder date survives what went in it");
        assert_eq!(d.mode, Some(0o750));
        assert_eq!(d.created, Some((1_000_000_100, 0)));
        assert_eq!(d.xattrs, vec![("com.example.folder".to_string(), hex(b"folder note"))]);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn setuid_does_not_cross_and_is_listed() {
        use std::os::unix::fs::PermissionsExt;
        let (src, dst, logs) = (Dir::new("src"), Dir::new("dst"), Dir::new("log"));
        with_log(&logs);
        let p = src.file("tool", b"#!/bin/sh\n");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o4755)).unwrap();
        let to = dst.0.join("copy");
        let report = copy(&src.0, &to).await;
        assert_eq!(std::fs::metadata(to.join("tool")).unwrap().permissions().mode() & 0o7777, 0o755);
        assert!(report.not_kept.iter().any(|l| l.name == "tool" && l.why.contains("setuid")), "{:?}", report.not_kept);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn names_windows_would_refuse_are_listed_by_a_sender_facing_windows() {
        let (src, dst, logs) = (Dir::new("src"), Dir::new("dst"), Dir::new("log"));
        with_log(&logs);
        src.file("fine.mov", b"fine");
        src.file("bad:name.mov", b"nope");
        std::fs::create_dir_all(src.0.join("empty?")).unwrap();
        let job = read_job(&src.0, false);
        let (mut a, b) = pair().await;
        let to = dst.0.join("copy");
        let rx = tokio::spawn(receive(b, write_job(&to, job.files().clone())));
        let mut jobs = vec![job];
        enable_sends(&mut jobs, Some("windows"));
        let mut tick = time::interval(Duration::from_millis(1));
        while !jobs.is_empty() {
            tokio::select! {
                _ = tick.tick() => { crate::file_speed::pump_read_jobs(&mut jobs, &mut a).await.unwrap(); }
                res = a.next() => {
                    let bytes = res.unwrap().unwrap();
                    if let Some(message::Union::Misc(m)) = Message::parse_from_bytes(&bytes).unwrap().union {
                        if let Some(misc::Union::PluginRequest(p)) = m.union {
                            on_wire(&mut jobs[0], Wire::from_json(&p.content).unwrap(), None);
                        }
                    }
                }
            }
        }
        let report = rx.await.unwrap();
        assert_eq!(report.verified, 1);
        assert_eq!(report.failed[0].name, "bad:name.mov");
        assert!(report.failed[0].why.contains("Windows"), "{:?}", report.failed);
        assert!(report.not_copied.iter().any(|l| l.name == "empty?"), "{:?}", report.not_copied);
        assert!(!to.join("empty?").exists(), "reported, not rewritten");
        assert!(to.join("fine.mov").exists());
    }

    /// A job resumed mid-file: the tail comes across, the whole file is hashed at both ends.
    #[tokio::test(flavor = "multi_thread")]
    async fn resume_re_verifies_the_whole_file() {
        let (src, dst, logs) = (Dir::new("src"), Dir::new("dst"), Dir::new("log"));
        with_log(&logs);
        let data = noise(1024 * 1024 + 3, 10);
        let file = src.file("a.mov", &data);
        let to = dst.0.join("a.mov");
        let offset = 512 * 1024;
        // What an interrupted run leaves: the start of it under .download, with its .digest.
        std::fs::write(format!("{}.download", to.display()), &data[..offset]).unwrap();
        std::fs::write(format!("{}.digest", to.display()), b"{}").unwrap();

        let (mut a, b) = pair().await;
        let mut job = read_job(&file, true);
        job.is_resume = true;
        let mut w = write_job(&to, job.files().clone());
        let answer = FileTransferSendConfirmRequest {
            id: 1,
            file_num: 0,
            union: Some(file_transfer_send_confirm_request::Union::OffsetBlk(offset as u32)),
            ..Default::default()
        };
        w.confirm(&answer).await;
        let rx = tokio::spawn(receive(b, w));
        let mut jobs = vec![job];
        enable_sends(&mut jobs, Some(this_os()));
        crate::file_speed::pump_read_jobs(&mut jobs, &mut a).await.unwrap();
        jobs[0].confirm(&answer).await;
        let mut tick = time::interval(Duration::from_millis(1));
        while !jobs.is_empty() {
            tokio::select! {
                _ = tick.tick() => { crate::file_speed::pump_read_jobs(&mut jobs, &mut a).await.unwrap(); }
                res = a.next() => {
                    let bytes = res.unwrap().unwrap();
                    if let Some(message::Union::Misc(m)) = Message::parse_from_bytes(&bytes).unwrap().union {
                        if let Some(misc::Union::PluginRequest(p)) = m.union {
                            on_wire(&mut jobs[0], Wire::from_json(&p.content).unwrap(), None);
                        }
                    }
                }
            }
        }
        let report = rx.await.unwrap();
        assert!(report.all_passed(), "{}", report.words());
        assert_eq!(std::fs::read(&to).unwrap(), data);
    }

    /// The same, with a start that was already wrong: only the read-back of the whole file sees it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_bad_partial_is_never_given_the_real_name() {
        let (src, dst, logs) = (Dir::new("src"), Dir::new("dst"), Dir::new("log"));
        with_log(&logs);
        let data = noise(1024 * 1024 + 3, 11);
        let file = src.file("a.mov", &data);
        let to = dst.0.join("a.mov");
        let offset = 512 * 1024;
        let mut partial = data[..offset].to_vec();
        partial[100] ^= 1;
        std::fs::write(format!("{}.download", to.display()), &partial).unwrap();
        std::fs::write(format!("{}.digest", to.display()), b"{}").unwrap();
        let (mut a, b) = pair().await;
        let mut job = read_job(&file, true);
        job.is_resume = true;
        let mut w = write_job(&to, job.files().clone());
        let answer = FileTransferSendConfirmRequest {
            id: 1,
            file_num: 0,
            union: Some(file_transfer_send_confirm_request::Union::OffsetBlk(offset as u32)),
            ..Default::default()
        };
        w.confirm(&answer).await;
        let rx = tokio::spawn(receive(b, w));
        let mut jobs = vec![job];
        enable_sends(&mut jobs, Some(this_os()));
        crate::file_speed::pump_read_jobs(&mut jobs, &mut a).await.unwrap();
        jobs[0].confirm(&answer).await;
        let mut tick = time::interval(Duration::from_millis(1));
        while !jobs.is_empty() {
            tokio::select! {
                _ = tick.tick() => { crate::file_speed::pump_read_jobs(&mut jobs, &mut a).await.unwrap(); }
                res = a.next() => {
                    let bytes = res.unwrap().unwrap();
                    if let Some(message::Union::Misc(m)) = Message::parse_from_bytes(&bytes).unwrap().union {
                        if let Some(misc::Union::PluginRequest(p)) = m.union {
                            on_wire(&mut jobs[0], Wire::from_json(&p.content).unwrap(), None);
                        }
                    }
                }
            }
        }
        let report = rx.await.unwrap();
        // Caught, then the resend starts from nothing and comes out right.
        assert!(report.all_passed(), "{}", report.words());
        assert_eq!(std::fs::read(&to).unwrap(), data);
    }

    /// A job resumed at a later file: the ones before it get compared, without being sent.
    #[tokio::test(flavor = "multi_thread")]
    async fn resuming_at_a_later_file_compares_the_earlier_ones() {
        let (src, dst, logs) = (Dir::new("src"), Dir::new("dst"), Dir::new("log"));
        with_log(&logs);
        let one = noise(10_000, 12);
        let two = noise(10_000, 13);
        src.file("a.mov", &one);
        src.file("b.mov", &two);
        let to = dst.0.join("copy");
        std::fs::create_dir_all(&to).unwrap();
        let mut wrong = one.clone();
        wrong[5] ^= 1;
        std::fs::write(to.join("a.mov"), &wrong).unwrap();
        let mut job = read_job(&src.0, false);
        job.file_num = 1;
        let (a, b) = pair().await;
        let mut w = write_job(&to, job.files().clone());
        w.file_num = 1;
        let rx = tokio::spawn(receive(b, w));
        tokio::spawn(send(a, job));
        let report = time::timeout(Duration::from_secs(60), rx).await.unwrap().unwrap();
        assert!(report.all_passed(), "{}", report.words());
        assert_eq!(std::fs::read(to.join("a.mov")).unwrap(), one, "the wrong one was caught and resent");
        assert_eq!(std::fs::read(to.join("b.mov")).unwrap(), two);
    }

    /// An overwrite answered "skip": nothing is sent. Same file counts, different file is listed
    /// and left exactly as it was.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_skip_is_compared_and_what_is_there_is_never_touched() {
        let (src, dst, logs) = (Dir::new("src"), Dir::new("dst"), Dir::new("log"));
        with_log(&logs);
        let same = noise(5000, 14);
        let source_other = noise(5000, 15);
        let dest_other = noise(5000, 16);
        src.file("different.mov", &source_other);
        src.file("same.mov", &same);
        let to = dst.0.join("copy");
        std::fs::create_dir_all(&to).unwrap();
        std::fs::write(to.join("different.mov"), &dest_other).unwrap();
        std::fs::write(to.join("same.mov"), &same).unwrap();
        let job = read_job(&src.0, true);
        let (mut a, b) = pair().await;
        let rx = tokio::spawn(receive(b, write_job(&to, job.files().clone())));
        let mut jobs = vec![job];
        enable_sends(&mut jobs, Some(this_os()));
        let mut tick = time::interval(Duration::from_millis(1));
        let mut answered = -1;
        while !jobs.is_empty() {
            tokio::select! {
                _ = tick.tick() => {
                    crate::file_speed::pump_read_jobs(&mut jobs, &mut a).await.unwrap();
                    if let Some(j) = jobs.first_mut() {
                        if j.file_is_waiting() && j.file_num() != answered {
                            answered = j.file_num();
                            let r = FileTransferSendConfirmRequest {
                                id: 1,
                                file_num: j.file_num(),
                                union: Some(file_transfer_send_confirm_request::Union::Skip(true)),
                                ..Default::default()
                            };
                            j.confirm(&r).await;
                        }
                    }
                }
                res = a.next() => {
                    let bytes = res.unwrap().unwrap();
                    if let Some(message::Union::Misc(m)) = Message::parse_from_bytes(&bytes).unwrap().union {
                        if let Some(misc::Union::PluginRequest(p)) = m.union {
                            on_wire(&mut jobs[0], Wire::from_json(&p.content).unwrap(), None);
                        }
                    }
                }
            }
        }
        let report = rx.await.unwrap();
        assert_eq!(report.verified, 1, "{:?}", report);
        assert_eq!(report.skipped[0].name, "different.mov");
        assert!(report.words().starts_with("Not verified: 1 of 2 files skipped: different.mov ("), "{}", report.words());
        assert_eq!(std::fs::read(to.join("different.mov")).unwrap(), dest_other);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_single_file_job_lands_on_its_own_path() {
        let (src, dst, logs) = (Dir::new("src"), Dir::new("dst"), Dir::new("log"));
        with_log(&logs);
        let data = noise(70_000, 17);
        let file = src.file("a.mov", &data);
        let to = dst.0.join("renamed.mov");
        let report = copy(&file, &to).await;
        assert!(report.all_passed(), "{}", report.words());
        assert_eq!(std::fs::read(&to).unwrap(), data);
        assert!(!Path::new(&format!("{}.download", to.display())).exists());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn many_small_files_all_get_verdicts() {
        let (src, dst, logs) = (Dir::new("src"), Dir::new("dst"), Dir::new("log"));
        with_log(&logs);
        for i in 0..300 {
            src.file(&format!("d{}/f{}.bin", i % 7, i), &noise(i * 37 + 1, i as u64 + 100));
        }
        let to = dst.0.join("copy");
        let report = copy(&src.0, &to).await;
        assert!(report.all_passed(), "{}", report.words());
        assert_eq!(report.verified, 300);
        for i in 0..300 {
            assert_eq!(
                std::fs::read(to.join(format!("d{}/f{}.bin", i % 7, i))).unwrap(),
                noise(i * 37 + 1, i as u64 + 100)
            );
        }
    }

    /// No hello, so nothing is on: the job runs as upstream's, says nothing on the wire, and renames
    /// without a hash. This is every old peer, in either direction.
    #[tokio::test(flavor = "multi_thread")]
    async fn without_a_hello_the_wire_is_upstreams() {
        let (src, dst) = (Dir::new("src"), Dir::new("dst"));
        let data = noise(300_000, 18);
        let file = src.file("a.mov", &data);
        let to = dst.0.join("a.mov");
        let job = read_job(&file, false);
        let (mut a, mut b) = pair().await;
        let mut w = write_job(&to, job.files().clone());
        let rx = tokio::spawn(async move {
            let mut plugin_requests = 0;
            while let Some(Ok(bytes)) = b.next().await {
                match Message::parse_from_bytes(&bytes).unwrap().union {
                    Some(message::Union::FileResponse(fr)) => match fr.union {
                        Some(file_response::Union::Block(block)) => w.write(block).await.unwrap(),
                        Some(file_response::Union::Done(_)) => {
                            w.modify_time();
                            assert!(finish(&w).is_none());
                            return plugin_requests;
                        }
                        _ => {}
                    },
                    Some(message::Union::Misc(_)) => plugin_requests += 1,
                    _ => {}
                }
            }
            panic!("no Done")
        });
        let mut jobs = vec![job];
        enable_sends(&mut jobs, None);
        assert!(!jobs[0].boring.active());
        while !jobs.is_empty() {
            crate::file_speed::pump_read_jobs(&mut jobs, &mut a).await.unwrap();
            tokio::task::yield_now().await;
        }
        assert_eq!(rx.await.unwrap(), 0, "an old peer never sees one of ours");
        for _ in 0..200 {
            if std::fs::metadata(&to).map_or(false, |m| m.len() as usize == data.len()) {
                break;
            }
            time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(std::fs::read(&to).unwrap(), data);
    }

    #[test]
    fn a_read_back_comes_from_the_file_and_sees_every_byte() {
        let dir = Dir::new("rb");
        let data = noise(3 * CHUNK + 17, 19);
        let p = dir.file("x", &data);
        let cancel = AtomicBool::new(false);
        let (size, hash) = hash_from_disk(&p, &cancel).unwrap();
        assert_eq!(size, data.len() as u64);
        assert_eq!(hash, blake3::hash(&data).to_hex().to_string());
        let mut f = data.clone();
        f[2 * CHUNK + 1] ^= 1;
        std::fs::write(&p, &f).unwrap();
        assert_ne!(hash_from_disk(&p, &cancel).unwrap().1, hash);
        cancel.store(true, Ordering::Relaxed);
        assert!(hash_from_disk(&p, &cancel).is_err());
    }
}
