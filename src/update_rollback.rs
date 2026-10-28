//! App side of the update rollback (ADR 0004, spec slice 7). install-update.sh
//! leaves `update-pending` (root-owned) plus two world-writable files in
//! `/Library/Application Support/Boring Remote`: the app writes its version into
//! `update-healthy` once healthy (the root watchdog then deletes `.previous` and
//! the pending marker), and empties `update-failed` after showing it once.
use std::path::Path;

pub const SUPPORT_DIR: &str = "/Library/Application Support/Boring Remote";

/// Call once the main window is up. Returns the version the update tried to reach
/// if it failed and was rolled back (show "Update failed, still on <running>"
/// once). Reports health when an update to `running` is pending and `healthy`.
pub fn on_launch(dir: &Path, running: &str, healthy: bool) -> Option<String> {
    let read = |f: &str| std::fs::read_to_string(dir.join(f)).unwrap_or_default();
    let failed = read("update-failed").trim().to_owned();
    if !failed.is_empty() {
        // Truncate, not delete: the dir is root-owned, the file is 0666.
        let _ = std::fs::write(dir.join("update-failed"), "");
        return Some(failed);
    }
    let pending_to = read("update-pending").lines().find_map(|l| l.strip_prefix("to=").map(str::to_owned));
    if healthy && pending_to.as_deref() == Some(running) {
        let _ = std::fs::write(dir.join("update-healthy"), format!("{running}\n"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn dir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("boring-rb-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("update-healthy"), "").unwrap();
        fs::write(d.join("update-failed"), "").unwrap();
        d
    }
    fn read(d: &Path, f: &str) -> String {
        fs::read_to_string(d.join(f)).unwrap_or_default()
    }

    #[test]
    fn failed_update_is_reported_once_then_cleared() {
        let d = dir();
        fs::write(d.join("update-failed"), "1.6.0\n").unwrap();
        assert_eq!(on_launch(&d, "1.5.0", true), Some("1.6.0".into()));
        assert_eq!(on_launch(&d, "1.5.0", true), None);
    }

    #[test]
    fn healthy_launch_of_pending_version_reports_health() {
        let d = dir();
        fs::write(d.join("update-pending"), "from=1.5.0\nto=1.6.0\ntime=1\n").unwrap();
        assert_eq!(on_launch(&d, "1.6.0", true), None);
        assert_eq!(read(&d, "update-healthy"), "1.6.0\n");
    }

    #[test]
    fn unhealthy_or_other_version_does_not_report_health() {
        let d = dir();
        fs::write(d.join("update-pending"), "from=1.5.0\nto=1.6.0\ntime=1\n").unwrap();
        on_launch(&d, "1.6.0", false);
        on_launch(&d, "1.5.0", true);
        assert_eq!(read(&d, "update-healthy"), "");
    }

    #[test]
    fn nothing_pending_nothing_written() {
        let d = dir();
        assert_eq!(on_launch(&d, "1.6.0", true), None);
        assert_eq!(read(&d, "update-healthy"), "");
        let none = d.join("missing");
        assert_eq!(on_launch(&none, "1.6.0", true), None);
    }
}
