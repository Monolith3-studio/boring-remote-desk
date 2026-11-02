//! v1.7 ticket 17: the Mac bundle is "Boring Remote.app". 1.6.x installed
//! "/Applications/BoringRemote.app" with both launchd plists pointing there, and its own
//! updater can only drop the new version at that old path. Once per launch, with the main
//! window up and no update pending, the app finishes the move: one admin prompt runs
//! `Resources/boring-install-update.sh --move-bundle` (one bundle left, plists rewritten by
//! the new `service --write-plists`, both jobs reloaded, the app reopened if it ran from the
//! old path). Exe, bundle id, labels and config dirs keep the internal name, so settings,
//! Trusted Controllers and TCC grants carry over.
use std::path::Path;

pub const BUNDLE: &str = "/Applications/Boring Remote.app";
/// 1.6.x's bundle.
pub const OLD_BUNDLE: &str = "/Applications/BoringRemote.app";
pub const AGENT_LABEL: &str = "io.boringlabs.remote.agent";
/// The LaunchDaemon (hostd) and LaunchAgent plists `service --write-plists` writes.
pub const PLISTS: [&str; 2] = [
    "/Library/LaunchDaemons/io.boringlabs.remote.hostd.plist",
    "/Library/LaunchAgents/io.boringlabs.remote.agent.plist",
];

fn under(root: &Path, abs: &str) -> std::path::PathBuf {
    root.join(abs.trim_start_matches('/'))
}

/// True while `root` ("/" for real) still has 1.6.x's bundle, a plist that runs it, or an agent
/// plist that leaves `--server` down after a clean exit (KeepAlive SuccessfulExit=false, before t17).
pub fn needs_move(root: &Path) -> bool {
    let old = format!("{OLD_BUNDLE}/");
    under(root, OLD_BUNDLE).exists()
        || PLISTS
            .iter()
            .any(|p| std::fs::read_to_string(under(root, p)).is_ok_and(|t| t.contains(&old)))
        || std::fs::read_to_string(under(root, PLISTS[1])).is_ok_and(|t| t.contains("SuccessfulExit"))
}

/// Some(true) when `exe` runs from the old bundle, Some(false) from the new one, None when
/// it isn't installed (a DMG or Downloads copy, which never moves anything).
pub fn running_from_old(exe: &Path) -> Option<bool> {
    if exe.starts_with(OLD_BUNDLE) {
        Some(true)
    } else if exe.starts_with(BUNDLE) {
        Some(false)
    } else {
        None
    }
}

/// One admin prompt naming Boring Remote; the script path is quoted, never spliced.
#[cfg(target_os = "macos")]
const OSA: &str = r#"on run argv
  do shell script (quoted form of item 1 of argv) & " --move-bundle" with prompt "Boring Remote needs your password to finish updating." with administrator privileges
end run"#;

/// Call once the main window is up. `support_dir` holds install-update.sh's `update-pending`:
/// a 1.6.x update's rollback watchdog owns the bundle until it drops that file. `quit` ends
/// this app when it ran from the old path (the script reopens it from the new one).
#[cfg(target_os = "macos")]
pub fn start(support_dir: &'static str, quit: fn()) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::thread::spawn(move || run(Path::new(support_dir), quit));
    });
}

#[cfg(target_os = "macos")]
fn run(support_dir: &Path, quit: fn()) {
    let Ok(exe) = std::env::current_exe() else { return };
    let Some(from_old) = running_from_old(&exe) else { return };
    let pending = support_dir.join("update-pending");
    for _ in 0..120 {
        if !pending.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    if pending.exists() {
        return;
    }
    if !needs_move(Path::new("/")) {
        start_agent();
        return;
    }
    let Some(script) = exe.parent().and_then(|m| m.parent()).map(|c| c.join("Resources/boring-install-update.sh"))
    else {
        return;
    };
    log::info!("moving {OLD_BUNDLE} to {BUNDLE}");
    match std::process::Command::new("osascript").arg("-e").arg(OSA).arg(&script).output() {
        Ok(out) if out.status.success() => {
            if from_old {
                quit();
            }
        }
        Ok(out) => log::warn!("bundle move: {}", String::from_utf8_lossy(&out.stderr).trim()),
        Err(e) => log::warn!("bundle move: {e}"),
    }
}

/// The agent (`--server`) serves sessions. Start it when remote access is on and it isn't up
/// (a plist written before t17 left it down after macOS's "Quit & Reopen").
#[cfg(target_os = "macos")]
fn start_agent() {
    if !Path::new(PLISTS[1]).exists() || hbb_common::config::Config::get_option("stop-service") == "Y" {
        return;
    }
    let target = format!("gui/{}/{AGENT_LABEL}", unsafe { libc::getuid() });
    let up = std::process::Command::new("launchctl")
        .args(["print", &target])
        .output()
        .is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).lines().any(|l| l == "\tstate = running"));
    if !up {
        log::info!("starting {target}");
        let _ = std::process::Command::new("launchctl").args(["kickstart", &target]).status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn root() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("boring-bm-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("Applications")).unwrap();
        fs::create_dir_all(d.join("Library/LaunchDaemons")).unwrap();
        fs::create_dir_all(d.join("Library/LaunchAgents")).unwrap();
        d
    }

    #[test]
    fn old_bundle_or_a_plist_running_it_needs_a_move() {
        let r = root();
        fs::create_dir_all(under(&r, OLD_BUNDLE)).unwrap();
        assert!(needs_move(&r));
        fs::remove_dir_all(under(&r, OLD_BUNDLE)).unwrap();
        // 1.6.x's daemon ran `/bin/sh -c /Applications/BoringRemote.app/Contents/MacOS/service`
        fs::write(under(&r, PLISTS[0]), "<string>/Applications/BoringRemote.app/Contents/MacOS/service</string>").unwrap();
        assert!(needs_move(&r));
    }

    #[test]
    fn agent_plist_that_stays_down_after_a_clean_exit_needs_a_rewrite() {
        let r = root();
        fs::create_dir_all(under(&r, BUNDLE)).unwrap();
        fs::write(under(&r, PLISTS[0]), "<string>/Applications/Boring Remote.app/Contents/MacOS/service</string>").unwrap();
        // 1.6.x / first 1.7 builds: KeepAlive {SuccessfulExit=false}, so "Quit & Reopen" left --server down
        fs::write(under(&r, PLISTS[1]), "<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>").unwrap();
        assert!(needs_move(&r));
    }

    #[test]
    fn new_bundle_with_new_plists_needs_nothing() {
        let r = root();
        fs::create_dir_all(under(&r, BUNDLE)).unwrap();
        for p in PLISTS {
            fs::write(under(&r, p), "<string>/Applications/Boring Remote.app/Contents/MacOS/service</string>").unwrap();
        }
        assert!(!needs_move(&r));
        assert!(!needs_move(&r.join("missing")));
    }

    #[test]
    fn only_an_installed_app_moves() {
        let exe = |s: &str| std::path::PathBuf::from(s);
        assert_eq!(running_from_old(&exe("/Applications/BoringRemote.app/Contents/MacOS/BoringRemote")), Some(true));
        assert_eq!(running_from_old(&exe("/Applications/Boring Remote.app/Contents/MacOS/BoringRemote")), Some(false));
        assert_eq!(running_from_old(&exe("/Volumes/Boring Remote/Boring Remote.app/Contents/MacOS/BoringRemote")), None);
        assert_eq!(running_from_old(&exe("/Applications/BoringRemote.app.previous/Contents/MacOS/BoringRemote")), None);
    }
}
