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
/// (a plist written before t17 left it down after macOS's "Quit & Reopen"; a replaced bundle can
/// leave launchd holding it at "spawn failed").
#[cfg(target_os = "macos")]
fn start_agent() {
    if !Path::new(PLISTS[1]).exists() || hbb_common::config::Config::get_option("stop-service") == "Y" {
        return;
    }
    let uid = unsafe { libc::getuid() };
    let target = format!("gui/{uid}/{AGENT_LABEL}");
    let mut launchctl = |args: &[&str]| {
        std::process::Command::new("launchctl")
            .args(args)
            .output()
            .ok()
            .map(|o| (o.status.success(), String::from_utf8_lossy(&o.stdout).into_owned()))
    };
    if launchctl(&["print", &target]).is_some_and(|(ok, out)| ok && agent_running(&out)) {
        return;
    }
    log::info!("starting {target}");
    let mut sleep = || std::thread::sleep(std::time::Duration::from_millis(500));
    if !restart_agent(&mut launchctl, &mut sleep, uid) {
        log::warn!("{target} is still not running");
    }
}

/// launchctl's own line for the job, not its endpoints' (those say active).
pub fn agent_running(launchctl_print: &str) -> bool {
    launchctl_print.lines().any(|l| l == "\tstate = running")
}

/// Start the agent and check it came up. `kickstart -k` alone is not enough: after the app
/// bundle is replaced, launchd can hold the job at "spawn failed" (EX_CONFIG 78, "needs LWCR
/// update"), and kickstart exits 0 without starting it. Only bootout + bootstrap clears that.
/// `launchctl` runs one launchctl command: Some((exited 0, stdout)). True once it is running.
pub fn restart_agent(
    launchctl: &mut dyn FnMut(&[&str]) -> Option<(bool, String)>,
    sleep: &mut dyn FnMut(),
    uid: u32,
) -> bool {
    const TRIES: usize = 10; // 0.5 s apart
    let job = format!("gui/{uid}/{AGENT_LABEL}");
    let came_up = |launchctl: &mut dyn FnMut(&[&str]) -> Option<(bool, String)>, sleep: &mut dyn FnMut()| {
        for i in 0..TRIES {
            if launchctl(&["print", &job]).is_some_and(|(ok, out)| ok && agent_running(&out)) {
                return true;
            }
            if i + 1 < TRIES {
                sleep();
            }
        }
        false
    };
    launchctl(&["kickstart", "-k", &job]);
    if came_up(launchctl, sleep) {
        return true;
    }
    launchctl(&["bootout", &job]);
    // bootout returns before the job is gone; bootstrap fails while it is still there
    for _ in 0..TRIES {
        if !launchctl(&["print", &job]).is_some_and(|(ok, _)| ok) {
            break;
        }
        sleep();
    }
    launchctl(&["bootstrap", &format!("gui/{uid}"), PLISTS[1]]);
    launchctl(&["kickstart", &job]); // loaded but not started
    came_up(launchctl, sleep)
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

    /// A fake launchctl holding the agent the way a real Mac (macOS 26) did after the bundle was
    /// replaced: "spawn failed", EX_CONFIG 78, "needs LWCR update"; kickstart exits 0 and does nothing.
    struct Launchd {
        calls: Vec<String>,
        loaded: bool,
        running: bool,
        kickstart_fixes: bool,
        bootstrap_fixes: bool,
    }
    const STUCK: &str = "gui/501/x = {\n\tstate = spawn scheduled\n\tjob state = spawn failed\n\tlast exit code = 78: EX_CONFIG\n}\n";
    const UP: &str = "gui/501/x = {\n\tstate = running\n\tpid = 4242\n}\n";
    impl Launchd {
        fn new(kickstart_fixes: bool, bootstrap_fixes: bool) -> Self {
            Launchd { calls: vec![], loaded: true, running: false, kickstart_fixes, bootstrap_fixes }
        }
        fn run(&mut self, args: &[&str]) -> Option<(bool, String)> {
            self.calls.push(args.join(" "));
            match args[0] {
                "print" => return Some((self.loaded, if self.running { UP } else { STUCK }.into())),
                "kickstart" => self.running |= self.kickstart_fixes,
                "bootout" => (self.loaded, self.running) = (false, false),
                "bootstrap" => (self.loaded, self.running) = (true, self.bootstrap_fixes),
                _ => {}
            }
            Some((true, String::new()))
        }
    }

    fn restart(l: &mut Launchd) -> bool {
        restart_agent(&mut |a: &[&str]| l.run(a), &mut || {}, 501)
    }

    #[test]
    fn agent_counts_as_running_only_on_launchctls_own_state_line() {
        assert!(agent_running(UP));
        assert!(!agent_running(STUCK));
        assert!(!agent_running("\t\tstate = active\n"));
    }

    #[test]
    fn kickstart_that_brings_the_agent_up_is_enough() {
        let mut l = Launchd::new(true, true);
        assert!(restart(&mut l));
        assert_eq!(l.calls[0], format!("kickstart -k gui/501/{AGENT_LABEL}"));
        assert!(!l.calls.iter().any(|c| c.starts_with("bootout")));
    }

    #[test]
    fn agent_stuck_at_spawn_failed_is_booted_out_and_in_again_then_checked() {
        let mut l = Launchd::new(false, true);
        assert!(restart(&mut l));
        let at = |c: &str| l.calls.iter().position(|x| x == c).unwrap_or_else(|| panic!("no {c} in {:?}", l.calls));
        assert!(at(&format!("bootout gui/501/{AGENT_LABEL}")) < at(&format!("bootstrap gui/501 {}", PLISTS[1])));
        assert!(l.calls.last().unwrap().starts_with("print "));
    }

    #[test]
    fn agent_still_down_after_bootstrap_says_so() {
        assert!(!restart(&mut Launchd::new(false, false)));
    }
}
