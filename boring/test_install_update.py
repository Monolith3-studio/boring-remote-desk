"""Install update script (spec slice 6) against a fake root.

Never runs as root and never touches the real /Applications: the script is run
as the current user with BORING_TEST_ROOT pointing at a temp dir, and
launchctl / xattr / pkill / osascript / sudo are stubs that only log their args.

    python3 -m unittest boring/test_install_update.py -v
"""
import os
import pathlib
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent
SCRIPTS = REPO / "src/platform/privileges_scripts"
SCRIPT = SCRIPTS / "install-update.sh"
GOOD_SIG = "GOOD-SIG"

INFO_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleShortVersionString</key><string>{v}</string>
</dict></plist>
"""
# Stand-in for the app binary: `--boring-verify-package <file> <sig>` exits 0 only for GOOD_SIG.
FAKE_BIN = """#!/bin/sh
echo "$0 $*" >> "$STUB_LOG"
[ "$1" = --boring-verify-package ] && [ -f "$2" ] && [ "$3" = "{sig}" ]
"""
STUB = ('#!/bin/sh\necho "$(basename "$0") $*" >> "$STUB_LOG"\n'
        # one [arg] per argument, so a path with a space shows whether it stayed one argument
        'if [ -n "$ARGS_LOG" ]; then { printf %s "$(basename "$0")"; for a in "$@"; do printf " [%s]" "$a"; done; echo; }'
        ' >> "$ARGS_LOG"; fi\n')
# t17: `service --write-plists` writes both plists for the new bundle (as the real one does, as root).
FAKE_SERVICE = """#!/bin/sh
echo "service $*" >> "$STUB_LOG"
[ "$1" = --write-plists ] || exit 1
for p in "$BORING_TEST_ROOT/Library/LaunchDaemons/{daemon}.plist" "$BORING_TEST_ROOT/Library/LaunchAgents/{agent}.plist"; do
  echo "<string>/Applications/Boring Remote.app/Contents/MacOS/service</string>" > "$p"
done
"""
BUNDLE = "Boring Remote.app"   # t17: what people see
OLD_BUNDLE = "BoringRemote.app"  # 1.6.x, and the top-level name inside the update package


def make_app(parent, version, marker, name=BUNDLE):
    app = parent / name
    (app / "Contents/MacOS").mkdir(parents=True)
    (app / "Contents/Info.plist").write_text(INFO_PLIST.format(v=version))
    b = app / "Contents/MacOS/BoringRemote"
    b.write_text(FAKE_BIN.format(sig=GOOD_SIG))
    b.chmod(0o755)
    svc = app / "Contents/MacOS/service"
    svc.write_text(FAKE_SERVICE.format(daemon=daemon_label(), agent=agent_label()))
    svc.chmod(0o755)
    (app / "Contents/marker").write_text(marker)
    return app


class InstallUpdate(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.root = self.tmp / "root"
        (self.root / "Applications").mkdir(parents=True)
        self.app = make_app(self.root / "Applications", "1.5.0", "old")
        self.stubs = self.tmp / "stubs"
        self.stubs.mkdir()
        for name in ("launchctl", "xattr", "pkill", "osascript", "sudo", "chown"):
            p = self.stubs / name
            p.write_text(STUB)
            p.chmod(0o755)
        self.log = self.tmp / "stub.log"
        self.log.write_text("")
        self.args_log = self.tmp / "args.log"
        self.args_log.write_text("")
        for d in ("LaunchDaemons", "LaunchAgents"):
            (self.root / "Library" / d).mkdir(parents=True)

    def package(self, version="1.6.0", name=OLD_BUNDLE):
        src = self.tmp / f"src-{version}-{name}"
        make_app(src, version, "new", name)
        pkg = self.tmp / f"pkg-{version}-{name}.tar.xz"
        with tarfile.open(pkg, "w:xz") as t:
            t.add(src / name, arcname=name)
        return pkg

    def run_script(self, *args, root=True, wait=2):
        env = {"PATH": f"{self.stubs}:/usr/bin:/bin:/usr/sbin:/sbin", "STUB_LOG": str(self.log),
               "ARGS_LOG": str(self.args_log),
               "TMPDIR": str(self.tmp), "BORING_ROLLBACK_WAIT": str(wait)}
        if root:
            env["BORING_TEST_ROOT"] = str(self.root)
        return subprocess.run(["/bin/sh", str(SCRIPT), *map(str, args)], env=env,
                              capture_output=True, text=True)

    def marker(self, app):
        return (app / "Contents/marker").read_text()

    def calls(self, tool):
        return [l for l in self.log.read_text().splitlines() if l.startswith(tool + " ")]

    def assert_untouched(self, r):
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertEqual(self.marker(self.app), "old")
        self.assertFalse(pathlib.Path(str(self.app) + ".previous").exists())
        self.assertFalse((self.root / "Library/Application Support/Boring Remote/update-pending").exists())
        self.assertEqual(self.calls("launchctl"), [])

    def test_good_package_is_swapped_in_and_service_restarted(self):
        r = self.run_script(self.package(), GOOD_SIG, "1.6.0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.marker(self.app), "new")
        self.assertEqual(self.marker(pathlib.Path(str(self.app) + ".previous")), "old")
        self.assertIn(f"xattr -cr {self.app}", self.log.read_text())
        self.assertIn(f"launchctl kickstart -k system/{daemon_label()}", self.log.read_text())
        self.assertTrue(any(c.startswith("launchctl asuser ") and c.endswith(f"open {self.app}")
                            for c in self.calls("launchctl")) or console_is_root())
        self.assertEqual(self.calls("osascript"), [])
        pending = (self.root / "Library/Application Support/Boring Remote/update-pending").read_text()
        self.assertRegex(pending, r"\Afrom=1\.5\.0\nto=1\.6\.0\ntime=\d+\n\Z")
        # the sig is checked on the script's own copy, not the caller's path
        verify = [l for l in self.log.read_text().splitlines() if "--boring-verify-package" in l][0]
        self.assertNotIn(str(self.tmp / "pkg-"), verify)

    def support(self, name):
        return self.root / "Library/Application Support/Boring Remote" / name

    def wait_for(self, cond, secs=10):
        end = time.time() + secs
        while time.time() < end:
            if cond():
                return True
            time.sleep(0.1)
        return False

    def test_unhealthy_new_app_is_rolled_back(self):
        r = self.run_script(self.package(), GOOD_SIG, "1.6.0", wait=1)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.wait_for(lambda: self.support("update-failed").exists()
                                      and self.support("update-failed").read_text()), "no rollback")
        prev = pathlib.Path(str(self.app) + ".previous")
        self.assertTrue(self.wait_for(lambda: not prev.exists()))
        self.assertEqual(self.marker(self.app), "old")
        self.assertEqual(self.support("update-failed").read_text(), "1.6.0\n")
        self.assertFalse(self.support("update-pending").exists())
        # install restart + rollback kill + rollback restart
        self.assertTrue(self.wait_for(lambda: len(self.calls("pkill")) == 3), self.calls("pkill"))
        self.assertTrue(self.wait_for(lambda: len([c for c in self.calls("launchctl") if c.endswith(f"open {self.app}")]) == 2) or console_is_root())
        self.assertEqual(self.calls("launchctl").count(f"launchctl kickstart -k system/{daemon_label()}"), 2)
        opens = [c for c in self.calls("launchctl") if c.endswith(f"open {self.app}")]
        self.assertTrue(len(opens) == 2 or console_is_root(), opens)
        # only the console user (who runs the app) can write them; no other local user
        for f in ("update-failed", "update-healthy"):
            self.assertEqual(os.stat(self.support(f)).st_mode & 0o077, 0, f)
            if not console_is_root():
                self.assertIn(f"chown {console_user()} {self.support(f)}", self.log.read_text())

    def test_healthy_new_app_keeps_update_and_drops_previous(self):
        r = self.run_script(self.package(), GOOD_SIG, "1.6.0", wait=10)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.support("update-healthy").write_text("1.6.0\n")  # what the new app writes once healthy
        prev = pathlib.Path(str(self.app) + ".previous")
        self.assertTrue(self.wait_for(lambda: not prev.exists()), "previous not removed")
        self.assertTrue(self.wait_for(lambda: not self.support("update-pending").exists()))
        self.assertEqual(self.marker(self.app), "new")
        self.assertFalse(self.support("update-failed").exists() and self.support("update-failed").read_text())
        self.assertEqual(self.calls("pkill"), ["pkill -x BoringRemote"])

    def test_stale_healthy_marker_does_not_count(self):
        self.support("update-healthy").parent.mkdir(parents=True)
        self.support("update-healthy").write_text("1.6.0\n")  # left over from an earlier run
        self.run_script(self.package(), GOOD_SIG, "1.6.0", wait=1)
        self.assertTrue(self.wait_for(lambda: self.support("update-failed").exists()
                                      and self.support("update-failed").read_text()))
        self.assertTrue(self.wait_for(lambda: self.marker(self.app) == "old"))

    def stub(self, name, body):
        p = self.stubs / name
        p.write_text(STUB + body)
        p.chmod(0o755)

    def test_failing_xattr_after_swap_still_rolls_back(self):
        self.stub("xattr", "exit 1\n")
        self.run_script(self.package(), GOOD_SIG, "1.6.0", wait=1)
        self.assertTrue(self.wait_for(lambda: self.support("update-failed").exists()
                                      and self.support("update-failed").read_text()), "no rollback")
        self.assertTrue(self.wait_for(lambda: self.marker(self.app) == "old"))

    def test_healthy_marker_without_a_running_service_rolls_back(self):
        self.stub("launchctl", '[ "$1" = print ] && exit 1\n')
        self.run_script(self.package(), GOOD_SIG, "1.6.0", wait=2)
        self.support("update-healthy").write_text("1.6.0\n")
        self.assertTrue(self.wait_for(lambda: self.support("update-failed").exists()
                                      and self.support("update-failed").read_text()), "no rollback")
        self.assertTrue(self.wait_for(lambda: self.marker(self.app) == "old"))

    def test_bad_sig_leaves_install_untouched(self):
        self.assert_untouched(self.run_script(self.package(), "EVIL", "1.6.0"))

    def test_version_mismatch_leaves_install_untouched(self):
        self.assert_untouched(self.run_script(self.package("1.6.1"), GOOD_SIG, "1.6.0"))

    def test_not_newer_leaves_install_untouched(self):
        for v in ("1.5.0", "1.4.9"):
            self.assert_untouched(self.run_script(self.package(v), GOOD_SIG, v))

    def test_bad_version_arg_or_missing_bundle_leaves_install_untouched(self):
        self.assert_untouched(self.run_script(self.package(), GOOD_SIG, "1.6"))
        self.assert_untouched(self.run_script(self.package(name="Other.app"), GOOD_SIG, "1.6.0"))
        self.assert_untouched(self.run_script(self.tmp / "missing.tar.xz", GOOD_SIG, "1.6.0"))

    def test_without_root_or_test_root_it_refuses(self):
        r = self.run_script(self.package(), GOOD_SIG, "1.6.0", root=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.marker(self.app), "old")

    # --- v1.7 t17: the bundle is "Boring Remote.app"; 1.6.x left "BoringRemote.app" ----------
    def args(self, tool):
        return [l for l in self.args_log.read_text().splitlines() if l.startswith(tool + " ")]

    def plists(self):
        return [self.root / f"Library/LaunchDaemons/{daemon_label()}.plist",
                self.root / f"Library/LaunchAgents/{agent_label()}.plist"]

    def old_install(self, version="1.6.4", plists=True):
        """A 1.6.x Mac: BoringRemote.app, and plists that run it (the daemon through sh -c)."""
        shutil.rmtree(self.app)
        old = make_app(self.root / "Applications", version, "old16", OLD_BUNDLE)
        if plists:
            for p in self.plists():
                p.write_text("<string>/bin/sh</string><string>-c</string>"
                             "<string>/Applications/BoringRemote.app/Contents/MacOS/service</string>")
        return old

    def assert_new_plists(self):
        for p in self.plists():
            self.assertIn("/Applications/Boring Remote.app/", p.read_text())
            self.assertNotIn("/Applications/BoringRemote.app/", p.read_text())

    def test_move_bundle_renames_a_16x_install_and_rewrites_its_plists(self):
        old = self.old_install()
        r = self.run_script("--move-bundle")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(old.exists())
        self.assertEqual(self.marker(self.app), "old16")
        self.assert_new_plists()
        self.assertIn("service --write-plists", self.log.read_text())
        args = self.args("launchctl")
        self.assertIn(f"launchctl [bootout] [system/{daemon_label()}]", args)
        self.assertIn(f"launchctl [bootstrap] [system] [{self.plists()[0]}]", args)
        self.assertLess(args.index(f"launchctl [bootout] [system/{daemon_label()}]"),
                        args.index(f"launchctl [bootstrap] [system] [{self.plists()[0]}]"))
        # reopened from the new path, which stays one argument with its space
        self.assertTrue(self.wait_for(lambda: any(a.endswith(f"[open] [{self.app}]") for a in self.args("launchctl")))
                        or console_is_root(), self.args("launchctl"))

    def test_move_bundle_keeps_the_newer_of_two_bundles(self):
        old = self.old_install("1.6.4")
        make_app(self.root / "Applications", "1.7.0", "dmg")  # 1.7 dragged from the DMG beside 1.6.x
        r = self.run_script("--move-bundle")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(old.exists())
        self.assertEqual(self.marker(self.app), "dmg")
        self.assert_new_plists()

    def test_move_bundle_once_moved_does_nothing(self):
        r = self.run_script("--move-bundle")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.marker(self.app), "old")
        self.assertEqual(self.calls("launchctl"), [])
        self.assertEqual(self.calls("service"), [])

    def test_move_bundle_without_a_service_only_renames(self):
        old = self.old_install(plists=False)
        r = self.run_script("--move-bundle")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(old.exists())
        self.assertEqual(self.marker(self.app), "old16")
        self.assertEqual([c for c in self.calls("launchctl") if " asuser " not in f" {c} "], [])
        self.assertEqual(self.calls("service"), [])

    def test_update_over_a_16x_install_moves_it_first(self):
        old = self.old_install("1.6.4")
        r = self.run_script(self.package("1.7.0"), GOOD_SIG, "1.7.0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(old.exists())
        self.assertEqual(self.marker(self.app), "new")
        self.assertEqual(self.marker(pathlib.Path(str(self.app) + ".previous")), "old16")
        self.assert_new_plists()

    def test_package_with_the_new_bundle_name_installs_too(self):
        r = self.run_script(self.package(name=BUNDLE), GOOD_SIG, "1.6.0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.marker(self.app), "new")

    def test_service_label_is_the_daemon_plist_label(self):
        m = re.search(r'^SERVICE_LABEL="([^"]+)"$', SCRIPT.read_text(), re.M)
        self.assertEqual(m.group(1), daemon_label())

    def test_rebrand_patches_the_label_from_hostd_id(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("rebrand", REPO / "boring/rebrand.py")
        rb = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(rb)
        hits = [p for p in rb.PATCHES if p[0] == "src/platform/privileges_scripts/install-update.sh"]
        self.assertEqual([(p[1], p[2]) for p in hits],
                         [('SERVICE_LABEL="com.carriez.RustDesk_service"', f'SERVICE_LABEL="{rb.HOSTD_ID}"'),
                          ('AGENT_LABEL="com.carriez.RustDesk_server"', f'AGENT_LABEL="{rb.AGENT_ID}"')])  # t17
        daemon = [p[2] for p in rb.PATCHES if p[0].endswith("daemon.plist") and "RustDesk_service" in p[1]]
        self.assertEqual(daemon, [rb.HOSTD_ID])


def daemon_label():
    t = (SCRIPTS / "daemon.plist").read_text()
    return re.search(r"<key>Label</key>\s*<string>([^<]+)</string>", t).group(1)


def agent_label():
    t = (SCRIPTS / "agent.plist").read_text()
    return re.search(r"<key>Label</key>\s*<string>([^<]+)</string>", t).group(1)


def console_user():
    return subprocess.run(["stat", "-f", "%Su", "/dev/console"], capture_output=True, text=True).stdout.strip()


def console_is_root():
    return subprocess.run(["stat", "-f", "%Su", "/dev/console"], capture_output=True, text=True).stdout.strip() in ("", "root")


if __name__ == "__main__":
    unittest.main()
