"""Install update script (spec slice 6) against a fake root.

Never runs as root and never touches the real /Applications: the script is run
as the current user with BORING_TEST_ROOT pointing at a temp dir, and
launchctl / xattr / pkill / osascript / sudo are stubs that only log their args.

    python3 -m unittest boring/test_install_update.py -v
"""
import os
import pathlib
import re
import subprocess
import tarfile
import tempfile
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
STUB = '#!/bin/sh\necho "$(basename "$0") $*" >> "$STUB_LOG"\n'


def make_app(parent, version, marker):
    app = parent / "BoringRemote.app"
    (app / "Contents/MacOS").mkdir(parents=True)
    (app / "Contents/Info.plist").write_text(INFO_PLIST.format(v=version))
    b = app / "Contents/MacOS/BoringRemote"
    b.write_text(FAKE_BIN.format(sig=GOOD_SIG))
    b.chmod(0o755)
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

    def package(self, version="1.6.0", name="BoringRemote.app"):
        src = self.tmp / f"src-{version}-{name}"
        app = make_app(src, version, "new")
        if name != app.name:
            app.rename(src / name)
        pkg = self.tmp / f"pkg-{version}-{name}.tar.xz"
        with tarfile.open(pkg, "w:xz") as t:
            t.add(src / name, arcname=name)
        return pkg

    def run_script(self, *args, root=True):
        env = {"PATH": f"{self.stubs}:/usr/bin:/bin:/usr/sbin:/sbin", "STUB_LOG": str(self.log),
               "TMPDIR": str(self.tmp)}
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
                         [('SERVICE_LABEL="com.carriez.RustDesk_service"', f'SERVICE_LABEL="{rb.HOSTD_ID}"')])
        daemon = [p[2] for p in rb.PATCHES if p[0].endswith("daemon.plist") and "RustDesk_service" in p[1]]
        self.assertEqual(daemon, [rb.HOSTD_ID])


def daemon_label():
    t = (SCRIPTS / "daemon.plist").read_text()
    return re.search(r"<key>Label</key>\s*<string>([^<]+)</string>", t).group(1)


def console_is_root():
    return subprocess.run(["stat", "-f", "%Su", "/dev/console"], capture_output=True, text=True).stdout.strip() in ("", "root")


if __name__ == "__main__":
    unittest.main()
