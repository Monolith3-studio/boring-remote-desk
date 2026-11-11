"""Mac release: signing, DMG, verify.

Seams: boring/dmg/release-mac.sh run as a command (exit code, files written, output), boring/dmg/settings.py as dmgbuild
reads it, and the text of boring/release/build-mac (the local release). The Mac-only tests build a throwaway self-signed
identity in a temp keychain; nothing touches the real signing identity.

Run: python3 -m unittest boring/test_dmg.py -v
"""
import hashlib
import json
import os
import pathlib
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
DMG = ROOT / "boring" / "dmg"
RELEASE = DMG / "release-mac.sh"
ON_MAC = sys.platform == "darwin"
mac_only = unittest.skipUnless(ON_MAC and shutil.which("dmgbuild"), "needs macOS and dmgbuild")


def run(cmd, env=None, **kw):
    e = dict(os.environ)
    for k in ("MAC_SIGN_P12", "MAC_SIGN_P12_PASSWORD", "IS_TAG", "BR_SIGN_SHA1"):
        e.pop(k, None)
    e.update(env or {})
    return subprocess.run(cmd, env=e, capture_output=True, text=True, **kw)


def make_app(where, version="1.5.0"):
    app = pathlib.Path(where) / "BoringRemote.app"
    (app / "Contents" / "MacOS").mkdir(parents=True)
    (app / "Contents" / "Resources").mkdir()
    for exe in ("BoringRemote", "service"):
        shutil.copy("/usr/bin/true", app / "Contents" / "MacOS" / exe)
    shutil.copy(ROOT / "boring" / "art" / "AppIcon.icns", app / "Contents" / "Resources" / "AppIcon.icns")
    with open(app / "Contents" / "Info.plist", "wb") as f:
        plistlib.dump({"CFBundleIdentifier": "io.boringlabs.remote.agent", "CFBundleExecutable": "BoringRemote",
                       "CFBundleShortVersionString": version, "CFBundlePackageType": "APPL",
                       "CFBundleIconFile": "AppIcon"}, f)
    return app


def make_identity(where, cn, p12pw):
    """Throwaway self-signed code-signing identity: (p12 bytes, SHA-1 hex upper)."""
    where = pathlib.Path(where)
    cnf = where / f"{cn}.cnf"
    cnf.write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n"
                   f"[dn]\nCN={cn}\n[ext]\nbasicConstraints=critical,CA:false\n"
                   "keyUsage=critical,digitalSignature\nextendedKeyUsage=critical,codeSigning\n")
    key, crt, p12 = where / f"{cn}.key", where / f"{cn}.crt", where / f"{cn}.p12"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
                    "-days", "30", "-config", cnf], check=True, capture_output=True)
    subprocess.run(["openssl", "pkcs12", "-export", "-inkey", key, "-in", crt, "-passout", f"pass:{p12pw}",
                    "-out", p12], check=True, capture_output=True)
    der = subprocess.run(["openssl", "x509", "-in", crt, "-outform", "der"], check=True, capture_output=True).stdout
    return p12.read_bytes(), hashlib.sha1(der).hexdigest().upper()


def search_list():
    return subprocess.run(["security", "list-keychains", "-d", "user"], capture_output=True, text=True).stdout


@mac_only
class ReleaseMac(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="br-dmg-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.app = make_app(self.tmp / "build")
        self.out = self.tmp / "out"

    def release(self, env=None):
        env = {"RUNNER_TEMP": str(self.tmp), **(env or {})}
        return run(["bash", str(RELEASE), str(self.app), "1.5.0", str(self.out)], env=env, cwd=ROOT)

    def test_no_secrets_on_a_branch_builds_an_adhoc_dmg_and_says_so(self):
        r = self.release({"IS_TAG": "false"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("ad-hoc", r.stdout + r.stderr)
        dmg = self.out / "BoringRemote-1.5.0-macos-arm64-adhoc.dmg"
        self.assertTrue(dmg.is_file())
        sums = self.out / (dmg.name + ".sha256")
        self.assertEqual(sums.read_text(), f"{hashlib.sha256(dmg.read_bytes()).hexdigest()}  {dmg.name}\n")
        self.assertIn("PASS", r.stdout)

    def test_a_tag_without_secrets_is_refused(self):
        r = self.release({"IS_TAG": "true"})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("never ad-hoc", r.stderr)
        self.assertFalse(self.out.exists() and any(self.out.iterdir()))

    def test_only_one_secret_is_refused(self):
        for env in ({"MAC_SIGN_P12": "QUJD"}, {"MAC_SIGN_P12_PASSWORD": "x"}):
            r = self.release({"IS_TAG": "false", **env})
            self.assertNotEqual(r.returncode, 0, env)
            self.assertIn("set both or neither", r.stderr)

    def signed(self, cn="Boring Remote Code Signing", pin=None, extra=None):
        p12pw = "pw-" + os.urandom(8).hex()
        p12, sha = make_identity(self.tmp, cn, p12pw)
        b64 = __import__("base64").b64encode(p12).decode()
        before = search_list()
        r = self.release({"IS_TAG": "true", "MAC_SIGN_P12": b64, "MAC_SIGN_P12_PASSWORD": p12pw,
                          "BR_SIGN_SHA1": pin or sha, **(extra or {})})
        self.assertEqual(search_list(), before, "keychain search list not restored")
        self.assertEqual(list(self.tmp.glob("boring-sign-*")), [], "temp keychain left behind")
        for secret in (p12pw, b64, b64[:40]):
            self.assertNotIn(secret, r.stdout + r.stderr, "secret printed")
        return r, sha

    def test_secrets_sign_with_the_pinned_leaf_and_clean_up(self):
        r, sha = self.signed()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        dmg = self.out / "BoringRemote-1.5.0-macos-arm64.dmg"
        self.assertTrue(dmg.is_file())
        self.assertIn(f"PASS: {dmg} (v1.5.0, signed {sha})", r.stdout)
        # The installed app is what TCC sees: check its designated requirement independently.
        mnt = self.tmp / "mnt"
        mnt.mkdir()
        subprocess.run(["hdiutil", "attach", dmg, "-readonly", "-nobrowse", "-mountpoint", mnt, "-quiet"], check=True)
        try:
            d = subprocess.run(["codesign", "-d", "-r-", mnt / "BoringRemote.app"], capture_output=True, text=True)
        finally:
            subprocess.run(["hdiutil", "detach", mnt, "-quiet", "-force"])
        self.assertIn(f'designated => identifier "io.boringlabs.remote.agent" and certificate leaf = '
                      f'H"{sha.lower()}"', d.stdout + d.stderr)

    def test_a_certificate_that_is_not_the_pinned_one_is_refused(self):
        r, _ = self.signed(pin="B82B9E874D0CA6CD653F1EA8D4A6367F39CAE0C6")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("expected the pinned", r.stderr)
        self.assertFalse((self.out / "BoringRemote-1.5.0-macos-arm64.dmg").exists())

    def test_keychain_identity_signs_in_place_with_the_pinned_leaf(self):
        p12pw = "pw-" + os.urandom(8).hex()
        p12, sha = make_identity(self.tmp, "Boring Remote Code Signing", p12pw)
        kc, kcpw = self.tmp / "local.keychain-db", "kc-" + os.urandom(8).hex()
        before = search_list()
        subprocess.run(["security", "create-keychain", "-p", kcpw, kc], check=True)
        self.addCleanup(subprocess.run, ["security", "delete-keychain", kc], capture_output=True)
        subprocess.run(["security", "unlock-keychain", "-p", kcpw, kc], check=True)
        subprocess.run(["security", "import", self.tmp / "Boring Remote Code Signing.p12", "-k", kc, "-f", "pkcs12",
                        "-P", p12pw, "-T", "/usr/bin/codesign"], check=True, capture_output=True)
        subprocess.run(["security", "set-key-partition-list", "-S", "apple-tool:,apple:,codesign:", "-s", "-k", kcpw,
                        kc], check=True, capture_output=True)
        keep = [l.strip().strip('"') for l in before.splitlines() if l.strip()]
        subprocess.run(["security", "list-keychains", "-d", "user", "-s", kc, *keep], check=True)
        try:
            r = self.release({"BR_SIGN_KEYCHAIN": "1", "BR_SIGN_SHA1": sha})
        finally:
            subprocess.run(["security", "list-keychains", "-d", "user", "-s", *keep], check=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        dmg = self.out / "BoringRemote-1.5.0-macos-arm64.dmg"
        self.assertIn(f"PASS: {dmg} (v1.5.0, signed {sha})", r.stdout)
        self.assertEqual(list(self.tmp.glob("boring-sign-*")), [], "keychain mode made a temp keychain")

    def test_keychain_mode_without_the_identity_is_refused(self):
        r = self.release({"BR_SIGN_KEYCHAIN": "1", "BR_SIGN_SHA1": "00" * 20})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("identity", r.stderr)
        self.assertFalse((self.out / "BoringRemote-1.5.0-macos-arm64.dmg").exists())

    def test_verify_fails_a_plain_dmg(self):
        plain = self.tmp / "plain.dmg"
        subprocess.run(["codesign", "--force", "--deep", "-s", "-", self.app], check=True, capture_output=True)
        subprocess.run(["hdiutil", "create", "-srcfolder", self.app, "-volname", "Boring Remote", "-format", "UDZO",
                        "-quiet", plain], check=True)
        r = run(["bash", str(DMG / "verify-dmg.sh"), str(plain), "1.5.0"])
        self.assertEqual(r.returncode, 1)
        for what in ("Applications link", "background missing", "volume icon missing", "layout missing"):
            self.assertIn(what, r.stdout)


BUILD_MAC = ROOT / "boring" / "release" / "build-mac"
PIN = "B82B9E874D0CA6CD653F1EA8D4A6367F39CAE0C6"  # the cert TCC grants are keyed on


VERSION_FILE = DMG / "write-version-file.sh"


class VersionFile(unittest.TestCase):
    """A tagged build writes the-boring-remote-version.json beside the DMG."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.cargo = self.tmp / "Cargo.toml"
        self.cargo.write_text('[package]\nname = "x"\nversion = "1.5.0"\n\n[dependencies]\nfoo = { version = "9.9.9" }\n')
        self.out = self.tmp / "out"
        self.out.mkdir()
        self.dmg = self.out / "BoringRemote-1.5.0-macos-arm64.dmg"
        self.dmg.write_bytes(b"not really a dmg")
        self.pkg = self.out / "BoringRemote-1.5.0-macos-arm64.app.tar.xz"
        self.pkg.write_bytes(b"not really a package")
        self.minv = self.tmp / "min-version"
        self.minv.write_text("1.4.0\n")

    def write(self, tag):
        return run(["bash", str(VERSION_FILE), str(self.cargo), tag, str(self.dmg), str(self.pkg),
                    str(self.minv), str(self.out)])

    def assert_refused(self, min_version):
        self.minv.write_text(min_version)
        r = self.write("v1.5.0")
        self.assertNotEqual(r.returncode, 0, f"accepted min-version {min_version!r}")
        self.assertIn("min-version", r.stderr)
        self.assertFalse((self.out / "the-boring-remote-version.json").exists())

    def test_min_version_above_version_fails(self):
        self.assert_refused("1.6.0\n")
        self.assert_refused("1.5.1\n")
        self.assert_refused("2.0.0\n")

    def test_min_version_malformed_fails(self):
        for bad in ("1.4\n", "v1.4.0\n", "1.4.0-rc1\n", "\n", "1.4.0\n1.3.0\n", "01.4.0\n"):
            self.assert_refused(bad)

    def test_min_version_equal_to_version_is_allowed(self):
        self.minv.write_text("1.5.0")
        self.assertEqual(self.write("v1.5.0").returncode, 0)

    def test_min_version_compares_numerically(self):
        self.cargo.write_text('[package]\nversion = "1.10.0"\n')
        self.minv.write_text("1.9.0\n")
        self.assertEqual(self.write("v1.10.0").returncode, 0)

    def test_checked_in_min_version_is_strict_and_not_above_cargo(self):
        mv = (ROOT / "boring" / "min-version").read_text()
        self.assertRegex(mv, r"\A(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\n?\Z")
        cargo = re.search(r'^version *= *"([^"]+)"', (ROOT / "Cargo.toml").read_text(), re.M).group(1)
        key = lambda v: tuple(map(int, v.strip().split(".")))
        self.assertLessEqual(key(mv), key(cargo))

    def test_writes_the_contract_json_beside_the_dmg(self):
        r = self.write("v1.5.0")
        self.assertEqual(r.returncode, 0, r.stderr)
        got = json.loads((self.out / "the-boring-remote-version.json").read_text())
        self.assertEqual(got, {
            "version": "1.5.0",
            "sha256": hashlib.sha256(b"not really a dmg").hexdigest(),
            "url": "https://boringlabs.online/downloads/BoringRemote-1.5.0-macos-arm64.dmg",
            "package_sha256": hashlib.sha256(b"not really a package").hexdigest(),
            "package_sig": "",
            "min_version": "1.4.0",
        })
        self.assertEqual(sorted(p.name for p in self.out.iterdir() if p.suffix == ".sig"), [])

    def test_bare_tag_without_v_also_matches(self):
        self.assertEqual(self.write("1.5.0").returncode, 0)

    def test_tag_that_differs_from_cargo_fails_and_writes_nothing(self):
        r = self.write("v1.5.1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("1.5.1", r.stderr)
        self.assertFalse((self.out / "the-boring-remote-version.json").exists())

    def test_non_semver_tag_fails(self):
        self.assertNotEqual(self.write("v1.5.0-rc1").returncode, 0)


PACKAGE = DMG / "make-update-package.sh"


class UpdatePackage(unittest.TestCase):
    """The Update package: the DMG's .app as tar.xz, bundle at the top level."""

    def test_packs_the_app_bundle_at_top_level(self):
        tmp = pathlib.Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, tmp, True)
        app = make_app(tmp / "build")
        r = run(["bash", str(PACKAGE), str(app), "1.5.0", str(tmp / "out")])
        self.assertEqual(r.returncode, 0, r.stderr)
        pkg = tmp / "out" / "BoringRemote-1.5.0-macos-arm64.app.tar.xz"
        self.assertEqual(r.stdout.strip().splitlines()[-1], str(pkg))
        with tarfile.open(pkg, "r:xz") as t:
            names = t.getnames()
        self.assertEqual({n.split("/")[0] for n in names}, {"BoringRemote.app"})
        self.assertIn("BoringRemote.app/Contents/Info.plist", names)

    def test_missing_app_fails(self):
        tmp = pathlib.Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, tmp, True)
        self.assertNotEqual(run(["bash", str(PACKAGE), str(tmp / "nope.app"), "1.5.0", str(tmp)]).returncode, 0)


class ReleaseScripts(unittest.TestCase):
    def test_no_secret_is_echoed_or_traced(self):
        for f in (BUILD_MAC, DMG / "release-mac.sh"):
            text = f.read_text()
            self.assertNotRegex(text, r"set -x|set -o xtrace|bash -x", f)
            for line in text.splitlines():
                if re.search(r"\b(echo|printf)\b", line) and re.search(r"\$\{?(MAC_SIGN_P12\w*|p12|p12pw|pw|kcpw)\b", line):
                    # only allowed: piping the value straight into a consumer
                    self.assertRegex(line, r"\| *base64 --decode", f"{f.name}: {line}")

    def test_pin_is_the_same_everywhere(self):
        for f in (DMG / "release-mac.sh", BUILD_MAC):
            self.assertIn(f"PIN=${{BR_SIGN_SHA1:-{PIN}}}", f.read_text())

    def test_temp_keychain_is_deleted_on_exit(self):
        rel = (DMG / "release-mac.sh").read_text()
        self.assertIn('KC="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/boring-sign-', rel)
        self.assertIn("trap cleanup EXIT", rel)

    def test_dmg_is_built_with_pinned_dmgbuild_never_finder_scripting(self):
        self.assertIn('"dmgbuild==$DMGBUILD_VERSION"', BUILD_MAC.read_text())
        self.assertRegex((ROOT / "boring/release/pins.env").read_text(), r'(?m)^DMGBUILD_VERSION="\d+\.\d+\.\d+"$')
        for f in [BUILD_MAC, *DMG.glob("*.sh"), DMG / "settings.py"]:
            self.assertNotRegex(f.read_text(), r"osascript|tell application \"Finder\"", f)

    def test_the_release_runs_this_suite(self):
        self.assertIn("boring/test_dmg.py", BUILD_MAC.read_text())
        self.assertIn("boring/test_dmg.py", (ROOT / "run-tests.sh").read_text())


class Settings(unittest.TestCase):
    def settings(self):
        g = {"defines": {"app": "/x/BoringRemote.app", "art": str(DMG)}}
        exec(compile((DMG / "settings.py").read_text(), "settings.py", "exec"), g)
        return g

    def test_house_dmg_minimum(self):
        s = self.settings()
        for k in ("show_toolbar", "show_sidebar", "show_pathbar", "show_status_bar", "show_tab_view"):
            self.assertIs(s[k], False, k)
        self.assertEqual(s["window_rect"][1], (640, 468))
        self.assertEqual(s["symlinks"], {"Applications": "/Applications"})
        self.assertEqual(s["files"], ["/x/BoringRemote.app"])
        self.assertEqual(s["icon"], "/x/BoringRemote.app/Contents/Resources/AppIcon.icns")
        self.assertEqual(s["background"], str(DMG / "background.png"))
        self.assertEqual(s["icon_locations"], {"BoringRemote.app": (160, 178), "Applications": (480, 178)})

    def test_art_is_committed_at_1x_and_2x_and_not_blank(self):
        import struct
        for name, size in (("background.png", (640, 440)), ("background@2x.png", (1280, 880))):
            data = (DMG / name).read_bytes()
            self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
            self.assertEqual(struct.unpack(">II", data[16:24]), size, name)
            self.assertGreater(len(data), 20000, f"{name} looks blank")
        self.assertNotIn("background", subprocess.run(["git", "check-ignore", "boring/dmg/background.png",
                                                        "boring/dmg/background@2x.png"], cwd=ROOT,
                                                       capture_output=True, text=True).stdout)

    def test_art_prints_the_first_launch_step(self):
        self.assertIn("right-click the app, then Open", (DMG / "make_art.py").read_text())


if __name__ == "__main__":
    unittest.main()
