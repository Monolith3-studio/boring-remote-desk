"""Mac release (ticket 05): signing, DMG, verify, secret export.

Seams: boring/dmg/release-mac.sh and boring/dmg/export-signing-secret.sh run as
commands (exit code, files written, output), boring/dmg/settings.py as dmgbuild
reads it, and the workflow text. The Mac-only tests build a throwaway self-signed
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

    def test_verify_fails_a_plain_dmg(self):
        plain = self.tmp / "plain.dmg"
        subprocess.run(["codesign", "--force", "--deep", "-s", "-", self.app], check=True, capture_output=True)
        subprocess.run(["hdiutil", "create", "-srcfolder", self.app, "-volname", "Boring Remote", "-format", "UDZO",
                        "-quiet", plain], check=True)
        r = run(["bash", str(DMG / "verify-dmg.sh"), str(plain), "1.5.0"])
        self.assertEqual(r.returncode, 1)
        for what in ("Applications link", "background missing", "volume icon missing", "layout missing"):
            self.assertIn(what, r.stdout)


WORKFLOW = ROOT / ".github" / "workflows" / "boring-build.yml"
PIN = "B82B9E874D0CA6CD653F1EA8D4A6367F39CAE0C6"  # ticket 01: the cert TCC grants are keyed on


def job(name):
    """The text of one job in the workflow (two-space job keys)."""
    text = WORKFLOW.read_text()
    m = re.search(rf"^  {name}:\n(.*?)(?=^  [a-z][\w-]*:\n|\Z)", text, re.S | re.M)
    assert m, f"no job {name}"
    return m.group(1)


def step(job_text, name):
    m = re.search(rf"^      - name: {re.escape(name)}\n(.*?)(?=^      - |\Z)", job_text, re.S | re.M)
    assert m, f"no step {name}"
    return m.group(1)


VERSION_FILE = DMG / "write-version-file.sh"


class VersionFile(unittest.TestCase):
    """Ticket 04: a tagged build writes the-boring-remote-version.json beside the DMG."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.cargo = self.tmp / "Cargo.toml"
        self.cargo.write_text('[package]\nname = "x"\nversion = "1.5.0"\n\n[dependencies]\nfoo = { version = "9.9.9" }\n')
        self.out = self.tmp / "out"
        self.out.mkdir()
        self.dmg = self.out / "BoringRemote-1.5.0-macos-arm64.dmg"
        self.dmg.write_bytes(b"not really a dmg")

    def write(self, tag):
        return run(["bash", str(VERSION_FILE), str(self.cargo), tag, str(self.dmg), str(self.out)])

    def test_writes_the_contract_json_beside_the_dmg(self):
        r = self.write("v1.5.0")
        self.assertEqual(r.returncode, 0, r.stderr)
        got = json.loads((self.out / "the-boring-remote-version.json").read_text())
        self.assertEqual(got, {
            "version": "1.5.0",
            "sha256": hashlib.sha256(b"not really a dmg").hexdigest(),
            "url": "https://boringlabs.online/downloads/BoringRemote-1.5.0-macos-arm64.dmg",
        })

    def test_bare_tag_without_v_also_matches(self):
        self.assertEqual(self.write("1.5.0").returncode, 0)

    def test_tag_that_differs_from_cargo_fails_and_writes_nothing(self):
        r = self.write("v1.5.1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("1.5.1", r.stderr)
        self.assertFalse((self.out / "the-boring-remote-version.json").exists())

    def test_non_semver_tag_fails(self):
        self.assertNotEqual(self.write("v1.5.0-rc1").returncode, 0)

    def test_workflow_runs_it_on_tags_and_ships_the_file_with_the_dmg(self):
        text = WORKFLOW.read_text()
        st = step(job("build-macos"), "Write version file (tags only)")
        self.assertIn("if: startsWith(github.ref, 'refs/tags/')", st)
        self.assertIn("boring/dmg/write-version-file.sh", st)
        self.assertIn("dmg-out", st)
        self.assertLess(job("build-macos").index("Sign, build DMG"), job("build-macos").index("Write version file"))
        self.assertLess(job("build-macos").index("Write version file"), job("build-macos").index("path: dmg-out/*"))
        self.assertNotRegex(text, r"(curl|scp|rsync|wrangler)[^\n]*boringlabs")


class Workflow(unittest.TestCase):
    def test_ci_never_publishes_an_approved_release(self):
        # The Engine installs GitHub's Latest release (the approved release); only Jason sets it.
        creates = [l for l in WORKFLOW.read_text().splitlines() if "gh release create" in l]
        self.assertEqual(len(creates), 2)
        for l in creates:
            self.assertIn("--prerelease", l)
            self.assertIn("--latest=false", l)

    def test_secrets_reach_only_the_sign_step(self):
        text = WORKFLOW.read_text()
        self.assertEqual(sorted(re.findall(r"secrets\.\w+", text)),
                         ["secrets.MAC_SIGN_P12", "secrets.MAC_SIGN_P12_PASSWORD"])
        sign = step(job("build-macos"), "Sign, build DMG, mount and verify")
        self.assertIn("MAC_SIGN_P12: ${{ secrets.MAC_SIGN_P12 }}", sign)
        self.assertIn("MAC_SIGN_P12_PASSWORD: ${{ secrets.MAC_SIGN_P12_PASSWORD }}", sign)
        self.assertIn("IS_TAG: ${{ startsWith(github.ref, 'refs/tags/') }}", sign)
        self.assertIn("boring/dmg/release-mac.sh", sign)

    def test_no_secret_is_echoed_or_traced(self):
        for f in (WORKFLOW, DMG / "release-mac.sh", DMG / "export-signing-secret.sh"):
            text = f.read_text()
            self.assertNotRegex(text, r"set -x|set -o xtrace|bash -x", f)
            for line in text.splitlines():
                if re.search(r"\b(echo|printf)\b", line) and re.search(r"\$\{?(MAC_SIGN_P12\w*|p12|p12pw|pw|kcpw)\b", line):
                    # only allowed: piping the value straight into a consumer
                    self.assertRegex(line, r"\| *(base64 --decode|gh secret set|swift)", f"{f.name}: {line}")

    def test_pin_override_never_set_in_ci(self):
        self.assertNotIn("BR_SIGN_SHA1", WORKFLOW.read_text())
        self.assertNotIn("BR_EXPORT_KEYCHAIN", WORKFLOW.read_text())
        for f in ("release-mac.sh", "export-signing-secret.sh"):
            self.assertIn(f"PIN=${{BR_SIGN_SHA1:-{PIN}}}", (DMG / f).read_text())

    def test_temp_keychain_is_deleted_even_if_the_step_dies(self):
        mac = job("build-macos")
        cleanup = step(mac, "Delete temp signing keychain")
        self.assertIn("if: always()", cleanup)
        self.assertIn('"$RUNNER_TEMP"/boring-sign-*.keychain-db', cleanup)
        self.assertIn("security delete-keychain", cleanup)
        self.assertLess(mac.index("Sign, build DMG"), mac.index("Delete temp signing keychain"))
        rel = (DMG / "release-mac.sh").read_text()
        self.assertIn('KC="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/boring-sign-', rel)
        self.assertIn("trap cleanup EXIT", rel)

    def test_tags_publish_signed_dmg_and_sha256_to_the_release(self):
        rel = job("release-macos")
        self.assertIn("needs: build-macos", rel)
        self.assertIn("if: startsWith(github.ref, 'refs/tags/')", rel)
        self.assertIn("contents: write", rel)
        self.assertIn("-adhoc.dmg", rel)
        self.assertIn("sha256sum -c ./*.dmg.sha256", rel)
        self.assertIn("gh release upload \"$TAG\" --repo \"$GITHUB_REPOSITORY\" --clobber ./*.dmg ./*.dmg.sha256", rel)
        self.assertNotIn("secrets.", rel)
        # same release as the MSI: both jobs create-if-missing with the same notes
        for j in ("release-macos", "release-windows"):
            self.assertIn('--notes "$RELEASE_NOTES"', job(j))

    def test_dmg_is_built_with_dmgbuild_never_finder_scripting(self):
        mac = job("build-macos")
        self.assertIn("dmgbuild==", mac)
        for f in [WORKFLOW, *DMG.glob("*.sh"), DMG / "settings.py"]:
            self.assertNotRegex(f.read_text(), r"osascript|tell application \"Finder\"", f)

    def test_ci_runs_this_suite(self):
        self.assertIn("boring/test_dmg.py", job("rebrand-check"))


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


EXPORT = DMG / "export-signing-secret.sh"


@unittest.skipUnless(ON_MAC, "needs macOS")
class ExportSecret(unittest.TestCase):
    """export-signing-secret.sh against a temp keychain holding the target and a decoy."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="br-export-"))
        cls.kc = cls.tmp / "test.keychain-db"
        subprocess.run(["security", "create-keychain", "-p", "kcpw", cls.kc], check=True)
        subprocess.run(["security", "unlock-keychain", "-p", "kcpw", cls.kc], check=True)
        cls.sha = {}
        for cn in ("Boring Remote Code Signing", "Boring Stories Local Code Signing"):
            p12, sha = make_identity(cls.tmp, cn, "x")
            # -A: the test keychain lets any app export, so no GUI prompt in the suite
            subprocess.run(["security", "import", cls.tmp / f"{cn}.p12", "-k", cls.kc, "-f", "pkcs12", "-P", "x",
                            "-A"], check=True, capture_output=True)
            cls.sha[cn] = sha
        cls.bin = cls.tmp / "bin"
        cls.bin.mkdir()
        gh = cls.bin / "gh"
        # Stub gh: logs argv, stores what `secret set` read on stdin (test key only).
        gh.write_text('#!/bin/bash\necho "$*" >> "$GH_LOG"\n'
                      'if [ "$1 $2" = "secret set" ]; then cat > "$GH_DIR/$3"; fi\n')
        gh.chmod(0o755)

    @classmethod
    def tearDownClass(cls):
        subprocess.run(["security", "delete-keychain", cls.kc])
        shutil.rmtree(cls.tmp, True)

    def export(self, *args, pin=None):
        d = pathlib.Path(tempfile.mkdtemp(dir=self.tmp))
        env = {"BR_EXPORT_KEYCHAIN": str(self.kc), "BR_SIGN_SHA1": pin or self.sha["Boring Remote Code Signing"],
               "PATH": f"{self.bin}:{os.environ['PATH']}", "GH_LOG": str(d / "gh.log"), "GH_DIR": str(d),
               "TMPDIR": str(d) + "/"}
        return run(["bash", str(EXPORT), *args], env=env), d

    def p12_certs(self, p12, pw):
        out = subprocess.run(["openssl", "pkcs12", "-nokeys", "-passin", f"pass:{pw}"], input=p12,
                             capture_output=True).stdout.decode()
        return [hashlib.sha1(subprocess.run(["openssl", "x509", "-outform", "der"], input=c.encode(),
                                            capture_output=True).stdout).hexdigest().upper()
                for c in re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out, re.S)]

    def test_sets_both_secrets_with_only_the_boring_remote_identity(self):
        r, d = self.export()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        log = (d / "gh.log").read_text()
        self.assertIn("secret set MAC_SIGN_P12 -R Monolith3-studio/boring-remote-desk", log)
        self.assertIn("secret set MAC_SIGN_P12_PASSWORD -R Monolith3-studio/boring-remote-desk", log)
        pw = (d / "MAC_SIGN_P12_PASSWORD").read_text()
        b64 = (d / "MAC_SIGN_P12").read_text()
        self.assertGreaterEqual(len(pw), 32)
        p12 = __import__("base64").b64decode(b64)
        self.assertEqual(self.p12_certs(p12, pw), [self.sha["Boring Remote Code Signing"]])
        keys = subprocess.run(["openssl", "pkcs12", "-nocerts", "-nodes", "-passin", f"pass:{pw}"], input=p12,
                              capture_output=True).stdout.count(b"BEGIN PRIVATE KEY")
        self.assertEqual(keys, 1)
        for secret in (pw, b64[:40]):
            self.assertNotIn(secret, r.stdout + r.stderr)
        # Nothing the script wrote to TMPDIR holds the key (gh stub's own files aside).
        for f in d.rglob("*"):
            if f.is_file() and f.name not in ("MAC_SIGN_P12", "MAC_SIGN_P12_PASSWORD", "gh.log"):
                self.assertNotIn(p12[:64], f.read_bytes(), f)

    def test_round_trips_into_release_mac(self):
        r, d = self.export()
        self.assertEqual(r.returncode, 0, r.stderr)
        rel = run(["bash", "-c", 'printf "%s" "$MAC_SIGN_P12" | base64 --decode | openssl pkcs12 -nokeys '
                   '-passin env:MAC_SIGN_P12_PASSWORD | openssl x509 -noout -subject'],
                  env={"MAC_SIGN_P12": (d / "MAC_SIGN_P12").read_text(),
                       "MAC_SIGN_P12_PASSWORD": (d / "MAC_SIGN_P12_PASSWORD").read_text()})
        self.assertIn("Boring Remote Code Signing", rel.stdout)

    def test_dry_run_sets_nothing(self):
        r, d = self.export("--dry-run")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse((d / "gh.log").exists() and "secret set" in (d / "gh.log").read_text())
        self.assertIn("dry run", r.stdout)

    def test_wrong_pin_sets_nothing(self):
        r, d = self.export(pin=self.sha["Boring Stories Local Code Signing"][::-1])
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse((d / "MAC_SIGN_P12").exists())
        self.assertFalse((d / "MAC_SIGN_P12_PASSWORD").exists())


if __name__ == "__main__":
    unittest.main()
