"""boring/release/build-mac: the local Mac release (spec slice 7). Its pure parts only.

Seam: the script run as a command with --dry-run against a throwaway git repo
(BR_REPO) shaped like the fork: arguments, the tag/Cargo.toml check, the
signing choice, the output names and the order of the plan. `security`,
`codesign`, `dmgbuild` and `hdiutil` are stubs on PATH, so nothing is built,
signed or mounted, and the real keychain is never read.

    python3 -m unittest boring/release/test_build_mac.py -v
"""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE / "build-mac"
PIN = "B82B9E874D0CA6CD653F1EA8D4A6367F39CAE0C6"


def git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


class DryRun(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="build-mac-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        (self.repo / "Cargo.toml").write_text('[package]\nname = "x"\nversion = "1.8.0"\n')
        git(self.repo, "add", "-A")
        git(self.repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "x")
        git(self.repo, "tag", "v1.8.0")
        git(self.repo, "tag", "v1.9.0")  # a tag that does not match Cargo.toml
        self.out = self.tmp / "out"
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.touched = self.tmp / "touched"
        for tool in ("codesign", "dmgbuild", "hdiutil", "flutter", "cargo"):
            self.stub(tool, f'echo {tool} >> "{self.touched}"; exit 1')
        self.identity(True)

    def stub(self, name, body):
        f = self.bin / name
        f.write_text(f"#!/bin/bash\n{body}\n")
        f.chmod(0o755)

    def identity(self, present):
        line = f'  1) {PIN} "Boring Remote Code Signing"' if present else ""
        self.stub("security", f'[ "$1" = find-identity ] && printf "%s\\n" \'{line}\' '
                              f'"     {1 if present else 0} valid identities found"; exit 0')

    def run_script(self, *args, env=None):
        e = {k: v for k, v in os.environ.items() if not k.startswith(("MAC_SIGN", "BR_"))}
        e.update({"BR_REPO": str(self.repo), "PATH": f"{self.bin}:{os.environ['PATH']}", **(env or {})})
        return subprocess.run(["bash", str(SCRIPT), *args], env=e, capture_output=True, text=True)

    def plan(self, *args, **kw):
        r = self.run_script("--dry-run", *args, str(self.out), **kw)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(self.out.exists(), "dry run wrote the out dir")
        self.assertFalse(self.touched.exists(), "dry run ran a build/sign/mount tool")
        return r.stdout

    def test_no_tag_is_a_usage_error(self):
        r = self.run_script()
        self.assertEqual(r.returncode, 2)
        self.assertIn("usage: build-mac", r.stderr)

    def test_tag_must_be_x_y_z(self):
        for bad in ("1.8", "v1.8.0-rc1", "latest"):
            r = self.run_script("--dry-run", bad)
            self.assertEqual(r.returncode, 2, bad)
            self.assertIn("not vX.Y.Z", r.stderr)

    def test_unknown_tag_is_refused(self):
        r = self.run_script("--dry-run", "v2.0.0")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no tag v2.0.0", r.stderr)

    def test_tag_that_is_not_cargo_version_is_refused(self):
        r = self.run_script("--dry-run", "v1.9.0")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Cargo.toml at v1.9.0 says 1.8.0", r.stderr)

    def test_signed_plan_has_the_ci_names_in_the_ci_order(self):
        out = self.plan("v1.8.0")
        self.assertIn(f'signing: keychain identity "Boring Remote Code Signing" ({PIN})', out)
        for name in ("BoringRemote-1.8.0-macos-arm64.dmg", "BoringRemote-1.8.0-macos-arm64.dmg.sha256",
                     "BoringRemote-1.8.0-macos-arm64.app.tar.xz", "the-boring-remote-version.json",
                     "BoringRemote-1.8.0-macos-arm64-unsigned.zip"):
            self.assertIn(f"  {self.out}/{name}\n", out)
        steps = ["boring/rebrand.py", "boring/check.py", "flutter_rust_bridge_codegen", "vcpkg",
                 "build.py --flutter --unix-file-copy-paste --screencapturekit", "--version",
                 "BoringRemote-1.8.0-macos-arm64-unsigned.zip", "boring/test_dmg.py",
                 "boring/dmg/release-mac.sh", "boring/dmg/make-update-package.sh",
                 "boring/dmg/write-version-file.sh"]
        at = [out.index(s, out.index("plan:")) for s in steps]
        self.assertEqual(at, sorted(at), out)
        self.assertRegex(out, r"write-version-file\.sh \S*/Cargo\.toml v1\.8\.0 ")
        self.assertIn("then: boring/release/sign-release", out)

    def test_no_identity_falls_back_to_adhoc_loudly_and_writes_no_version_file(self):
        self.identity(False)
        out = self.plan("v1.8.0")
        self.assertIn("WARNING", out)
        self.assertIn("ad-hoc", out)
        self.assertIn("BoringRemote-1.8.0-macos-arm64-adhoc.dmg", out)
        self.assertNotIn("the-boring-remote-version.json", out)
        self.assertNotIn("write-version-file.sh", out)

    def test_adhoc_flag_forces_adhoc_with_an_identity_present(self):
        out = self.plan("--adhoc", "v1.8.0")
        self.assertIn("BoringRemote-1.8.0-macos-arm64-adhoc.dmg", out)
        self.assertNotIn("keychain identity", out)

    def test_from_app_skips_the_build_and_packages_that_app(self):
        app = self.tmp / "Boring Remote.app"  # v1.7 t17: the bundle people see
        app.mkdir()
        out = self.plan("--from-app", str(app), "v1.8.0")
        self.assertNotIn("build.py", out)
        self.assertNotIn("unsigned.zip", out)
        # signs a copy, never the app it was handed
        shown = str(app).replace(" ", "\\ ")  # build-mac prints argv shell-quoted
        self.assertIn(f"+ ditto {shown} ", out)
        rel = next(l for l in out.splitlines() if "boring/dmg/release-mac.sh" in l)
        self.assertNotIn(f" {shown} ", rel)
        self.assertIn("Boring\\ Remote.app 1.8.0", rel)
        self.assertNotIn("BoringRemote.app", out)

    def test_signing_secrets_in_the_environment_are_ignored(self):
        self.identity(False)
        out = self.plan("v1.8.0", env={"MAC_SIGN_P12": "QUJD", "MAC_SIGN_P12_PASSWORD": "pw"})
        self.assertIn("-adhoc.dmg", out)
        self.assertNotIn("QUJD", out)
        for line in SCRIPT.read_text().splitlines():
            if "MAC_SIGN_P12" in line and not line.lstrip().startswith("#"):
                self.assertRegex(line, r"^\s*unset MAC_SIGN_P12 MAC_SIGN_P12_PASSWORD")

    def test_never_publishes_or_uses_finder_scripting(self):
        text = SCRIPT.read_text()
        self.assertNotRegex(text, r"gh release|curl|wrangler|scp |rsync|osascript|tell application")
        self.assertNotRegex(text, r"set -x|bash -x")


if __name__ == "__main__":
    unittest.main()
