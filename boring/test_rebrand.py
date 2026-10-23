#!/usr/bin/env python3
"""Seam 2: the rebrand script against a clean copy of this checkout.

Run:  python3 -m unittest boring/test_rebrand.py -v
Needs git and an initialised libs/hbb_common submodule. Each test exports a
fresh tree (committed HEAD of the repo and of the submodule) into a temp dir,
so your working tree is never touched.
"""
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
REBRAND = HERE / "rebrand.py"
CHECK = HERE / "check.py"


def export_clean_tree(dest):
    for sub, out in (("", dest), ("libs/hbb_common", dest / "libs/hbb_common")):
        out.mkdir(parents=True, exist_ok=True)
        archive = subprocess.run(["git", "-C", str(REPO / sub), "archive", "HEAD"],
                                 check=True, capture_output=True).stdout
        subprocess.run(["tar", "-x", "-C", str(out)], input=archive, check=True)
    # Our own workflows come from the working tree, so the tests see what you are editing.
    wf = dest / ".github/workflows"
    wf.mkdir(parents=True, exist_ok=True)
    for ours in (REPO / ".github/workflows").glob("boring-*.yml"):
        shutil.copy2(ours, wf / ours.name)
    # An unpatched upstream tree still has its own workflows; put one back so the
    # tree under test looks like a fresh upstream checkout.
    (wf / "flutter-build.yml").write_text(
        "jobs:\n  b:\n    steps:\n      - run: ./build.py --flutter --hwcodec --unix-file-copy-paste\n")


def run(script, root, *extra):
    return subprocess.run([sys.executable, str(script), str(root), *extra],
                          capture_output=True, text=True)


def tree_hashes(root):
    import hashlib
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


class RebrandSeam(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="rebrand-"))
        self.root = self.tmp / "tree"
        export_clean_tree(self.root)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def rebrand(self):
        r = run(REBRAND, self.root)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r

    def test_check_fails_on_clean_upstream_tree(self):
        r = run(CHECK, self.root, "--no-rerun")
        self.assertNotEqual(r.returncode, 0)
        for fact in ("rendezvous servers empty", "whitelist", "app name", "hwcodec"):
            self.assertIn(fact, r.stdout)

    def test_check_passes_after_rebrand(self):
        self.rebrand()
        r = run(CHECK, self.root)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertRegex(r.stdout, r"rebrand check: \d+ passed, 0 failed")

    def test_second_run_is_noop(self):
        self.rebrand()
        before = tree_hashes(self.root)
        r = self.rebrand()
        self.assertIn("rebrand: 0 changed, 0 moved", r.stdout)
        self.assertEqual(before, tree_hashes(self.root))

    def test_banned_codec_in_a_workflow_fails_check(self):
        self.rebrand()
        (self.root / ".github/workflows/boring-sneaky.yml").write_text(
            "jobs:\n  b:\n    steps:\n      - run: python3 build.py --flutter --vram\n")
        r = run(CHECK, self.root, "--no-rerun")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("boring-sneaky.yml", r.stdout)

    def test_build_py_refuses_banned_codecs(self):
        self.rebrand()
        for flag in ("--hwcodec", "--vram"):
            r = subprocess.run([sys.executable, "build.py", "--flutter", flag, "--print-features"],
                               cwd=self.root, capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0, flag)
            self.assertIn("banned", r.stdout + r.stderr)

    def test_moved_patch_target_stops_the_script(self):
        cfg = self.root / "libs/hbb_common/src/config.rs"
        cfg.write_text(cfg.read_text().replace('&["rs-ny.rustdesk.com"]', '&["rs-sg.rustdesk.com"]'))
        r = run(REBRAND, self.root)
        self.assertEqual(r.returncode, 2)
        self.assertIn("patch target moved", r.stderr)
        self.assertIn("libs/hbb_common/src/config.rs", r.stderr)


if __name__ == "__main__":
    unittest.main()
