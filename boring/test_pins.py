#!/usr/bin/env python3
"""The pin step: boring/pins.py compares our workflow's toolchain pins with
upstream's at a git ref, and --fix copies upstream's values over.

Run:  python3 -m unittest boring/test_pins.py -v
Each test builds a throwaway git repo shaped like the fork: upstream's
workflow files committed at a ref, our boring-build.yml in the tree.
"""
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

PINS = pathlib.Path(__file__).resolve().parent / "pins.py"

UPSTREAM_BUILD = """env:
  RUST_VERSION: "1.75" # sciter
  MAC_RUST_VERSION: "1.81"
  LLVM_VERSION: "15.0.6"
  FLUTTER_VERSION: "3.24.5"
  VCPKG_COMMIT_ID: "9e593bb18ea69cc5095e012465dcd675a822ed0d"
  VERSION: "1.5.0"
jobs:
  mac:
    steps:
      - run: |
          MIN_MACOS_VERSION="12.3"
"""
UPSTREAM_BRIDGE = """env:
  CARGO_EXPAND_VERSION: "1.0.95"
  FLUTTER_RUST_BRIDGE_VERSION: "1.80.1"
  RUST_VERSION: "1.75"
jobs:
  b:
    strategy:
      matrix:
        job:
          - { flutter-version: "3.22.3" }
          - { flutter-version: "3.44.8" }
"""
UPSTREAM_CARGO = '[package]\nname = "rustdesk"\nversion = "1.5.0"\n'
OURS = """env:
  FLUTTER_VERSION: "3.24.5"
  BRIDGE_FLUTTER_VERSION: "3.22.3"
  FLUTTER_RUST_BRIDGE_VERSION: "1.80.1"
  CARGO_EXPAND_VERSION: "1.0.95"
  BRIDGE_RUST_VERSION: "1.75"
  WIN_RUST_VERSION: "1.75"
  MAC_RUST_VERSION: "1.81"
  LLVM_VERSION: "15.0.6"
  VCPKG_COMMIT_ID: "9e593bb18ea69cc5095e012465dcd675a822ed0d"
  VERSION: "1.5.0"
jobs:
  mac:
    steps:
      - run: |
          MIN_MACOS_VERSION="12.3"
"""


def git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


class PinStep(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="pins-"))
        git(self.root, "init", "-q")
        self.upstream(UPSTREAM_BUILD, UPSTREAM_BRIDGE, UPSTREAM_CARGO, tag="old")
        self.ours = self.root / ".github/workflows/boring-build.yml"
        self.ours.write_text(OURS)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def upstream(self, build, bridge, cargo, tag):
        wf = self.root / ".github/workflows"
        wf.mkdir(parents=True, exist_ok=True)
        (wf / "flutter-build.yml").write_text(build)
        (wf / "bridge.yml").write_text(bridge)
        (self.root / "Cargo.toml").write_text(cargo)
        git(self.root, "add", "-A")
        git(self.root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", tag)
        git(self.root, "tag", tag)

    def pins(self, *args):
        return subprocess.run([sys.executable, str(PINS), "--root", str(self.root), *args],
                              capture_output=True, text=True)

    def test_matching_pins_pass(self):
        r = self.pins("old")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("pins: 11 ok, 0 stale", r.stdout)

    def test_bumped_upstream_pin_is_reported_stale(self):
        self.upstream(UPSTREAM_BUILD.replace('VERSION: "1.5.0"', 'VERSION: "1.5.1"')
                      .replace('"9e593bb18ea69cc5095e012465dcd675a822ed0d"', '"abc123"'),
                      UPSTREAM_BRIDGE.replace('"3.22.3"', '"3.27.0"'),
                      UPSTREAM_CARGO.replace("1.5.0", "1.5.1"), tag="new")
        r = self.pins("new")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("STALE VERSION: ours 1.5.0, upstream 1.5.1", r.stdout)
        self.assertIn("STALE VCPKG_COMMIT_ID: ours 9e593bb18ea69cc5095e012465dcd675a822ed0d, upstream abc123",
                      r.stdout)
        self.assertIn("STALE BRIDGE_FLUTTER_VERSION: ours 3.22.3, upstream 3.27.0", r.stdout)
        self.assertIn("pins: 8 ok, 3 stale", r.stdout)

    def test_fix_copies_upstream_values_then_passes(self):
        self.upstream(UPSTREAM_BUILD.replace('MAC_RUST_VERSION: "1.81"', 'MAC_RUST_VERSION: "1.85"')
                      .replace('MIN_MACOS_VERSION="12.3"', 'MIN_MACOS_VERSION="13.0"'),
                      UPSTREAM_BRIDGE, UPSTREAM_CARGO, tag="new")
        r = self.pins("--fix", "new")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        text = self.ours.read_text()
        self.assertIn('  MAC_RUST_VERSION: "1.85"\n', text)
        self.assertIn('MIN_MACOS_VERSION="13.0"\n', text)
        self.assertEqual(text.count("1.81"), 0)
        self.assertEqual(self.pins("new").returncode, 0)

    def test_missing_upstream_pin_stops_with_exit_2(self):
        self.upstream(UPSTREAM_BUILD.replace('  LLVM_VERSION: "15.0.6"\n', ""),
                      UPSTREAM_BRIDGE, UPSTREAM_CARGO, tag="new")
        r = self.pins("new")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("pin source moved: LLVM_VERSION", r.stderr)


if __name__ == "__main__":
    unittest.main()
