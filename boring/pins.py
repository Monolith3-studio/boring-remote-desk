#!/usr/bin/env python3
"""Compare our workflow's toolchain pins with upstream's at a git ref.

Usage:  python3 boring/pins.py [--fix] [--root REPO] UPSTREAM_REF

Our tree deletes upstream's workflows, so their pins are read from the ref
with `git show`. The pins come from upstream's own build so ours build the
same way. Exit 0 = all match, 1 = some stale (--fix copies upstream's values
into boring-build.yml and exits 0), 2 = a pin's source moved upstream (fix the
entry in PINS below). Run it on every rebase (boring/REBASE.md).

Stdlib only.
"""
import argparse
import pathlib
import re
import subprocess
import sys

OURS = ".github/workflows/boring-build.yml"
BUILD = ".github/workflows/flutter-build.yml"
BRIDGE = ".github/workflows/bridge.yml"


def env(key):
    return rf'^  {key}: "([^"]*)"'


MIN_MACOS = r'MIN_MACOS_VERSION="([^"]*)"'

# (our name, upstream file, upstream regex, our regex). Group 1 is the value.
PINS = [
    ("FLUTTER_VERSION", BUILD, env("FLUTTER_VERSION"), env("FLUTTER_VERSION")),
    ("MAC_RUST_VERSION", BUILD, env("MAC_RUST_VERSION"), env("MAC_RUST_VERSION")),
    ("WIN_RUST_VERSION", BUILD, env("RUST_VERSION"), env("WIN_RUST_VERSION")),
    ("LLVM_VERSION", BUILD, env("LLVM_VERSION"), env("LLVM_VERSION")),
    ("VCPKG_COMMIT_ID", BUILD, env("VCPKG_COMMIT_ID"), env("VCPKG_COMMIT_ID")),
    ("MIN_MACOS_VERSION", BUILD, MIN_MACOS, MIN_MACOS),
    ("BRIDGE_RUST_VERSION", BRIDGE, env("RUST_VERSION"), env("BRIDGE_RUST_VERSION")),
    ("FLUTTER_RUST_BRIDGE_VERSION", BRIDGE, env("FLUTTER_RUST_BRIDGE_VERSION"),
     env("FLUTTER_RUST_BRIDGE_VERSION")),
    ("CARGO_EXPAND_VERSION", BRIDGE, env("CARGO_EXPAND_VERSION"), env("CARGO_EXPAND_VERSION")),
    # the default bridge is the first matrix entry (the one for Flutter 3.24.x builds)
    ("BRIDGE_FLUTTER_VERSION", BRIDGE, r'flutter-version: "([^"]*)"', env("BRIDGE_FLUTTER_VERSION")),
    # the app version; the Mac smoke test compares `--version` with it
    ("VERSION", "Cargo.toml", r'^version = "([^"]*)"', env("VERSION")),
]


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("ref")
    ap.add_argument("--fix", action="store_true")
    ap.add_argument("--root", default=pathlib.Path(__file__).resolve().parent.parent)
    a = ap.parse_args(argv[1:])
    root = pathlib.Path(a.root)
    ours_path = root / OURS
    ours = ours_path.read_text(encoding="utf-8")
    files, ok, stale, moved = {}, 0, [], []
    for name, path, up_re, our_re in PINS:
        if path not in files:
            r = subprocess.run(["git", "-C", str(root), "show", f"{a.ref}:{path}"],
                               capture_output=True, text=True)
            files[path] = r.stdout if r.returncode == 0 else ""
        up = re.search(up_re, files[path], re.M)
        mine = re.search(our_re, ours, re.M)
        if not up:
            moved.append(f"pin source moved: {name} (not found in {a.ref}:{path})")
        elif not mine:
            moved.append(f"pin source moved: {name} (not found in {OURS})")
        elif up.group(1) == mine.group(1):
            ok += 1
        else:
            stale.append((name, mine, up.group(1)))
    for name, mine, val in stale:
        print(f"STALE {name}: ours {mine.group(1)}, upstream {val}")
    for m in moved:
        print("ERROR", m, file=sys.stderr)
    print(f"pins: {ok} ok, {len(stale)} stale")
    if moved:
        return 2
    if stale and a.fix:
        for name, mine, val in sorted(stale, key=lambda s: -s[1].start(1)):
            ours = ours[:mine.start(1)] + val + ours[mine.end(1):]
        ours_path.write_text(ours, encoding="utf-8")
        print(f"fixed {len(stale)} pin(s) in {OURS}")
        return 0
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
