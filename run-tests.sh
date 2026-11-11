#!/usr/bin/env bash
# The boring/ suite; boring/release/build-mac runs it on the fresh tag checkout before any build.
set -euo pipefail
cd "$(dirname "$0")"
python3 -m unittest boring/test_rebrand.py boring/test_pins.py boring/test_dmg.py \
  boring/test_check_workflows.py boring/release/test_build_mac.py
