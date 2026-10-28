#!/usr/bin/env bash
# The suite CI runs before any build (rebrand-check job).
set -euo pipefail
cd "$(dirname "$0")"
python3 -m unittest boring/test_rebrand.py boring/test_pins.py boring/test_dmg.py
