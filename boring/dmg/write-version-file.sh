#!/bin/bash
# Write the update-notice version file beside a release DMG (docs/version-file.md, ADR 0003).
#   boring/dmg/write-version-file.sh <Cargo.toml> <tag> <dmg> <out dir>
# version = Cargo.toml's package version; the tag (leading "v" optional) must equal it, else exit 1
# and nothing is written. Writes <out dir>/the-boring-remote-version.json. Uploads nothing.
set -euo pipefail
CARGO=${1:?usage: write-version-file.sh <Cargo.toml> <tag> <dmg> <out dir>}
TAG=${2:?usage: write-version-file.sh <Cargo.toml> <tag> <dmg> <out dir>}
DMG=${3:?usage: write-version-file.sh <Cargo.toml> <tag> <dmg> <out dir>}
OUT=${4:?usage: write-version-file.sh <Cargo.toml> <tag> <dmg> <out dir>}
die() { echo "write-version-file: $*" >&2; exit 1; }

[ -f "$CARGO" ] || die "no $CARGO"
[ -f "$DMG" ] || die "no DMG at $DMG"
# first `version = "..."` line, which is the [package] one in this Cargo.toml
VER=$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$CARGO" | head -1)
[[ $VER =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Cargo.toml version '$VER' is not X.Y.Z"
T=${TAG#v}
[ "$T" = "$VER" ] || die "tag '$TAG' does not match Cargo.toml version $VER"

NAME=$(basename "$DMG")
SHA=$(shasum -a 256 "$DMG" | awk '{print $1}')
mkdir -p "$OUT"
printf '{"version":"%s","sha256":"%s","url":"https://boringlabs.online/downloads/%s"}\n' "$VER" "$SHA" "$NAME" \
  > "$OUT/the-boring-remote-version.json"
cat "$OUT/the-boring-remote-version.json"
