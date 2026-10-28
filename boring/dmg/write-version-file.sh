#!/bin/bash
# Write the version file beside a release DMG (docs/version-file.md, ADR 0003/0004).
#   boring/dmg/write-version-file.sh <Cargo.toml> <tag> <dmg> <package> <min-version file> <out dir>
# version = Cargo.toml's package version; the tag (leading "v" optional) must equal it. min_version
# comes from the checked-in file (boring/min-version): strict X.Y.Z and <= version. Any failure exits
# 1 and writes nothing. package_sig stays empty: signing is local (slice 4); no .sig is written here.
# Writes <out dir>/the-boring-remote-version.json. Uploads nothing.
set -euo pipefail
CARGO=${1:?usage: write-version-file.sh <Cargo.toml> <tag> <dmg> <package> <min-version file> <out dir>}
TAG=${2:?usage: write-version-file.sh <Cargo.toml> <tag> <dmg> <package> <min-version file> <out dir>}
DMG=${3:?usage: write-version-file.sh <Cargo.toml> <tag> <dmg> <package> <min-version file> <out dir>}
PKG=${4:?usage: write-version-file.sh <Cargo.toml> <tag> <dmg> <package> <min-version file> <out dir>}
MINF=${5:?usage: write-version-file.sh <Cargo.toml> <tag> <dmg> <package> <min-version file> <out dir>}
OUT=${6:?usage: write-version-file.sh <Cargo.toml> <tag> <dmg> <package> <min-version file> <out dir>}
die() { echo "write-version-file: $*" >&2; exit 1; }

[ -f "$CARGO" ] || die "no $CARGO"
[ -f "$DMG" ] || die "no DMG at $DMG"
[ -f "$PKG" ] || die "no update package at $PKG"
[ -f "$MINF" ] || die "no min-version file at $MINF"
# first `version = "..."` line, which is the [package] one in this Cargo.toml
VER=$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$CARGO" | head -1)
[[ $VER =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Cargo.toml version '$VER' is not X.Y.Z"
T=${TAG#v}
[ "$T" = "$VER" ] || die "tag '$TAG' does not match Cargo.toml version $VER"

N='(0|[1-9][0-9]*)'
[ "$(wc -l < "$MINF" | tr -d ' ')" -le 1 ] || die "min-version file has more than one line"
MIN=$(tr -d '\n' < "$MINF")
[[ $MIN =~ ^$N\.$N\.$N$ ]] || die "min-version '$MIN' is not strict X.Y.Z"
IFS=. read -r a b c <<< "$MIN"; IFS=. read -r x y z <<< "$VER"
(( a < x || (a == x && (b < y || (b == y && c <= z))) )) || die "min-version $MIN is above version $VER"

NAME=$(basename "$DMG")
SHA=$(shasum -a 256 "$DMG" | awk '{print $1}')
PSHA=$(shasum -a 256 "$PKG" | awk '{print $1}')
mkdir -p "$OUT"
printf '{"version":"%s","sha256":"%s","url":"https://boringlabs.online/downloads/%s","package_sha256":"%s","package_sig":"","min_version":"%s"}\n' \
  "$VER" "$SHA" "$NAME" "$PSHA" "$MIN" \
  > "$OUT/the-boring-remote-version.json"
cat "$OUT/the-boring-remote-version.json"
