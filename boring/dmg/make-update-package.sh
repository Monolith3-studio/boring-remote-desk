#!/bin/bash
# Build the Update package beside the DMG (spec slice 3, ADR 0004): the same signed .app that went
# into the DMG, tar -cJf with the bundle at the top level. v1.7 t17: "Boring Remote.app" goes in
# as "BoringRemote.app", the only name a 1.6.x installer takes; 1.7's takes either and installs
# "Boring Remote.app". Drop the rename once boring/min-version is 1.7.0 or later.
#   boring/dmg/make-update-package.sh <app> <version> <out dir>
# Writes <out dir>/BoringRemote-<version>-macos-arm64.app.tar.xz and prints its path. Signs nothing.
set -euo pipefail
APP=${1:?usage: make-update-package.sh <app> <version> <out dir>}
VER=${2:?usage: make-update-package.sh <app> <version> <out dir>}
OUT=${3:?usage: make-update-package.sh <app> <version> <out dir>}
[ -d "$APP" ] || { echo "make-update-package: no app at $APP" >&2; exit 1; }
mkdir -p "$OUT"
PKG="$(cd "$OUT" && pwd)/BoringRemote-$VER-macos-arm64.app.tar.xz"
NAME=$(basename "$APP")
COPYFILE_DISABLE=1 tar -cJf "$PKG" -s "|^${NAME//./\\.}|BoringRemote.app|" -C "$(dirname "$APP")" "$NAME"
echo "$PKG"
