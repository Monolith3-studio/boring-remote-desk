#!/bin/bash
# Sign the Mac app, build the branded DMG with dmgbuild, mount and verify it, write its sha256.
#   boring/dmg/release-mac.sh <BoringRemote.app> <version> <out dir>     (run from the repo root)
#
# Signing identity comes from the environment (GitHub Actions secrets):
#   MAC_SIGN_P12           base64 of a PKCS#12 holding ONLY "Boring Remote Code Signing"
#   MAC_SIGN_P12_PASSWORD  its passphrase
# Both set   -> imported into a temp keychain (deleted on exit, search list restored), the app is
#               signed with the pinned certificate, the DMG is BoringRemote-<v>-macos-arm64.dmg.
# Neither    -> ad-hoc signed, BoringRemote-<v>-macos-arm64-adhoc.dmg, and the log says so.
#               Refused when IS_TAG=true: a tag never ships an ad-hoc build.
# One of two -> refused.
# The pin is the certificate's SHA-1 (ticket 01). TCC keeps grants only for this exact leaf.
# Never prints a secret. Needs dmgbuild (pip) and Xcode's codesign.
set -euo pipefail
set +x

APP=${1:?usage: release-mac.sh <app> <version> <out dir>}
VER=${2:?usage: release-mac.sh <app> <version> <out dir>}
OUT=${3:?usage: release-mac.sh <app> <version> <out dir>}
PIN=${BR_SIGN_SHA1:-B82B9E874D0CA6CD653F1EA8D4A6367F39CAE0C6}  # override is for the test suite only
HERE=$(cd "$(dirname "$0")" && pwd)
p12=${MAC_SIGN_P12:-}
p12pw=${MAC_SIGN_P12_PASSWORD:-}
unset MAC_SIGN_P12 MAC_SIGN_P12_PASSWORD  # nothing below needs them in the environment

die() { echo "release-mac: $*" >&2; exit 1; }
[ -d "$APP" ] || die "no app at $APP"

if [ -n "$p12" ] && [ -n "$p12pw" ]; then
  MODE=signed
elif [ -n "$p12" ] || [ -n "$p12pw" ]; then
  die "only one of MAC_SIGN_P12 / MAC_SIGN_P12_PASSWORD is set; set both or neither"
elif [ "${IS_TAG:-false}" = true ]; then
  die "tag build without MAC_SIGN_P12 / MAC_SIGN_P12_PASSWORD: a release is never ad-hoc signed"
else
  MODE=adhoc
fi

KC=
ORIG_LIST=()
cleanup() {
  if [ -n "$KC" ]; then
    if [ ${#ORIG_LIST[@]} -gt 0 ]; then security list-keychains -d user -s "${ORIG_LIST[@]}" || true; fi
    security delete-keychain "$KC" 2>/dev/null || true
    rm -f "$KC"
    echo "release-mac: temp keychain deleted"
  fi
}
trap cleanup EXIT

if [ $MODE = signed ]; then
  while IFS= read -r k; do ORIG_LIST+=("$k"); done < <(security list-keychains -d user | sed -e 's/^ *"//' -e 's/"$//')
  KC="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/boring-sign-$$.keychain-db"
  kcpw=$(openssl rand -hex 24)
  security create-keychain -p "$kcpw" "$KC"
  security set-keychain-settings -lut 3600 "$KC"
  security unlock-keychain -p "$kcpw" "$KC"
  # The key goes from the secret straight into the keychain through a pipe, never a file.
  printf '%s' "$p12" | base64 --decode | security import /dev/stdin -k "$KC" -f pkcs12 -P "$p12pw" \
    -T /usr/bin/codesign >/dev/null || die "could not import MAC_SIGN_P12 (bad base64 or passphrase?)"
  p12='' p12pw=''
  ids=$(security find-identity -p codesigning "$KC" | grep -E '^ +[0-9]+\) ' || true)
  n=$(printf '%s\n' "$ids" | grep -c . || true)
  [ "$n" = 1 ] || die "MAC_SIGN_P12 holds $n code-signing identities; it must hold exactly one"
  got=$(printf '%s\n' "$ids" | awk '{print $2}')
  [ "$got" = "$PIN" ] || die "MAC_SIGN_P12 certificate is $got, expected the pinned $PIN"
  security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$kcpw" "$KC" >/dev/null
  kcpw=''
  security list-keychains -d user -s "$KC" "${ORIG_LIST[@]}"
  codesign --force --deep --sign "$PIN" "$APP"
  echo "release-mac: signed with the pinned Boring Remote Code Signing certificate ($PIN)"
  NAME="BoringRemote-$VER-macos-arm64.dmg"
else
  echo "::warning::No MAC_SIGN_P12 secrets (fork or PR): ad-hoc signed. TCC grants will not survive an update with this build."
  echo "release-mac: ad-hoc signed (no signing secrets)"
  codesign --force --deep --sign - "$APP"
  NAME="BoringRemote-$VER-macos-arm64-adhoc.dmg"
fi
codesign --verify --deep --strict "$APP"

mkdir -p "$OUT"
DMG="$OUT/$NAME"
rm -f "$DMG" "$DMG.sha256"
dmgbuild -s "$HERE/settings.py" -D app="$APP" -D art="$HERE" "Boring Remote" "$DMG"
if [ $MODE = signed ]; then "$HERE/verify-dmg.sh" "$DMG" "$VER" "$PIN"; else "$HERE/verify-dmg.sh" "$DMG" "$VER"; fi
(cd "$OUT" && shasum -a 256 "$NAME" > "$NAME.sha256")
cat "$DMG.sha256"
