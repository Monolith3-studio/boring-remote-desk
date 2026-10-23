#!/bin/bash
# Mount a Boring Remote DMG read-only and check what a person sees, then the signature.
#   boring/dmg/verify-dmg.sh <dmg> <version> [<pinned cert SHA-1>]
# Checks: the app and its version, the Applications link, the background (1x + 2x HiDPI TIFF),
# the volume icon (file + custom-icon flag), the Finder layout in .DS_Store (icon positions,
# background, toolbar off), and the code signature. With a pin, the app's designated
# requirement must be exactly: identifier "io.boringlabs.remote.agent" and certificate leaf =
# H"<pin>" (what TCC keys grants on). Without one, the app must be ad-hoc signed.
# Exit 0 = PASS; otherwise one FAIL line per problem.
set -uo pipefail
DMG=${1:?usage: verify-dmg.sh <dmg> <version> [pin]}; WANT=${2:?usage: verify-dmg.sh <dmg> <version> [pin]}
PIN=${3:-}
APP="BoringRemote.app"
ID="io.boringlabs.remote.agent"
MNT=$(mktemp -d)
hdiutil attach "$DMG" -readonly -nobrowse -noautoopen -mountpoint "$MNT" -quiet || { echo "FAIL: cannot mount $DMG"; exit 1; }
trap 'hdiutil detach "$MNT" -quiet -force 2>/dev/null; rmdir "$MNT" 2>/dev/null' EXIT
bad=0
fail() { echo "FAIL: $*"; bad=1; }

if [ -x "$MNT/$APP/Contents/MacOS/BoringRemote" ] && [ -f "$MNT/$APP/Contents/Info.plist" ]; then
  plist="$MNT/$APP/Contents/Info.plist"
  got=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$plist" 2>/dev/null)
  [ "$got" = "$WANT" ] || fail "app version is '$got', expected '$WANT'"
  got=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$plist" 2>/dev/null)
  [ "$got" = "$ID" ] || fail "bundle id is '$got', expected '$ID'"
  [ -f "$MNT/$APP/Contents/Resources/AppIcon.icns" ] || fail "app has no AppIcon.icns"
else
  fail "app missing: $APP"
fi
extra=
for f in "$MNT"/* "$MNT"/.[!.]*; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  case ${f##*/} in "$APP"|Applications|.background.tiff|.VolumeIcon.icns|.DS_Store|.fseventsd|.Trashes) ;; *) extra="$extra ${f##*/}" ;; esac
done
[ -z "$extra" ] || fail "unexpected files on the volume:$extra"

[ -L "$MNT/Applications" ] && [ "$(readlink "$MNT/Applications")" = /Applications ] || fail "Applications link missing or wrong"

if [ ! -f "$MNT/.background.tiff" ]; then fail "background missing (.background.tiff)"
else
  widths=$(tiffutil -info "$MNT/.background.tiff" 2>/dev/null | awk '/Image Width/ {print $3}' | sort -n | xargs)
  [ "$widths" = "640 1280" ] || fail "background is not 640 + 1280 wide (1x + 2x), got '$widths'"
fi

[ -f "$MNT/.VolumeIcon.icns" ] || fail "volume icon missing (.VolumeIcon.icns)"
cmp -s "$MNT/.VolumeIcon.icns" "$MNT/$APP/Contents/Resources/AppIcon.icns" || fail "volume icon is not the app icon"
[ "$(GetFileInfo -aC "$MNT" 2>/dev/null)" = 1 ] || fail "volume icon not switched on (custom-icon flag off)"

if [ -f "$MNT/.DS_Store" ]; then
  # ds_store comes with dmgbuild.
  python3 - "$MNT/.DS_Store" "$APP" <<'PY' || bad=1
import sys
from ds_store import DSStore
bad = 0
def fail(msg):
    global bad
    print("FAIL: " + msg); bad = 1
with DSStore.open(sys.argv[1], "r") as d:
    recs = {(e.filename, e.code.decode()): e.value for e in d}
for name, want in ((sys.argv[2], (160, 178)), ("Applications", (480, 178))):
    got = recs.get((name, "Iloc"))
    if tuple(got or ()) != want:
        fail(f"{name} icon at {got}, expected {want}")
bwsp = recs.get((".", "bwsp")) or {}
if bwsp.get("ShowToolbar") is not False or bwsp.get("ShowSidebar") is not False \
        or bwsp.get("ShowStatusBar") is not False or bwsp.get("ShowPathbar") is not False:
    fail(f"toolbar/sidebar/status/path bar not all off: {bwsp}")
bounds = bwsp.get("WindowBounds", "")
if "{640, 468}" not in bounds:
    fail(f"window is {bounds!r}, expected 640x468")
icvp = recs.get((".", "icvp")) or {}
if icvp.get("backgroundType") != 2 or not icvp.get("backgroundImageAlias"):
    fail("icon view has no background picture")
sys.exit(bad)
PY
else
  fail "layout missing (.DS_Store)"
fi

if codesign --verify --deep --strict "$MNT/$APP" 2>/dev/null; then
  req=$(codesign -d -r- "$MNT/$APP" 2>&1 | sed -n 's/^designated => //p')
  if [ -n "$PIN" ]; then
    pin=$(printf '%s' "$PIN" | tr 'A-F' 'a-f')
    [ "$req" = "identifier \"$ID\" and certificate leaf = H\"$pin\"" ] \
      || fail "designated requirement is '$req', expected identifier \"$ID\" and certificate leaf = H\"$pin\""
  else
    info=$(codesign -dv "$MNT/$APP" 2>&1); grep -qx "Signature=adhoc" <<<"$info" || fail "app is not ad-hoc signed"
  fi
else
  fail "app signature does not verify"
fi

if [ -n "$PIN" ]; then how="signed $PIN"; else how=ad-hoc; fi
[ $bad = 0 ] && echo "PASS: $DMG (v$WANT, $how)"
exit $bad
