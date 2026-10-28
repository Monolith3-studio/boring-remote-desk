#!/bin/sh
# boring-remote: Install update (ADR 0004, spec slice 6). Runs as root, once,
# through `osascript ... with administrator privileges` from src/update_install_run.rs.
# Shipped in the bundle as Contents/Resources/boring-install-update.sh.
#
#   boring-install-update.sh <package.app.tar.xz> <base64 sig> <X.Y.Z>
#
# Trusts nothing from the caller: copies the package somewhere only root can
# write, re-verifies its sig with the installed app's own `--boring-verify-package`,
# and checks the bundle's version before touching /Applications.
set -eu

# The LaunchDaemon label. rebrand.py patches this line from the same HOSTD_ID it
# writes into daemon.plist; boring/test_install_update.py asserts they match.
SERVICE_LABEL="com.carriez.RustDesk_service"
APP_NAME="BoringRemote"

if [ "$(id -u)" = 0 ]; then
  ROOT=""
  PATH=/usr/bin:/bin:/usr/sbin:/sbin
  TMPDIR=/private/tmp
  export PATH TMPDIR
else
  # Tests only: a fake root holding Applications/ and Library/. Never set as root.
  ROOT="${BORING_TEST_ROOT:?run as root, or set BORING_TEST_ROOT for a test}"
fi

APP="$ROOT/Applications/$APP_NAME.app"
PREV="$APP.previous"
SUPPORT="$ROOT/Library/Application Support/Boring Remote"

fail() { echo "install-update: $*" >&2; exit 1; }

[ $# -eq 3 ] || fail "usage: <package> <sig> <version>"
PKG=$1 SIG=$2 VERSION=$3

semver() { echo "$1" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+'; }
# 0 when $1 > $2, both strict X.Y.Z.
newer() {
  old_ifs=$IFS; IFS=.
  set -- $1 $2
  IFS=$old_ifs
  [ "$1" -gt "$4" ] && return 0; [ "$1" -lt "$4" ] && return 1
  [ "$2" -gt "$5" ] && return 0; [ "$2" -lt "$5" ] && return 1
  [ "$3" -gt "$6" ]
}
bundle_version() { plutil -extract CFBundleShortVersionString raw -o - "$1/Contents/Info.plist"; }

semver "$VERSION" || fail "bad version: $VERSION"
[ -x "$APP/Contents/MacOS/$APP_NAME" ] || fail "no installed app at $APP"
FROM=$(bundle_version "$APP") || fail "cannot read installed version"
newer "$VERSION" "$FROM" || fail "$VERSION is not newer than $FROM"

STAGE=$(mktemp -d "${TMPDIR:-/tmp}/boring-update.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT
cp "$PKG" "$STAGE/package.tar.xz" || fail "cannot copy package"
"$APP/Contents/MacOS/$APP_NAME" --boring-verify-package "$STAGE/package.tar.xz" "$SIG" \
  || fail "package signature does not verify"

mkdir "$STAGE/x"
tar -xJf "$STAGE/package.tar.xz" -C "$STAGE/x" || fail "cannot extract package"
NEW="$STAGE/x/$APP_NAME.app"
[ -d "$NEW" ] || fail "package has no $APP_NAME.app"
GOT=$(bundle_version "$NEW") || fail "cannot read new version"
[ "$GOT" = "$VERSION" ] || fail "package is $GOT, expected $VERSION"
[ -z "$ROOT" ] && chown -R root:wheel "$NEW"

# Ticket 13's rollback reads this: from-version, to-version, time.
mkdir -p "$SUPPORT"
printf 'from=%s\nto=%s\ntime=%s\n' "$FROM" "$VERSION" "$(date +%s)" > "$SUPPORT/update-pending"

rm -rf "$PREV"
mv "$APP" "$PREV"
mv "$NEW" "$APP" || { mv "$PREV" "$APP"; rm -f "$SUPPORT/update-pending"; fail "cannot move new app into place"; }
xattr -cr "$APP"

# Hook point for ticket 13: start the rollback watchdog here (it waits for the
# healthy marker, else restores $PREV). No-op until then.
start_rollback_watchdog() { :; }
start_rollback_watchdog

launchctl kickstart -k "system/$SERVICE_LABEL" || true
pkill -x "$APP_NAME" || true

user=$(stat -f %Su /dev/console)
uid=$(stat -f %u /dev/console)
if [ -n "$user" ] && [ "$user" != root ]; then
  launchctl asuser "$uid" sudo -u "$user" open "$APP" || true
fi
echo "install-update: $FROM -> $VERSION"
