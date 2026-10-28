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

# Seconds the rollback watchdog waits for the new app to say it is healthy.
# Tests shorten it; as root it is always 60.
WAIT=60
[ -n "$ROOT" ] && WAIT=${BORING_ROLLBACK_WAIT:-60}

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

# Rollback state (spec slice 7). Root writes update-pending. The user-run app
# writes its version into update-healthy once healthy, and empties update-failed
# after showing it; those two are world-writable files in a root-owned dir.
mkdir -p "$SUPPORT"
HEALTHY="$SUPPORT/update-healthy" FAILED="$SUPPORT/update-failed"
: > "$HEALTHY"; chmod 666 "$HEALTHY"
: > "$FAILED"; chmod 666 "$FAILED"
printf 'from=%s\nto=%s\ntime=%s\n' "$FROM" "$VERSION" "$(date +%s)" > "$SUPPORT/update-pending"

rm -rf "$PREV"
mv "$APP" "$PREV"
mv "$NEW" "$APP" || { mv "$PREV" "$APP"; rm -f "$SUPPORT/update-pending"; fail "cannot move new app into place"; }
xattr -cr "$APP"

restart() {
  launchctl kickstart -k "system/$SERVICE_LABEL" || true
  pkill -x "$APP_NAME" || true
  user=$(stat -f %Su /dev/console)
  uid=$(stat -f %u /dev/console)
  if [ -n "$user" ] && [ "$user" != root ]; then
    launchctl asuser "$uid" sudo -u "$user" open "$APP" || true
  fi
}

# Healthy within $WAIT s: keep the update, drop .previous and the pending marker.
# Else: kill the new app, put .previous back, restart, and leave update-failed.
rollback_watchdog() {
  i=0
  while [ "$i" -lt "$WAIT" ]; do
    sleep 1; i=$((i + 1))
    if [ "$(cat "$HEALTHY" 2>/dev/null)" = "$VERSION" ]; then
      rm -rf "$PREV"; rm -f "$SUPPORT/update-pending"
      return
    fi
  done
  pkill -x "$APP_NAME" || true
  rm -rf "$APP"
  mv "$PREV" "$APP"
  echo "$VERSION" > "$FAILED"
  rm -f "$SUPPORT/update-pending"
  restart
}

restart
# Detached so osascript returns; it outlives this script.
( trap '' HUP; rollback_watchdog ) </dev/null >/dev/null 2>&1 &
echo "install-update: $FROM -> $VERSION"
