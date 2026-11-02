#!/bin/sh
# boring-remote: Install update (ADR 0004, spec slice 6). Runs as root, once,
# through `osascript ... with administrator privileges` from src/update_install_run.rs.
# Shipped in the bundle as Contents/Resources/boring-install-update.sh.
#
#   boring-install-update.sh <package.app.tar.xz> <base64 sig> <X.Y.Z>
#   boring-install-update.sh --move-bundle
#
# v1.7 t17: the bundle is "Boring Remote.app"; 1.6.x installed "BoringRemote.app" and its
# updater can only put a new version there. --move-bundle (the app runs it once, with one
# admin prompt) and every install leave one bundle at the new path, with both launchd
# plists rewritten by its own `service --write-plists` and both jobs reloaded. The exe
# stays BoringRemote and the bundle id is unchanged, so TCC grants carry over.
# Trusts nothing from the caller: copies the package somewhere only root can
# write, re-verifies its sig with the installed app's own `--boring-verify-package`,
# and checks the bundle's version before touching /Applications.
set -eu

# The LaunchDaemon label. rebrand.py patches this line from the same HOSTD_ID it
# writes into daemon.plist; boring/test_install_update.py asserts they match.
SERVICE_LABEL="com.carriez.RustDesk_service"
AGENT_LABEL="com.carriez.RustDesk_server"
APP_NAME="BoringRemote"   # the exe and process name
BUNDLE="Boring Remote.app"
OLD_BUNDLE="$APP_NAME.app"  # 1.6.x, and the top-level name in the update package for its installer

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

APP="$ROOT/Applications/$BUNDLE"
OLD="$ROOT/Applications/$OLD_BUNDLE"
PREV="$APP.previous"
SUPPORT="$ROOT/Library/Application Support/Boring Remote"
DAEMON_PLIST="$ROOT/Library/LaunchDaemons/$SERVICE_LABEL.plist"
AGENT_PLIST="$ROOT/Library/LaunchAgents/$AGENT_LABEL.plist"
# The logged-in user, from the dynamic store as the app reads it (/dev/console can stay owned by
# root while someone is logged in); stat only when the store has no answer.
console() { echo "show State:/Users/ConsoleUser" | scutil 2>/dev/null | awk -v k="$1" '$1 == k && $2 == ":" { print $3; exit }'; }
CONSOLE_USER=$(console Name); CONSOLE_UID=$(console UID)
[ -n "$CONSOLE_USER" ] && [ -n "$CONSOLE_UID" ] || { CONSOLE_USER=$(stat -f %Su /dev/console); CONSOLE_UID=$(stat -f %u /dev/console); }
[ "$CONSOLE_USER" = loginwindow ] && CONSOLE_USER=root

fail() { echo "install-update: $*" >&2; exit 1; }

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
user_session() { [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != root ]; }

# 1.6.x's bundle is still there, a plist still runs it, or the agent plist is one that leaves
# --server down after a clean exit (KeepAlive SuccessfulExit=false, before t17).
needs_move() {
  [ -d "$OLD" ] || grep -qsF "/Applications/$OLD_BUNDLE/" "$DAEMON_PLIST" "$AGENT_PLIST" \
    || grep -qsF SuccessfulExit "$AGENT_PLIST"
}

# The per-user agent (--server, the screen capturer) lives in the user's GUI domain, not root's.
agent_out() {
  launchctl bootout "gui/$CONSOLE_UID/$AGENT_LABEL" 2>/dev/null || true
  i=0  # bootout returns before the job is gone; bootstrap fails while it is still there
  while [ $i -lt 20 ] && launchctl print "gui/$CONSOLE_UID/$AGENT_LABEL" >/dev/null 2>&1; do
    sleep 0.5; i=$((i + 1))
  done
}
agent_in() {
  launchctl bootstrap "gui/$CONSOLE_UID" "$AGENT_PLIST" 2>/dev/null \
    || launchctl kickstart -k "gui/$CONSOLE_UID/$AGENT_LABEL" 2>/dev/null || true
  launchctl kickstart "gui/$CONSOLE_UID/$AGENT_LABEL" 2>/dev/null || true  # loaded but not started
}

# Keep the newer bundle (the new path wins a tie) at the new path, then point both jobs at it.
move_bundle() {
  service=; [ -f "$DAEMON_PLIST" ] && service=1
  if [ -n "$service" ]; then
    launchctl bootout "system/$SERVICE_LABEL" 2>/dev/null || true
    user_session && agent_out
  fi
  if [ -d "$OLD" ]; then
    old_v=$(bundle_version "$OLD" 2>/dev/null) || old_v=0.0.0
    new_v=$(bundle_version "$APP" 2>/dev/null) || new_v=
    if [ -n "$new_v" ] && ! newer "$old_v" "$new_v"; then
      rm -rf "$OLD"
    else
      rm -rf "$APP"
      mv "$OLD" "$APP" || fail "cannot move $OLD to $APP"
    fi
  fi
  [ -x "$APP/Contents/MacOS/$APP_NAME" ] || fail "no app at $APP"
  [ -n "$service" ] || return 0
  # Whatever still runs from the old path (its --server, a 1.6.x window) would hold on to it.
  pkill -f "$OLD/Contents/MacOS/" 2>/dev/null || true
  [ -n "$service" ] || return 0
  "$APP/Contents/MacOS/service" --write-plists || fail "cannot rewrite the launchd plists"
  launchctl bootstrap system "$DAEMON_PLIST" 2>/dev/null || launchctl load -w "$DAEMON_PLIST" || true
  user_session && agent_in
  return 0
}

if [ "${1:-}" = --move-bundle ]; then
  [ $# -eq 1 ] || fail "usage: --move-bundle"
  needs_move || exit 0
  move_bundle
  # The app that asked quits once this returns; open the moved one after it has gone.
  if user_session; then
    ( trap '' HUP; sleep 2; launchctl asuser "$CONSOLE_UID" sudo -u "$CONSOLE_USER" open "$APP" ) </dev/null >/dev/null 2>&1 &
  fi
  echo "install-update: moved to $APP"
  exit 0
fi

[ $# -eq 3 ] || fail "usage: <package> <sig> <version>"
PKG=$1 SIG=$2 VERSION=$3

semver "$VERSION" || fail "bad version: $VERSION"
needs_move && move_bundle
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
NEW="$STAGE/x/$BUNDLE"
[ -d "$NEW" ] || NEW="$STAGE/x/$OLD_BUNDLE"
[ -d "$NEW" ] || fail "package has no $BUNDLE"
GOT=$(bundle_version "$NEW") || fail "cannot read new version"
[ "$GOT" = "$VERSION" ] || fail "package is $GOT, expected $VERSION"
[ -z "$ROOT" ] && chown -R root:wheel "$NEW"

# Rollback state (spec slice 7). Root writes update-pending. The app writes its
# version into update-healthy once its main window is up, and empties update-failed
# after showing it. Both belong to the console user, mode 600, in a root-owned
# dir: no other local user can write or replace them (ticket 13 Comments).
mkdir -p "$SUPPORT"
HEALTHY="$SUPPORT/update-healthy" FAILED="$SUPPORT/update-failed"
for f in "$HEALTHY" "$FAILED"; do
  rm -f "$f"; : > "$f"; chmod 600 "$f"
  [ "$CONSOLE_USER" != root ] && chown "$CONSOLE_USER" "$f"
done
printf 'from=%s\nto=%s\ntime=%s\n' "$FROM" "$VERSION" "$(date +%s)" > "$SUPPORT/update-pending"

restart() {
  launchctl kickstart -k "system/$SERVICE_LABEL" || true
  pkill -x "$APP_NAME" || true
  if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != root ]; then
    launchctl asuser "$CONSOLE_UID" sudo -u "$CONSOLE_USER" open "$APP" || true
  fi
}

# Healthy = the app wrote $VERSION into update-healthy AND root sees the service
# loaded itself. Within $WAIT s: keep the update, drop .previous and the pending
# marker. Else: kill the new app, put .previous back, restart, leave update-failed.
rollback_watchdog() {
  i=0
  while [ "$i" -lt "$WAIT" ]; do
    sleep 1; i=$((i + 1))
    if [ "$(cat "$HEALTHY" 2>/dev/null)" = "$VERSION" ] &&
       launchctl print "system/$SERVICE_LABEL" >/dev/null 2>&1; then
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

rm -rf "$PREV"
mv "$APP" "$PREV"
mv "$NEW" "$APP" || { mv "$PREV" "$APP"; rm -f "$SUPPORT/update-pending"; fail "cannot move new app into place"; }
# The watchdog starts right after the swap, so any later failure still rolls back.
# Detached so osascript returns; it outlives this script.
( trap '' HUP; rollback_watchdog ) </dev/null >/dev/null 2>&1 &
xattr -cr "$APP" || echo "install-update: xattr -cr failed" >&2
restart
echo "install-update: $FROM -> $VERSION"
