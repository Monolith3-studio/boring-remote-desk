#!/usr/bin/env bash
# The Corresponding Source for one build (AGPL 6, 13), for boringlabs.online/remote/source/.
#
#   boring/release/source-tarball.sh [commit, default HEAD] [out dir, default .]
#
# Writes BoringRemote-<shortsha>-source.tar.gz: `git archive` of the commit plus the hbb_common
# submodule at the commit it pins, with no git history. NOTICE gets a last line saying which commit
# and date this copy is (AGPL 5(a)). Same commit in, same bytes out; owners are blank, so nothing
# about this machine goes in. Prints the path, the size and the sha256.
set -euo pipefail
die() { echo "source-tarball: $*" >&2; exit 1; }

ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
COMMIT=$(git -C "$ROOT" rev-parse --verify "${1:-HEAD}^{commit}") || die "no such commit: ${1:-HEAD}"
OUT=${2:-.}
mkdir -p "$OUT"
NAME="BoringRemote-$(git -C "$ROOT" rev-parse --short=9 "$COMMIT")-source"
HBB=$(git -C "$ROOT" rev-parse "$COMMIT:libs/hbb_common") || die "$COMMIT has no libs/hbb_common"
git -C "$ROOT/libs/hbb_common" cat-file -e "$HBB^{commit}" 2>/dev/null \
  || die "hbb_common $HBB not here: git submodule update --init libs/hbb_common"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
git -C "$ROOT" archive --prefix="$NAME/" "$COMMIT" | tar -x -C "$WORK"
git -C "$ROOT/libs/hbb_common" archive --prefix="$NAME/libs/hbb_common/" "$HBB" | tar -x -C "$WORK"
[ -f "$WORK/$NAME/LICENCE" ] || die "$COMMIT has no LICENCE"
[ -f "$WORK/$NAME/NOTICE" ] || die "$COMMIT has no NOTICE"
[ -f "$WORK/$NAME/libs/hbb_common/Cargo.toml" ] || die "hbb_common came out empty"

STAMP=$(git -C "$ROOT" log -1 --format=%ct "$COMMIT")
printf '\nThis copy is commit %s, dated %s.\n' "$COMMIT" "$(git -C "$ROOT" log -1 --format=%cs "$COMMIT")" \
  >>"$WORK/$NAME/NOTICE"

TARBALL="$OUT/$NAME.tar.gz"
python3 -I - "$WORK" "$NAME" "$TARBALL" "$STAMP" <<'PY'
import gzip, os, sys, tarfile
work, name, out, stamp = sys.argv[1:]

def plain(info):  # no owner, one date: the commit's
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = int(stamp)
    return info

with open(out, "wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as gz, \
        tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
    tar.add(os.path.join(work, name), arcname=name, recursive=False, filter=plain)
    for folder, dirs, files in os.walk(os.path.join(work, name)):
        dirs.sort()
        for entry in sorted(dirs + files):
            path = os.path.join(folder, entry)
            tar.add(path, arcname=os.path.relpath(path, work), recursive=False, filter=plain)
PY
echo "$TARBALL"
wc -c <"$TARBALL" | tr -d ' '
shasum -a 256 "$TARBALL" | cut -d' ' -f1
