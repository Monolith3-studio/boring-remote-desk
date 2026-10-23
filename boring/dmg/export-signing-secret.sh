#!/bin/bash
# One-time, on Jason's Mac: put the "Boring Remote Code Signing" identity into the fork's
# GitHub Actions secrets MAC_SIGN_P12 (base64 PKCS#12) and MAC_SIGN_P12_PASSWORD.
#   boring/dmg/export-signing-secret.sh [--dry-run]
# Exports ONLY that identity, pinned by name and certificate SHA-1 (the login keychain also
# holds "Boring Stories Local Code Signing", which must never leave). The private key and the
# passphrase live only in shell variables and pipes: no file, no argv, no output. macOS asks
# once to allow the export (keychain prompt). --dry-run does everything but `gh secret set`.
# Needs: gh (logged in, admin on the repo), openssl, swift (Xcode command line tools).
set -euo pipefail
set +x
umask 077

REPO=Monolith3-studio/boring-remote-desk
NAME="Boring Remote Code Signing"
PIN=${BR_SIGN_SHA1:-B82B9E874D0CA6CD653F1EA8D4A6367F39CAE0C6}  # override is for the test suite only
HERE=$(cd "$(dirname "$0")" && pwd)
DRY=false
[ "${1:-}" = --dry-run ] && DRY=true

die() { echo "export-signing-secret: $*" >&2; exit 1; }
for t in openssl swift base64; do command -v "$t" >/dev/null || die "missing $t"; done
if ! $DRY; then
  command -v gh >/dev/null || die "missing gh"
  gh secret list -R "$REPO" >/dev/null || die "gh cannot read $REPO secrets (gh auth login? admin on the repo?)"
fi

pw=$(openssl rand -base64 36)
kc=()
[ -n "${BR_EXPORT_KEYCHAIN:-}" ] && kc=("$BR_EXPORT_KEYCHAIN")  # test suite only; default = your keychains
echo "export-signing-secret: exporting \"$NAME\" ($PIN); allow it if macOS asks"
p12=$(printf '%s' "$pw" | swift "$HERE/export-identity.swift" "$NAME" "$PIN" ${kc[@]+"${kc[@]}"} | base64) \
  || die "export failed; nothing was set"
[ -n "$p12" ] || die "export produced nothing; nothing was set"

# Check the bundle before it goes anywhere: one certificate, the pinned one, and one key.
certs=$(printf '%s' "$p12" | base64 --decode | P12PW=$pw openssl pkcs12 -nokeys -passin env:P12PW 2>/dev/null) \
  || die "exported bundle does not open with its passphrase; nothing was set"
n=$(printf '%s\n' "$certs" | grep -c 'BEGIN CERTIFICATE' || true)
[ "$n" = 1 ] || die "exported bundle holds $n certificates, expected 1; nothing was set"
got=$(printf '%s\n' "$certs" | openssl x509 -noout -fingerprint -sha1 | sed 's/.*=//; s/://g')
[ "$got" = "$PIN" ] || die "exported certificate is $got, expected $PIN; nothing was set"
keys=$(printf '%s' "$p12" | base64 --decode | P12PW=$pw openssl pkcs12 -nocerts -nodes -passin env:P12PW 2>/dev/null \
  | grep -c 'BEGIN .*PRIVATE KEY' || true)
[ "$keys" = 1 ] || die "exported bundle holds $keys private keys, expected 1; nothing was set"
echo "export-signing-secret: bundle checked: 1 certificate ($got), 1 key"

if $DRY; then
  echo "export-signing-secret: dry run, no secrets set"
else
  printf '%s' "$p12" | gh secret set MAC_SIGN_P12 -R "$REPO"
  printf '%s' "$pw" | gh secret set MAC_SIGN_P12_PASSWORD -R "$REPO"
  echo "export-signing-secret: set MAC_SIGN_P12 and MAC_SIGN_P12_PASSWORD on $REPO"
fi
p12='' pw='' certs=''
