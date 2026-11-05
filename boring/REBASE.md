# Rebasing onto upstream RustDesk

The fork is upstream at a release tag plus our commits: `boring/`, `.github/workflows/boring-build.yml`, and the deletion of upstream's workflows and `FUNDING.yml`. The rebrand runs at build time and is never committed. A rebase means moving those commits to a new base. Nothing upstream gets hand-edited.

New files are ours, wherever they sit: `src/update_*.rs`, `src/license_key*.rs`, `flutter/lib/desktop/kit/`, and the v1.7 modules in `libs/base/src/` (`direct_link`, `trust`, `lan`, `high_efficiency`, `update_feed`, `file_speed`, `file_verify`). `libs/base` itself is upstream's crate: its `lib.rs` and every file it had are upstream text. The `mod` lines and every hook into upstream code (the Direct Link listener and handshake, trust, High Efficiency, LAN Discovery, full-speed file transfer, file verification) are `PATCHES` entries in `boring/rebrand.py`, and `check.py` looks for that patch text. Our `libs/base` modules' tests run from `libs/base/tests/boring.rs`, so `cargo test -p base` covers them on a raw checkout too. `file_verify`'s tests are in the module itself, so they run only on a tree `rebrand.py` has patched: it needs `blake3`, and `libs/base/Cargo.toml` and `Cargo.lock` get that from `PATCHES` too. `libs/base/examples/transfer_bench.rs` measures file transfer; on a raw checkout it runs upstream's engine, so `--mode pump` means what ships only on a tree `rebrand.py` has patched.

`OLD` is the tag we're on now. It's the `version` in `Cargo.toml` and `VERSION` in our workflow. `NEW` is the target.

## Normal release rebase

```
git fetch upstream --tags
git tag --sort=-creatordate | head            # pick NEW (a release tag, never `nightly`)
git switch -c rebase/NEW open-fork
git rebase --onto NEW OLD
```

The only conflicts you should see are `deleted by us` on upstream workflows upstream changed since `OLD`. Keep them deleted with `git rm <file>` and run `git rebase --continue`. Any other conflict means someone hand-edited an upstream file. Stop and move that change into `boring/rebrand.py`.

```
git submodule update --init libs/hbb_common   # NEW's hbb_common
python3 boring/pins.py NEW                     # exit 1 = stale pins, 3 = bad ref
python3 boring/pins.py --fix NEW               # copies upstream's values into boring-build.yml
git diff .github/workflows/boring-build.yml    # read it, then commit: "ci: pins from upstream NEW"
python3 -m unittest boring/test_rebrand.py boring/test_pins.py -v
python3 boring/rebrand.py                      # exit 2 = moved target, see below
python3 boring/check.py                        # must end "N passed, 0 failed"
git reset --hard && git -C libs/hbb_common reset --hard   # drop the scripted output (commit your own edits first)
```

`pins.py` covers Flutter, the bridge Flutter, Rust (Mac, Windows, bridge), LLVM, the vcpkg commit, flutter_rust_bridge, cargo-expand, the minimum macOS version and the app `VERSION`. `check.py` also fails in CI if `VERSION` doesn't match `Cargo.toml`. If upstream adds a toolchain pin we don't track, add it to `PINS`. To spot new pins, run `git diff OLD NEW -- .github/workflows/flutter-build.yml .github/workflows/bridge.yml`.

If `check.py` fails `protocol files are upstream's`, upstream changed a `.proto`. Confirm the change is upstream's and read it (`git diff OLD NEW -- '*.proto'`, and `git -C libs/hbb_common diff <old-sha> <new-sha> -- protos`), then record the new hashes on an LF checkout:

```
sha256sum libs/base/protos/message.proto libs/hbb_common/protos/rendezvous.proto > boring/protocol.sha256
```

If upstream added or moved a `.proto`, list it there too. Commit it with the pin bump.

Then look for new code that contacts RustDesk. `check.py` catches the known server names, but not new kinds of contact:

```
git diff OLD NEW -- src libs/hbb_common flutter/lib | grep -E '^\+' | grep -iE 'https?://|rustdesk\.com'
```

Push `rebase/NEW`, wait for CI to go green on both macOS and Windows, then move `open-fork` to it. The rebase rewrote history, so this push is a force push of `open-fork`.

## Security fix fast path

Don't wait for a release. As soon as upstream lands a fix for a known hole:

```
git switch -c sec/<topic> open-fork
git cherry-pick -x <upstream-sha>             # main repo fix
# or, for a fix inside hbb_common: move the submodule pointer
git -C libs/hbb_common fetch origin && git -C libs/hbb_common checkout <hbb-sha>
git add libs/hbb_common && git commit -m "hbb_common: security fix <hbb-sha>"
```

Then run the same tests, `rebrand.py` and `check.py` as above. Push, wait for green CI, and fast-forward `open-fork`. Leave `pins.py` and `VERSION` alone: the base tag hasn't changed. The next normal rebase drops the cherry-pick on its own once the fix is in `NEW`. If git stops on it, run `git rebase --skip`.

## When `rebrand.py` exits 2 (patch target moved)

It checks every target before it changes any file. It prints `ERROR <file>: patch target moved (<why>)` for every entry whose upstream text it can't find, then `rebrand: nothing written, N moved`, and leaves the tree exactly as it was: no patch, no copied art, no workflow removed. So there's nothing to reset. Fix the script, not the tree:

1. Find what upstream did: `git log -p OLD..NEW -- <file>` (run it inside `libs/hbb_common` for `libs/hbb_common/...` paths).
2. Edit that entry in `PATCHES` in `boring/rebrand.py`. The new `old` text has to be upstream's current text exactly. Keep `new` doing the same job. If the setting moved to another file, change the path.
3. If the feature is gone upstream, delete the entry only if `check.py` still proves the spec fact some other way. Otherwise rewrite the check fact as well.
4. If the behaviour changed, add or adjust a test in `boring/test_rebrand.py` first. Then run the tests, `rebrand.py` and `check.py` again.

`pins.py` exits 2 the same way (`pin source moved: <NAME>`) when upstream renames or drops a pin. Fix that entry in `PINS` in `boring/pins.py`. Exit 3 (`bad ref <ref>`) means the ref isn't a commit in your clone: a typo, or `git fetch upstream --tags` hasn't run. Nothing is compared.

## When the branding check fails after a rebase

`check.py` scans every string a person can see in the Mac and Windows app (Flutter `lib/` minus mobile and web, `src/` minus translations and Linux-only files, the Mac and Windows runners), every translation value, and the app metadata (Info.plist, the Mac menu, exe properties). A new RustDesk name or `rustdesk.com` / `github.com/rustdesk` link fails it. Triage each one:

- A person sees it: add a patch in the branding block of `boring/rebrand.py` (our name, or no link, or one of our own pages).
- Never shown (a code name, path, window class, log line): add it to `INTERNAL` in `boring/check.py` with the reason.

RustDesk is named once, on purpose: `LEGAL_CREDIT`, in the Legal dialog (`flutter/lib/desktop/kit/legal.dart`) that the plain Legal item on the About page opens. AGPL 5(d) needs that item, and AGPL 6 and 13 need its source link (`FORK_URL`): `check.py` fails if either goes, and if anything shipped names the owner. `boring/release/source-tarball.sh` makes the source tarball for that page, one per released version. Keep `NOTICE` (AGPL 5(a)) and upstream's copyright headers. Translations are rewritten by the script (`RustDesk` becomes the display name in every language) and `lang.rs` does the same at run time for keys that fall back to themselves, so a new translation needs no work.

Logos: `boring/upstream-logos.sha256` lists upstream's logo files. If any of those bytes ship anywhere, or a slot doesn't hold our copy, the check fails. If upstream redraws its icon, add the new file's hash there and a `COPIES` entry for its slot. Our art comes from `python3 boring/art/make_app_art.py` (needs Pillow and the Mac kit's `AppIcon.icns`). Re-run it, never edit the outputs, and look at `boring/art/preview/` before committing.
