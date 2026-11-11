# Rebasing onto upstream RustDesk

The fork is upstream at a release tag plus our commits: `boring/` and the deletion of upstream's workflows and `FUNDING.yml`. There is no GitHub Actions workflow at all (`check.py` fails on any file under `.github/workflows/`); releases build on the Studio with `boring/release/build-mac`. The rebrand runs at build time and is never committed. A rebase means moving those commits to a new base. Nothing upstream gets hand-edited. Our own files outside `boring/` are new files upstream doesn't have, wired in by `rebrand.py`: `src/password_lock.rs`, `src/trust_policy.rs`, `src/update_notice*.rs`, `src/update_install*.rs`, `src/update_rollback.rs`, `src/license_key*.rs`, `src/activate_link.rs`, `src/platform/privileges_scripts/install-update.sh` and the widgets in `flutter/lib/desktop/widgets/` they use (`generated_password.dart`, `trusted_controllers.dart`, `update_notice_banner.dart`, `license_key_field.dart`, `activate_link.dart`). A rebase never conflicts on them; if upstream adds a file of the same name, rename ours.

`OLD` is the tag we're on now. It's the `version` in `Cargo.toml`. `NEW` is the target.

## Normal release rebase

```
git fetch upstream --tags
git tag --sort=-creatordate | head            # pick NEW (a release tag, never `nightly`)
git switch -c rebase/NEW open-fork
git rebase --onto NEW OLD
```

The only conflicts you should see are `deleted by us` on upstream workflows upstream changed since `OLD` (or on `.github/workflows/boring-build.yml`, which we removed). Keep them deleted with `git rm <file>` and run `git rebase --continue`. Any other conflict means someone hand-edited an upstream file. Stop and move that change into `boring/rebrand.py`.

```
git submodule update --init libs/hbb_common   # NEW's hbb_common
python3 boring/pins.py NEW                     # exit 1 = stale pins, 3 = bad ref
python3 boring/pins.py --fix NEW               # copies upstream's values into boring/release/pins.env
git diff boring/release/pins.env               # read it, then commit: "release: pins from upstream NEW"
bash run-tests.sh
python3 boring/rebrand.py                      # exit 2 = moved target, see below
python3 boring/check.py                        # must end "N passed, 0 failed"
git reset --hard && git -C libs/hbb_common reset --hard   # drop the scripted output (commit your own edits first)
```

`pins.py` covers Flutter, the bridge Flutter, Rust (Mac, Windows, bridge), LLVM, the vcpkg commit, flutter_rust_bridge, cargo-expand, the minimum macOS version. The app version is `Cargo.toml`'s alone; `build-mac` refuses a tag that differs from it. If upstream adds a toolchain pin we don't track, add it to `PINS`. To spot new pins, run `git diff OLD NEW -- .github/workflows/flutter-build.yml .github/workflows/bridge.yml`.

If `check.py` fails `protocol files are upstream's`, upstream changed a `.proto`. Confirm the change is upstream's and read it (`git diff OLD NEW -- '*.proto'`, and `git -C libs/hbb_common diff <old-sha> <new-sha> -- protos`), then record the new hashes on an LF checkout:

```
sha256sum libs/base/protos/message.proto libs/hbb_common/protos/rendezvous.proto > boring/protocol.sha256
```

If upstream added or moved a `.proto`, list it there too. Commit it with the pin bump.

Then look for new code that contacts RustDesk. `check.py` catches the known server names, but not new kinds of contact:

```
git diff OLD NEW -- src libs/hbb_common flutter/lib | grep -E '^\+' | grep -iE 'https?://|rustdesk\.com'
```

Run `boring/release/build-mac --dry-run NEW` (toolchain and plan), then a real local build on the Studio (Windows: the Windows build machine), then move `open-fork` to `rebase/NEW`. The rebase rewrote history, so this push is a force push of `open-fork`.

## Security fix fast path

Don't wait for a release. As soon as upstream lands a fix for a known hole:

```
git switch -c sec/<topic> open-fork
git cherry-pick -x <upstream-sha>             # main repo fix
# or, for a fix inside hbb_common: move the submodule pointer
git -C libs/hbb_common fetch origin && git -C libs/hbb_common checkout <hbb-sha>
git add libs/hbb_common && git commit -m "hbb_common: security fix <hbb-sha>"
```

Then run the same tests, `rebrand.py` and `check.py` as above. Build locally (`boring/release/build-mac`), then fast-forward `open-fork`. Leave `pins.py` alone: the base tag hasn't changed. The next normal rebase drops the cherry-pick on its own once the fix is in `NEW`. If git stops on it, run `git rebase --skip`.

## When `rebrand.py` exits 2 (patch target moved)

It checks every target before it changes any file. It prints `ERROR <file>: patch target moved (<why>)` for every entry whose upstream text it can't find, then `rebrand: nothing written, N moved`, and leaves the tree exactly as it was: no patch, no copied art, no workflow removed. So there's nothing to reset. Fix the script, not the tree:

1. Find what upstream did: `git log -p OLD..NEW -- <file>` (run it inside `libs/hbb_common` for `libs/hbb_common/...` paths).
2. Edit that entry in `PATCHES` in `boring/rebrand.py`. The new `old` text has to be upstream's current text exactly. Keep `new` doing the same job. If the setting moved to another file, change the path.
3. If the feature is gone upstream, delete the entry only if `check.py` still proves the spec fact some other way. Otherwise rewrite the check fact as well.
4. If the behaviour changed, add or adjust a test in `boring/test_rebrand.py` first. Then run the tests, `rebrand.py` and `check.py` again.

`pins.py` exits 2 the same way (`pin source moved: <NAME>`) when upstream renames or drops a pin. Fix that entry in `PINS` in `boring/pins.py`. Exit 3 (`bad ref <ref>`) means the ref isn't a commit in your clone: a typo, or `git fetch upstream --tags` hasn't run. Nothing is compared.

## When the branding check fails after a rebase

`check.py` scans every string a person can see in the Mac and Windows app (Flutter `lib/` minus mobile and web, `src/` minus translations and Linux-only files, the Mac and Windows runners), every translation value, and the app metadata (Info.plist, the Mac menu, exe properties). A new RustDesk name or `rustdesk.com` / `github.com/rustdesk` link fails it. Triage each one:

- A person sees it: add a patch in the branding block of `boring/rebrand.py` (our name, or no link, or `FORK_URL`).
- Never shown (a code name, path, window class, log line): add it to `INTERNAL` in `boring/check.py` with the reason.

RustDesk is named once, on purpose: `LEGAL_LINE`, plain text on the About page. Translations are rewritten by the script (`RustDesk` becomes the display name in every language) and `lang.rs` does the same at run time for keys that fall back to themselves, so a new translation needs no work.

Logos: `boring/upstream-logos.sha256` lists upstream's logo files. If any of those bytes ship anywhere, or a slot doesn't hold our copy, the check fails. If upstream redraws its icon, add the new file's hash there and a `COPIES` entry for its slot. Our art comes from `python3 boring/art/make_app_art.py` (needs Pillow and the Mac kit's `AppIcon.icns`). Re-run it, never edit the outputs, and look at `boring/art/preview/` before committing.
