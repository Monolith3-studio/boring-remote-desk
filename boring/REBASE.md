# Rebasing onto upstream RustDesk

The fork is upstream at a release tag plus our commits: `boring/`, `.github/workflows/boring-build.yml`, and the deletion of upstream's workflows and `FUNDING.yml`. The rebrand runs at build time and is never committed. A rebase means moving those commits to a new base. Nothing upstream gets hand-edited.

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
