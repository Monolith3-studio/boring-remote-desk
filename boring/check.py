#!/usr/bin/env python3
"""Rebrand check: prove a scripted tree is the Boring Remote Desk app.

Usage:  python3 boring/check.py [ROOT] [--no-rerun]

Reads the tree after boring/rebrand.py has run and asserts what the spec asks
for: name, bundle IDs, empty servers, Direct IP on, tailnet whitelist, listener
on all interfaces, allow-only-conn-window-open available and off, sync / NAT
test / updater unreachable, no RustDesk public server named in shipped code,
no hwcodec/vram in any build invocation, Mac build with file copy-paste, and
(unless --no-rerun) that a second rebrand run changes nothing.

Prints one PASS/FAIL line per fact, then
    rebrand check: <n> passed, <m> failed
and exits 1 if anything failed. Stdlib only.
"""
import hashlib
import pathlib
import plistlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import rebrand  # noqa: E402

AGENT, HOSTD = "io.boringlabs.remote.agent", "io.boringlabs.remote.hostd"
PUBLIC_SERVER = re.compile(r"\b(?:rs-[a-z0-9-]+|api|admin)\.rustdesk\.com\b")
BANNED = re.compile(r"hwcodec|vram")
BUILD_CALL = re.compile(r"build\.py|cargo\b|FEATURES")


class Check:
    def __init__(self, root):
        self.root = pathlib.Path(root)
        self.passed, self.failed = 0, 0

    def read(self, rel):
        p = self.root / rel
        return p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""

    def fact(self, name, ok, detail=""):
        if ok:
            self.passed += 1
            print(f"PASS {name}")
        else:
            self.failed += 1
            print(f"FAIL {name}" + (f": {detail}" if detail else ""))


def rust_map(text, static):
    m = re.search(rf"static ref {static}: RwLock<HashMap<String, String>> = (.*?);\n", text)
    return dict(re.findall(r'\("([^"]*)", "([^"]*)"\)', m.group(1))) if m else {}


def first_statement(text, signature):
    i = text.find(signature)
    if i < 0:
        return None
    body = text[text.index("{", i + len(signature) - 1) + 1:]
    return body.lstrip().split("\n", 1)[0]


def strip_tests_and_comments(text):
    """Drop #[cfg(test)] modules and // comment lines, keep shipped code."""
    out, i = [], 0
    for m in re.finditer(r"#\[cfg\(test\)\]\s*(?:pub\s+)?mod\s+\w+\s*\{", text):
        if m.start() < i:
            continue
        out.append(text[i:m.start()])
        depth, j = 1, m.end()
        while j < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[j], 0)
            j += 1
        i = j
    out.append(text[i:])
    return "\n".join(l for l in "".join(out).splitlines() if not l.lstrip().startswith("//"))


def plist_label(c, rel):
    try:
        return plistlib.loads((c.root / rel).read_bytes()).get("Label")
    except Exception as e:  # missing or unparsable
        return f"<{e}>"


def run_checks(root, rerun=True):
    c = Check(root)
    cfg = c.read("libs/hbb_common/src/config.rs")

    # identity
    m = re.search(r'static ref APP_NAME: RwLock<String> = RwLock::new\("([^"]*)"', cfg)
    c.fact("app name is BoringRemote", m and m.group(1) == "BoringRemote", m and m.group(1))
    try:
        info = plistlib.loads((c.root / "flutter/macos/Runner/Info.plist").read_bytes())
    except Exception:
        info = {}
    c.fact("app name shown as Boring Remote on Mac", info.get("CFBundleDisplayName") == "Boring Remote")
    c.fact("app name shown as Boring Remote on Windows",
           'VALUE "ProductName", "Boring Remote"' in c.read("flutter/windows/runner/Runner.rc"))
    ids = set(re.findall(r"PRODUCT_BUNDLE_IDENTIFIER = ([^;\s]+)",
                         c.read("flutter/macos/Runner.xcodeproj/project.pbxproj")
                         + c.read("flutter/macos/Runner/Configs/AppInfo.xcconfig")))
    c.fact("Mac bundle id is io.boringlabs.remote.agent", ids == {AGENT}, str(ids))
    c.fact("LaunchAgent label is io.boringlabs.remote.agent",
           plist_label(c, "src/platform/privileges_scripts/agent.plist") == AGENT)
    c.fact("LaunchDaemon label is io.boringlabs.remote.hostd",
           plist_label(c, "src/platform/privileges_scripts/daemon.plist") == HOSTD)
    mac = c.read("src/platform/macos.rs")
    stale = re.findall(r"com\.carriez\.\{\}|\{\}_server|\{\}_service", mac)
    c.fact("Mac code builds launchd labels from our ids", not stale and AGENT in mac and HOSTD in mac,
           f"stale label formats: {stale}")
    scripts = "".join(c.read(f"src/platform/privileges_scripts/{f}")
                      for f in ("install.scpt", "uninstall.scpt", "update.scpt"))
    c.fact("install scripts use our launchd labels", "com.carriez" not in scripts and HOSTD in scripts)

    # servers and locked settings
    c.fact("rendezvous servers empty", re.search(r"RENDEZVOUS_SERVERS: &\[&str\] = &\[\s*\];", cfg))
    locked = rust_map(cfg, "OVERWRITE_SETTINGS")
    for key in ("custom-rendezvous-server", "relay-server", "api-server"):
        c.fact(f"{key} locked empty", key in locked and locked[key] == "", locked.get(key))
    c.fact("whitelist locked to 100.64.0.0/10", locked.get("whitelist") == "100.64.0.0/10",
           locked.get("whitelist"))
    c.fact("Direct IP locked on", locked.get("direct-server") == "Y")
    conn = c.read("src/server/connection.rs")
    c.fact("whitelist is enforced on incoming connections",
           'Config::get_option("whitelist")' in conn and "check_whitelist(&addr)" in conn)
    med, tcp = c.read("src/rendezvous_mediator.rs"), c.read("libs/hbb_common/src/tcp.rs")
    c.fact("Direct IP listener on all interfaces",
           "hbb_common::tcp::listen_any(" in med and "Ipv6Addr::UNSPECIFIED), port)" in tcp
           and "set_only_v6(false)" in tcp)
    defaults = rust_map(cfg, "DEFAULT_SETTINGS")
    c.fact("allow-only-conn-window-open off by default",
           defaults.get("allow-only-conn-window-open") == "N"
           and 'Config::get_option("allow-only-conn-window-open") == "Y"' in conn)
    c.fact("allow-only-conn-window-open available in settings",
           "'allow-only-conn-window-open'" in c.read("flutter/lib/desktop/pages/desktop_setting_page.dart"))

    # sync, NAT test, updater
    for rel, sig, what in (
        ("src/common.rs", "pub fn test_nat_type() {", "NAT test"),
        ("src/common.rs", "pub fn check_software_update() {", "update check"),
        ("src/common.rs", "pub async fn do_check_software_update() -> hbb_common::ResultType<()> {",
         "update check request"),
        ("src/hbbs_http/sync.rs", "async fn start_hbbs_sync_async() {", "stats sync"),
        ("src/updater.rs", "fn start_auto_update_check_(rx_msg: Receiver<UpdateMsg>) {", "Windows updater"),
        ("src/updater.rs", "pub fn start_auto_update_macos() {", "Mac updater"),
    ):
        first = first_statement(c.read(rel), sig)
        c.fact(f"{what} returns before doing anything",
               first is not None and re.match(r"(if true \{ )?return\b", first), f"{rel}: {first!r}")
    c.fact("auto update locked off", locked.get("allow-auto-update") == "N")
    c.fact("update check locked off", rust_map(cfg, "OVERWRITE_LOCAL_SETTINGS").get("enable-check-update") == "N")
    lib = c.read("libs/hbb_common/src/lib.rs")
    c.fact("version check endpoint empty", 'const URL: &str = "";' in lib)

    hits = []
    for base in ("src", "libs", "flutter/lib"):
        for p in sorted((c.root / base).rglob("*")):
            if p.suffix not in (".rs", ".dart") or not p.is_file() or "/lang/" in p.as_posix():
                continue
            code = strip_tests_and_comments(p.read_text(encoding="utf-8", errors="replace"))
            hits += [f"{p.relative_to(c.root)}: {h}" for h in PUBLIC_SERVER.findall(code)]
    c.fact("no shipped code names a RustDesk public server", not hits, "; ".join(hits[:10]))

    # banned codecs and the Mac build flags
    wf_dir = c.root / ".github/workflows"
    workflows = sorted(wf_dir.glob("*.y*ml")) if wf_dir.is_dir() else []
    upstream = [w.name for w in workflows if not w.name.startswith(rebrand.OUR_WORKFLOW_PREFIX)]
    c.fact("only our workflows remain", not upstream, ", ".join(upstream))
    bad = []
    for p in sorted(c.root.rglob("*")):
        rel = p.relative_to(c.root).as_posix()
        if not p.is_file() or rel.startswith(("boring/", ".git/", "target/")):
            continue
        is_wf = rel.startswith(".github/workflows/")
        if not (is_wf or p.suffix in (".sh", ".ps1", ".bat", ".cmd", ".py") or p.name == "Dockerfile"):
            continue
        for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if BANNED.search(line) and (is_wf or BUILD_CALL.search(line)):
                bad.append(f"{rel}:{n}")
    c.fact("no hwcodec or vram in any build invocation", not bad, ", ".join(bad[:10]))
    cargo = c.read("Cargo.toml")
    m = re.search(r"^default = \[(.*)\]", cargo, re.M)
    c.fact("hwcodec and vram not default features", m is not None and not BANNED.search(m.group(1)))
    c.fact("build.py refuses hwcodec and vram", "hwcodec and vram are banned" in c.read("build.py")
           and "features.append('hwcodec')" not in c.read("build.py"))
    mac_builds = [l for w in workflows for l in w.read_text().splitlines()
                  if "build.py" in l and "--flutter" in l and "--portable" not in l]
    c.fact("Mac build has --unix-file-copy-paste",
           mac_builds and all("--unix-file-copy-paste" in l for l in mac_builds), str(mac_builds))

    # protocol untouched
    c.fact("protocol files untouched by the script",
           not any("protos/" in rel or rel.endswith(".proto") for rel, *_ in rebrand.PATCHES))

    if rerun:
        def snap():
            files = {rel for rel, *_ in rebrand.PATCHES} | {
                f".github/workflows/{w.name}" for w in workflows}
            return {f: hashlib.sha256((c.root / f).read_bytes()).hexdigest()
                    for f in files if (c.root / f).is_file()}
        before = snap()
        changed, moved = rebrand.apply(c.root)
        c.fact("second rebrand run is a no-op", not changed and not moved and snap() == before,
               "; ".join(changed + moved))

    print(f"rebrand check: {c.passed} passed, {c.failed} failed")
    return 1 if c.failed else 0


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = args[0] if args else pathlib.Path(__file__).resolve().parent.parent
    sys.exit(run_checks(root, rerun="--no-rerun" not in sys.argv))
