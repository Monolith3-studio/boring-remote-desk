#!/usr/bin/env python3
"""Rebrand check: prove a scripted tree is the Boring Remote Desk app.

Usage:  python3 boring/check.py [ROOT] [--no-rerun]

Reads the tree after boring/rebrand.py has run and asserts what the spec asks
for: name, bundle IDs, empty servers, Direct IP on, tailnet whitelist, listener
on all interfaces, allow-only-conn-window-open available and off, sync / NAT
test / updater / LAN discovery unreachable, no RustDesk public server named in shipped code,
no hwcodec/vram in any build invocation, Mac build with file copy-paste, the
Windows MSI (name, exe, art sizes, license, icon, no RustDesk text, release on
tags), and (unless --no-rerun) that a second rebrand run changes nothing.

Prints one PASS/FAIL line per fact, then
    rebrand check: <n> passed, <m> failed
and exits 1 if anything failed. Stdlib only.
"""
import hashlib
import pathlib
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import rebrand  # noqa: E402

AGENT, HOSTD = "io.boringlabs.remote.agent", "io.boringlabs.remote.hostd"
PUBLIC_SERVER = re.compile(r"\b(?:rs-[a-z0-9-]+|api|admin)\.rustdesk\.com\b")
BANNED = re.compile(r"hwcodec|vram")
BUILD_CALL = re.compile(r"build\.py|cargo\b|FEATURES")
HBB = rebrand.HBB


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


def fn_body(text, signature):
    """The brace-matched body of the first function with this signature, or None."""
    i = text.find(signature)
    if i < 0:
        return None
    start = text.index("{", i + len(signature) - 1) + 1
    depth, j = 1, start
    while j < len(text) and depth:
        depth += {"{": 1, "}": -1}.get(text[j], 0)
        j += 1
    return text[start:j - 1]


def whitelist_enforced(conn, hbb_lib):
    """(ok, why): every incoming connection is v4-normalised, then whitelist-checked first."""
    opens = re.findall(r"(.*)\n\s*if !conn\.on_open\(addr\)\.await \{", conn)
    if len(opens) != 1 or opens[0].strip() != "let addr = hbb_common::try_into_v4(addr);":
        return False, f"on_open must come right after try_into_v4: {opens}"
    v4 = fn_body(hbb_lib, "pub fn try_into_v4(addr: SocketAddr) -> SocketAddr {") or ""
    if ".to_ipv4" not in v4 or "IpAddr::V4(" not in v4:
        return False, "try_into_v4 no longer maps ::ffff:a.b.c.d to IPv4"
    body = fn_body(conn, "async fn on_open(&mut self, addr: SocketAddr) -> bool {") or ""
    stmts = [l.strip() for l in body.splitlines() if l.strip() and not l.strip().startswith(("log::", "//"))]
    if stmts[:3] != ["if !self.check_whitelist(&addr).await {", "return false;", "}"]:
        return False, f"on_open does not start with the whitelist check: {stmts[:3]}"
    check = fn_body(conn, "async fn check_whitelist(&mut self, addr: &SocketAddr) -> bool {") or ""
    if 'Config::get_option("whitelist")' not in check or "contains(addr.ip())" not in check:
        return False, "check_whitelist no longer matches the peer against the whitelist option"
    return True, ""


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


MSI_DIR = "res/msi/Package"
VISIBLE_ATTR = re.compile(r'\b(?:Value|Text|Title|Name|Description)="([^"]*)"')


def installer_strings(pkg):
    """Every string a person can read in the WiX sources, as "<file>: <value>".

    Localisation values, dialog text, shortcut and folder names; XML comments
    dropped. RuntimeBroker_* is an internal helper process name, never shown."""
    out = []
    for f in sorted(pkg.rglob("*.wx[sli]")) if pkg.is_dir() else []:
        text = re.sub(r"<!--.*?-->", "", f.read_text(encoding="utf-8-sig", errors="replace"), flags=re.S)
        out += [f"{f.name}: {v}" for v in VISIBLE_ATTR.findall(text) if not v.startswith("RuntimeBroker_")]
    return out
ART = {"banner": ("WixUIBannerBmp", (493, 58)), "dialog": ("WixUIDialogBmp", (493, 312))}


def bmp_facts(path):
    """(width, height, bits per pixel, distinct colours sampled) of a BMP, or None."""
    try:
        b = path.read_bytes()
    except OSError:
        return None
    if b[:2] != b"BM":
        return None
    off, w, h, bpp = (int.from_bytes(b[10:14], "little"), int.from_bytes(b[18:22], "little"),
                      abs(int.from_bytes(b[22:26], "little", signed=True)), int.from_bytes(b[28:30], "little"))
    px = b[off:]
    colours = {px[i:i + 3] for i in range(0, len(px) - 2, 3 * 7)} if bpp == 24 else set()
    return w, h, bpp, len(colours)


def license_after_preprocess(root, app_name):
    """License.rtf as the MSI gets it: upstream's preprocess.py license step, run on a copy."""
    src = root / "res/msi/preprocess.py"
    if not src.is_file() or not (root / MSI_DIR / "License.rtf").is_file():
        return None
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        shutil.copy(src, tmp / "preprocess.py")
        (tmp / "Package").mkdir()
        shutil.copy(root / MSI_DIR / "License.rtf", tmp / "Package/License.rtf")
        code = ("import sys; sys.path.insert(0, sys.argv[1]); sys.argv[0] = sys.argv[1] + '/preprocess.py'; "
                "import preprocess; preprocess.update_license_file(sys.argv[2])")
        r = subprocess.run([sys.executable, "-I", "-c", code, str(tmp), app_name or ""], capture_output=True)
        return (tmp / "Package/License.rtf").read_bytes() if r.returncode == 0 else None


PROTOCOL_HASHES = pathlib.Path(__file__).resolve().parent / "protocol.sha256"


def protocol_matches(root):
    """(ok, why): the tree's .proto files are exactly those in protocol.sha256, unchanged.

    The hashes are upstream's at our base, taken with LF endings so a CRLF
    checkout matches; a rebase that changes a proto updates them (boring/REBASE.md)."""
    want = dict(reversed(l.split(maxsplit=1)) for l in PROTOCOL_HASHES.read_text().splitlines() if l.strip())
    have = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
            for p in root.rglob("*.proto") if p.is_file() and not p.relative_to(root).as_posix().startswith(
                ("target/", ".git/"))}
    bad = sorted(f for f in want.keys() | have.keys() if want.get(f) != have.get(f))
    return not bad, ", ".join(bad)


def msi_checks(c, workflows):
    """Windows installer: name, exe, art, license, no RustDesk text, release on tags."""
    pkg = c.root / MSI_DIR
    wxs = c.read(f"{MSI_DIR}/Package.wxs")
    pre = c.read("res/msi/preprocess.py")
    c.fact("MSI product name is Boring Remote (installer, Apps list)",
           f'<Package Name="{rebrand.DISPLAY_NAME}"' in wxs)
    app = re.search(r'"--app-name", type=str, default="([^"]*)"', pre)
    c.fact(f"MSI installs {rebrand.APP_NAME}.exe", app and app.group(1) == rebrand.APP_NAME
           and 'Name="$(var.Product).exe"' in c.read(f"{MSI_DIR}/Components/RustDesk.wxs"), app and app.group(1))
    m = re.search(r'"--manufacturer",\s*type=str,\s*default="([^"]*)"', pre)
    c.fact("MSI manufacturer is Boring Labs", m and m.group(1) == rebrand.MANUFACTURER, m and m.group(1))
    shortcut = re.search(r'<String Id="SC_Client" Value="([^"]*)"', c.read(rebrand.WXL))
    c.fact("Start menu shortcut is Boring Remote", shortcut and shortcut.group(1) == rebrand.DISPLAY_NAME)

    hits = [h for h in installer_strings(pkg) if "rustdesk" in h.split(": ", 1)[1].lower()]
    arp = re.search(r"g_arpsystemcomponent = \{(.*?)\n\}", pre, re.S)
    if arp is None or "rustdesk" in arp.group(1).lower():
        hits.append("preprocess.py: Apps list support links")
    c.fact("no RustDesk in installer text", pkg.is_dir() and not hits, "; ".join(hits[:10]))

    for what, (name, size) in ART.items():
        facts = bmp_facts(pkg / f"Resources/{name}.bmp")
        c.fact(f"MSI {what} art is {size[0]}x{size[1]}, 24-bit, designed (not blank)",
               facts is not None and facts[:3] == (*size, 24) and facts[3] >= 8
               and f'"{name}"' in pre and "Package/Resources/{var}.bmp" in pre, str(facts))
    ours_lic = (rebrand.HERE / "msi/License.rtf").read_bytes()
    built = license_after_preprocess(c.root, app and app.group(1))
    c.fact("installer license is the Boring Remote AGPL notice",
           b"GNU Affero General Public License" in ours_lic and b"personal data" not in ours_lic
           and b"modified version of RustDesk" in ours_lic  # the upstream credit stays
           and built == ours_lic and '<WixVariable Id="WixUILicenseRtf" Value="License.rtf" />' in wxs,
           "preprocess.py rewrites License.rtf" if built != ours_lic else "")
    icon = (rebrand.HERE / "msi/icon.ico").read_bytes()
    c.fact("product icon is Boring Remote's", all(
        (c.root / p).is_file() and (c.root / p).read_bytes() == icon
        for p in ("res/icon.ico", "flutter/windows/runner/resources/app_icon.ico")))
    amyuni = [w.name for w in workflows if "usbmmidd" in w.read_text()]
    if 'Custom Action="RemoveAmyuniIdd"' in c.read(f"{MSI_DIR}/Components/RustDesk.wxs"):
        amyuni.append("RustDesk.wxs")
    c.fact("no Amyuni driver in the build or the installer", not amyuni, ", ".join(amyuni))

    ours = "".join(w.read_text() for w in workflows if w.name.startswith(rebrand.OUR_WORKFLOW_PREFIX))
    c.fact("tags publish a GitHub release with the MSI and its sha256",
           "startsWith(github.ref, 'refs/tags/')" in ours and "preprocess.py" in ours
           and ".msi.sha256" in ours and "contents: write" in ours)
    # PowerShell's Set-Content ends lines with CRLF; sha256sum -c on Ubuntu then looks for "x.msi\r"
    writers = [l.strip() for l in ours.splitlines() if ".sha256" in l and re.search(r"Set-Content|Out-File|>", l)]
    c.fact("MSI .sha256 is written with LF, so sha256sum -c passes on Linux",
           writers and all("-NoNewline" in l and '`n"' in l for l in writers), str(writers))


def run_checks(root, rerun=True):
    c = Check(root)
    cfg = c.read(HBB)

    # identity
    m = re.search(r'static ref APP_NAME: RwLock<String> = RwLock::new\("([^"]*)"', cfg)
    app_name = m and m.group(1)
    c.fact("app name is BoringRemote", app_name == "BoringRemote", app_name)
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
    # the app's real config dir is ~/Library/Preferences/<ORG>.<APP_NAME> (hbb_common Config::path)
    org = re.search(r'static ref ORG: RwLock<String> = RwLock::new\("([^"]*)"', cfg)
    conf_dir = f"{org and org.group(1)}.{app_name}"
    install = c.read("src/platform/privileges_scripts/install.scpt")
    dirs = set(re.findall(r"Library/Preferences/([^/\"]+)/", install))
    tomls = set(re.findall(r'"([^"/]+\.toml)"', install))
    c.fact("install script copies the real config dir, Preferences/io.boringlabs.BoringRemote/",
           conf_dir == "io.boringlabs.BoringRemote" and dirs == {conf_dir}
           and tomls == {"BoringRemote.toml", "BoringRemote2.toml"}, f"config dir {conf_dir}, script {dirs} {tomls}")

    # servers and locked settings
    c.fact("rendezvous servers empty", re.search(r"RENDEZVOUS_SERVERS: &\[&str\] = &\[\s*\];", cfg))
    locked = rust_map(cfg, "OVERWRITE_SETTINGS")
    for key in ("custom-rendezvous-server", "relay-server", "api-server"):
        c.fact(f"{key} locked empty", key in locked and locked[key] == "", locked.get(key))
    c.fact("whitelist locked to the tailnet (100.64.0.0/10, fd7a:115c:a1e0::/48)",
           sorted(locked.get("whitelist", "").split(",")) == ["100.64.0.0/10", "fd7a:115c:a1e0::/48"],
           locked.get("whitelist"))
    c.fact("Direct IP locked on", locked.get("direct-server") == "Y")
    conn = c.read("src/server/connection.rs")
    ok, why = whitelist_enforced(conn, c.read("libs/hbb_common/src/lib.rs"))
    c.fact("whitelist is enforced on incoming connections", ok, why)
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
        ("src/lan.rs", "pub(super) fn start_listening() -> ResultType<()> {", "LAN discovery listener"),
        # lock bypasses: each of these writes past OVERWRITE_SETTINGS
        ("src/platform/windows.rs", "pub fn get_license_from_exe_name() -> ResultType<CustomServer> {",
         "Windows exe-name license (sets rendezvous and API server)"),
        ("src/common.rs", "pub fn read_custom_client(config: &str) {",
         "custom.txt reader (writes OVERWRITE_SETTINGS)"),
        (HBB, "pub fn get_rendezvous_servers() -> Vec<String> {",
         "rendezvous server list (rendezvous-servers option, serial path)"),
    ):
        first = first_statement(c.read(rel), sig)
        c.fact(f"{what} returns before doing anything",
               first is not None and re.match(r"(if true \{ )?(return\b|bail!)", first), f"{rel}: {first!r}")
    c.fact("rendezvous-servers locked empty", locked.get("rendezvous-servers") == "",
           locked.get("rendezvous-servers"))
    body = fn_body(cfg, "pub fn get_rendezvous_server() -> String {") or ""
    c.fact("no rendezvous server read from the config file",
           body and "rendezvous_server = CONFIG2" not in body and "get_rendezvous_servers()" in body)
    c.fact("auto update locked off", locked.get("allow-auto-update") == "N")
    c.fact("LAN discovery locked off", locked.get("enable-lan-discovery") == "N",
           locked.get("enable-lan-discovery"))
    c.fact("update check locked off", rust_map(cfg, "OVERWRITE_LOCAL_SETTINGS").get("enable-check-update") == "N")
    lib = c.read("libs/hbb_common/src/lib.rs")
    c.fact("version check endpoint empty", 'const URL: &str = "";' in lib)

    hits, index = [], []
    for base in ("src", "libs", "flutter/lib"):
        for p in sorted((c.root / base).rglob("*")):
            if p.suffix not in (".rs", ".dart") or not p.is_file() or "/lang/" in p.as_posix():
                continue
            code = strip_tests_and_comments(p.read_text(encoding="utf-8", errors="replace"))
            hits += [f"{p.relative_to(c.root)}: {h}" for h in PUBLIC_SERVER.findall(code)]
            index += [f"{p.relative_to(c.root)}: {h}" for h in re.findall(r"RENDEZVOUS_SERVERS\[[^\]]*\]", code)]
    c.fact("no shipped code names a RustDesk public server", not hits, "; ".join(hits[:10]))
    c.fact("no code indexes the empty RENDEZVOUS_SERVERS (id@public panics)", not index, "; ".join(index))
    public = re.search(r"if other_server == PUBLIC_SERVER \{(.*?)\} else", c.read("src/client.rs"), re.S)
    c.fact("id@public peer fails with an error", public is not None and "split_first()" in public.group(1)
           and "bail!(" in public.group(1), public and public.group(1)[:200])

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
    # the other pins can only be checked against upstream's workflows: boring/pins.py
    app = re.search(r'(?m)^version = "([^"]*)"', c.read("Cargo.toml"))
    wfv = re.search(r'(?m)^  VERSION: "([^"]*)"', c.read(".github/workflows/boring-build.yml"))
    c.fact("workflow VERSION matches Cargo.toml version",
           app and wfv and app.group(1) == wfv.group(1),
           f"workflow {wfv and wfv.group(1)}, Cargo.toml {app and app.group(1)}; run boring/pins.py --fix")

    msi_checks(c, workflows)

    # protocol untouched: every .proto in the tree is upstream's, byte for byte
    c.fact("protocol files are upstream's (boring/protocol.sha256)", *protocol_matches(c.root))

    if rerun:
        def snap():
            files = {rel for rel, *_ in rebrand.PATCHES} | {rel for _, rel, _ in rebrand.COPIES} | {
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
