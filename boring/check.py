#!/usr/bin/env python3
"""Rebrand check: prove a scripted tree is the Boring Remote Desk app.

Usage:  python3 boring/check.py [ROOT]

Reads the tree after boring/rebrand.py has run and asserts what the spec asks
for: name, bundle IDs, the Hosted servers as the only servers with every override forced to
them, their key baked in from boring/server-key.pub (ADR 0005), no global whitelist (the Direct
Link listener answers Tailscale and private LAN only, ADR 0003), Direct IP on, listener on all
interfaces, allow-only-conn-window-open available and off, sync / NAT test / updater unreachable,
LAN discovery on (ADR 0003) (ADR 0004: only the version file, its .sig and fulfillment /update),
no RustDesk public server named in shipped code, no GitHub Actions workflow, no hwcodec/vram in
any build invocation, Mac build with file copy-paste, the Windows MSI (name, exe, art sizes,
license, icon, no RustDesk text), no RustDesk name, link or logo a person sees on Mac or Windows
(strings, translations, app metadata, every logo slot; AGPL notices in the Legal dialog, license
and source link), that the connect box takes a name or IP as a Direct Link only and lets only a
Machine ID reach the Hosted servers (after its own pinned Direct Link), that the Target shows its
Machine ID, that the protocol files are upstream's plus our two LoginRequest fields, that a Target
without a generated Unattended Password stays off the Hosted servers and Setup asks for one, and
that the Update keeps 1.7.x's config (ticket 09). It only reads the tree.
Idempotence is proved by test_rebrand.py and build-mac's second-run step.

Prints one PASS/FAIL line per fact, then
    rebrand check: <n> passed, <m> failed
and exits 1 if anything failed. Stdlib only.
"""
import base64
import codecs
import hashlib
import json
import pathlib
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import rebrand  # noqa: E402

AGENT, HOSTD, APP, SHOWN = rebrand.AGENT_ID, rebrand.HOSTD_ID, rebrand.APP_NAME, rebrand.DISPLAY_NAME
# Upstream lines that would log an incoming link, and with it an activate link's License key.
LINK_LOGS = [
    ("src/platform/delegate.rs", 'log::debug!("URL received: {}", theurl);'),
    ("flutter/lib/common.dart", 'debugPrint("A uri was received: $uri.'),
    ("flutter/lib/common.dart", 'print("initialLink: $initialLink");'),
    ("flutter/lib/main.dart", 'debugPrint("launch args: $args");'),
]
PUBLIC_SERVER = re.compile(r"\b(?:rs-[a-z0-9-]+|api|admin)\.rustdesk\.com\b")
# ADR 0005, pinned here (not taken from rebrand.py): the one rendezvous/relay host the app
# knows, and the key file the build bakes. RustDesk's public servers' key never ships.
HOSTED = "rs.theboringremote.com"
SERVER_KEY = pathlib.Path(__file__).resolve().parent / "server-key.pub"
# The Hosted servers' public key itself, pinned: a key swapped in server-key.pub and baked by the
# rebrand fails here. Where the servers repo sits next to this one, its copy must match too.
PINNED_KEY = "2hUye2snQY5Roz1FXgypyJQwCjUuNcIX08ukFeo6TYk="
SERVERS_REPO_KEY = pathlib.Path(__file__).resolve().parents[2] / "boring-remote-servers/keys/id_ed25519.pub"
RUSTDESK_KEY = "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw="
# Ticket 09, pinned here (not taken from rebrand.py): what 1.7.x shipped. The config (saved
# machines, settings, trusted list) lives in ~/Library/Preferences/<ORG>.<APP_NAME> on Mac and
# %APPDATA%\<APP_NAME> on Windows; the License key is a local option. Change any and the
# 1.8.0 Update starts from an empty config.
SHIPPED_ORG, SHIPPED_APP, SHIPPED_KEY_OPTION = "io.boringlabs", "BoringRemote", "boring-license-key"
# Calls that clear saved machines or settings in bulk; nothing we add may make them.
CONFIG_WIPE = re.compile(r"PeerConfig::remove\(|\b(?:Config|Config2|LocalConfig)::set\(|set_options\(\s*"
                         r"(?:HashMap::new\(\)|Default::default\(\))|Config::path\(|mainRemovePeer|mainForgetPassword")
CONFIG_PATH = re.compile(r"Preferences|AppData|\.toml\b")
FORCE_SERVERS = ("if true { return RENDEZVOUS_SERVERS.iter().map(|x| x.to_string()).collect(); }"
                 " // boring-remote: the Hosted servers only")
FORCE_SERVER = ('if true { return format!("{}:{RENDEZVOUS_PORT}", RENDEZVOUS_SERVERS[0]); }'
                " // boring-remote: the Hosted servers only")
# Upstream update endpoints and GitHub releases URLs never appear in shipped code
# (ADR 0004 keeps this from ADR 0003; see updater_checks for the allowlist).
_U = r"[^\s\"'`)]*"
UPDATE_URL = re.compile(
    r"https?://(?:" + r"[\w.-]*rustdesk\.com/" + _U + r"(?:version|update|latest|release)" + _U
    + r"|api\.github\.com/" + _U + r"releases" + _U
    + r"|github\.com/" + _U + r"/releases/(?:latest|download)" + _U + r")")
VERSION_URL_DECL = re.compile(r'pub const VERSION_URL: &str = "(https://boringlabs\.online/[^"\s]+)";')
BANNED = re.compile(r"hwcodec|vram")
BUILD_CALL = re.compile(r"build\.py|cargo\b|FEATURES")
HBB = rebrand.HBB
RELEASE_SCRIPT = "boring/release/build-mac"  # the local release (spec slice 7); GitHub never builds


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


def whitelist_is_private(value):
    """The locked whitelist is exactly ADR 0003's set, and none of it is a public range."""
    import ipaddress
    want = {ipaddress.ip_network(n) for n in rebrand.WHITELIST.split(",")}
    try:
        got = {ipaddress.ip_network(n.strip()) for n in value.split(",") if n.strip()}
    except ValueError:
        return False
    return got == want and not any(n.is_global for n in got)


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
# Our two LoginRequest fields (ticket 06), pinned here rather than taken from rebrand.py, so
# renumbering or retyping them there (onto a number upstream may use) fails until this changes
# too, on purpose: it is a protocol change for trusted Controllers (boring/REBASE.md).
OUR_PROTO_FIELDS = ("  bytes boring_controller_pk = 1000;\n", "  bytes boring_login_sig = 1001;\n")


def protocol_matches(root):
    """(ok, why): the tree's .proto files are exactly those in protocol.sha256, plus our one addition.

    The hashes are upstream's at our base, taken with LF endings so a CRLF checkout matches; a
    rebase that changes a proto updates them (boring/REBASE.md). Our only change is
    rebrand.PROTO_PATCH (two LoginRequest fields, ticket 06): it has to be there exactly once,
    and with it undone the file has to hash to upstream's, so nothing else in it moved."""
    want = dict(reversed(l.split(maxsplit=1)) for l in PROTOCOL_HASHES.read_text().splitlines() if l.strip())
    rel_ours, old, new, _ = rebrand.PROTO_PATCH
    have, why = {}, []
    fields = tuple(l for l in new.splitlines(keepends=True)
                   if l.strip() and not l.lstrip().startswith(("//", "}")) and l not in old)
    if fields != OUR_PROTO_FIELDS or old != "  string avatar = 17;\n}\n":
        why.append(f"our LoginRequest fields aren't the pinned ones: {fields}")
    for p in root.rglob("*.proto"):
        rel = p.relative_to(root).as_posix()
        if not p.is_file() or rel.startswith(("target/", ".git/")):
            continue
        data = p.read_bytes().replace(b"\r\n", b"\n")
        if rel == rel_ours:
            text = data.decode("utf-8")
            if text.count(new) != 1:
                why.append(f"{rel}: our LoginRequest fields missing or changed")
            data = text.replace(new, old, 1).encode("utf-8")
        have[rel] = hashlib.sha256(data).hexdigest()
    bad = sorted(f for f in want.keys() | have.keys() if want.get(f) != have.get(f))
    return not bad and not why, ", ".join(why + bad)


def msi_checks(c):
    """Windows installer: name, exe, art, license, no RustDesk text."""
    pkg = c.root / MSI_DIR
    wxs = c.read(f"{MSI_DIR}/Package.wxs")
    pre = c.read("res/msi/preprocess.py")
    c.fact(f"MSI product name is {SHOWN} (installer, Apps list)",
           f'<Package Name="{rebrand.DISPLAY_NAME}"' in wxs)
    app = re.search(r'"--app-name", type=str, default="([^"]*)"', pre)
    c.fact(f"MSI installs {rebrand.APP_NAME}.exe", app and app.group(1) == rebrand.APP_NAME
           and 'Name="$(var.Product).exe"' in c.read(f"{MSI_DIR}/Components/RustDesk.wxs"), app and app.group(1))
    m = re.search(r'"--manufacturer",\s*type=str,\s*default="([^"]*)"', pre)
    c.fact(f"MSI manufacturer is {rebrand.MANUFACTURER}", m and m.group(1) == rebrand.MANUFACTURER, m and m.group(1))
    shortcut = re.search(r'<String Id="SC_Client" Value="([^"]*)"', c.read(rebrand.WXL))
    c.fact(f"Start menu shortcut is {SHOWN}", shortcut and shortcut.group(1) == rebrand.DISPLAY_NAME)

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
    c.fact(f"installer license is the {SHOWN} AGPL notice",
           b"GNU Affero General Public License" in ours_lic and b"personal data" not in ours_lic
           and b"modified version of RustDesk" in ours_lic  # the upstream credit stays
           and built == ours_lic and '<WixVariable Id="WixUILicenseRtf" Value="License.rtf" />' in wxs,
           "preprocess.py rewrites License.rtf" if built != ours_lic else "")
    icon = (rebrand.HERE / "msi/icon.ico").read_bytes()
    c.fact(f"product icon is {SHOWN}'s", all(
        (c.root / p).is_file() and (c.root / p).read_bytes() == icon
        for p in ("res/icon.ico", "flutter/windows/runner/resources/app_icon.ico")))
    amyuni = [RELEASE_SCRIPT] if "usbmmidd" in c.read(RELEASE_SCRIPT) else []
    if 'Custom Action="RemoveAmyuniIdd"' in c.read(f"{MSI_DIR}/Components/RustDesk.wxs"):
        amyuni.append("RustDesk.wxs")
    c.fact("no Amyuni driver in the build or the installer", not amyuni, ", ".join(amyuni))


# --- branding: what a person sees on Mac and Windows ------------------------
BRAND = re.compile(r"RustDesk|rustdesk\.com|github\.com/rustdesk")
NOT_SHIPPED = ("flutter/lib/mobile/", "flutter/lib/web/",  # Android/iOS pages and the web client
               "src/lang/",  # translations: their own fact below
               "src/ui/", "src/ui.rs")  # the old Sciter UI, not built with --flutter
LINUX_ONLY = ("src/server/wayland.rs", "src/server/uinput.rs", "src/server/dbus.rs", "src/ipc/drm.rs",
              "src/whiteboard/linux.rs", "src/clipboard.rs")  # clipboard.rs: the KDE-only placeholder
UI_SOURCES = (("flutter/lib", (".dart",)), ("src", (".rs",)),
              ("flutter/macos/Runner", (".swift",)), ("flutter/windows/runner", (".cpp", ".h")))
# (file, regex the whole literal matches): never shown to a person. Code names, paths, driver ids.
INTERNAL = {
    ("flutter/lib/models/rustdesk_terminal.dart", r"\[RustDeskTerminal\] .*"): "debug log tag",
    ("src/common.rs", r"RustDesk"): "is_rustdesk() / is_custom_client() compare the app name",
    ("src/common.rs", r"\.?rustdesk\.com"): "is_public() spots RustDesk's hosts to refuse them",
    ("src/lang.rs", r"RustDesk"): "the translation lookup's own replacement logic",
    ("src/platform/macos.rs", r"RustDesk"): "correct_app_name() rewrites scripts to our app name",
    ("src/platform/macos.rs", r"(?s).*\[root-update\] RustDesk GUI process did not stop.*"): "updater log line",
    ("src/platform/windows.rs", r"RustDesk(CustomClientStaging)?"): "custom-client staging dir",
    ("src/privacy_mode/win_topmost_window.rs", r"RustDeskPrivacyWindow(Class)?"): "window class, never shown",
    ("src/server/connection.rs", r"RustDesk://FsJob//Printer/\{\}"): "printer job path",
    ("src/virtual_display_manager.rs", r"RustDeskIddDriver Device\\0"): "driver device id",
    ("flutter/macos/Runner/MainFlutterWindow.swift", r"RustDeskPlugin"): "Flutter plugin registrar name",
    ("flutter/windows/runner/main.cpp", r"RustDesk"): "fallback window name for FindWindow",
}
LOG_CALL = re.compile(r"\b(?:debugPrint|print|NSLog|log::\w+|(?:log|debug|info|warn|error|trace)!)\s*\(|std::cout")
DART_TOKENS = re.compile(r"//[^\n]*|/\*.*?\*/|'''.*?'''|\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'", re.S)
C_TOKENS = re.compile(r'//[^\n]*|/\*.*?\*/|r#*"(?:.|\n)*?"#*|"(?:[^"\\\n]|\\.)*"', re.S)
LOGOS = pathlib.Path(__file__).resolve().parent / "upstream-logos.sha256"
LOGO_SKIP = (".git/", "target/", "boring/", "flutter/build/", "flutter/android/", "flutter/ios/")


def string_literals(text, tokens):
    """(literal without quotes, its source line) for every string literal, comments skipped."""
    for m in tokens.finditer(text):
        s = m.group(0)
        if s.startswith(("//", "/*")):
            continue
        line = text[text.rfind("\n", 0, m.start()) + 1:text.find("\n", m.end())]
        yield re.sub(r'^r?#*["\']+|["\']+#*$', "", s), line


def ui_brand_hits(root):
    """(hits, files with the legal line): RustDesk names and links a person could see in the app."""
    hits, legal = [], []
    for base, exts in UI_SOURCES:
        for p in sorted((root / base).rglob("*")) if (root / base).is_dir() else []:
            rel = p.relative_to(root).as_posix()
            if p.suffix not in exts or not p.is_file() or rel.startswith(NOT_SHIPPED) or rel in LINUX_ONLY:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
            if p.suffix == ".rs":
                text = strip_tests_and_comments(text)
            for s, line in string_literals(text, DART_TOKENS if p.suffix == ".dart" else C_TOKENS):
                if not BRAND.search(s) or LOG_CALL.search(line):
                    continue
                if s == rebrand.LEGAL_CREDIT:
                    legal.append(rel)
                elif not any(f == rel and re.fullmatch(pat, s) for f, pat in INTERNAL):
                    hits.append(f"{rel}: {s[:80]}")
    return hits, legal


LANG_VALUE = re.compile(r'\(\s*"((?:[^"\\]|\\.)*)",\s*"((?:[^"\\]|\\.)*)"\s*\)')


def lang_hits(root):
    """Translation values that name RustDesk or link to it, in any language."""
    out = []
    for p in sorted((root / "src/lang").glob("*.rs")):
        for key, value in LANG_VALUE.findall(p.read_text(encoding="utf-8", errors="replace")):
            if BRAND.search(value):
                out.append(f"{p.name}: {key}")
    return out


def native_brand_hits(c):
    """App metadata the OS shows: Finder, Get Info, the Mac menu, exe Properties."""
    out = []
    try:
        info = plistlib.loads((c.root / "flutter/macos/Runner/Info.plist").read_bytes())
    except Exception:
        info = {}
    out += [f"Info.plist {k}" for k, v in info.items() if isinstance(v, str) and re.search(r"RustDesk|Purslane", v)]
    if info.get("CFBundleName") != SHOWN:
        out.append(f"Info.plist CFBundleName {info.get('CFBundleName')}")
    xc = c.read("flutter/macos/Runner/Configs/AppInfo.xcconfig")
    out += [f"AppInfo.xcconfig: {l}" for l in xc.splitlines() if re.search(r"RustDesk|Purslane", l)]
    xib = c.read("flutter/macos/Runner/Base.lproj/MainMenu.xib")
    out += [f"MainMenu.xib: {t}" for t in re.findall(r'\btitle="([^"]*)"', xib) if re.search(r"RustDesk|APP_NAME", t)]
    rc = c.read("flutter/windows/runner/Runner.rc")
    out += [f"Runner.rc: {k}" for k, v in re.findall(r'VALUE "(\w+)", "([^"]*)"', rc)
            if re.search(r"RustDesk|Purslane", v)]
    cargo = c.read("Cargo.toml")
    for section in ("package.metadata.winres", "package.metadata.bundle"):
        m = re.search(rf"^\[{re.escape(section)}\]\n(.*?)(?=^\[)", cargo, re.S | re.M)
        if m is None or re.search(r"RustDesk|Purslane", m.group(1)):
            out.append(f"Cargo.toml [{section}]")
    return out


def png_pixels(path):
    """(width, height, [(r, g, b, a)]) of an 8-bit RGBA non-interlaced PNG, else None. Stdlib only."""
    import struct
    import zlib
    try:
        b = path.read_bytes()
    except OSError:
        return None
    if b[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    i, idat, hdr = 8, b"", None
    while i + 8 <= len(b):
        n, kind = struct.unpack(">I4s", b[i:i + 8])
        data = b[i + 8:i + 8 + n]
        if kind == b"IHDR":
            hdr = struct.unpack(">IIBBBBB", data)
        elif kind == b"IDAT":
            idat += data
        i += 12 + n
    if not hdr or hdr[2:5] != (8, 6, 0) or hdr[6] != 0:
        return None
    w, h = hdr[:2]
    raw, stride, prev, px = zlib.decompress(idat), w * 4, bytearray(w * 4), []
    for y in range(h):
        f = raw[y * (stride + 1)]
        line = bytearray(raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)])
        for x in range(stride):
            a = line[x - 4] if x >= 4 else 0
            up, ul = prev[x], (prev[x - 4] if x >= 4 else 0)
            if f == 1:
                line[x] = (line[x] + a) & 255
            elif f == 2:
                line[x] = (line[x] + up) & 255
            elif f == 3:
                line[x] = (line[x] + (a + up) // 2) & 255
            elif f == 4:
                p = a + up - ul
                pa, pb, pc = abs(p - a), abs(p - up), abs(p - ul)
                line[x] = (line[x] + (a if pa <= pb and pa <= pc else up if pb <= pc else ul)) & 255
        px += [tuple(line[x:x + 4]) for x in range(0, stride, 4)]
        prev = line
    return w, h, px


def contrast(fg, bg):
    """WCAG 2 contrast ratio of two RRGGBB colours."""
    def lum(h):
        rgb = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
        r, g, b = [v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4 for v in rgb]
        return 0.2126 * r + 0.7152 * g + 0.0722 * b
    a, b = sorted((lum(fg), lum(bg)), reverse=True)
    return (a + 0.05) / (b + 0.05)


ARGS = r"(?:[^()]|\((?:[^()]|\([^()]*\))*\))*?"  # call arguments, two levels of parentheses
CORAL_UNDER_TEXT = [
    re.compile(r"TextStyle\(" + ARGS + r"(?:MyTheme\.accent(?:50|80)?\b|_accentColor)"),  # coral text
    re.compile(r"buildButton\(" + ARGS + r"color: MyTheme\.accent\b"),  # fill under white text
    re.compile(r"(?:backgroundColor|foregroundColor): (?:MaterialStateProperty\.all\(\s*)?"
               r"(?:[\w.]+\s*\?\s*)?(?:MyTheme\.accent(?:50|80)?\b)"),
    re.compile(r"(?s)backgroundColor: MaterialStateProperty\.all\((?:(?!\)\s*,).)*?MyTheme\.accent"),
    re.compile(r"isOwnMessage \? MyTheme\.accent\b"),
    re.compile(r"BoxDecoration\(\s*color: pressed\.value\s*\? MyTheme\.accent\b"),  # button fill
]


def coral_text_hits(root):
    """Places in the desktop Dart where coral is the colour of text, or the fill behind it."""
    out = []
    for p in sorted((root / "flutter/lib").rglob("*.dart")) if (root / "flutter/lib").is_dir() else []:
        rel = p.relative_to(root).as_posix()
        if rel.startswith(NOT_SHIPPED):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        for pat in CORAL_UNDER_TEXT:
            out += [f"{rel}:{text.count(chr(10), 0, m.start()) + 1}" for m in pat.finditer(text)]
    return sorted(set(out))


ABOUT_LEGAL = "About page has a plain Legal item that opens the Legal dialog, the one place RustDesk is named"
LEGAL_NOTICES = "Legal dialog has AGPL's notices: RustDesk's copyright, no warranty, may share, read the license, source"
LICENCE_BUNDLED = "the license ships inside the app, byte for byte, and Legal reads it from there"
SOURCE_LINK = "the source link reaches the user: Legal and the installer license name FORK_URL, the install screen opens Legal"
SOURCE_NOTICE = "the source says it is modified, with a date, and source-tarball.sh can make it (AGPL 5(a), 6)"
NO_OWNER = "nothing shipped names the owner"
# Text that ships, or that the app is built from. boring/ and tests don't ship.
# The words are rot13 because this file is in the public source tarball: it must not name them either.
OWNER_WORDS = codecs.decode("zbabyvgu3 wnfba obevatfgbevrf", "rot_13").split()
OWNER = re.compile("|".join(OWNER_WORDS), re.I)
OWNER_DIRS = ("flutter/lib", "flutter/macos/Runner", "flutter/windows/runner", "flutter/assets", "src", "libs", "res")
OWNER_FILES = ("Cargo.toml", "flutter/pubspec.yaml", "flutter/macos/Runner.xcodeproj/project.pbxproj")
OWNER_EXTS = {".dart", ".rs", ".swift", ".cpp", ".cc", ".c", ".h", ".mm", ".m", ".plist", ".xcconfig", ".xib",
              ".rc", ".wxl", ".wxs", ".rtf", ".txt", ".toml", ".yaml", ".json", ".py", ".strings"}
NOT_THE_OWNER = "libs/clipboard/src/windows/wf_cliprdr.c"  # upstream's copyright header, someone else, stays
LEGAL_ITEM = "onTap: () => showLegalDialog(context),"


def owner_hits(root):
    paths = [root / f for f in OWNER_FILES]
    for base in OWNER_DIRS:
        paths += [p for p in (root / base).rglob("*") if p.suffix in OWNER_EXTS]
    out = []
    for p in paths:
        rel = p.relative_to(root).as_posix()
        if p.is_file() and rel != NOT_THE_OWNER and OWNER.search(p.read_text(encoding="utf-8", errors="replace")):
            out.append(rel)
    return sorted(out)


def legal_checks(c, legal):
    """AGPL 5(d) + 0, 6 + 13: the notices, the license and the source stay reachable (ticket 32)."""
    words = c.read(rebrand.LEGAL_DART)
    about = c.read(rebrand.SETTINGS)
    c.fact(ABOUT_LEGAL, legal == [rebrand.LEGAL_DART] and rebrand.ABOUT_NEW in about and LEGAL_ITEM in about,
           f"credit found in {legal}")
    missing = [w for w in (f"credit = '{rebrand.LEGAL_CREDIT}'", "licensed under the GNU AGPL, version 3",
                           "copy, change and share it", "no warranty", "readLicense = 'Read the license'",
                           "Text(LegalWords.credit)", "Text(LegalWords.license)", "Text(LegalWords.noWarranty)",
                           "Text(LegalWords.readLicense)", "Text(LegalWords.sourceUrl)",
                           "openUrl(LegalWords.sourceUrl)", "Text(LegalWords.getSource)") if w not in words]
    c.fact(LEGAL_NOTICES, not missing, "; ".join(missing))
    asset, licence = c.root / rebrand.LICENCE_ASSET, c.root / "LICENCE"
    c.fact(LICENCE_BUNDLED,
           asset.is_file() and licence.is_file() and asset.read_bytes() == licence.read_bytes()
           and "GNU AFFERO GENERAL PUBLIC LICENSE" in licence.read_text()
           and "    - assets/\n" in c.read("flutter/pubspec.yaml")
           and f"kLicenseAsset = '{rebrand.LICENCE_ASSET.removeprefix('flutter/')}'" in words)
    rtf = c.read(f"{MSI_DIR}/License.rtf")
    bad = [w for w, ok in ((f"Legal: sourceUrl is not {rebrand.FORK_URL}",
                            f"sourceUrl = '{rebrand.FORK_URL}'" in words),
                           ("installer license has no source link", rebrand.FORK_URL in rtf),
                           ("install screen does not open Legal",
                            "onLicence: () => showLegalDialog(this.context)," in c.read(rebrand.LOOK_INSTALL))) if not ok]
    c.fact(SOURCE_LINK, not bad, "; ".join(bad))
    notice = c.read("NOTICE")
    c.fact(SOURCE_NOTICE, "modified version of RustDesk" in notice and "Purslane" in notice
           and re.search(r"since \d{4}-\d{2}-\d{2}", notice) is not None
           and (c.root / "boring/release/source-tarball.sh").is_file())
    hits = owner_hits(c.root)
    c.fact(NO_OWNER, not hits, ", ".join(hits[:12]))


def branding_checks(c):
    """No RustDesk name, link or logo a person sees in the Mac and Windows app."""
    hits, legal = ui_brand_hits(c.root)
    c.fact("no RustDesk name or link in the Mac and Windows app's strings", not hits, "; ".join(hits[:12]))
    legal_checks(c, legal)
    lang = lang_hits(c.root)
    c.fact("no RustDesk name or link in any translation", (c.root / "src/lang").is_dir() and not lang,
           f"{len(lang)} values: " + "; ".join(lang[:8]))
    lookup = fn_body(c.read("src/lang.rs"), "pub fn translate_locale(name: String, locale: &str) -> String {") or ""
    c.fact(f"translated text shows {SHOWN}, also when a key falls back to itself",
           f'let mut s = s.replace("RustDesk", "{SHOWN}");' in lookup)
    native = native_brand_hits(c)
    c.fact("no RustDesk in app metadata (Info.plist, Mac menu, exe properties)", not native, "; ".join(native))
    win = fn_body(c.read("flutter/lib/common.dart"), "String getWindowName({WindowType? overrideType}) {") or ""
    tray = fn_body(c.read("src/tray.rs"), "fn make_tray() -> hbb_common::ResultType<()> {") or "crate::get_app_name()"
    c.fact(f"window titles and tray tooltip say {SHOWN}",
           f"final name = '{SHOWN}';" in win and f": '{SHOWN}'," in c.read("flutter/lib/main.dart")
           and "crate::get_app_name()," not in tray)
    c.fact("app accent is Boring Labs coral",
           "static const Color accent = Color(0xFFFF5949);" in c.read("flutter/lib/common.dart"))
    low = [f"{fg} on {bg} {contrast(fg, bg):.2f}:1 ({where})" for fg, bg, where in rebrand.TEXT_PAIRS
           if contrast(fg, bg) < 4.5]
    common = c.read("flutter/lib/common.dart")
    ink, paper = rebrand.INK, rebrand.PAPER
    uses = (f"static const Color button = Color(0xFF{ink});" in common
            and "static Color get accentText => currentThemeMode() == ThemeMode.dark ? paper : ink;" in common
            and f"static const Color ink = Color(0xFF{ink});" in common
            and f"static const Color paper = Color(0xFF{paper});" in common
            and common.count("backgroundColor: MyTheme.ink,\n        foregroundColor: Colors.white,") == 2)
    c.fact("every text colour pair clears 4.5:1 (ink buttons with white text, ink or paper accent text)",
           not low and uses, "; ".join(low) or "tree does not use the TEXT_PAIRS colours")
    coral = coral_text_hits(c.root)
    c.fact("coral is never text or a fill under text", not coral, "; ".join(coral[:10]))

    upstream = dict(reversed(l.split(maxsplit=1)) for l in LOGOS.read_text().splitlines() if l.strip())
    bad_hash = set(upstream.values())
    still = sorted(p.relative_to(c.root).as_posix() for p in c.root.rglob("*")
                   if p.is_file() and not p.relative_to(c.root).as_posix().startswith(LOGO_SKIP)
                   and hashlib.sha256(p.read_bytes()).hexdigest() in bad_hash)
    c.fact("no upstream RustDesk logo or icon ships (boring/upstream-logos.sha256)", not still, ", ".join(still))
    ours = {dest: src for src, dest, _ in rebrand.COPIES}
    missing = [slot for slot in upstream if slot not in ours or not (c.root / slot).is_file()
               or (c.root / slot).read_bytes() != (rebrand.HERE / ours[slot]).read_bytes()]
    c.fact(f"every logo slot holds {SHOWN} art", not missing, ", ".join(missing))
    for slot in ("res/mac-tray-dark-x2.png", "res/mac-tray-light-x2.png"):
        img = png_pixels(c.root / slot)
        ink = [p for p in img[2] if p[3] > 0] if img else []
        c.fact(f"Mac menu-bar icon {slot} is a template glyph (black, alpha only, not blank)",
               img is not None and img[0] == img[1] and img[0] >= 36 and {p[:3] for p in ink} == {(0, 0, 0)}
               and 0.08 < len(ink) / len(img[2]) < 0.7, img and f"{img[0]}x{img[1]}")


DIRECT_LINK = "libs/base/src/direct_link.rs"
CONNECT_ENCRYPTED = "Direct Link is always encrypted and pinned, Tailscale too; plaintext refused both ends (ADR 0005, 0004 amendment)"
# A Machine ID is digits only: never an address, a tailnet name or id@server (another server).
MACHINE_ID_TEST = "!peer.is_empty() && peer.len() <= 20 && peer.bytes().all(|b| b.is_ascii_digit())"
CONNECT_DIRECT = ("connect box: a name or IP is a Direct Link only; only a Machine ID reaches the Hosted servers, "
                  "after its own Direct Link")
ROUTE_AROUND = re.compile(r"rendezvous|RENDEZVOUS|_start_inner|other_server|is_domain_port_str|get_lch")


def tailnet_exprs():
    """The Rust tests for rebrand.TAILNET's two ranges, derived from the CIDRs."""
    import ipaddress
    v4, v6 = (ipaddress.ip_network(n) for n in rebrand.TAILNET.split(","))
    assert v4.prefixlen == 10 and v6.prefixlen == 48, "is_tailscale is written for a /10 and a /48"
    o = v4.network_address.packed
    mask = (0xFF << (16 - v4.prefixlen)) & 0xFF
    segs = ", ".join(f"0x{int.from_bytes(v6.network_address.packed[i:i + 2], 'big'):x}" for i in (0, 2, 4))
    return (f"v4.octets()[0] == {o[0]} && (v4.octets()[1] & 0x{mask:x}) == {o[1]}",
            f"v6.segments()[..3] == [{segs}]")


def connect_checks(c):
    """v1.7 t03 + 1.8 ticket 08: a name or IP is a Direct Link only (own address, then Tailscale,
    ADR 0004; encrypted or refused, ADR 0005), never the ID path; only a Machine ID goes on to the
    Hosted servers (ADR 0005 hosted), after its own Direct Link attempt."""
    client = c.read("src/client.rs")
    body = fn_body(client, "    async fn _start(\n") or ""
    guard = body.find(rebrand.DIRECT_LINK_CALL)
    pre = strip_tests_and_comments(body[:guard]) if guard >= 0 else ""
    block = strip_tests_and_comments(body[guard:guard + len(rebrand.DIRECT_LINK_CALL)]) if guard >= 0 else ""
    tops = [l.strip() for l in pre.splitlines() if l.startswith("        ") and not l.startswith("         ")]
    why = []
    if guard < 0:
        why.append("no Direct Link return for names and IPs in _start")
    if ROUTE_AROUND.search(pre):
        why.append(f"_start touches the ID path first: {ROUTE_AROUND.findall(pre)}")
    if "if config::is_incoming_only()" not in pre or any(not t.startswith(("if ", "}", "bail!")) for t in tops):
        why.append(f"only the incoming-only branch may come before the Direct Link: {tops}")
    head = block.split("crate::connect_plan::direct_first", 1)[0]
    if guard >= 0 and (not head.lstrip().startswith("if !boring_is_machine_id(peer) {") or "return Ok((" not in head
                       or "else" in block or "?;" not in head or block.count("return Ok((") != 2):
        why.append("the name/IP Direct Link block does not always return, or not first")
    is_id = re.sub(r"\s+", " ", fn_body(client, "pub(crate) fn boring_is_machine_id(peer: &str) -> bool {") or "").strip()
    if is_id != MACHINE_ID_TEST:
        why.append(f"a Machine ID isn't digits only: {is_id!r}")
    calls = [m.start() for m in re.finditer(r"Self::_start_inner\(", client)]
    start = client.find("    async fn _start(\n")
    if not calls or any(not (start < i < start + len(body) + 200) for i in calls) or \
            len(re.findall(r"::_start\(", client)) != 1:
        why.append("_start / _start_inner are called from somewhere else")
    c.fact(CONNECT_DIRECT, not why,
           "; ".join(why))

    link = c.read(DIRECT_LINK)
    plan = fn_body(link, "pub async fn plan_for(") or ""
    is_ts = fn_body(link, "pub fn is_tailscale(ip: IpAddr) -> bool {") or ""
    v4, v6 = tailnet_exprs()
    why = []
    for name, text in rebrand.CONNECT_ERRORS.items():
        if link.count(f'pub const {name}: &str =') != 1 or f'"{text}"' not in link:
            why.append(f"{name} is not rebrand's text")
    for need in ("lookup_host(host)", "_ => bail!(NOT_FOUND),",
                 "if addrs.is_empty() || !addrs.iter().all(|a| crate::lan::is_allowed(a.ip())) {\n        bail!(NOT_FOUND);"):
        if need not in plan:
            why.append(f"resolver lost: {need.splitlines()[0]}")
    for need in (f"V4(v4) => {v4},", f"V6(v6) => {v6},"):
        if need not in is_ts:
            why.append(f"Tailscale test is not {need}")
    race = fn_body(link, "pub async fn race<") or ""
    if "bail!(NOT_ON_THIS_NETWORK)" not in race or "Err(Failure::Refused(e)) => return Err(e)," not in race:
        why.append("race no longer ends in Not on this network, or falls back past a refusal")
    if "hbb_common::timeout(ms, connect(addr)).await" not in race or "match handshake(s, addr).await {" not in race:
        why.append("the ~1 s no-answer budget no longer covers the TCP connect only")
    if "let ms = if is_tailscale(addr.ip()) || addr == last { slow_ms } else { direct_ms };" not in race:
        why.append("a LAN address with no fallback after it gets the ~1 s budget, not the full one")
    c.fact("connect box dials only Tailscale or private-LAN addresses, else the plain error", not why, "; ".join(why))

    dial = strip_tests_and_comments(fn_body(link, "pub async fn handshake(") or "")
    need = strip_tests_and_comments(fn_body(link, "pub fn require_encrypted(peer: IpAddr, stream: &Stream) -> ResultType<()> {") or "")
    server = c.read("src/server.rs")
    mediator = c.read("src/rendezvous_mediator.rs")
    why = []
    # Audit H2 (ADR 0004 amendment): no address range, Tailscale's included, skips the encryption.
    if "must_encrypt" in link:
        why.append("direct_link.rs still has a must_encrypt exemption")
    if not dial.lstrip().startswith("let who = secure(&mut stream, known, addr, ms).await?;\n"
                                    "    if !stream.is_secured() {\n        return Err(Failure::Refused("):
        why.append("controller: a dial is not handshake-then-is_secured first thing")
    if "is_tailscale" in dial or "is_tailscale" in need or "if !stream.is_secured() {" not in need:
        why.append("an address decides whether a Direct Link is encrypted")
    if rebrand.T03_HANDSHAKE_CALL not in server:
        why.append("target: create_tcp_connection does not refuse an unkeyed Direct Link")
    if rebrand.T03_LISTENER not in mediator or "direct_link: true," not in rebrand.T03_LISTENER \
            or "                            true,\n" not in rebrand.T03_LISTENER:
        why.append("target: the direct listener does not ask for encryption on every Direct Link")
    c.fact(CONNECT_ENCRYPTED, not why, "; ".join(why))

    home = c.read(rebrand.HOME)
    board = fn_body(home, "buildIDBoard(BuildContext context) {") or ""
    get_id = re.sub(r"\s+", " ", fn_body(c.read(HBB), "pub fn get_id() -> String {") or "").strip()
    builtin = re.search(r"static ref BUILTIN_SETTINGS: RwLock<HashMap<String, String>> = (.*?);\n", c.read(HBB))
    c.fact("the Target shows its Machine ID and keeps it across restarts (made once, then read from its config)",
           "      if (!isOutgoingOnly) buildIDBoard(context),\n" in home
           and f'translate("{rebrand.MACHINE_ID_LABEL}")' in board and "controller: model.serverId," in board
           and get_id == ("let mut id = CONFIG.read().unwrap().id.clone(); if id.is_empty() { "
                          "if let Some(tmp) = Config::gen_id() { id = tmp; Config::set_id(&id); } } id")
           and "config.store();" in (fn_body(c.read(HBB), "pub fn set_id(id: &str) {") or "")
           and builtin is not None and rust_map(c.read(HBB), "BUILTIN_SETTINGS") == {"disable-change-id": "Y"},
           f"label {'Machine ID' if rebrand.MACHINE_ID_LABEL in board else 'missing'}, get_id {get_id[:60]!r}")

    langs = sorted((c.root / rebrand.LANG_DIR).glob("*.rs"))
    missing = [f"{p.name}: {text[:30]}" for p in langs for text in rebrand.CONNECT_ERROR_KEYS
               if p.read_text(encoding="utf-8").count(f'("{text}", ') != 1]
    c.fact("every connect error is in every translation file",
           langs and not missing, ", ".join(missing[:10]))
    look = c.read("flutter/lib/desktop/kit/kit_look.dart")
    unmapped = [t[:40] for t in rebrand.CONNECT_ERROR_KEYS if f'  "{t}":\n      (_couldNot, null, null),' not in look]
    c.fact("the kit's message box shows each connect error as it is, with no second next step",
           not unmapped, "; ".join(unmapped))

    secure = fn_body(link, "pub async fn secure(") or ""
    pin = fn_body(link, "pub fn pin_ok(") or ""
    why = []
    if "if !known.pin_ok(dialled, &id_pk.id, &sign_pk) {\n        return Err(refused(IDENTITY_CHANGED));" not in secure:
        why.append("secure() does not check the pin for the address it dialled")
    if "(t.lan != at && t.tailscale != at) || (known_id == id && t.pk == pk)" not in pin or "self.0.get(id).map_or(true, |t| t.pk == pk)" not in pin:
        why.append("pin_ok no longer keeps an address's Target and an ID's key")
    c.fact("Direct Link pins the Target on the address dialled and on its ID (identity changed otherwise)",
           not why, "; ".join(why))


# ADR 0004 (docs/adr/0004-in-app-updater.md, supersedes 0003): the app may fetch
# the signed version file and its .sig, and POST the license key to fulfillment
# /update. Nothing else in shipped code is an update endpoint, and the only thing
# run as root for an update is install-update.sh.
UPDATE_ENDPOINTS = {
    "VERSION_URL": ("src/update_notice.rs", "https://boringlabs.online/downloads/the-boring-remote-version.json"),
    "UPDATE_ENDPOINT": ("src/license_key.rs", "https://boring-store-fulfillment.restless-term-7ead.workers.dev/update"),
    # v1.7 ticket 12 / ADR 0007: Windows downloads the MSI the signed version file names, only from here.
    "WINDOWS_DOWNLOADS": ("libs/base/src/update_feed.rs", "https://boringlabs.online/downloads/"),
}
UPDATEISH_URL = re.compile(r"https?://[^\s\"'`)<>]*(?:version|update|release|latest|download)[^\s\"'`)<>]*", re.I)
# Not app updates: (prefix, why).
NOT_UPDATE_URLS = (("https://api.telegram.org/bot{}/getUpdates", "2FA Telegram bot polling"),)
INSTALL_SCRIPT = "src/platform/privileges_scripts/install-update.sh"
# Every `with administrator privileges` site, as file or file:enclosing fn/const.
ROOT_CALLERS = {
    "src/update_install_run.rs:OSA": "runs Resources/boring-install-update.sh (slice 6), the one update path",
    "libs/base/src/bundle_move.rs:OSA": "runs the same script --move-bundle: 1.6.x's bundle to Boring Remote.app (t17)",
    "src/platform/macos.rs:elevate": "upstream daemon install/uninstall elevation, not an update",
    "src/platform/macos.rs:update_me": "upstream updater; dead because start_auto_update_macos returns first",
    "src/platform/privileges_scripts/update.scpt": "upstream updater script, only reached from update_me",
    "src/platform/privileges_scripts/install.scpt": "daemon install",
    "src/platform/privileges_scripts/uninstall.scpt": "daemon unload",
}
ROOT_SUFFIXES = (".rs", ".dart", ".scpt", ".swift", ".sh", ".py", ".m", ".mm")


def shipped_files(c, suffixes):
    for base in ("src", "libs", "flutter/lib"):
        for p in sorted((c.root / base).rglob("*")):
            if p.suffix in suffixes and p.is_file() and "/lang/" not in p.as_posix():
                yield p.relative_to(c.root).as_posix(), p.read_text(encoding="utf-8", errors="replace")


def multi_window_checks(c, cfg):
    """v1.7 ticket 11: sessions open in windows; a full-screen Target remembers its monitor."""
    c.fact("new sessions open in windows (tabs option off by default)",
           rust_map(cfg, "DEFAULT_LOCAL_SETTINGS").get(rebrand.T11_TABS_OPTION) == "N")
    # Ticket 09: the simple page's Advanced link opens the full page (General tab) holding this checkbox.
    c.fact("tabs option still on the Advanced settings page",
           "kOptionOpenNewConnInTabs" in c.read("flutter/lib/desktop/pages/desktop_setting_page.dart"))
    common = c.read(rebrand.T11_COMMON)
    hooks = ["import 'package:flutter_hbb/desktop/kit/session_window.dart';",
             "_boringLiveFrame = await wc.getFrame();", "return peerFrameWhileFull(",
             "window_size.getScreenList()).map((s) => s.frame)"]
    missing = [h for h in hooks if h not in common]
    c.fact("full-screen Target remembers its monitor (hooks landed)", not missing, "; ".join(missing))
    c.fact("restore moves the window to its monitor before full screen on Mac",
           "        // boring-remote: Mac too, so full screen lands on the Target's monitor.\n"
           "        await restoreFrame();\n" in common and "if (!isMacOS) {\n          await restoreFrame();" not in common)


# Colours an extras screen may not use once rebranded: upstream theme statics and raw colours.
EXTRAS_OFF_KIT = re.compile(r"MyTheme\.(?!color\(context\))\w+|Colors\.(?!transparent\b)\w+|Color\(0x[0-9A-Fa-f]+\)|kColorCanvas")


def simple_settings_checks(c):
    """v1.7 ticket 09: extras in the kit, Mac Settings = one simple page + Advanced."""
    pages = (rebrand.PORT_FWD, rebrand.TERMINAL, rebrand.CAMERA)
    off = [f"{rel}: {h}" for rel in pages
           for h in EXTRAS_OFF_KIT.findall(strip_tests_and_comments(c.read(rel)))]
    off += [f"{rel}: no kit theme" for rel in pages if "data: kitThemeKeeping(context)," not in c.read(rel)]
    if "theme: kitTerminalTheme," not in c.read("flutter/lib/models/terminal_mouse_handler.dart"):
        off.append("terminal_mouse_handler.dart: no kit terminal theme")
    c.fact("port forward, terminal and camera use kit tokens only", not off, "; ".join(off[:10]))
    settings = c.read(rebrand.SETTINGS)
    needles = ["simple_settings.dart", "if ((isMacOS || isWindows) && !_boringAdvanced) {", "SimpleSettings(",
               "generatePassword: () => bind.mainGeneratePermanentPassword(),",
               "label: 'All settings',", "child: const Text('Back to Settings'),"]
    missing = [n for n in needles if n not in settings]
    c.fact("Mac Settings is one simple page with Advanced behind it", not missing, "; ".join(missing))


SETUP_DART = "flutter/lib/desktop/kit/setup.dart"


def setup_checks(c):
    """v1.7 ticket 06: Setup on first launch (Mac), again from Settings, naming this Mac as Settings
    and LAN Discovery do, and opening the exact System Settings panes."""
    home, kit = c.read(rebrand.HOME), c.read(SETUP_DART)
    hooks = [
        (home, "if ((isMacOS || isWindows) && _boringSetup) {"),
        (home, "_boringSetup = setupNeeded(bind.mainGetLocalOption(key: kSetupDoneOption));"),
        (home, "SetupFlow("),
        (home, f"const nameKey = '{rebrand.BORING_MAC_NAME_OPTION}';"),
        (home, "onName: (n) => bind.mainSetOption(key: nameKey, value: n),"),
        (home, "generatePassword: () => bind.mainGeneratePermanentPassword(),"),
        (c.read(rebrand.SETTINGS), "onRunSetup: () =>"),
        (kit, "?Privacy_ScreenCapture'"),
        (kit, "?Privacy_Accessibility'"),
        (kit, "UnattendedPasswordPanel("),
        (kit, "?Privacy_ListenEvent'"),  # t21: the third switch
        (home, "canMonitorInput: () => bind.mainIsCanInputMonitoring(prompt: false),"),
        (home, "welcome: setupNeeded(bind.mainGetLocalOption(key: kSetupDoneOption)),"),
        (home, "readyChecks: boringAccessChecks(),"),
        (kit, "const kSetupDownloadUrl = "),
    ]
    missing = [n for text, n in hooks if n not in text]
    c.fact("Setup wired: first launch, Settings, this Mac's name, System Settings panes (v1.7 t06)",
           not missing, "; ".join(missing))


CLEAR_SWITCHES = "Switch is on but still not working: clears our three switches only, fixed in code (t31)"
SERVER_ANSWERS = "Ready asks --server over IPC, a new process reads the switches, a switch going on restarts the agent (t31)"


def switch_recovery_checks(c):
    """v1.7 ticket 31. tccutil with no bundle id resets every app on the Mac, so the argument list is
    pinned here and nothing else in the app may run it."""
    home, settings, setup, access = (c.read(rebrand.HOME), c.read(rebrand.SETTINGS), c.read(SETUP_DART),
                                     c.read("flutter/lib/desktop/kit/access.dart"))
    bad = [n for n, ok in [
        ("bundle id is ours", f"const kBundleId = '{AGENT}';" in access),
        ("the three services", "const kSwitchServices = ['Accessibility', 'ScreenCapture', 'ListenEvent'];" in access),
        ("fixed arguments", "run('/usr/bin/tccutil', ['reset', service, kBundleId]);" in access),
        ("one call site", access.count("tccutil'") == 1),
        ("takes no bundle or service from a caller", "Future<bool> clearSwitches(RunProcess run) async {" in access),
        ("nothing else runs tccutil", not any("tccutil" in c.read(rel) for rel in (rebrand.HOME, rebrand.SETTINGS, SETUP_DART))),
        ("Setup offers it", "clearSwitches: isMacOS ? boringClearSwitches : null," in home
         and "clear: clear, onCleared: _cleared)" in setup),
        ("Access offers it", "access: AccessSection(checks: boringAccessChecks(), clearSwitches: isMacOS ? boringClearSwitches : null)," in settings
         and "SwitchesStuck(clear: widget.clearSwitches!, onCleared: read)" in access),
        ("clears, restarts --server, asks again, opens the pane",
         all(n in home for n in ("final ok = await clearSwitches(Process.run);", "boringServeWatch.forget();",
                                 "if (up && !await restartAgent(Process.run, await _boringUidNow()))",
                                 "launchUrl(Uri.parse(kScreenRecordingPane));"))),
    ] if not ok]
    c.fact(CLEAR_SWITCHES, not bad, "; ".join(bad))

    ipc, mac, core = c.read("src/ipc.rs"), c.read("src/platform/macos.rs"), c.read("src/core_main.rs")
    bad = [n for n, ok in [
        ("--server answers over IPC", 'name == "boring-serve-access"' in ipc
         and "value = Some(crate::platform::macos::boring_access_line());" in ipc),
        ("from its own process", all(n in mac for n in ("pub fn boring_access_line() -> String {", "yn(crate::is_server())",
                                                         "yn(is_can_screen_recording(false))", "yn(is_process_trusted(false))",
                                                         "yn(is_can_input_monitoring(false))"))),
        ("a new process prints the same line", 'args[0] == "--boring-access"' in core
         and 'println!("{}", crate::platform::macos::boring_access_line());' in core),
        ("names agree", "const kServeAccessConfig = 'boring-serve-access';" in access
         and "const kFreshCheckArg = '--boring-access';" in access),
        ("Dart asks them", "bind.cmGetConfig(name: kServeAccessConfig)" in home
         and "Process.run(Platform.resolvedExecutable, const [kFreshCheckArg])" in home),
        ("the switch rows read --server", all(f"boringServeWatch.serves((a) => a.{w})" in home for w in ("screen", "control", "input"))),
        ("the running row needs --server answering", "await boringServeWatch.answering();" in home),
        ("a switch going on restarts the agent", "restart: () async => restartAgent(Process.run, await _boringUidNow())," in home),
        ("never during a session", "if (s.sessions > 0 || !mayRestart() || _restarts >= maxRestarts) return;" in access),
        ("Setup reads it", "switchesNow: boringServeWatch.switchesNow," in home),
        ("Setup comes back after Quit & Reopen", "bind.mainGetLocalOption(key: kSetupStepOption).isNotEmpty) _boringSetup = true;" in home),
    ] if not ok]
    c.fact(SERVER_ANSWERS, not bad, "; ".join(bad))


def windows_checks(c):
    """v1.7 ticket 12 (ADRs 0006, 0007): the v1.7 UI on Windows, Setup's reach step, the
    installer's app rule, and a Windows update path off the same signed version file."""
    gate_files = (rebrand.HOME, rebrand.SETTINGS, rebrand.T07_TOOLBAR, rebrand.CM_PAGE)
    ui = "".join(c.read(rel) for rel in gate_files)
    off = [a.strip().splitlines()[0] for a, b in rebrand.T12_EDITS[:len(rebrand.T12_GATES)] if a in ui or b not in ui]
    words = "  if (isWindows) KitWords.windows();" in c.read("flutter/lib/main.dart")
    c.fact("v1.7 Home, Setup, Settings, toolbar and trust prompt open on Windows too (t12)",
           not off and words, "; ".join(off) or "main.dart does not set the Windows kit words")

    home, kit = c.read(rebrand.HOME), c.read(SETUP_DART)
    rule = rebrand.WINDOWS_RULE
    hooks = ["isWindows ? SetupPlatform.windows : SetupPlatform.mac", "platform: platform,",
             "Process.run('netsh', windowsRuleShowArgs())",
             "Process.run('powershell', windowsRuleAddArgs(Platform.resolvedExecutable))"]
    missing = [h for h in hooks if h not in home]
    if f"const kWindowsRuleName = '{rule}';" not in kit:
        missing.append(f"setup.dart rule name is not '{rule}'")
    c.fact("Windows Setup step 2 lets other computers reach this one, through the installer's rule (t12)",
           not missing, "; ".join(missing))

    # The MSI's custom action names the rule for people (t17), not after the exe as upstream does.
    wxs = c.read(f"{MSI_DIR}/Components/RustDesk.wxs")
    fw = strip_tests_and_comments(c.read("res/msi/CustomActions/FirewallRules.cpp"))
    win = c.read("src/platform/windows.rs")
    bad = [n for n, ok in [
        ("added on install", '<Custom Action="AddFirewallRules" Before="InstallFinalize"' in wxs),
        ("removed on uninstall", '<Custom Action="RemoveFirewallRules" Before="RemoveFiles"/>' in wxs),
        (f"named {rule}", f'L"{rule}");' in fw and 'L"%ls Service"' not in fw),
        ("every network type", "CurrentProfilesBitMask = NET_FW_PROFILE2_ALL;" in fw),
        ("any protocol and port", not re.search(r"put_(Protocol|LocalPorts|RemotePorts|Profiles\(NET_FW_PROFILE2_(DOMAIN|PRIVATE|PUBLIC))", fw)),
        ("self-install adds the same rule", f'netsh advfirewall firewall add rule name=\\"{rule}\\" dir=in action=allow program=' in win),
    ] if not ok]
    c.fact("installer's app rule lets other computers reach Direct Link 21118: any port, every network type (t12)",
           not bad, "; ".join(bad))

    notice, run = c.read("src/update_notice.rs"), c.read("src/update_install_run.rs")
    feed = c.read("libs/base/src/update_feed.rs")
    # The feed's Windows entry was written by the deleted workflow; it comes back with a local Windows
    # release script (ticket 11). The app side stays checked.
    needles = [
        ("libs/base/src/update_feed.rs", feed, '#[cfg(target_os = "windows")]\npub const THIS: Platform = Platform::Windows;'),
        ("src/update_notice.rs", notice, "base::update_feed::release_for(body, base::update_feed::THIS)"),
        ("src/update_notice.rs", notice, "store.set(KEY_LAST_PKG_URL, package_url(&body));"),
        ("src/update_install_run.rs", run, "crate::platform::update_to(p)"),
        ("src/update_install_run.rs", run, "LocalConfig::get_option(crate::update_notice::KEY_LAST_PKG_URL)"),
    ]
    missing = [f"{rel}: {n}" for rel, text, n in needles if n not in text]
    c.fact("Windows reads its own signed feed entry and installs the checked MSI (ADR 0007)",
           not missing, "; ".join(missing))


TRUST_RS = "libs/base/src/trust.rs"
REMOVED_ASKS = "a removed Trusted Controller is asked again; its password does not undo Remove (A2 step 5)"
TRUST_DART = "flutter/lib/desktop/kit/trust.dart"
PASSWORDISH = re.compile(r"password|salt", re.I)


def trust_checks(c, cfg):
    """v1.7 t04 (ADRs 0002, 0005): a Controller gets in by approval, the Unattended Password, or
    a token this Target issued and still trusts. Nothing ships a default password."""
    hooks = [
        (DIRECT_LINK, "crate::trust::present_for(&mut stream, &who.id, ms)"),
        ("src/server.rs", rebrand.T03_HANDSHAKE_FN),
        ("src/server.rs", rebrand.T03_HANDSHAKE_CALL),
        ("src/server/connection.rs", rebrand.T04_TRUSTED_SKIP),
        ("src/server/connection.rs", rebrand.T04_GRANT),
        (rebrand.SETTINGS, "label: kTrustedTitle,"),
        (rebrand.SETTINGS, "TrustedControllersPage("),
        (rebrand.CM_PAGE, "ApprovalPrompt("),
    ]
    missing = [f"{rel}: {n.strip().splitlines()[0]}" for rel, n in hooks if n not in c.read(rel)]
    conn = c.read("src/server/connection.rs")
    # The trusted skip must sit inside the login decision, right before the no-password gate (1.8) and
    # the approve-mode ask.
    i, j = conn.find(rebrand.T04_TRUSTED_SKIP), conn.find("if (password::approve_mode() == ApproveMode::Click")
    if i < 0 or conn[i + len(rebrand.T04_TRUSTED_SKIP):j].strip() != rebrand.NO_PASSWORD_GATE.strip():
        missing.append("connection.rs: trusted skip is not right before the no-password gate and the approve-mode ask")
    c.fact("LAN trust wired: token exchange both ends, approval prompt, Trusted Controllers (v1.7 t04)",
           not missing, "; ".join(missing))

    rs, dart, link = c.read(TRUST_RS), c.read(TRUST_DART), c.read(DIRECT_LINK)
    pairs = [(rs, "TRUSTED_OPTION", "kTrustedControllersOption"), (rs, "TOKENS_OPTION", "kTrustTokensOption"),
             (link, "KNOWN_OPTION", "kDirectLinkKnownOption")]
    off = []
    for src, rname, dname in pairs:
        r = re.search(rf'pub const {rname}: &str = "([^"]+)";', src)
        d = re.search(rf"const {dname} = '([^']+)';", dart)
        if not r or not d or r.group(1) != d.group(1):
            off.append(f"{rname} vs {dname}")
    check = fn_body(rs, "    pub fn check(&self, token: &[u8]) -> Option<&TrustedController> {") or ""
    if "const TOKEN_LEN: usize = 32;" not in rs or "randombytes(TOKEN_LEN)" not in (fn_body(rs, "pub async fn answer(") or "") \
            or "if token.len() != TOKEN_LEN {" not in check or "memcmp(&k, &d)" not in check:
        off.append("token is not 256 random bits compared in constant time")
    c.fact("trust tokens: 256-bit, constant-time, option names agree in Rust and Dart", not off, "; ".join(off))

    grant = fn_body(rs, "    fn approve_into(") or ""
    once = [n for n, ok in [
        ("Allow and the Unattended Password are told apart, everything else is this session",
         rebrand.T04_GRANT in conn and "_ => base::trust::SignIn::ThisSessionOnly," in rebrand.T04_GRANT),
        ("approve_into stores a new Controller only on Allow (1.8), nothing for ThisSessionOnly",
         "if how != SignIn::Allowed {\n            self.pending = None;\n            return false;\n        }" in grant),
    ] if not ok]
    c.fact("a one-time code lets a Controller in for that session only (ADR 0005)", not once, "; ".join(once))

    removed = [n for n, ok in [
        ("connection.rs sends a removed Controller to the ask before any password path",
         "if self.boring_trust.must_ask() {" in rebrand.T04_TRUSTED_SKIP and rebrand.T04_TRUSTED_SKIP in conn),
        ("approve_into re-trusts a removed Controller only on Allow",
         "if how != SignIn::Allowed {" in grant and "t.reinstate(&key, name)" in grant),
        ("Remove in Settings keeps the entry, hidden, so the token is still known",
         "t.removed = true;" in (fn_body(rs, "    pub fn remove(") or "")
         and "if !t.remove(key) {" in (fn_body(rs, "fn plan_edit(") or "")),
    ] if not ok]
    c.fact(REMOVED_ASKS, not removed, "; ".join(removed))
    always_ask_checks(c, conn, rs, dart)

    why = [f"rebrand map sets {k}" for d in (rebrand.LOCKED, rebrand.DEFAULTS, rebrand.LOCKED_LOCAL)
           for k in d if PASSWORDISH.search(k)]
    for name in ("DEFAULT_SETTINGS", "OVERWRITE_SETTINGS", "HARD_SETTINGS", "BUILTIN_SETTINGS",
                 "DEFAULT_LOCAL_SETTINGS", "OVERWRITE_LOCAL_SETTINGS"):
        m = re.search(rf"pub static ref {name}: RwLock<HashMap<String, String>> = (.*?);\n", cfg, re.S)
        # 1.8 ticket 05: the lock that leaves only the Unattended Password names a password and carries none.
        shipped = m and m.group(1).replace('("verification-method", "use-permanent-password")', "")
        if not m or PASSWORDISH.search(shipped):
            why.append(f"{name} ships a value: {m and m.group(1)[:80]}")
    for base in ("src", "libs", "flutter/lib"):
        for p in sorted((c.root / base).rglob("*")):
            if p.suffix not in (".rs", ".dart") or not p.is_file() or "/lang/" in p.as_posix():
                continue
            code = strip_tests_and_comments(p.read_text(encoding="utf-8", errors="replace"))
            for m in re.finditer(r'\.insert\(\s*"(?:password|salt)"\s*\.to_\w+\(\)\s*,\s*"[^"]+"|'
                                 r'set_permanent_password\(\s*"[^"]*"|mainSetPermanentPassword\w*\(\s*password:\s*\'[^\']*\'', code):
                why.append(f"{p.relative_to(c.root)}: {m.group(0)[:60]}")
    if rebrand.GUARD not in (fn_body(c.read("src/common.rs"), "pub fn read_custom_client(config: &str) {") or ""):
        why.append("read_custom_client (the preset-password path) is not stripped")
    c.fact("no default or blank password ships (ADR 0002)", not why, "; ".join(why[:10]))
    approval_checks(c)
    firewall_upgrade_checks(c)


ALWAYS_ASK = "an always-ask Trusted Controller gets in by the Unattended Password only, every connect"
ALWAYS_ASK_FORGET = "a Controller keeps no password for a Target that always asks it"
ALWAYS_ASK_SALT = "turning always ask on turns the Unattended Password's salt over: no saved copy still works (H1)"
TRUST_WRITES = "the Trusted list has one writer: the service's locked edit, never over an unreadable list (L2)"
NEW_ALWAYS_ASK = "New computers always ask for password: off unless set; on, every new Controller starts asking (M1)"
AUTHORIZED_ONCE = "connection.rs lets a session in at one place only: self.authorized = true once (L5)"


def always_ask_checks(c, conn, rs, dart):
    """"Always ask for password" per Trusted Controller (base::trust): its token is no longer enough.
    It gets in by this Mac's Unattended Password and nothing else (no click, one-time code or recent
    session), through upstream's attempt limits; a gate before any sign-in completes holds that for
    every other path; no sign-in changes its entry or issues it a token; only Settings, over the
    service, switches it."""
    ask, gate = rebrand.T04_ALWAYS_ASK, rebrand.T04_ALWAYS_ASK_GATE
    logon = fn_body(conn, "    async fn send_logon_response_and_keep_alive(&mut self) -> bool {") or ""
    grant, answer = fn_body(rs, "    fn approve_into(") or "", fn_body(rs, "pub async fn answer(") or ""
    settings = c.read(rebrand.SETTINGS)
    bad = [n for n, ok in [
        ("connection.rs sends an always-ask Controller to the password before its token or any ask",
         ask in conn and ask in rebrand.T04_TRUSTED_SKIP
         and -1 < conn.find(ask) < conn.find("if self.boring_trust.is_trusted() {")),
        ("only the Unattended Password counts, never a one-time code or a recent session",
         "self.validate_password(allow_logon_screen_password)\n"
         "                    && self.conn_audit_primary_auth == ConnAuditPrimaryAuth::PermanentPassword\n" in ask
         and "is_recent_session" not in ask and "try_start_cm(lr.my_id, lr.my_name, false)" not in ask),
        ("wrong passwords go through upstream's attempt limits",
         "let (failure, res) = self.check_failure(0).await;" in ask
         and "self.update_failure_with_scope(failure, false, 0, FailureScope::Default);" in ask),
        ("nothing but that password marks the session as having given it (always ask, and 1.8's trust gate after "
         "the permanent-only password check)",
         conn.count("self.boring_trust.unattended_password_right();") == 2
         and ask.find("ConnAuditPrimaryAuth::PermanentPassword") < ask.find("unattended_password_right()")
         and "self.boring_trust.unattended_password_right();" in trust_gate(conn)),
        ("a gate before any sign-in completes keeps it out otherwise",
         "if !self.boring_trust.may_let_in() {" in gate and gate in logon
         and logon.find(gate) < logon.find("self.authorized = true;")
         and "!self.always_ask() || self.password_right" in (fn_body(rs, "    pub fn may_let_in(") or "")),
        ("its token is checked as always ask before as Trusted, and no fresh token goes out",
         -1 < answer.find("Some(t) if !t.removed && t.always_ask =>") < answer.find("Some(t) if !t.removed =>")
         and "stream.send(&frame(&[])).await?;" in answer.split("Some(t) if !t.removed && t.always_ask =>", 1)[-1]
         .split("Some(t) if !t.removed =>", 1)[0]),
        ("no sign-in changes an always-ask entry",
         grant.lstrip().split("// A removed Controller", 1)[0].count("if self.always_ask() {\n            return false;\n        }") == 1),
        ("off unless set, and off is never written (1.7.0 lists load unchanged)",
         '#[serde(default, skip_serializing_if = "is_false")]\n    pub always_ask: bool,' in rs),
        ("Settings switches it through the service's edit, as Remove",
         "onAlwaysAsk: (k, on, pw) async => trustEditError(" in settings
         and "trustEdit('always_ask', k, on: on, password: pw)" in settings),
        ("switched on while it is in without the password: that session or tunnel ends within a second",
         rebrand.T04_ALWAYS_ASK_KICK_AT + rebrand.T04_ALWAYS_ASK_KICK in conn
         and rebrand.T04_ALWAYS_ASK_TUNNEL + rebrand.T04_ALWAYS_ASK_TUNNEL_AT
         in (fn_body(conn, "    async fn try_port_forward_loop(") or "")
         and rebrand.T04_ALWAYS_ASK_TUNNEL_TIMER in conn
         and "t.list.iter().any(|c| c.key == key && (c.removed || !self.password_right && !self.stays && c.always_ask))"
         in (fn_body(rs, "    fn lost_trust_in(") or "")),
        ("a sign-in that stores it switched on keeps that session and sends the marker",
         "self.stored_as_always_ask(t, name);" in grant and grant.count("self.stored_as_always_ask(t, name);") == 2
         and "self.always_ask = Some(name.to_owned());" in (fn_body(rs, "    fn stored_as_always_ask(") or "")),
    ] if not ok]
    c.fact(ALWAYS_ASK, not bad, "; ".join(bad))

    edit, rotate = fn_body(rs, "pub fn edit_in_session(request: &str, sessions: usize) -> String {") or "", fn_body(rs, "fn rotate_salt(") or ""
    salt = [n for n, ok in [
        ("turning it on turns the salt over first, or nothing is saved",
         -1 < edit.find("rotate_salt(password)?;") < edit.find("t.list = planned.list;")
         and "*on && !was" in (fn_body(rs, "fn plan_edit(") or "")),
        ("only the Unattended Password typed here does it, and the new salt and hash go in one write",
         -1 < rotate.find("return Err(WRONG_PASSWORD);") < rotate.find("Config::get_auto_password(32)")
         and rotate.count("Config::set_permanent_password_storage_for_sync(") == 1
         and "Config::set_permanent_password_storage_for_sync(&new_storage, &fresh)" in rotate
         and "Config::set_permanent_password(" not in rotate
         and "(decode_permanent_password_h1_from_storage(&storage) == Some(h1)).then_some(storage)"
         in (fn_body(rs, "fn resalted(") or "")),
        ("Settings asks for the password before it turns it on",
         "final password = on ? await _askPassword() : '';" in dart and "String alwaysAskAsk()" in dart),
    ] if not ok]
    c.fact(ALWAYS_ASK_SALT, not salt, "; ".join(salt))

    lib, ffi, kit_settings = c.read("src/ipc.rs"), c.read("src/flutter_ffi.rs"), settings
    elist = fn_body(rs, "fn edit_list<R>(") or ""
    writes = [n for n, ok in [
        ("Settings' edits go to the service and wait for its answer",
         rebrand.T04_EDIT_IPC in lib and rebrand.T04_EDIT_ASK in lib and rebrand.T04_EDIT_FFI in ffi),
        ("a settings window's whole-options write never carries its copy of the list",
         rebrand.T04_KEEP_LIST in lib and rebrand.T04_KEEP_LIST_OLD not in lib),
        ("one locked read-modify-write on the live list, never over an unreadable one",
         "EDIT_LOCK.lock()" in elist and "Trusted::parse_strict(&raw).ok_or(UNREADABLE)?" in elist
         and rs.count("t.save();") == 1 and "t.save();" in elist
         and "edit_list(" in (fn_body(rs, "    pub fn approve(") or "") and "edit_list(" in edit),
        ("Settings never writes the list option itself, and no answer is never taken as saved",
         not re.search(r"mainSet\w*Option\(\s*key: kTrustedControllersOption", kit_settings)
         and "return kTrustNoAnswer;" in (fn_body(dart, "String? trustEditError(String answer) {") or "")),
    ] if not ok]
    c.fact(TRUST_WRITES, not writes, "; ".join(writes))

    add = fn_body(rs, "    fn add(") or ""
    r = re.search(r'pub const NEW_ALWAYS_ASK_OPTION: &str = "([^"]+)";', rs)
    d = re.search(r"const kNewAlwaysAskOption = '([^']+)';", dart)
    new = [n for n, ok in [
        ("option names agree in Rust and Dart", r and d and r.group(1) == d.group(1)),
        ("off unless set: nothing ships it on", r and r.group(1) not in rebrand.DEFAULTS and r.group(1) not in rebrand.LOCKED),
        ("on: every Controller stored from then on starts asking",
         "self.new_always_ask ||" in add and "Config::get_option(NEW_ALWAYS_ASK_OPTION) == \"Y\"" in elist),
        ("Settings shows and saves the switch",
         "newAlwaysAsk: bind.mainGetOptionSync(key: kNewAlwaysAskOption) == 'Y'," in settings
         and "onNewAlwaysAsk: (on) => bind.mainSetOption(key: kNewAlwaysAskOption, value: on ? 'Y' : '')," in settings),
    ] if not ok]
    c.fact(NEW_ALWAYS_ASK, not new, "; ".join(new))
    n = conn.count("self.authorized = true;")
    c.fact(AUTHORIZED_ONCE, n == 1 and "conn.authorized = true" not in conn, f"{n} copies")

    peer = fn_body(c.read("src/client.rs"), "    pub fn handle_peer_info(&mut self, pi: &PeerInfo) {") or ""
    forget = [n for n, ok in [
        ("the Target says so in PeerInfo", rebrand.T04_ALWAYS_ASK_MARK in conn
         and 'pub const ALWAYS_ASK_MARKER: &str = "boring_always_ask";' in rs),
        ("the Controller drops the password it would keep before saving",
         -1 < peer.find(rebrand.T04_ALWAYS_ASK_FORGET) < peer.find("self.save_config(config);")),
    ] if not ok]
    c.fact(ALWAYS_ASK_FORGET, not forget, "; ".join(forget))


APPROVAL_RS = "src/boring_approval.rs"
APPROVAL_DART = "flutter/lib/desktop/kit/approval.dart"


def approval_checks(c):
    """v1.7 t04 follow-up: the connection window's ask also fills the main window, which comes
    to the front (opened if it is not running). Its Allow / Don't allow go back to the connection
    window, which runs its own (so trust is granted as a click there is, ADR 0005). Settings lists
    who is waiting and who was removed, each with Allow, over the server option as Remove."""
    rs, kit, trust = c.read(APPROVAL_RS), c.read(APPROVAL_DART), c.read(TRUST_DART)
    model, sm = c.read(rebrand.FFI_MODEL), c.read(rebrand.SERVER_MODEL)
    hooks = [
        ("src/lib.rs", rebrand.T04B_MOD), ("src/flutter_ffi.rs", rebrand.T04B_FFI),
        ("src/flutter_ffi.rs", rebrand.T04B_LISTEN), ("src/ui_cm_interface.rs", rebrand.T04B_CM_IPC),
        (rebrand.FFI_MODEL, rebrand.T04B_EVENT), (rebrand.SERVER_MODEL, rebrand.T04B_ASK),
        (rebrand.SERVER_MODEL, rebrand.T04B_DONE_REMOVE), (rebrand.SERVER_MODEL, rebrand.T04B_DONE_LOGIN),
        (rebrand.CM_PAGE, rebrand.T04B_CARD),
    ]
    bad = [f"{rel}: {n.strip().splitlines()[0]}" for rel, n in hooks if n not in c.read(rel)]
    for rname, dname in (("ASK", "kApprovalAsk"), ("DONE", "kApprovalDone"), ("ANSWER", "kApprovalAnswer"),
                         ("EVENT", "kApprovalEvent")):
        r = re.search(rf'pub const {rname}: &str = "([^"]+)";', rs)
        d = re.search(rf"const {dname} = '([^']+)';", kit)
        if not r or not d or r.group(1) != d.group(1):
            bad.append(f"{rname} vs {dname}")
    send = fn_body(rs, "pub fn send(msg: String) {") or ""
    if 'post("_cm", msg)' not in send or "crate::run_me(Vec::<&str>::new())" not in send:
        bad.append("answers go to the connection window's _cm; an ask opens the main window if needed")
    # The answer runs exactly the connection window's own buttons (T04_PROMPT): handleAccept is
    # sendLoginResponse(client, true); handleDisconnect is cmCloseConnection.
    if "sm!.sendLoginResponse(c, true);" not in rebrand.T04B_EVENT \
            or "bind.cmCloseConnection(connId: c.id);" not in rebrand.T04B_EVENT \
            or "onAllow: () => handleAccept(context)," not in c.read(rebrand.CM_PAGE):
        bad.append("main window's answer is not the connection window's own Allow / Don't allow")
    if "toFront: () => windowOnTop(null)," not in rebrand.T04B_EVENT:
        bad.append("main window does not come to the front")
    if "SingleChildScrollView(" not in (fn_body(kit, "  Widget build(BuildContext context) {") or "") \
            or "return SingleChildScrollView(" not in trust.split("class ApprovalPrompt", 1)[-1]:
        bad.append("an ask can clip: main window view or connection window prompt does not scroll")
    c.fact("the ask also fills the main window, which comes to the front; its Allow is the connection window's (t04)",
           not bad, "; ".join(bad))

    settings, simple = c.read(rebrand.SETTINGS), c.read("flutter/lib/desktop/kit/simple_settings.dart")
    reinstate = fn_body(c.read(TRUST_RS), "fn plan_edit(") or ""
    grant = fn_body(c.read(TRUST_RS), "    fn reinstate(") or ""
    bad = [n for n, ok in [
        ("Trusted Controllers lists removed ones with Allow", "removed: parseRemoved(" in settings
         and "onAllow: (c) async {" in settings and "child: const Text('Allow')," in trust),
        ("Allow there is the service's edit (as Remove), never a write of the option itself",
         "trustEditError(await bind.boringTrustEdit(edit: trustEdit('allow', c.key)))" in settings
         and not re.search(r"mainSet\w*Option\(\s*key: kTrustedControllersOption", settings)),
        ("the service's Allow is trust.rs reinstate", "Some(name) => t.reinstate(key, &name)," in reinstate
         and "t.removed = false;" in grant and "t.added = now();" in grant),
        ("Allow there also lets in a live ask from it, matched by its trust key, never its name (audit H1)",
         "for (final id in waitingFrom(c, ApprovalDesk.waitingNow.value)) {" in settings
         and "w.name" not in (fn_body(settings, "onAllow: (c) async {") or "x")
         and "w.trust == 'removed' && w.key.length >= kTrustKeyPrefixLen && c.key.startsWith(w.key)"
         in kit[kit.find("List<int> waitingFrom("):][:400]),
        ("whoever is waiting shows in Trusted Controllers and above Access",
         settings.count("waiting: WaitingApprovals(") == 2 and "widget.waiting!," in simple),
    ] if not ok]
    c.fact("Settings: Allow next to removed and waiting Controllers, over the service like Remove (t04)",
           not bad, "; ".join(bad))
    ask_info_checks(c, kit, trust)


ASK_INFO = "the ask says new or removed and the address; its trust key rides to Settings (audit H1)"


def ask_info_checks(c, kit, trust):
    """Audit H1: the Controller picks its own name, so the ask also carries what the Target's trust
    exchange found (new / removed, a key prefix) and the peer address, from try_start_cm to both
    prompts and to Settings' Allow."""
    rs = c.read(TRUST_RS)
    hooks = [("src/ipc.rs", rebrand.H1_LOGIN_FIELD), ("src/server/connection.rs", rebrand.H1_LOGIN_SEND),
             (rebrand.CM_IFACE, "    #[serde(flatten)]\n" + rebrand.H1_ASK_INFO),
             (rebrand.CM_IFACE, "privacy_mode, from_switch, boring, self.tx.clone());\n"),
             (rebrand.SERVER_MODEL, rebrand.H1_CLIENT_FIELDS), (rebrand.SERVER_MODEL, rebrand.H1_CLIENT_JSON),
             (rebrand.CM_PAGE, "            trust: client.boringTrust,\n            ip: client.boringIp,\n"),
             (rebrand.SERVER_MODEL, "trust: client.boringTrust, key: client.boringKey, ip: client.boringIp)")]
    bad = [f"{rel}: {n.strip().splitlines()[0]}" for rel, n in hooks if n not in c.read(rel)]
    ask = fn_body(rs, "    pub fn ask_info(&self, ip: &str) -> AskInfo {") or ""
    if '("removed", prefix(k))' not in ask or '("new", prefix(&hex(d)))' not in ask:
        bad.append("trust.rs ask_info does not name removed and new by their keys")
    r = re.search(r"pub const KEY_PREFIX_LEN: usize = (\d+);", rs)
    d = re.search(r"const kTrustKeyPrefixLen = (\d+);", trust)
    if not r or not d or r.group(1) != d.group(1) or int(r.group(1)) < 16:
        bad.append("key prefix length differs in Rust and Dart, or is under 64 bits")
    prompt = trust.split("class ApprovalPrompt", 1)[-1]
    view = kit.split("class ApprovalRequestView", 1)[-1].split("class ApprovalDesk", 1)[0]
    if "approvalWho(trust, ip)" not in prompt or "approvalWho(trust, ip)" not in view \
            or "approvalWho(w.trust, w.ip)" not in kit:
        bad.append("a prompt shows only the name: connection window, main window or Settings row")
    c.fact(ASK_INFO, not bad, "; ".join(bad))


def firewall_upgrade_checks(c):
    """Ticket 12: one reach rule each way. An MSI upgrade from before t17 left the old
    "BoringRemote Service" pair beside the new one; install, upgrade and self-install drop it first."""
    fw, win = c.read(rebrand.FW_CPP), c.read("src/platform/windows.rs")
    add = fn_body(fw, "bool AddFirewallRule(bool add, LPWSTR exeName, LPWSTR exeFile)") or ""
    clean = fn_body(fw, "static void BoringRemoveOldRules(INetFwPolicy2* pNetFwPolicy2, LPWSTR exeName)") or ""
    i, j = win.find(rebrand.WIN_FW_CLEAN), win.find(f'firewall add rule name=\\"{rebrand.WINDOWS_RULE}\\"')
    bad = [n for n, ok in [
        ("MSI drops the old-name and today's rules before adding", rebrand.FW_CALL in add
         and add.find(rebrand.FW_CALL) < add.find("    if (add) {")
         and 'L"%ls%ls", exeName, L" Service"' in clean and f'L"{rebrand.WINDOWS_RULE}"' in clean),
        ("MSI removes every rule with the name, not just one", "rules->Remove(b)" in fw and "rules->Item(b, &r)" in fw),
        ("self-install drops them before its two adds", 0 <= i < j),
    ] if not ok]
    c.fact("Windows install and upgrade leave one firewall rule each way: pre-t17 rules go first (t12)",
           not bad, "; ".join(bad))


def high_efficiency_checks(c):
    """v1.7 ticket 05 (ADR 0006): a Local link between two Boring Remotes asks for 60 fps, best
    quality, best software codec. The Target marks itself, the Controller applies it after the
    first PeerInfo, and the Link Badge reads the stream_type Rust re-reports. No hardware codec.
    ADR 0006 amendment (device check A3): AV1 only up to 1080p-sized frames, and a Retina Mac on a
    software codec captures its points size while High Efficiency is on."""
    he = c.read("libs/base/src/high_efficiency.rs")
    st = re.search(r'pub const STREAM_TYPE: &str = "([^"]+)";', he)
    hooks = [("src/server/connection.rs", rebrand.T05_MARKER), ("src/server/connection.rs", rebrand.T05_ANSWER),
             ("src/server.rs", rebrand.T05_RETINA),
             ("src/client/io_loop.rs", rebrand.T05_LINK_SET), ("src/client/io_loop.rs", rebrand.T05_ASK_FN),
             ("src/client/io_loop.rs", rebrand.T05_ASK_CALL), ("src/client/io_loop.rs", rebrand.T05_BADGE),
             ("flutter/lib/desktop/kit/session_toolbar.dart",
              f"'{st.group(1) if st else '?'}' => LinkState.localHighEfficiency,")]
    missing = [f"{rel}: {n.strip().splitlines()[0]}" for rel, n in hooks if n not in c.read(rel)]
    if not st:
        missing.append("high_efficiency.rs: STREAM_TYPE")
    if "AV1_MAX_PIXELS: i64 = 1920 * 1080" not in he or "&& av1_keeps_up" not in he:
        missing.append("high_efficiency.rs: AV1 not capped at 1080p frames (ADR 0006 amendment)")
    if re.search(r"PreferCodec::H26[45]", he):
        missing.append("high_efficiency.rs prefers a hardware codec (ADR 0006)")
    c.fact("High Efficiency wired: Target marks itself and answers the ask, badge waits for the answer",
           not missing, "; ".join(missing))


def support_checks(c):
    """v1.7 t20: Save a support file (Settings → Help) and crash files. Every process that logs
    installs the panic hook right after init_log; Home offers the file once after a crash. The
    zip never carries a secret: each one is removed by name, config only goes in redacted, and
    IDs are hashed in config and logs."""
    after_log = [("src/core_main.rs", "    hbb_common::init_log(false, &log_name);\n", rebrand.T20_HOOK_CORE),
                 ("src/flutter_ffi.rs", '        hbb_common::init_log(false, "flutter_ffi");\n', rebrand.T20_HOOK_FFI),
                 ("src/service.rs", '    hbb_common::init_log(false, "service");\n', rebrand.T20_HOOK_SERVICE)]
    missing = [f"{rel}: panic hook not right after init_log" for rel, log, hook in after_log
               if log + hook not in c.read(rel)]
    hooks = [(rebrand.BASE_LIB, rebrand.T20_MOD), ("src/flutter_ffi.rs", rebrand.T20_FFI),
             (rebrand.HOME, rebrand.T20_SAVE_FN), (rebrand.HOME, rebrand.T20_NOTICE), (rebrand.SETTINGS, rebrand.T20_HELP)]
    missing += [f"{rel}: {n.strip().splitlines()[0]}" for rel, n in hooks if n not in c.read(rel)]
    c.fact("support file and crash files wired: a panic hook at every startup, Settings Help, Home's notice (t20)",
           not missing, "; ".join(missing))

    sup = c.read("libs/base/src/support.rs")
    m = re.search(r"pub const SECRET_KEYS: &\[&str\] = &\[(.*?)\];", sup, re.S)
    keys = set(re.findall(r'"([^"]+)"', m.group(1))) if m else set()
    bad = [f"{k} not removed" for k in ("password", "salt", "key_pair", "enc_id", "trusted_devices",
                                        "boring-trust-tokens") if k not in keys]
    # the JSON options keep their names and drop the secret inside, under the names Rust stores them as
    opt = lambda rel, const: (re.search(rf'pub const {const}: &str = "([^"]+)";', c.read(rel)) or [None, "?"])[1]
    for name, field in ((opt("libs/base/src/trust.rs", "TRUSTED_OPTION"), "key"),
                        (opt("libs/base/src/direct_link.rs", "KNOWN_OPTION"), "pk")):
        if f'"{name}" =>' not in sup or f'.insert("{field}".into(), Json::String(REMOVED.into()))' not in sup:
            bad.append(f"{name}: {field} not removed")
    if opt("libs/base/src/trust.rs", "TOKENS_OPTION") not in keys:
        bad.append("trust tokens option name differs from trust.rs")
    for needle, why in (("redact_toml(&text).as_bytes()", "config goes in unredacted"),
                        ("scrub_ids(&String::from_utf8_lossy(&data), &s.ids)", "logs keep the ID"),
                        ('if key == "id" {', "the ID is not hashed in config"),
                        ('pub const ZIP_PREFIX: &str = "Boring Remote support";', "zip name")):
        if needle not in sup:
            bad.append(why)
    c.fact("the support file removes every secret by name and hashes IDs (t20)", not bad, "; ".join(bad))

def lan_both_ways_checks(c):
    """v1.7 ticket 21: discovery asks known and heard-from computers directly, the listener notes
    who pinged it, and nothing is sent to loopback or Tailscale's /32."""
    lan, base = c.read("src/lan.rs"), c.read("libs/base/src/lan.rs")
    missing = [n.strip().splitlines()[0] for n in (rebrand.T21_HEARD, rebrand.T21_SEND) if n not in lan]
    if rebrand.T21_SEND_OLD in lan:
        missing.append("src/lan.rs still broadcasts 255.255.255.255 from every socket")
    for fn in ("pub fn send_pings(", "pub fn ping_targets(", "pub fn heard_ping(", "pub fn known_ips("):
        if fn not in base:
            missing.append(f"libs/base/src/lan.rs: {fn}")
    c.fact("LAN Discovery both ways: asks known computers directly, skips loopback and Tailscale (t21)",
           not missing, "; ".join(missing))


FASTEST_LAN = "every LAN address carried in the pong, public ones dropped, fastest dialled first, dead ones fall through (t25)"


def fastest_lan_checks(c):
    """v1.7 ticket 25: the pong lists every LAN address in `misc`, the Controller stores and ranks
    them, a dead one falls through to the next. Never a public address (ADR 0003), and every dial
    is still the encrypted, pinned handshake."""
    lan, base, link = c.read("src/lan.rs"), c.read("libs/base/src/lan.rs"), c.read(DIRECT_LINK)
    why = [n.strip().splitlines()[0] for n in (rebrand.T25_NICS, rebrand.T25_PONG, rebrand.T25_STORE, rebrand.T25_LOCAL)
           if n not in lan]
    is_lan = fn_body(base, "pub fn is_lan(ip: IpAddr) -> bool {") or ""
    if "is_allowed(ip) && !crate::direct_link::is_tailscale(ip)" not in is_lan:
        why.append("is_lan lets through more than private LAN (ADR 0003)")
    if ".filter(|a| is_lan(a.ip))" not in (fn_body(base, "pub fn lenient(") or ""):
        why.append("an address from a pong is not checked before it is kept")
    if "crate::lan::is_lan(ip) && !mine && !dial.contains(&addr)" not in (fn_body(link, "fn widen(") or ""):
        why.append("a candidate address is dialled without the private-LAN check")
    if "crate::lan::is_lan(a.ip)" not in (fn_body(link, "pub fn set_addresses(") or ""):
        why.append("Known stores an address without the private-LAN check")
    dial = fn_body(link, "async fn dial(") or ""
    if "judge(strict, addr, handshake(stream, addr, known, HANDSHAKE_TIMEOUT_MS).await)" not in dial:
        why.append("a dial skips the encrypted, pinned handshake")
    race_body = fn_body(link, "pub async fn race<") or ""
    if "std::iter::once(plan.direct).chain(plan.others).chain(tailscale)" not in race_body:
        why.append("race no longer tries every address before Tailscale")
    if "(t.lan != at && t.tailscale != at)" not in (fn_body(link, "pub fn pin_ok(") or "") or "t.addrs" in (fn_body(link, "pub fn pin_ok(") or ""):
        why.append("a listed address became a pin: a spoofed pong could lock a Target out")
    badge = c.read("flutter/lib/desktop/kit/session_toolbar.dart")
    for word in ("'Local · wired'", "'Local · Wi-Fi'", "'LocalWired' => LinkState.localWired,", "'LocalWiFi' => LinkState.localWiFi,"):
        if word not in badge:
            why.append(f"badge: {word}")
    c.fact(FASTEST_LAN, not why, "; ".join(why))


# A word for this machine (KitWords, or a literal Mac) right after a word that points at the other end.
OTHER_END_MAC = re.compile(r"\b(?:that|other|another|both|from one|a|an|these)\s+"
                           r"(?:\$\{KitWords\.(?:one|many)\}|\$one|\$many|Macs?\b)", re.I)


def target_word_checks(c):
    """v1.7 t26: the machine at the other end can be a PC, so it is a computer on both builds; this
    machine keeps its own word. "Used before" collapses addresses in Home's view only."""
    kit_dir = c.root / "flutter/lib/desktop/kit"
    hits = [f"{p.name}:{n}: {m.group(0)}" for p in sorted(kit_dir.glob("*.dart"))
            for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
            if not line.lstrip().startswith("//")
            for m in [OTHER_END_MAC.search(line)] if m]
    home_kit, home, link = c.read("flutter/lib/desktop/kit/mac_home.dart"), c.read(rebrand.HOME), c.read(DIRECT_LINK)
    why = [f"Mac about the other end: {h}" for h in hits[:8]]
    for need in ("'Connect to a computer'", '"Type a computer\'s name or Machine ID"', "Text('Computers',",
                 "To reach this $one from another network", "pick this $one by name"):
        if need not in home_kit:
            why.append(f"Home lost {need}")
    if "'Unnamed Mac'" in home or "KitWords.unnamed" not in home:
        why.append("an unnamed recent says Mac")
    if "{Mac" in c.read("flutter/lib/desktop/kit/kit_look.dart"):
        why.append("the kit's messages still follow this machine's word")
    if "worded_for" in link or re.search(r'pub const [A-Z_]+: &str =\s*"[^"]*\bMac\b', link):
        why.append("a connect error says Mac")
    c.fact("the Target is a computer on both builds: Home, connect errors, other-end lines (t26)",
           not why, "; ".join(why))

    method = fn_body(home, "  Widget buildBoringHome(BuildContext context) {") or ""
    why = []
    for need in ("macs: usedBefore(),", "return oneEntryPerMachine(",
                 "identitiesFromKnown(bind.mainGetLocalOption(key: kDirectLinkKnownOption))",
                 "identity: who[p.id] ?? ''"):
        if need not in method:
            why.append(f"Home lost {need}")
    if re.search(r"mainRemovePeer|mainForgetPassword|removePeer", method):
        why.append("Home removes a stored peer")
    if "List<MacEntry> oneEntryPerMachine(List<MacEntry> newestFirst)" not in home_kit:
        why.append("the kit lost oneEntryPerMachine")
    c.fact("Used before lists each machine once, newest address, nothing deleted from disk (t26)",
           not why, "; ".join(why))


TRANSFER_HOME = "Home's Transfer files opens a transfer-only connection, on every row and the address box (t29)"
TRANSFER_ASK = "a transfer-only connection gets Allow like any other, and the ask says transfer files (t29)"
TRANSFER_NO_CAPTURE = "a transfer-only connection starts no screen capture or encoder on the Target (t29)"


def transfer_checks(c):
    """v1.7 t29: File Transfer alone from Home. It dials through _start like everything else, so the
    connect box facts above cover it; these are what's new about it."""
    home_kit = c.read("flutter/lib/desktop/kit/mac_home.dart")
    method = fn_body(c.read(rebrand.HOME), "  Widget buildBoringHome(BuildContext context) {") or ""
    why = []
    if "onTransferFiles: (t) => connect(context, t, isFileTransfer: true)," not in method:
        why.append("buildBoringHome does not open File Transfer alone")
    if "onConnect: (t) => connect(context, t)," not in method:
        why.append("a row no longer means control")
    if "transferFiles = 'Transfer files'" not in home_kit:
        why.append("the button lost its words")
    # One for each of On this network and Used before, one for the Address box, with the typed target.
    if home_kit.count("trailing: _transferButton(") != 2 or "_transferButton(() => _typedTarget(" not in home_kit:
        why.append("a list or the Address box has no Transfer files")
    c.fact(TRANSFER_HOME, not why, "; ".join(why))

    trust, approval = c.read("flutter/lib/desktop/kit/trust.dart"), c.read("flutter/lib/desktop/kit/approval.dart")
    page, model = c.read(rebrand.CM_PAGE), c.read(rebrand.SERVER_MODEL)
    conn = strip_tests_and_comments(c.read("src/server/connection.rs"))
    why = []
    if "wants to transfer files with this ${KitWords.one}." not in trust:
        why.append("the ask does not say transfer files in this machine's word")
    for text, need in ((trust, "approvalQuestion(name, files: files)"), (approval, "approvalQuestion(name, files: files)"),
                       (approval, "approvalQuestion(w.name, files: w.files)"),
                       (page, "files: client.type_() == ClientType.file,")):
        if need not in text:
            why.append(f"lost {need}")
    if model.count("approvalAsk(") != model.count("files: client.type_() == ClientType.file,"):
        why.append("an ask to the main window does not say what kind it is")
    # The trust gate runs once the login's kind is known and does not look at the kind.
    login = conn.find("if self.boring_trust.is_trusted() {")
    ask = conn.find("if self.boring_trust.must_ask() {")
    kind = conn.find("self.file_transfer = Some((ft.dir, ft.show_hidden));")
    if not 0 <= kind < login < ask:
        why.append("the trust gate does not run on every kind of login")
    if re.search(r"file_transfer[^\n]*\n[^\n]*boring_trust|boring_trust[^\n]*file_transfer", conn):
        why.append("the trust gate treats a transfer differently")
    c.fact(TRANSFER_ASK, not why, "; ".join(why))

    logon = fn_body(conn, "    async fn send_logon_response_and_keep_alive(&mut self) -> bool {") or ""
    only_info = "if self.file_transfer.is_some() || self.terminal {\n            res.set_peer_info(pi);\n        } else if"
    why = []
    if only_info not in logon or "sub_service = true" not in logon \
            or logon.index("sub_service = true") < logon.index(only_info):
        why.append("the login may reach sub_service before the file-transfer branch")
    if "if let Some((dir, show_hidden)) = self.file_transfer.clone() {" not in logon or "} else if sub_service {" not in logon \
            or logon.index("} else if sub_service {") < logon.index("self.file_transfer.clone()"):
        why.append("a transfer's login may subscribe the monitor services")
    if "self.file_transfer.is_none()" not in (fn_body(conn, "    fn is_remote(&self) -> bool {") or ""):
        why.append("is_remote counts a transfer")
    sub = fn_body(conn, "    fn try_sub_monitor_services(&mut self) {") or ""
    if "let is_remote = self.is_remote();" not in sub or "if is_remote && !self.services_subed {" not in sub:
        why.append("try_sub_monitor_services is not only for a remote connection")
    for call in ("try_add_monitor_service(", "add_monitor_connection("):
        if conn.count(call) != 1 or call not in sub:
            why.append(f"{call} is reached outside try_sub_monitor_services")
    scoped = fn_body(conn, "    fn is_file_transfer_scoped_message(msg: &Message) -> bool {") or ""
    misc = fn_body(conn, "    fn is_file_transfer_scoped_misc(misc: &Misc) -> bool {") or ""
    if set(re.findall(r"message::Union::(\w+)", scoped)) != {"FileAction", "FileResponse", "Misc"}:
        why.append("a transfer may send messages other than files")
    # PluginRequest is the file proof (t30), and only with our id: it can't reach a display.
    if set(re.findall(r"misc::Union::(\w+)", misc)) != {"SelectedSid", "PluginRequest"} \
            or "p.id == base::file_verify::WIRE_ID" not in misc:
        why.append("a transfer may send a Misc that can pick a display")
    if "if let Some(message) = self.authorized_scope_violation(&msg) {" not in conn:
        why.append("the scope gate no longer runs on messages")
    svc = c.read("src/server/service.rs")
    if svc.count("if sp.has_subscribes() {") != 2:
        why.append("a service runs with no subscriber")
    c.fact(TRANSFER_NO_CAPTURE, not why, "; ".join(why))


def rust_hook_checks(c):
    """v1.7: our Rust lives in new files under libs/base/src; upstream files only get these hooks,
    through rebrand.py. On a raw checkout every one of them is missing."""
    hooks = [
        (rebrand.BASE_LIB, rebrand.BASE_MODS),
        (rebrand.SERVER, rebrand.T03_META_FIELDS),
        (rebrand.MEDIATOR, "        ..Default::default() // boring-remote: Direct Link fields stay off here (v1.7 t03)\n"),
        ("src/lan.rs", rebrand.T02_END_CYCLE),
        ("src/ui_interface.rs", rebrand.T02_HOME_IP),
        ("src/client.rs", rebrand.CONTROLLER_NAME),
    ]
    missing = [f"{rel}: {n.strip().splitlines()[0]}" for rel, n in hooks if n not in c.read(rel)]
    c.fact("v1.7 Rust hooks landed: base modules, Direct Link meta, LAN end of cycle, Controller name",
           not missing, "; ".join(missing))


TRANSFER_HOOKS = "file transfer at full speed wired: the send slice, the CM windows, the Target's marker, speed and drives (v1.7 t27)"
NO_GAIN_MEDIA = "camera formats are on the no-compression list (v1.7 t27)"


def transfer_speed_checks(c):
    hooks = [
        (rebrand.BASE_LIB, rebrand.T27_MOD),
        (rebrand.FS_RS, rebrand.T27_COMPRESS),
        (rebrand.BASE_BUILD, rebrand.T27_BUILD),
        (rebrand.HBB_TCP, rebrand.T27_ENC_RUN),
        (rebrand.HBB_TCP, rebrand.T27_NEXT),
        (rebrand.HBB_STREAM, rebrand.T27_STREAM_RUN),
        (rebrand.CONN, rebrand.T27_CONN_ARM),
        (rebrand.CONN, rebrand.T27_CONN_GUARD),
        (rebrand.CONN, rebrand.T27_CONN_ACK),
        (rebrand.CONN, rebrand.T27_CONN_SPEND),
        (rebrand.CONN, rebrand.T27_MARKER),
        (rebrand.CONN, rebrand.T27_READ_ACK),
        (rebrand.IPC, rebrand.T27_IPC),
        (rebrand.UI_CM, rebrand.T27_CM_TICK),
        (rebrand.UI_CM, "allow_err!(self.tx.send(Data::FileWriteAck(n)));"),
        (rebrand.UI_CM, "Data::FileReadAck(bytes) => boring_read_window.refund(bytes),"),
        (rebrand.IO_LOOP, rebrand.T27_IO_ARM),
        (rebrand.IO_LOOP, rebrand.T27_IO_PEER),
        (rebrand.IO_LOOP, rebrand.T27_IO_SPEED),
        (rebrand.FILE_MGR, "TransferDrives(load: _boringLoadDrives"),
        (rebrand.FILE_MGR, "speed: j.speed,"),
        (rebrand.FILE_MGR, "_boringClock.observe("),
    ]
    missing = [f"{rel}: {n.strip().splitlines()[0]}" for rel, n in hooks if n not in c.read(rel)]
    # Upstream's one-block-per-tick calls must be gone from the paths a transfer takes at full speed.
    conn = c.read(rebrand.CONN)
    if "match fs::handle_read_jobs(" in conn:
        missing.append(f"{rebrand.CONN}: still one block per tick")
    if "MILLI5" in c.read(rebrand.UI_CM):
        missing.append(f"{rebrand.UI_CM}: still a 5 ms tick")
    c.fact(TRANSFER_HOOKS, not missing, "; ".join(missing))
    speed = c.read("libs/base/src/file_speed.rs")
    absent = [e for e in ("mov", "mp4", "mxf", "braw", "r3d", "jpg", "zip") if f'"{e}"' not in speed]
    c.fact(NO_GAIN_MEDIA, not absent, ", ".join(absent))


VERIFY_HOOKS = "every file proved: sender's hash, read-back before the real name, Done after the last verdict, the job's report (v1.7 t30)"
VERIFY_WORDS = "the job's words are the ticket's, and Verified takes every file passing (v1.7 t30)"
VERIFY_EVERYTHING = "a folder copy takes hidden files, and a read job lists links, folders and what it couldn't read (v1.7 t30)"


def transfer_verify_checks(c):
    hooks = [
        (rebrand.BASE_LIB, rebrand.T30_MOD),
        (rebrand.BASE_TOML, rebrand.T30_DEP),
        (rebrand.CARGO_LOCK, rebrand.T30_LOCK_BLAKE3),
        (rebrand.CARGO_LOCK, rebrand.T30_LOCK_CTE),
        (rebrand.FS_RS, rebrand.T30_HOOKS),
        (rebrand.FS_RS, rebrand.T30_TICK),
        (rebrand.FS_RS, "self.boring.sent_bytes(&buf);"),
        (rebrand.FS_RS, "if self.r#type == JobType::Printer || self.boring.receiving() {"),
        (rebrand.FS_RS, "if !job.boring_holds_done() && job.job_completed() {"),
        (rebrand.FS_RS, "self.boring.stream_moved();"),
        (rebrand.FS_RS, "crate::file_verify::create_work_file(&path).await?"),
        (rebrand.FS_RS, "crate::file_verify::write_work_file(dp,"),
        (rebrand.FS_RS, "if crate::file_verify::is_link(Path::new(&download_path)) {"),
        (rebrand.FS_RS, "self.boring_after_read(file_num, boring_changed);"),
        (rebrand.FS_RS, "self.boring.stamp_opened(stamp);"),
        (rebrand.IPC, "BoringWire(String),"),
        (rebrand.UI_CM, rebrand.T30_CM_WIRE),
        (rebrand.UI_CM, rebrand.T30_CM_DONE),
        (rebrand.UI_CM, rebrand.T30_CM_ROOM),
        (rebrand.UI_CM, rebrand.T30_CM_TICK),
        (rebrand.UI_CM, "if !job.boring_holds_done() && job.job_completed() {"),
        (rebrand.CONN, rebrand.T30_MARKER),
        (rebrand.CONN, rebrand.T30_CONN_SCOPE),
        (rebrand.CONN, rebrand.T30_CONN_MISC),
        (rebrand.CONN, rebrand.T30_CONN_ON_WIRE),
        (rebrand.CONN, rebrand.T30_CONN_ENABLE),
        (rebrand.CONN, rebrand.T30_CONN_CM_ENABLE),
        (rebrand.IO_LOOP, rebrand.T30_IO_PEER),
        (rebrand.IO_LOOP, rebrand.T30_IO_MISC),
        (rebrand.IO_LOOP, rebrand.T30_IO_ON_WIRE),
        (rebrand.IO_LOOP, rebrand.T30_IO_REPORT),
        (rebrand.IO_LOOP, "base::file_verify::enable_sends(&mut self.read_jobs"),
        (rebrand.IO_LOOP, "base::file_verify::check_room(job)"),
        (rebrand.UI_SESSION, rebrand.T30_TRAIT),
        (rebrand.FLUTTER_RS, rebrand.T30_FLUTTER),
        (rebrand.FFI_MODEL, rebrand.T30_DART_MODEL),
        (rebrand.FILE_MODEL, rebrand.T30_DART_JOB),
    ]
    missing = [f"{rel}: {n.strip().splitlines()[0]}" for rel, n in hooks if n not in c.read(rel)]
    c.fact(VERIFY_HOOKS, not missing, "; ".join(missing))
    verify = c.read("libs/base/src/file_verify.rs").split("#[cfg(test)]\nmod tests {")[0]
    kit = c.read("flutter/lib/desktop/kit/file_transfer.dart")
    why = []
    if '"Not verified: the other computer needs the latest Boring Remote"' not in verify:
        why.append("the old peer's words changed")
    if ("pub fn all_passed(&self) -> bool {\n        self.failed.is_empty()\n            && self.skipped.is_empty()\n"
            "            && self.not_copied.is_empty()\n            && self.verified == self.files\n"
            "            && self.files + self.folders > 0\n") not in verify:
        why.append("all_passed no longer takes every file")
    if verify.count('"Verified: ') != 2 or "let mut out = if self.all_passed() {" not in verify:
        why.append("Verified can be said outside all_passed")
    if "report.startsWith('Not verified')" not in kit:
        why.append("the list doesn't mark Not verified")
    if "Verified" in kit.replace("notVerified", "").replace("Not verified", "not verified"):
        why.append("the kit makes up Verified on its own")
    c.fact(VERIFY_WORDS, not why, "; ".join(why))
    io_loop = c.read(rebrand.IO_LOOP)
    every = []
    if "Data::SendFiles((id, r#type, path, to, file_num, include_hidden, is_remote))" in io_loop:
        every.append("SendFiles still takes the pane's hidden setting")
    if "Data::AddJob((id, r#type, path, to, file_num, include_hidden, is_remote))" in io_loop:
        every.append("AddJob still takes the pane's hidden setting")
    if "readEmptyDirs(item.path, isLocal, true)" not in c.read(rebrand.FILE_MODEL):
        every.append("empty folders still follow the pane's hidden setting")
    for needle in ("fn walk_dir(", "kind.is_symlink()", "couldn't read this folder", "this name isn't valid text", "not a regular file"):
        if needle not in verify:
            every.append(f"file_verify.rs: {needle}")
    c.fact(VERIFY_EVERYTHING, not every, "; ".join(every))


T07_KIT = "flutter/lib/desktop/kit/session_toolbar.dart"
SIMPLE_SETTINGS_KIT = "flutter/lib/desktop/kit/simple_settings.dart"


def tailnet_dart():
    """kit/tailscale.dart's tests for rebrand.TAILNET's two ranges, derived from the CIDRs."""
    import ipaddress
    v4, v6 = (ipaddress.ip_network(n) for n in rebrand.TAILNET.split(","))
    o = v4.network_address.packed
    mask = (0xFF << (16 - v4.prefixlen)) & 0xFF
    b6 = v6.network_address.packed[:v6.prefixlen // 8]
    return (f"b[0] == {o[0]} && (b[1] & 0x{mask:x}) == {o[1]}",
            " && ".join(f"b[{i}] == 0x{x:02x}" for i, x in enumerate(b6)))


def home_checks(c):
    """v1.7 review: Home, Settings and copy. Outside the building is Tailscale (ADR 0004): Home's
    sheet gives this computer's Tailscale address, never the numeric ID."""
    home = fn_body(c.read(rebrand.HOME), "  Widget buildBoringHome(BuildContext context) {") or ""
    kit = c.read("flutter/lib/desktop/kit/tailscale.dart")
    why = []
    if "MacHome(" not in home or "tailscaleAddress: thisTailscaleAddress," not in home:
        why.append("buildBoringHome does not hand MacHome this computer's Tailscale address")
    why += [f"buildBoringHome still reads the ID ({n})" for n in ("serverId", "myId") if n in home]
    why += [f"tailscale.dart range is not rebrand.TAILNET: {e}" for e in tailnet_dart() if e not in kit]
    c.fact("Home's outside-the-building sheet gives this computer's Tailscale address, never the ID (ADR 0004)",
           not why, "; ".join(why))

    # Ticket 05 follow-up: the Quality pick names High Efficiency while it is on, and a hand pick
    # drops the Link Badge back to plain Local.
    bar = fn_body(c.read(rebrand.T07_TOOLBAR), "  Widget buildBoringSessionToolbar(BuildContext context, List<Widget> more) {") or ""
    st = re.search(r'pub const STREAM_TYPE: &str = "([^"]+)";', c.read("libs/base/src/high_efficiency.rs"))
    pick = "await bind.sessionSetImageQuality(sessionId: ffi.sessionId, value: v);\n" \
           "            // v1.7 review: a hand pick replaces High Efficiency, so the badge goes back to Local.\n" \
           "            linkType.setStreamType(streamTypeAfterQualityPick(linkType.stream_type.value));"
    why = [] if pick in bar else ["toolbar's quality pick does not drop High Efficiency"]
    if not st or f"'{st.group(1)}' => 'Local'," not in c.read(T07_KIT):
        why.append("session_toolbar.dart does not map Rust's High Efficiency stream type back to Local")
    c.fact("a hand-picked quality ends High Efficiency: badge back to Local (v1.7 t05 follow-up)",
           not why, "; ".join(why))

    # Ticket 15, app side: Settings links to the download page and says how to set up another computer.
    settings = fn_body(c.read(rebrand.SETTINGS), "  Widget buildBoringSettings(BuildContext context) {") or ""
    kit = c.read(SIMPLE_SETTINGS_KIT)
    why = [] if "SimpleSettings(" in settings and "openUrl: (u) => launchUrlString(u)," in settings \
        else ["Settings does not hand SimpleSettings a way to open the download page"]
    why += [f"simple_settings.dart lost {n}" for n in (
        "const kDownloadUrl = 'https://theboringremote.com/download';",
        "onPressed: () => widget.openUrl!(kDownloadUrl)",
        "Clipboard.setData(const ClipboardData(text: kDownloadUrl))") if n not in kit]
    c.fact("Settings: Download Boring Remote and set up another computer (ticket 15)", not why, "; ".join(why))

    # Ticket 08 follow-up: the kit job list shows delete jobs as well as transfers.
    fm = c.read(rebrand.FILE_MGR)
    i = fm.find("  Widget boringTransferList() => Obx(() => TransferList(")
    jobs = fm[i:fm.find("      ));\n", i)] if i >= 0 else ""
    need = ("            if (j.type != JobType.none)\n", "                  delete: j.type != JobType.transfer,")
    c.fact("File Transfer lists delete jobs too (v1.7 t08 follow-up)", all(n in jobs for n in need),
           "boringTransferList drops delete jobs")

    # Ticket 12 follow-ups: Windows Setup names the computer by its Windows name (scutil is Mac only),
    # and the reach check counts the installer's rule only when it is for this exe.
    page = fn_body(c.read(rebrand.HOME), "Widget boringSetupPage({required VoidCallback onDone, bool passwordOnly = false}) {") or ""
    named = "            : isWindows // v1.7 review: Windows' own computer name; scutil is Mac only\n" \
            "                ? Future.value(windowsComputerName(Platform.environment, Platform.localHostname))\n" \
            "            : Process.run('scutil', ['--get', 'ComputerName'])"
    c.fact("Windows Setup starts from the Windows computer name, never scutil (v1.7 t12 follow-up)", named in page,
           "boringSetupPage does not branch to windowsComputerName before scutil")
    kit = c.read(SETUP_DART)
    why = [] if "Process.run('netsh', windowsRuleShowArgs())\n" \
                 "            .then((r) => r.exitCode == 0 && windowsRuleAllowsExe('${r.stdout}', Platform.resolvedExecutable))" \
        in page else ["canBeReached does not check the rule's program is this exe"]
    if "'dir=in', 'verbose']" not in kit:
        why.append("windowsRuleShowArgs does not ask netsh for the program path (verbose)")
    c.fact("Windows reach check counts the installer's rule only for this exe (v1.7 t12 follow-up)",
           not why, "; ".join(why))


def activate_link_checks(c):
    """Ticket 14: boringremote://activate?key= rides upstream's URL scheme, renamed; nothing else new."""
    plist = c.read("flutter/macos/Runner/Info.plist")
    schemes = re.findall(r"<key>CFBundleURLSchemes</key>\s*<array>(.*?)</array>", plist, re.S)
    names = [n for block in schemes for n in re.findall(r"<string>(.*?)</string>", block)]
    c.fact("Mac URL scheme is boringremote only", names == [rebrand.APP_NAME.lower()], names)
    src = c.read("src/activate_link.rs")
    c.fact("activate link parser uses the app's scheme",
           f'const SCHEME: &str = "{rebrand.APP_NAME.lower()}://";' in src)
    dart = c.read("flutter/lib/common.dart")
    branch = re.findall(r'uri\.authority == "activate"\) \{(.*?)return null;', dart, re.S)
    c.fact("one activate branch, and it only hands the link to Rust",
           len(branch) == 1 and "bind.mainActivateLink(url: url)" in branch[0] and "--" not in branch[0],
           branch)
    run = fn_body(c.read("src/license_key_run.rs"), "pub fn activate_link(url: &str) -> String {") or ""
    c.fact("activate link stores a key only via the parser", "crate::activate_link::parse(url)" in run
           and run.count("set_and_check(") == 1, run[:200])
    logged = [f"{rel}: {needle}" for rel, needle in LINK_LOGS if needle in c.read(rel)]
    c.fact("incoming links (and the key in them) are never logged", not logged, "; ".join(logged))


def bundle_checks(c):
    """v1.7 t17: the Mac app file is "Boring Remote.app" and Windows shows Boring Remote; exe,
    bundle id, launchd labels, config dirs and the Windows install dir keep the internal name,
    so settings, Trusted Controllers and TCC grants carry over."""
    bundle, old, apps = rebrand.MAC_BUNDLE, rebrand.OLD_MAC_BUNDLE, f"/Applications/{rebrand.MAC_BUNDLE}"
    xc = dict(re.findall(r"(?m)^(\w+) = (.*)$", c.read("flutter/macos/Runner/Configs/AppInfo.xcconfig")))
    scheme = c.read("flutter/macos/Runner.xcodeproj/xcshareddata/xcschemes/Runner.xcscheme")
    build_mac = c.read("boring/release/build-mac")
    bad = [n for n, ok in [
        (f"PRODUCT_NAME is {xc.get('PRODUCT_NAME')}", xc.get("PRODUCT_NAME") == SHOWN),
        (f"EXECUTABLE_NAME is {xc.get('EXECUTABLE_NAME')}", xc.get("EXECUTABLE_NAME") == APP),
        ("project's product path not quoted", f'path = "{bundle}";' in c.read("flutter/macos/Runner.xcodeproj/project.pbxproj")),
        ("scheme", set(re.findall(r'BuildableName = "([^"]*\.app)"', scheme)) == {bundle}),
        ("build.py service copy", f'"./build/macos/Build/Products/Release/{bundle}/Contents/MacOS/"' in c.read("build.py")),
        ("verify-dmg.sh", f'APP="{bundle}"' in c.read("boring/dmg/verify-dmg.sh")),
        ("build-mac", f'"$SRC/flutter/build/macos/Build/Products/Release/{bundle}"' in build_mac and old not in build_mac),
    ] if not ok]
    c.fact(f"Mac bundle is {bundle}; its exe stays {APP} (t17)", not bad, "; ".join(bad))

    def plist(name):  # as the app writes it: correct_app_name turns RustDesk into APP
        try:
            text = c.read(f"src/platform/privileges_scripts/{name}").replace("RustDesk", APP)
            return plistlib.loads(text.encode())
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}
    agent, daemon = plist("agent.plist"), plist("daemon.plist")
    wd = f"{apps}/Contents/MacOS/"
    bad = [n for n, ok in [
        (f"agent runs {agent.get('ProgramArguments')}", agent.get("ProgramArguments") == [f"{wd}{APP}", "--server"]),
        (f"agent KeepAlive is {agent.get('KeepAlive')}", agent.get("KeepAlive") is True),
        (f"daemon runs {daemon.get('ProgramArguments')}", daemon.get("ProgramArguments") == [f"{wd}service"]),
        ("working directories", agent.get("WorkingDirectory") == wd and daemon.get("WorkingDirectory") == wd),
    ] if not ok]
    c.fact(f"launchd plists run {bundle} directly, no sh -c (t17)", not bad, "; ".join(bad))
    home, settings, access = c.read(rebrand.HOME), c.read(rebrand.SETTINGS), c.read("flutter/lib/desktop/kit/access.dart")
    bad = [n for n, ok in [
        ("Home's not-ready line", "AccessSummary(checks: boringAccessChecks())," in home),
        ("Settings' Access section", "access: AccessSection(checks: boringAccessChecks()," in settings),
        ("remote access is its own switch", "remoteAccess: bind.mainIsInstalledDaemon(prompt: false) &&" in settings
         and "await mainSetBoolOption(kOptionStopService, !on);" in settings
         and settings.count("kOptionStopService") == 2 and "openAtLoginPlist(" in settings),
        ("checks the --server agent, its port and all three panes",
         all(n in home for n in ("'gui/${await uid()}/$kAgentLabel'", "Socket.connect('127.0.0.1', kDirectLinkPort",
                                 "pane(kScreenRecordingPane)", "pane(kAccessibilityPane)", "pane(kInputMonitoringPane)",
                                 "bind.mainIsCanScreenRecording(prompt: true)"))),
        ("pane ids", all(f"?{p}'" in c.read(SETUP_DART) for p in ("Privacy_ScreenCapture", "Privacy_Accessibility",
                                                                   "Privacy_ListenEvent"))
         and f"kAgentLabel = '{AGENT}'" in access),
    ] if not ok]
    c.fact("Access: Settings and Home check what serves sessions; remote access is its own switch (t17)",
           not bad, "; ".join(bad))

    # A replaced bundle can leave launchd holding the agent at "spawn failed" (EX_CONFIG 78, "needs
    # LWCR update"); kickstart exits 0 and does nothing. Every restart checks and boots it out and in.
    move, script = c.read("libs/base/src/bundle_move.rs"), c.read(INSTALL_SCRIPT)
    kit_restart = access[access.find("Future<bool> restartAgent("):]
    bad = [n for n, ok in [
        ("kit restartAgent kickstarts, checks, then bootout + bootstrap",
         all(n in kit_restart for n in ("['kickstart', '-k', job]", "if (await cameUp()) return true;",
                                        "['bootout', job]", "['bootstrap', 'gui/$uid', kAgentPlist]",
                                        "return cameUp();"))),
        ("Access Fix uses restartAgent", "await restartAgent(Process.run, await uid())" in home
         and "'kickstart'" not in home and "agentRunning('${r.stdout}')" in home),
        ("bundle_move start_agent uses restart_agent", "restart_agent(&mut launchctl, &mut sleep, uid)" in move
         and all(n in move for n in ('launchctl(&["bootout", &job]);',
                                     'launchctl(&["bootstrap", &format!("gui/{uid}"), PLISTS[1]]);'))),
        ("install-update.sh boots the agent out and in after the swap, checks both jobs",
         "  user_session && agent_restart\n" in script and "  daemon_restart\n" in script
         and "job_up \"gui/$CONSOLE_UID/$AGENT_LABEL\"" in script and "job_up \"system/$SERVICE_LABEL\"" in script),
    ] if not ok]
    c.fact("the agent restart checks --server came up; a job stuck at spawn failed is booted out and in again (t17)",
           not bad, "; ".join(bad))

    mac, ipc, auth = c.read("src/platform/macos.rs"), c.read("src/ipc.rs"), c.read("src/ipc/auth.rs")
    move, script = c.read("libs/base/src/bundle_move.rs"), c.read(INSTALL_SCRIPT)
    stale = '.arg(&format!("/Applications/{}.app", crate::get_app_name()))'
    bad = [n for n, ok in [
        ("is_installed", rebrand.MAC_INSTALLED + "        // boring-remote (v1.7 t17)" in mac
         and f'if p.starts_with("{apps}") {{' in mac),
        ("reopen paths", stale not in mac + ipc and f'.arg("{apps}")' in mac and f'.arg("{apps}")' in ipc),
        ("IPC trusts the user server from both bundles", f'["{bundle}", "{old}"].iter().any(|bundle| {{' in auth),
        ("base mod", "pub mod bundle_move;" in c.read(rebrand.BASE_LIB)),
        ("move hook", "base::bundle_move::start(crate::update_rollback::SUPPORT_DIR, crate::platform::quit_gui);"
         in c.read("src/update_notice_run.rs")),
        ("bundle_move paths", f'BUNDLE: &str = "{apps}";' in move and f'OLD_BUNDLE: &str = "/Applications/{old}";' in move
         and f'"/Library/LaunchDaemons/{HOSTD}.plist"' in move and f'"/Library/LaunchAgents/{AGENT}.plist"' in move),
        ("install-update.sh", f'BUNDLE="{bundle}"' in script and f'AGENT_LABEL="{AGENT}"' in script
         and '"${1:-}" = --move-bundle' in script and "needs_move && move_bundle" in script),
    ] if not ok]
    c.fact("a 1.6.x BoringRemote.app is moved once; both paths count as installed until then (t17)",
           not bad, "; ".join(bad))

    tab = c.read(rebrand.LOOK_TAB_PAGE)
    c.fact("Settings opens from a gear, not the three-line menu (t17)",
           "message: 'Settings',\n                  icon: Icons.settings_outlined," in tab and "IconFont.menu" not in tab)

    rule, fw, win = rebrand.WINDOWS_RULE, c.read("res/msi/CustomActions/FirewallRules.cpp"), c.read("src/platform/windows.rs")
    wxl = c.read(f"{MSI_DIR}/Language/Package.en-us.wxl")
    bad = [n for n, ok in [
        ("MSI firewall rule", f'L"{rule}");' in fw and 'L"%ls Service"' not in fw),
        ("MSI service", f'<String Id="Service_DisplayName" Value="{rule}" />' in wxl),
        ("self-install firewall rule", 'rule name=\\"{app_name} Service\\" dir=' not in win
         and win.count(f'firewall add rule name=\\"{rule}\\"') == 2
         and f'firewall delete rule name=\\"{rule}\\"' in win),
        ("self-install service", 'DisplayName= \\"{app_name} Service\\"' not in win),
        ("self-install Apps list", f'/v DisplayName /t REG_SZ /d \\"{SHOWN}\\"' in win),
        (f"exe and install dir are {APP}", f'set(BINARY_NAME "{APP}")' in c.read("flutter/windows/CMakeLists.txt")
         and 'format!("{}\\\\{}", pf, crate::get_app_name())' in win),
    ] if not ok]
    c.fact("Windows service, firewall rule and Apps list say Boring Remote; exe and install dir unchanged (t17)",
           not bad, "; ".join(bad))


def updater_checks(c):
    for name, (rel, want) in UPDATE_ENDPOINTS.items():
        m = re.search(rf'pub const {name}: &str = "([^"]*)";', c.read(rel))
        c.fact(f"{name} is {want} (ADR 0004)", m is not None and m.group(1) == want, m and m.group(1))
    allowed = {want for _, want in UPDATE_ENDPOINTS.values()}
    stray = []
    for rel, text in shipped_files(c, (".rs", ".dart")):
        code = strip_tests_and_comments(text)
        stray += [f"{rel}: {h}" for h in UPDATE_URL.findall(code)]
        if rel.endswith(".rs"):  # network calls live in Rust; Dart URLs are links opened in a browser
            stray += [f"{rel}: {h}" for h in UPDATEISH_URL.findall(code)
                      if h not in allowed and not h.startswith(tuple(p for p, _ in NOT_UPDATE_URLS))]
    c.fact("the only update endpoints are VERSION_URL, its .sig, fulfillment /update and the Windows downloads (ADR 0004/0007)",
           not stray, "; ".join(stray[:10]))

    callers = []
    for rel, text in shipped_files(c, ROOT_SUFFIXES):
        if rel.endswith(".rs"):
            code = strip_tests_and_comments(text)
        else:
            code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith(("#", "--", "//")))
        for m in re.finditer(r"with administrator privileges", code):
            owner = re.findall(r"\b(?:fn|const|static)\s+(\w+)", code[:m.start()])
            key = f"{rel}:{owner[-1]}" if rel.endswith(".rs") and owner else rel
            if key not in ROOT_CALLERS:
                callers.append(key)
    runner = c.read("src/update_install_run.rs")
    c.fact("the only root-run update path is install-update.sh (ADR 0004)",
           not callers and (c.root / INSTALL_SCRIPT).is_file()
           and "Resources/boring-install-update.sh" in runner,
           "; ".join(callers) or f"{INSTALL_SCRIPT} missing or not what update_install_run.rs runs")

    try:
        keys = json.loads(c.read("boring/update-pubkeys.json"))
        cur, bak = (base64.b64decode(keys[k], validate=True) for k in ("current", "backup"))
        ok = len(cur) == 32 and len(bak) == 32 and cur != bak
    except Exception as e:  # noqa: BLE001
        ok, keys = False, e
    c.fact("both update public keys present and different (ADR 0004)", ok, str(keys))


# v1.7 review (spec Decision 5): our kit files for the upstream surfaces, kit tokens only.
LOOK_KIT = ("flutter/lib/desktop/kit/kit_look.dart", "flutter/lib/desktop/kit/connection_window.dart",
            "flutter/lib/desktop/kit/install.dart")
LOOK_OFF_KIT = re.compile(r"MyTheme\.\w+|Colors\.(?!transparent\b)\w+|Color\(0x[0-9A-Fa-f]+\)")
LOOK_CORAL_TEXT = re.compile(r"(?:TextStyle\(" + ARGS + r"|(?:foreground|label)Color: (?:const )?)Kit\.coral\b")


def look_checks(c):
    """v1.7 review, spec Decision 5 (nothing left in the RustDesk look): the upstream surfaces Mac
    and Windows still show wear the kit, in the rebranded tree."""
    common, gate = c.read(rebrand.DART_COMMON), rebrand.LOOK_GATE
    off = [f"{rel}: {h}" for rel in LOOK_KIT for h in LOOK_OFF_KIT.findall(strip_tests_and_comments(c.read(rel)))]
    off += [f"{rel}: coral text" for rel in LOOK_KIT if not c.read(rel) or LOOK_CORAL_TEXT.search(c.read(rel))]
    for needle in ("final ThemeData boringKitTheme = kitLook(Kit.theme())",
                   f"{gate} ? Theme(key: key, data: boringKitTheme, child: child) : child;",
                   f"if {gate} return ThemeMode.dark;"):
        if needle not in common:
            off.append(f"common.dart: no {needle[:48]}")
    c.fact("look kit wired: Mac and Windows run the dark kit, kit look files use kit tokens, coral never text",
           not off, "; ".join(off[:10]))

    # Dialogs: the kit branch of msgboxContent comes before RustDesk's coloured icons.
    msg = fn_body(common, "Widget msgboxContent(String type, String title, String text) {") or ""
    i, j = msg.find("return KitMessage("), msg.find("msgboxIcon(type)")
    dialog = c.read(rebrand.LOOK_DIALOGS)
    missing = [n for text, n in [
        (common, "child: boringKit(builder(setState, close, overlayState.context)),"),
        (msg, "final plain = kitMessageWords(type, title, text);"),
        (dialog, f"title: {gate}\n          ? Text(KitPasswordWords.title)"),
        (dialog, "? KitPasswordWords.body"), (dialog, f"{gate} ? KitPasswordWords.remember"),
    ] if n not in text]
    if not 0 <= i < j:
        missing.append("msgboxContent shows RustDesk's icon before the kit message")
    c.fact("dialogs in the kit on Mac and Windows: password prompt, connecting and errors in plain words",
           not missing, "; ".join(missing))

    # Session toolbar: every menu behind More inherits the kit; the toolbar's palette is kit tokens.
    bar = c.read(rebrand.T07_TOOLBAR)
    palette = fn_body(bar, "class _ToolbarTheme {") or ""
    missing = [f"{rel}: not wrapped" for rel in rebrand.LOOK_REMOTE_PAGES
               if "remoteToolbar(BuildContext context) => boringKit(RemoteToolbar(" not in c.read(rel)]
    missing += [n for n in ("static const Color blueColor = Kit.glass;", "static const Color redColor = Kit.coral;")
                if n not in palette]
    missing += [f"_ToolbarTheme: {h}" for h in re.findall(r"MyTheme\.(?:button|accent)\b|Colors\.(?:red|grey)\w*", palette)]
    c.fact("session toolbar and its More menus in the kit on Mac and Windows", not missing, "; ".join(missing))

    # All settings: the kit theme, kit sections and the kit tab list, no Theme card.
    settings = c.read(rebrand.SETTINGS)
    card = fn_body(settings, "    List<Widget>? title_suffix}) {") or ""
    missing = [n for text, n in [
        (c.read(rebrand.LOOK_TAB_PAGE), "page: boringKit(\n              DesktopSettingPage("),
        (card, "return KitSection(title: translate(title)"),
        (settings, "return KitTabRow("),
        (settings, f"if {gate} return const Offstage(); // boring-remote: the kit is always dark"),
    ] if n not in text]
    if card.find("return KitSection(") > card.find("Card(\n") >= 0:
        missing.append("_Card builds RustDesk's card before the kit section")
    c.fact("All settings in the kit on Mac and Windows: sections, tab list, buttons, checkboxes",
           not missing, "; ".join(missing))

    # Connection window: kit card, plain switches, kit buttons, and Allow leaves the window up.
    cm = c.read(rebrand.CM_PAGE)
    prompt = cm[cm.find("ApprovalPrompt("):cm.find("onDeny:", cm.find("ApprovalPrompt("))]
    missing = [n for n in ("final body = boringKit(Scaffold(", "return Obx(() => ConnectedHeader(",
                           f"if {gate} return _boringPermissions(canModifyPermission);", "return PermissionSwitches(",
                           "final kitButton = CmButton(", "onAllow: () => handleAccept(context),") if n not in cm]
    if "ApprovalPrompt(" not in cm or "minimize" in prompt:
        missing.append("Allow minimises the connection window")
    if "? (isOwnMessage ? Kit.glass : Kit.line)" not in c.read(rebrand.LOOK_CHAT):
        missing.append("chat bubbles not in the kit")
    c.fact("connection window in the kit: who is in, plain switches, kit buttons; Allow keeps it open",
           not missing, "; ".join(missing))

    inst = c.read(rebrand.LOOK_INSTALL)
    missing = [n for n in (f"if {gate} return boringInstallScreen();", "Obx(() => InstallScreen(",
                           "child: boringKit(Scaffold(", "onLicence: () => showLegalDialog(this.context),")
               if n not in inst]
    c.fact("Windows install screen in the kit, plain words", not missing, "; ".join(missing))


ROOT_BUNDLE = "root runs only a bundle no user can change: root:wheel, go-w, or it refuses (audit H3)"


def root_bundle_checks(c):
    """Audit H3: the root LaunchDaemon and the root scripts run code from the bundle, so every
    path that installs, moves or replaces it leaves it root:wheel and not group/other-writable,
    and root refuses to run anything from a bundle a user could still change."""
    scpt = "src/platform/privileges_scripts/"
    install, update = c.read(scpt + "install.scpt"), c.read(scpt + "update.scpt")
    mac, script = c.read("src/platform/macos.rs"), c.read(INSTALL_SCRIPT)
    verify = fn_body(c.read("src/update_install.rs"), "pub fn verify_cli(args: &[String]) -> i32 {") or ""
    bm = c.read("libs/base/src/bundle_move.rs")
    lock = fn_body(script, "lock_bundle() {") or ""
    move = fn_body(script, "move_bundle() {") or ""
    main = script.split('[ $# -eq 3 ] || fail "usage: <package> <sig> <version>"', 1)[-1]
    bad = [n for n, ok in [
        ("install.scpt locks the bundle first, or installs nothing", rebrand.H3_INSTALL_LOCK in install
         and "set sh to sh0 & sh1" in install and '|| exit 1;"' in rebrand.H3_INSTALL_LOCK),
        ("no upstream path hands the bundle to the user (:staff)", ":staff " not in install + update + mac),
        ("lock_bundle: chown root:wheel, chmod go-w, then refuses anything still loose",
         'chown -R root:wheel "$1"' in lock and 'chmod -R go-w "$1"' in lock and "-perm -020 -o -perm -002" in lock
         and '! -user "$OWNER"' in lock and 'fail "refusing to run' in lock and "OWNER=root\n" in script),
        ("update: the installed bundle is locked before root runs its verifier",
         0 <= main.find('lock_bundle "$APP"') < main.find("--boring-verify-package") and 'lock_bundle "$NEW"' in main),
        ("move: the bundle is locked before root runs its service",
         0 <= move.find('lock_bundle "$APP"') < move.find("--write-plists")),
        ("--boring-verify-package refuses as root from a loose bundle",
         0 <= verify.find("base::bundle_move::refuse_as_root(&e)") < verify.find("match args {")
         and "libc::geteuid() } != 0" in bm and "first_loose(bundle, 0)" in bm),
    ] if not ok]
    c.fact(ROOT_BUNDLE, not bad, "; ".join(bad))


def workflow_guard(c):
    """No GitHub Actions: any file under .github/workflows/, on disk or tracked in git, fails.
    Releases build on the Studio (boring/release/build-mac). .github/patches/ is fine."""
    wf = c.root / ".github/workflows"
    found = {p.relative_to(c.root).as_posix() for p in wf.rglob("*") if p.is_file()} if wf.is_dir() else set()
    if (c.root / ".git").exists():
        r = subprocess.run(["git", "-C", str(c.root), "ls-files", "--", ".github/workflows"],
                           capture_output=True, text=True)
        found |= set(r.stdout.split())
    c.fact("no GitHub Actions workflow (.github/workflows/ is empty)", not found, ", ".join(sorted(found)))


THROTTLED_LOGIN = re.compile(
    r"let \(failure, res\) = self\.check_failure\(0\)\.await;\s*if !res \{\s*return true;\s*\}\s*"
    r"if !self\.validate_password\([^)]*\) \{\s*"
    r"self\.update_failure_with_scope\(failure, false, 0, FailureScope::Default\);")
LOGON = "send_logon_response_and_keep_alive().await"
# The prompt-and-wait tail both gates copy from upstream's click branch.
CLICK_WAIT = (r"#\[cfg\(not\(any\(target_os = \"android\", target_os = \"ios\"\)\)\)\]\s*"
              r"if should_use_terminal_os_login_scope\(self\.terminal, &lr\.os_login\.username\) \{\s*"
              r"if let Some\(keep_alive\) = self\.prepare_terminal_login_for_authorization\(\)\.await \{\s*"
              r"return keep_alive;\s*\}\s*\}\s*"
              r"self\.try_start_cm\(lr\.my_id, lr\.my_name, false\);\s*"
              r"if hbb_common::get_version_number\(&lr\.version\)\s*>= hbb_common::get_version_number\(\"1\.2\.0\"\)\s*\{\s*"
              r"self\.send_login_error\(crate::client::LOGIN_MSG_NO_PASSWORD_ACCESS\)\.await;\s*\}\s*return true;")
BUMP = r"self\.update_failure_with_scope\(failure, false, 0, FailureScope::Default\);"
# The key a login proves, folded into its Admission before any Trusted check (base::trust).
PROVE_CALL = ("self.boring_trust.prove(\n                crate::trust_policy::login_key(\n"
              "                    &lr.my_id,\n                    &lr.boring_controller_pk,\n"
              "                    &lr.boring_login_sig,\n                    &self.hash.challenge,\n"
              "                    &Config::get_id(),\n                    self.stream.is_secured(),\n"
              "                ),\n                &base::trust::Trusted::load(),\n            );")
# Ticket 07, the Controller side: the login is signed where it is sent, from the stream that carries it.
SIGN_CALL = ("let challenge = lc.read().unwrap().hash.challenge.clone();\n"
             "    if let Some(message::Union::LoginRequest(lr)) = msg_out.union.as_mut() {\n"
             "        crate::trust_policy::sign_login(lr, &challenge, peer.is_secured());\n    }\n"
             "    allow_err!(peer.send(&msg_out).await);")
# A Machine ID runs only with the baked key; an unverified one is refused without a prompt, and a
# verified one keeps the key it was first verified with.
KEY_GUARD = ("if boring_is_machine_id(peer) && !crate::trust_policy::baked_key(key) {\n"
             '            bail!("Boring Remote checks Machine IDs against its own servers only");\n        }')
REFUSE_IO = ("let boring_refused = if !is_secured && crate::client::boring_is_machine_id(&self.handler.get_id()) {\n"
             "                    Some(crate::client::BORING_UNVERIFIED)\n                } else if is_secured\n"
             "                    && crate::client::boring_is_machine_id(&self.handler.get_id())\n"
             "                    && !crate::connect_plan::pin_target(&self.handler.get_id(), pk.as_deref())\n"
             "                {\n                    Some(base::direct_link::IDENTITY_CHANGED)\n")
REFUSE_PF = ("if !stream.is_secured() && crate::client::boring_is_machine_id(id) {\n"
             "        bail!(crate::client::BORING_UNVERIFIED);\n    }\n"
             "    if stream.is_secured() && crate::client::boring_is_machine_id(id) && "
             "!crate::connect_plan::pin_target(id, _pk.as_deref()) {\n"
             "        bail!(base::direct_link::IDENTITY_CHANGED);\n    }\n"
             "    if !stream.is_secured() && !crate::common::is_direct_ip_access(id) {")


def option_consts(c):
    """OPTION_* name -> option key, from base's keys.rs and the hbb_common keys it re-exports."""
    text = c.read("libs/base/src/config/keys.rs") + c.read(HBB)
    return dict(re.findall(r'pub const (OPTION_\w+): &str = "([^"]*)";', text))


def str_array(c, text, name, extra=None):
    """The resolved items of `pub const <name>: &[&str] = &[...]`, None for one that doesn't resolve."""
    m = re.search(rf"pub const {name}: &\[&str\] = &\[(.*?)\];", text, re.S)
    if not m:
        return []
    consts = {**option_consts(c), **(extra or {})}
    return [i[1:-1] if i.startswith('"') else consts.get(i.split("::")[-1])
            for i in re.findall(r'"[^"]*"|[\w:]+', m.group(1))]


def no_password_gate(conn):
    """(gate start, click branch start, the no-password block or None)."""
    gate = conn.find("if crate::password_lock::refuse_login(")
    click = conn.find("if (password::approve_mode() == ApproveMode::Click && !allow_logon_screen_password)")
    unset = re.search(r"if !Config::has_permanent_password\(\) \{(.*?)" + CLICK_WAIT + r"\s*\}",
                      conn[gate:click] if 0 <= gate < click else "", re.S)
    return gate, click, unset


def trust_gate(conn):
    """The trust gate's text, if it sits after the password check and before the reset and logon."""
    check = conn.find("if !self.validate_password(")
    gate = conn.find("self.boring_trust.unattended_password_right();\n"
                     "                    if !self.boring_trust.skips_click() {", check)
    reset = conn.find("self.update_failure_with_scope(failure, true, 0, FailureScope::Default);", check)
    logon = conn.find("if !self." + LOGON + " {", check)
    ok = 0 <= check < gate < reset < logon and "LOGIN_MSG_PASSWORD_WRONG" in conn[check:gate]
    return conn[gate:reset] if ok else ""


def password_lock_checks(c, locked):
    """Ticket 05: permanent password only, refused without one, throttled, fixed during a session."""
    c.fact("one-time password off: only the permanent password is accepted",
           locked.get("verification-method") == "use-permanent-password", locked.get("verification-method"))
    # The option only hides settings in the UI (common.dart canBeBlocked ignores it in full access
    # mode, and the home page's Set Password doesn't check it); the daemon's session guard holds them.
    c.fact("allow-remote-config-modification locked off (a UI hint; the session guard holds the settings)",
           locked.get("allow-remote-config-modification") == "N", locked.get("allow-remote-config-modification"))

    conn = c.read("src/server/connection.rs")
    lock = strip_tests_and_comments(c.read("src/password_lock.rs"))
    gate, click, unset = no_password_gate(conn)
    refuse = fn_body(lock, "pub fn refuse_login(verification_method: &str) -> bool {")
    live = "if crate::password_lock::refuse_login(&Config::get_option(keys::OPTION_VERIFICATION_METHOD)) {"
    c.fact("no Unattended Password: no unattended access, only Allow on the Target, for that session only",
           0 <= gate < click and conn[gate:].startswith(live) and "return false;" in conn[gate:click]
           and unset is not None
           and re.search(BUMP + r"\s*self\.boring_trust\.wait_for_allow\(false\);", unset.group(1)) is not None
           and refuse is not None and refuse.strip() == "verification_method != PERMANENT_ONLY",
           f"gate at {gate}, click branch at {click}, no-password click path {unset is not None}, "
           f"refuse_login {refuse!r}")

    throttle = fn_body(conn, "async fn check_failure_with_scope(") or ""
    always = re.search(r"let \(failure, res\) = self\.check_failure\(0\)\.await;\s*if !res \{\s*return true;\s*\}\s*"
                       r"if self\.validate_password\(allow_logon_screen_password\)", conn)
    ok = (THROTTLED_LOGIN.search(conn) is not None and always is not None and conn.count("self.validate_password(") == 2
          and '"Too many wrong attempts"' in throttle and '"Please try 1 minute later"' in throttle
          and "let res = if failure.2 > 30 {" in throttle and "} else if time == failure.0 && failure.1 > 6 {" in throttle
          and "self.check_failure_with_scope(i, FailureScope::Default)"
          in (fn_body(conn, "async fn check_failure(&mut self, i: usize)") or ""))
    c.fact("wrong passwords are still throttled before and after every password check", ok)

    ipc = c.read("src/ipc.rs")
    arms = [re.search(rf'name == "{k}" \{{\s*if {re.escape(rebrand.IPC_GUARD)} \{{\s*log::warn!\(', ipc)
            for k in ("permanent-password", "salt", "unlock-pin")]
    options = re.search(r"let value = crate::password_lock::guard_options\(\s*value,\s*&Config::get_options\(\),"
                        r"\s*crate::password_lock::authed_sessions\(\),\s*\);\s*" + re.escape(rebrand.T04_KEEP_LIST.lstrip()), ipc)
    guard = fn_body(lock, "pub fn config_write_allowed(name: &str, remote_sessions: usize) -> bool {") or ""
    sessions = (fn_body(lock, "pub fn authed_sessions() -> usize {") or "").strip()
    base_trust = c.read("libs/base/src/trust.rs")
    consts = {n: (re.search(rf'pub const {n}: &str = "([^"]+)";', base_trust) or [None, None])[1]
              for n in ("TRUSTED_OPTION", "NEW_ALWAYS_ASK_OPTION")}
    guarded = str_array(c, lock, "SECURITY_OPTIONS", consts)
    gen_key = (re.search(r'pub const GENERATED_CONFIG: &str = "([^"]+)";', lock) or [None, None])[1]
    protected = str_array(c, lock, "PROTECTED_CONFIG", {"GENERATED_CONFIG": gen_key})
    need = ("approve-mode", "verification-method", "allow-remote-config-modification", "access-mode", "whitelist",
            consts["TRUSTED_OPTION"], consts["NEW_ALWAYS_ASK_OPTION"])
    c.fact("a remote session can't change the password, PIN or security options",
           all(arms) and ipc.count(rebrand.IPC_GUARD) == 3 and options is not None and "remote_sessions == 0" in guard
           and sessions == "crate::server::AUTHED_CONNS.lock().unwrap().len()"
           and set(protected) - {gen_key} == {"permanent-password", "salt", "unlock-pin"}
           and None not in guarded and all(k in guarded for k in need),
           f"guarded arms {[a is not None for a in arms]}, options guard {options is not None}, "
           f"authed_sessions {sessions!r}, unresolved or missing {[k for k in need if k not in guarded]}")
    sync = re.search(r"Data::SyncConfig\(Some\(configs\)\) => \{\s*(?://[^\n]*\s*)*if crate::password_lock::authed_sessions\(\) > 0 \{"
                     r"\s*log::warn!\([^)]*\);\s*return;\s*\}\s*let \(config, config2\) = \*configs;", ipc)
    c.fact("a remote session can't replace the whole config (Data::SyncConfig refused)", sync is not None)

    alphabet = re.search(r'pub const ALPHABET: &\[u8\] = b"([^"]*)";', lock)
    length = re.search(r"pub const LEN: usize = (\d+);", lock)
    gen = fn_body(lock, "pub fn generate() -> String {") or ""
    gen_with = re.sub(r"\s+", "", fn_body(lock, "pub fn generate_with<R: Rng>(rng: &mut R) -> String {") or "")
    hooks = [("src/lib.rs", "mod password_lock;"), ("src/flutter_ffi.rs", "pub fn main_generate_permanent_password()"),
             (rebrand.HOME, "showGeneratedPasswordOnce(pass)")]
    missing = [f"{rel}: {needle}" for rel, needle in hooks if needle not in c.read(rel)]
    c.fact("generated password: OS RNG, 16+ characters, no look-alike characters, wired to Set Password",
           alphabet and length and int(length.group(1)) >= 16 and not set("0O1lI") & set(alphabet.group(1))
           and "OsRng" in gen and gen_with == "(0..LEN).map(|_|ALPHABET[rng.gen_range(0..ALPHABET.len())]aschar).collect()"
           and not missing, "; ".join(missing) or gen_with)

    home = c.read(rebrand.HOME)
    dialog = fn_body(home, "void setPasswordDialog({VoidCallback? notEmptyCallback}) async {") or ""
    sizes = [int(n) for n in re.findall(r"MinCharactersValidationRule\((\d+)\)", dialog)]
    validate = dialog.find("rules.where((r) => !r.validate(pass))")
    actions = re.search(r"return \[\s*cancelButton,\s*if \(localPasswordSet\) removeButton,\s*okButton,\s*"
                        r"generateButton,\s*\];", dialog)
    c.fact("a typed password needs 16+ characters; Generate (Reset once set) is the main action",
           sizes and min(sizes) >= 16 and 0 <= validate < dialog.find("mainSetPermanentPasswordWithResult(password: pass)")
           and actions is not None and 'permanentPasswordSet ? "Reset" : "Generate"' in dialog,
           f"min length {sizes}, Generate last {actions is not None}")

    shown = c.read("flutter/lib/desktop/widgets/generated_password.dart")
    once = fn_body(shown, "void showGeneratedPasswordOnce(String password) {") or ""
    copy = fn_body(shown, "void copyPasswordBriefly(String password) {") or ""
    c.fact("the new password closes only on I've saved it, and Reset asks before replacing",
           "\"I've saved it\", onPressed: close" in once and "onSubmit" not in once and "onCancel" not in once
           and "clickMaskDismiss" not in once and "copyPasswordBriefly(password)" in once
           and re.search(r"if \(permanentPasswordSet\) \{\s*final go = await confirmReplacePassword\(\);\s*"
                         r"if \(go == null\) return;", dialog) is not None)
    c.fact("a copied password leaves the clipboard after a minute",
           "Clipboard.setData(ClipboardData(text: password));" in copy
           and "Timer(const Duration(seconds: 60)," in copy and "if (now?.text == password)" in copy
           and "Clipboard.setData(const ClipboardData(text: ''))" in copy)
    c.fact("one-time password label hidden when it is off (desktop and mobile)",
           'translate(showOneTime ? "One-time Password" : "Password"),' in home
           and "translate(showOneTime ? 'One-time Password' : 'Password')," in c.read(rebrand.MOBILE_SERVER))

    langs = sorted((c.root / rebrand.LANG_DIR).glob("*.rs"))
    # Keys English shows as they are aren't in en.rs (AGENTS.md); every other file has each once.
    en_only = [rebrand.MACHINE_ID_LABEL, rebrand.UNVERIFIED]
    missing = [f"{p.name}: {k}" for p in langs for k in rebrand.UI_KEYS + en_only
               if p.read_text(encoding="utf-8").count(f'("{k}", ') != (0 if p.name == "en.rs" and k in en_only else 1)]
    c.fact("new UI strings (tickets 05, 06, 07, 09) have a key in every translation file", langs and not missing,
           ", ".join(missing[:5]))


def logon_sites(conn, locked):
    """Every way into a session: (count, [unexplained sites])."""
    sites = [m.start() for m in re.finditer(r"if !(?:self|conn)\." + re.escape(LOGON), conn)]
    why = {
        "Allow, after the trust gate's take_wait":
            lambda before: before[-1800:].rfind("if !conn.boring_trust.take_wait(crate::password_lock::authed_sessions()) {")
            > before[-1800:].rfind("ipc::Data::Authorize => {") >= 0,
        "recent session: only a one-time password login records one, and that is locked off":
            lambda before: before.endswith("} else if self.is_recent_session(false) {\n                ")
            and locked.get("verification-method") == "use-permanent-password",
        "right password, after the trust gate":
            lambda before: before.rstrip().endswith("self.update_failure_with_scope(failure, true, 0, FailureScope::Default);")
            and before[-2500:].rfind("if !self.boring_trust.skips_click() {") > before[-2500:].rfind("if !self.validate_password(") >= 0,
        "2FA, only after a gated logon asked for it":
            lambda before: before[-1500:].rfind("if !self.awaiting_2fa {") > before[-1500:].rfind("message::Union::Auth2fa(tfa)") >= 0
            and conn.count("self.awaiting_2fa = true;") == 1
            and "self.awaiting_2fa = true;" in (fn_body(conn, "async fn send_logon_response_and_keep_alive(&mut self) -> bool {") or ""),
        "switch sides this computer asked for (uuid match)":
            lambda before: "if uuid == uuid_old {" in before[-1500:],
        "always ask (1.7): this computer's Unattended Password, and nothing else":
            lambda before: before.rstrip().endswith("self.boring_trust.unattended_password_right();")
            and before[-1500:].rfind("if self.boring_trust.always_ask() {") >= 0,
        "a token this computer issued and still trusts (1.7 Direct Link)":
            lambda before: before.rstrip().endswith("if self.boring_trust.is_trusted() {"),
    }
    unexplained = [s for s in sites if sum(bool(ok(conn[:s])) for ok in why.values()) != 1]
    return len(sites), unexplained


def proof_checks(c, conn, trust):
    """Trust binding (option B) on the merged list: the Controller signs each login with its own key
    pair over this challenge, the Target's Machine ID and its own ID, only over a stream it verified
    as that Machine ID; the Target proves the key only for its own Machine ID on a keyed stream."""
    squash = lambda s: re.sub(r"\s+", " ", s or "").strip()
    policy = strip_tests_and_comments(c.read("src/trust_policy.rs"))
    proven = squash(fn_body(trust, "pub fn proven_key(controller: &str, pk: &[u8], sig: &[u8], challenge: &str, target: &str) -> Option<[u8; 32]> {"))
    message = fn_body(trust, "pub fn login_message(challenge: &str, target: &str, controller: &str) -> Option<Vec<u8>> {") or ""
    login_key = squash(fn_body(policy, "pub fn login_key("))
    why = []
    if proven != ("let key: [u8; 32] = pk.try_into().ok()?; let want = login_message(challenge, target, controller)?; "
                  "let signed = sign::verify(sig, &sign::PublicKey(key)).ok()?; (signed == want).then_some(key)"):
        why.append("proven_key doesn't verify the signature over this login")
    if login_key != ("if !secured || !crate::client::boring_is_machine_id(own_id) { return None; } "
                     "base::trust::proven_key(my_id, pk, sig, challenge, own_id)"):
        why.append(f"login_key is {login_key[:90]!r}")
    if PROVE_CALL not in conn or not 0 <= conn.find(PROVE_CALL) < conn.find(rebrand.T04_ALWAYS_ASK):
        why.append("the key this login proves isn't checked before the always-ask and Trusted checks")
    if not re.search(r'const LOGIN_DOMAIN: &\[u8\] = b"\\0[^"]*";', trust):
        why.append("the signed login has no zero-led domain (could read as a SignedId)")
    if not re.search(r"let challenge_ok =\s*!challenge\.is_empty\(\) && challenge\.len\(\) <= 64 && "
                     r"challenge\.bytes\(\)\.all\(\|b\| b\.is_ascii_alphanumeric\(\)\);\s*if !challenge_ok \{\s*return None;",
                     message):
        why.append("the Controller would sign any challenge a Target sends")
    c.fact("a Trusted login by key needs that key's signature over this login, for this Target; a known ID alone "
           "never skips Allow", not why, "; ".join(why))

    client = c.read("src/client.rs")
    built = fn_body(client, "async fn send_login(") or ""
    hash_fn = fn_body(client, "pub async fn handle_hash(") or ""
    signing = squash(fn_body(policy, "pub fn sign_login(lr: &mut LoginRequest, challenge: &str, secured: bool) {"))
    lib = c.read("src/lib.rs")
    why = []
    if not 0 <= built.find(rebrand.SIGN_LOGIN) < built.find("allow_err!(peer.send(&msg_out).await);"):
        why.append("send_login doesn't sign before sending")
    if rebrand.HASH_FIRST_NEW.split("    true\n")[0] not in hash_fn:
        why.append("handle_hash sends the login before it stores the challenge")
    want = ('let Some(target) = signed_target(&lr.username, secured) else { return; }; '
            'if base::trust::login_message(challenge, &target, &lr.my_id).is_none() { return; } '
            '#[cfg(any(target_os = "android", target_os = "ios"))] let pair = Some(Config::get_key_pair()); '
            '#[cfg(not(any(target_os = "android", target_os = "ios")))] let pair = Config::get_existing_key_pair(); '
            'let Some((sk, pk)) = pair else { return; }; '
            'if let Some(sig) = base::trust::login_signature(challenge, &target, &lr.my_id, &sk) { '
            'lr.boring_controller_pk = pk.into(); lr.boring_login_sig = sig.into(); }')
    if signing != want:
        why.append("sign_login isn't the service's key pair over (challenge, Target's Machine ID, own ID)")
    if SIGN_CALL not in built or "sign_login(" in (fn_body(client, "    fn create_login_msg(") or ""):
        why.append("the login isn't signed from the stream that carries it")
    if not re.search(r"(?<!Target side only\n)mod trust_policy;", lib):
        why.append("trust_policy is left out of iOS Controllers")
    c.fact("Controllers sign each login with their own key (this challenge, the Target's Machine ID, their ID)",
           not why, "; ".join(why))
    hosted_signing_checks(c, client, policy, squash)


def hosted_signing_checks(c, client, trust, squash):
    """Tickets 07 + 08: a Machine-ID login is signed only over a stream keyed to the Target it
    verified (a pinned Direct Link to that Machine ID, or the servers' word under the baked key),
    decided from that stream when the login is sent. A Machine ID never runs with another key, an
    unverified one is refused (no Continue), and a verified one keeps its pinned key."""
    why = []
    if squash(fn_body(trust, "pub fn baked_key(key: &str) -> bool {")) != \
            "key.is_empty() || key == hbb_common::config::RS_PUB_KEY":
        why.append("baked_key accepts another key")
    signed = squash(fn_body(trust, "pub fn signed_target(peer: &str, secured: bool) -> Option<String> {"))
    if signed != "(secured && crate::client::boring_is_machine_id(peer)).then(|| peer.to_owned())":
        why.append(f"signed_target is {signed[:90]!r}")
    code = strip_tests_and_comments(client)
    start = fn_body(code, "    pub async fn start(\n") or ""
    if not 0 <= start.find(KEY_GUARD) < start.find("Self::_start("):
        why.append("Client::start lets a Machine ID run with a key that isn't the baked one")
    if "boring_verified_target" in code or "verified_target(" in trust:
        why.append("a verified flag is kept per session again (shared by its connections)")
    io_loop = strip_tests_and_comments(c.read("src/client/io_loop.rs"))
    pf = strip_tests_and_comments(c.read("src/port_forward.rs"))
    io_refuse, io_prompt = io_loop.find(REFUSE_IO), io_loop.find("client::confirm_insecure_connection(")
    if not (0 <= io_refuse < io_prompt and io_loop.count("confirm_insecure_connection(") == 1
            and pf.count(REFUSE_PF) == pf.count("confirm_insecure_connection(") == 2):
        why.append("an unverified Machine-ID session can still be continued past the insecure prompt, "
                   "or a verified one isn't held to its pinned key")
    secure = fn_body(code, "    async fn secure_connection(\n") or ""
    vouched = re.search(r"let rs_pk = get_rs_pk\(if key\.is_empty\(\) \{\s*config::RS_PUB_KEY\s*\} else \{\s*key\s*\}\);", secure)
    target_key = re.search(r"if let Ok\(\(id, pk\)\) = decode_id_pk\(&signed_id_pk, &rs_pk\) \{\s*if id == peer_id \{\s*"
                           r"sign_pk = Some\(sign::PublicKey\(pk\)\);\s*option_pk = Some\(pk\.to_vec\(\)\);", secure)
    signed_id = secure.find("decode_id_pk_dtls(&si.id, &sign_pk)")
    same_id = secure.find("if id == peer_id {", signed_id)
    keyed = secure.find("conn.set_negotiated_key(")
    if not (vouched and target_key and secure.count("option_pk = Some") == 1
            and 0 <= signed_id < same_id < keyed and code.count("set_negotiated_key(") == 1
            and not re.search(r"\.set_key(?:_split)?\(", code)):
        why.append("secure_connection no longer keys the stream only after the Target's signed ID checks out "
                   "under the servers' word (is_secured() would not mean verified)")
    c.fact("Controllers sign a Machine-ID login only on a stream that verified the Target (pinned Direct Link or "
           "the baked server key)", not why, "; ".join(why))


# Ticket 08 on 1.7's Direct Link, pinned here (not taken from rebrand.py).
DIRECT_FIRST = ("if let Some((stream, path, pk)) =\n"
                "            crate::connect_plan::direct_first(peer, interface.is_force_relay()).await\n"
                "        {\n")
CONNECT_PLAN = ("if !crate::client::boring_is_machine_id(peer) { return vec![Attempt::DirectLink]; } "
                "let mut attempts = Vec::new(); if known && !relay_only { attempts.push(Attempt::DirectLink); } "
                "attempts.push(Attempt::Hosted); attempts")
MACHINE_ID_PLAN = ("let port = hbb_common::config::RELAY_PORT as u16 + 1; let tailscale = known.tailscale_of(id); "
                   "let direct = crate::lan::advert_of(id).first().map(|a| SocketAddr::new(a.ip, port)); "
                   "let mut plan = match (direct, tailscale) { (Some(direct), ts) => widen(direct, ts, Some(id), known, None), "
                   "(None, Some(ts)) => Plan::single(ts, None), (None, None) => return None, }; "
                   "plan.target = Some(id.to_owned()); plan.dialled = None; Some(plan)")
REMEMBERED = ("crate::connect_plan::save_reported(\n                            &self.handler.get_id(),\n"
              "                            peer.is_secured(),\n                            &pi.platform_additions,\n"
              "                        );")
HOSTED_DOWN = ("Can't reach the Boring Remote servers (rs.theboringremote.com). Check this computer's internet"
               " connection, or connect by Tailscale name or IP.")
HOSTED_DOWN_MAP = ("let socket = socket.map_err(crate::connect_plan::hosted_down); "
                   "// boring-remote: say so, naming them (ticket 08)\n        let mut socket = socket?;")
HOSTED_RELAY = "let err = crate::connect_plan::hosted_error(err);"


def direct_first_checks(c):
    """Ticket 08 (and 16) on 1.7's Direct Link: a Machine ID tries a Direct Link where it was met
    (pinned, only that Machine ID counts), then the Hosted servers; a typed name or address is a
    Direct Link only; the Hosted path holds the same pin; a reported tailnet address is kept only
    from a keyed stream to a pinned Target; a plain error when the Hosted servers are down."""
    squash = lambda s: re.sub(r"\s+", " ", s or "").strip()
    client = c.read("src/client.rs")
    plan_code = strip_tests_and_comments(c.read("src/connect_plan.rs"))
    link = strip_tests_and_comments(c.read(DIRECT_LINK))
    io_loop = strip_tests_and_comments(c.read("src/client/io_loop.rs"))
    body = fn_body(client, "    async fn _start(\n") or ""
    call, rendezvous = body.find(DIRECT_FIRST), body.find("let other_server = interface.get_lch()")
    why = []
    if "mod connect_plan;" not in c.read("src/lib.rs"):
        why.append("no connect_plan module")
    if not 0 <= body.find(rebrand.DIRECT_LINK_CALL) <= call < rendezvous:
        why.append("_start doesn't try a Machine ID's Direct Link after the name/IP branch and before the Hosted servers")
    if squash(fn_body(plan_code, "pub fn plan(peer: &str, known: bool, relay_only: bool) -> Vec<Attempt> {")) != CONNECT_PLAN:
        why.append("plan isn't: names Direct Link only; a Machine ID's Direct Link where met, then the Hosted servers")
    first = squash(fn_body(plan_code, "pub async fn direct_first("))
    if "base::direct_link::machine_id_known(peer, &known)" not in first or \
            "base::direct_link::connect_machine_id(peer, DIRECT_FIRST_MS, known).await" not in first:
        why.append("direct_first isn't the strict Machine-ID Direct Link")
    if squash(fn_body(link, "fn plan_for_machine_id(id: &str, known: &Known) -> Option<Plan> {")) != MACHINE_ID_PLAN:
        why.append("a Machine ID's Direct Link plan isn't strict (target set, nothing exempt, no name lookups)")
    judge = squash(fn_body(link, "fn judge<S>("))
    if "Err(Failure::Refused(e)) => Err(Failure::Stale(e))," not in judge or \
            "Ok((_, Some(who))) if who.id != target && plan.dialled != Some(addr) =>" not in judge:
        why.append("another computer at a Machine ID's address isn't passed over")
    if "pub const DIRECT_FIRST_MS: u64 = 3_000;" not in plan_code:
        why.append("the Tailscale attempt isn't ~3 s")
    if re.search(r"TAILNET_STREAM|tailnet_first|boring_tailnet_stream|TAILNET_OPTION", strip_tests_and_comments(client) + io_loop):
        why.append("a plaintext tailnet-first path or its exemption is back")
    c.fact("a Machine ID tries a pinned Direct Link where it was met (~3 s on Tailscale), then the Hosted servers (ticket 08)",
           not why, "; ".join(why))

    pin = squash(fn_body(plan_code, "pub fn pin_target(id: &str, pk: Option<&[u8]>) -> bool {"))
    pin_id = squash(fn_body(link, "pub fn pin_id(&mut self, id: &str, sign_pk: &[u8]) -> bool {"))
    learn = squash(fn_body(link, "pub fn learn_tailscale(&mut self, id: &str, ip: IpAddr) -> bool {"))
    save = squash(fn_body(plan_code, "pub fn save_reported(id: &str, secured: bool, additions: &str) {"))
    peer_info = io_loop[io_loop.find("Some(login_response::Union::PeerInfo(pi)) => {"):]
    conn = c.read("src/server/connection.rs")
    reported = conn.find("crate::connect_plan::add_own_tailnet(&mut platform_additions);")
    why = []
    if not pin.startswith("let Some(pk) = pk.filter(|pk| pk.len() == 32) else { return false; };") or \
            "let ok = known.pin_id(id, pk);" not in pin:
        why.append("pin_target doesn't refuse a missing key or check the pin")
    if pin_id != ("let pk = hex(sign_pk); match self.0.get(id) { Some(t) => t.pk == pk, None => { "
                  "self.0.insert(id.to_owned(), KnownTarget { pk, ..Default::default() }); true } }"):
        why.append("a Machine ID met before doesn't keep its key")
    if not learn.startswith("if !is_tailscale(ip) { return false; } let Some(t) = self.0.get_mut(id) else { return false };"):
        why.append("a reported address is kept for an unpinned Target or isn't a Tailscale one")
    if not save.startswith("if !(secured && crate::client::boring_is_machine_id(id)) { return; }") or \
            "known.learn_tailscale(id, ip)" not in save:
        why.append("save_reported keeps an address from an unverified stream")
    if not 0 <= peer_info.find(REMEMBERED) < peer_info.find("self.set_peer_info(&pi);"):
        why.append("io_loop doesn't keep the address its verified Target reports")
    if not 0 <= reported < conn.find("pi.platform_additions = serde_json::to_string(&platform_additions)"):
        why.append("the Target doesn't report its tailnet address after login")
    c.fact("the Hosted path holds the same pin as a Direct Link, and a tailnet address is kept only from a pinned Target "
           "(tickets 08, 16)", not why, "; ".join(why))

    code = strip_tests_and_comments(client)
    inner = fn_body(code, "    async fn _start_inner(\n") or ""
    langs = sorted((c.root / rebrand.LANG_DIR).glob("*.rs"))
    missing = [p.name for p in langs for k in (HOSTED_DOWN,)
               if p.read_text(encoding="utf-8").count(f'("{k}", ') != (0 if p.name == "en.rs" else 1)]
    c.fact(f"Hosted servers unreachable: a plain error naming {HOSTED} (ticket 08)",
           HOSTED_DOWN_MAP in inner and inner.count("socket?;") == 1 and HOSTED in HOSTED_DOWN
           and HOSTED_RELAY in (fn_body(code, "    pub async fn start(\n") or "")
           and 'starts_with("Failed to connect via relay server")' in plan_code
           and f'pub const HOSTED_DOWN: &str = "{HOSTED_DOWN}";' in plan_code and rebrand.HOSTED_DOWN == HOSTED_DOWN
           and bool(langs) and not missing, ", ".join(missing[:5]))


# The one way a key lets a login skip Allow: a Trusted entry found by the key this login proved.
SKIPS = "matches!(self.by_key, Some(ByKey::Trusted(..)))"
PROVE = ("self.pk = pk.map(|k| hex(&k)); self.by_key = None; "
         "if self.trusted.is_some() || self.always_ask.is_some() || self.removed.is_some() { return; } "
         "let Some(c) = self.pk.as_deref().and_then(|pk| t.by_pk(pk)) else { return };")
TAKE_WAIT = ("match self.waiting.take() { Some(password_right) => { self.may_remember = password_right && others == 0; "
             "self.may_reinstate = others == 0; true } None => false, }")
EFFECTIVE = ("let ok = if self.removed_key().is_some() { self.may_reinstate } else { self.may_remember }; "
             "if how == SignIn::Allowed && !ok { SignIn::ThisSessionOnly } else { how }")


def controller_key_checks(c, locked):
    """Ticket 06 on 1.7's Trusted list: a new Controller needs the password and Allow; only a token
    (1.7, Direct Link) or a key it proves over this login (1.8, signed) finds its entry; Allow stores
    only after the right password with no other session open; Remove ends its sessions; while
    anyone is connected Settings only tightens the list. The ID it reports is never enough."""
    c.fact("new Controllers need the password and Allow on the Target (approve mode locked, ask can't hide)",
           locked.get("approve-mode") == "" and "approve-mode" in locked and locked.get("allow-hide-cm") == "N",
           f"approve-mode {locked.get('approve-mode')!r}, allow-hide-cm {locked.get('allow-hide-cm')!r}")
    squash = lambda s: re.sub(r"\s+", " ", s or "").strip()
    conn = c.read("src/server/connection.rs")
    trust = strip_tests_and_comments(c.read("libs/base/src/trust.rs"))
    wait = trust_gate(conn)
    why = []
    if not wait or "self.boring_trust.unattended_password_right();" not in wait \
            or "if !self.boring_trust.skips_click() {" not in wait or "self.boring_trust.wait_for_allow(true);" not in wait \
            or not re.search(BUMP + r"\s*self\.boring_trust\.wait_for_allow\(true\);\s*" + CLICK_WAIT, wait):
        why.append("trust gate missing, out of place, or not counted")
    if squash(fn_body(trust, "pub fn skips_click(&self) -> bool {")) != SKIPS:
        why.append("something other than a Trusted entry's proven key skips Allow")
    if not squash(fn_body(trust, "pub fn prove(&mut self, pk: Option<[u8; 32]>, t: &Trusted) {")).startswith(PROVE):
        why.append("prove doesn't let a token decide first, or matches on something other than the proven key")
    if "pub fn by_pk(&self, pk: &str) -> Option<&TrustedController> {\n        if pk.len() != 64 {" not in trust:
        why.append("by_pk matches a short or empty key")
    c.fact("a right password waits for Allow on the Target unless a Trusted Controller proves its key",
           not why, "; ".join(why))

    accept = conn.find("ipc::Data::Authorize => {")
    gate = conn.find("if !conn.boring_trust.take_wait(crate::password_lock::authed_sessions()) {", accept)
    audit = conn.find("conn.set_conn_audit_primary_auth(ConnAuditPrimaryAuth::Click);", accept)
    stray = conn[gate:audit]
    approve = squash(fn_body(trust, "fn approve_into(&mut self, t: &mut Trusted, how: SignIn, name: &str) -> bool {"))
    c.fact("Allow only counts for a login waiting on it, and stores a Controller only after its password, "
           "with no other session open",
           0 <= accept < gate < audit and "conn.send_close_reason_no_retry(\"\").await;" in stray and "break;" in stray
           and "clear_failures(&mut LOGIN_FAILURES[0].lock().unwrap(), &conn.failure_keys());" in stray
           and squash(fn_body(trust, "pub fn take_wait(&mut self, others: usize) -> bool {")) == TAKE_WAIT
           and squash(fn_body(trust, "fn effective(&self, how: SignIn) -> SignIn {")) == EFFECTIVE
           and "let how = self.effective(how);" in (fn_body(trust, "pub fn approve(&mut self, how: SignIn, name: &str) {") or "")
           and "if how != SignIn::Allowed { self.pending = None; return false; }" in approve
           and "LOGIN_GRACE" in conn,
           f"Authorize arm at {accept}, take_wait at {gate}")
    login = conn.find("if let Some(message::Union::LoginRequest(lr)) = msg.union {")
    waits = re.findall(r"self\.boring_trust\.wait_for_allow\((?:true|false)\);", conn)
    c.fact("a new login on a connection waiting on Allow ends it (the click can't land on another login)",
           re.search(r"if self\.boring_trust\.waiting\(\) \{\s*self\.send_login_error\(\"Connection not allowed\"\)\.await;"
                     r"\s*return false;", conn[login:login + 800]) is not None and len(waits) == 3,
           f"{len(waits)} waits")
    c.fact("no Allow prompt for a login without the right password (empty or wrong)",
           rebrand.EMPTY_PASSWORD_NO_CM in conn and rebrand.EMPTY_PASSWORD_CM not in conn
           and rebrand.WRONG_PASSWORD_CM not in conn)
    n, odd = logon_sites(conn, locked)
    c.fact("exactly seven ways into a session, each gated or explained", n == 7 and not odd,
           f"{n} logon calls, unexplained at {odd}")

    lost = squash(fn_body(trust, "fn lost_trust_in(&self, t: &Trusted) -> bool {"))
    plan = fn_body(trust, "fn plan_edit(raw: &str, edit: &Edit, sessions: usize) -> Result<(Trusted, bool), &'static str> {") or ""
    ipc = c.read("src/ipc.rs")
    why = []
    if "(c.removed || !self.password_right && !self.stays && c.always_ask)" not in lost:
        why.append("Remove doesn't end that Controller's session")
    if "Edit::Allow { .. } if sessions > 0 => return Err(IN_SESSION)," not in plan or \
            "if !*on && was && sessions > 0 {\n                return Err(IN_SESSION);" not in plan:
        why.append("Settings can let more in while someone is connected")
    if "base::trust::edit_in_session(&value, crate::password_lock::authed_sessions())" not in ipc:
        why.append("the service's edit doesn't know who is connected")
    c.fact("Remove ends that Controller's sessions; while anyone is connected Settings only tightens the list",
           not why, "; ".join(why))
    proof_checks(c, conn, trust)


def stored_controller_key_checks(c):
    """1.8 keys on 1.7's Trusted list: optional, never written empty, never a token."""
    trust = strip_tests_and_comments(c.read("libs/base/src/trust.rs"))
    c.fact("the Controller's key rides 1.7's list: optional, never written empty, its own entries never match a token",
           '#[serde(default, skip_serializing_if = "String::is_empty")]\n    pub pk: String,' in trust
           and 'pub const PK_KEY_PREFIX: &str = "pk:";' in trust
           and "let ok = unhex(&t.key).map_or(false, |k| k.len() == d.len() && memcmp(&k, &d));" in trust)


def baked_key():
    """(the checked-in server public key, None) or (None, why it can't be the baked key)."""
    try:
        text = SERVER_KEY.read_text(encoding="ascii").strip()
        raw = base64.b64decode(text, validate=True)
    except (OSError, UnicodeError, ValueError) as e:
        return None, f"{SERVER_KEY.name} missing or not base64 ({e.__class__.__name__})"
    if len(raw) != 32 or base64.b64encode(raw).decode() != text:
        return None, f"{SERVER_KEY.name} is not a 32-byte Ed25519 public key"
    if text == RUSTDESK_KEY:
        return None, f"{SERVER_KEY.name} is RustDesk's public servers' key"
    if text != PINNED_KEY:
        return None, f"{SERVER_KEY.name} isn't the pinned Hosted servers' key (check.py PINNED_KEY)"
    if SERVERS_REPO_KEY.is_file() and SERVERS_REPO_KEY.read_text(encoding="ascii").strip() != text:
        return None, f"{SERVER_KEY.name} differs from {SERVERS_REPO_KEY}"
    return text, None


def hosted_checks(c, cfg, locked):
    """ADR 0005: the Hosted servers are the only servers, every override forces them, their key
    is the checked-in one, and no Tailscale whitelist is left."""
    servers = re.search(r"pub const RENDEZVOUS_SERVERS: &\[&str\] = &\[(.*?)\];", cfg, re.S)
    c.fact(f"the only rendezvous server is {HOSTED} (ADR 0005)",
           servers is not None and servers.group(1).strip() == f'"{HOSTED}"' and rebrand.HOSTED == HOSTED,
           servers and servers.group(1))
    firsts = {sig: first_statement(cfg, sig) for sig in ("pub fn get_rendezvous_servers() -> Vec<String> {",
                                                         "pub fn get_rendezvous_server() -> String {")}
    c.fact("rendezvous server and list are always ours (exe name, Settings, config file, serial path skipped)",
           list(firsts.values()) == [FORCE_SERVERS, FORCE_SERVER], firsts)
    want = {"custom-rendezvous-server": HOSTED, "relay-server": HOSTED, "rendezvous-servers": HOSTED,
            "api-server": ""}
    bad = {k: locked.get(k) for k, v in want.items() if locked.get(k) != v}
    c.fact(f"server settings locked to {HOSTED} (relay follows; no API server)", not bad, bad)

    key, why = baked_key()
    rs = re.search(r'pub const RS_PUB_KEY: &str = "([^"]*)";', cfg)
    if key and (rs is None or rs.group(1) != key):
        why = f"RS_PUB_KEY is {rs and rs.group(1)}, not {SERVER_KEY.name}"
    elif key and locked.get("key") != key:
        why = f"locked key option is {locked.get('key')!r}, not {SERVER_KEY.name}"
    c.fact(f"baked server key is {SERVER_KEY.name} (built-in key and locked key option)", key and not why, why)

    tailnet = set(rebrand.TAILNET.split(","))
    maps = {name: rust_map(cfg, name) for name in ("OVERWRITE_SETTINGS", "DEFAULT_SETTINGS", "BUILTIN_SETTINGS",
                                                   "HARD_SETTINGS", "OVERWRITE_LOCAL_SETTINGS",
                                                   "DEFAULT_LOCAL_SETTINGS")}
    left = [f"{name} {k}" for name, m in maps.items() for k, v in m.items()
            if k == "whitelist" or tailnet & set(v.split(","))]
    c.fact("no global whitelist left (ADR 0005: Hosted connections arrive from anywhere)", not left, ", ".join(left))
    exposure_checks(c, cfg)


ICE_URL = re.compile(r"\b(?:stun|stuns|turn|turns):(?://)?([\w.-]+)")
RELAY_OURS = "let relay_server = boring_relay(&relay_server)?;"
BORING_RELAY = ('let ours = hbb_common::config::Config::get_option("relay-server"); if ours.is_empty() '
                '{ bail!("no relay server"); } if !advertised.is_empty() && advertised != ours '
                '&& !advertised.starts_with(&format!("{ours}:")) { log::warn!("relay {advertised} named by the peer '
                'ignored, using {ours}"); } Ok(ours)')
DIRECT_LAN_ONLY = ('log::info!("direct access from {}", addr);\n'
                   "                // boring-remote: the Direct Link answers Tailscale and private-LAN addresses only (ADR 0003, 0005).\n"
                   "                if !base::lan::is_allowed(addr.ip()) {\n                    continue;\n                }\n")


def exposure_checks(c, cfg):
    """Ticket 07: what the Hosted path newly exposes stays shut. The Controller's relay is ours,
    nothing reaches a third-party STUN server, 21118 answers Tailscale and private LAN only (1.7's
    whitelist, now a listener hook), and the Machine ID can't be changed."""
    squash = lambda t: re.sub(r"\s+", " ", t or "").strip()
    client = strip_tests_and_comments(c.read("src/client.rs"))
    relay = fn_body(client, "    async fn create_relay(\n") or ""
    c.fact("the Controller's relay is always the locked relay-server, never a host the peer names",
           relay.lstrip().startswith(RELAY_OURS) and squash(fn_body(client, "fn boring_relay(advertised: &str) -> ResultType<String> {")) == BORING_RELAY
           and client.count("check_port(relay_server, RELAY_PORT)") == 1, relay.lstrip()[:120])

    local = rust_map(cfg, "OVERWRITE_LOCAL_SETTINGS")
    med = c.read("src/rendezvous_mediator.rs")
    stun = []
    for rel, text in shipped_files(c, (".rs", ".dart")):
        code = strip_tests_and_comments(text) if rel.endswith(".rs") else text
        stun += [f"{rel}: {h}" for h in ICE_URL.findall(code) if h != HOSTED]
    why = [f"{k} not locked N" for k in ("enable-webrtc", "enable-ipv6-punch", "enable-udp-punch") if local.get(k) != "N"]
    if "        let webrtc_viable = false\n" not in med:
        why.append("the Target answers WebRTC offers")
    if first_statement(med, "    slot: Option<PunchSlot>,\n) -> bytes::Bytes {") != \
            "if true { return Default::default(); } // boring-remote: no IPv6 punch (ticket 07)":
        why.append("the Target starts IPv6 punches (STUN probes)")
    c.fact("no WebRTC, IPv6 or UDP punch, and no third-party STUN or TURN host ships",
           not why and not stun, "; ".join(why + stun[:6]))

    accept = med.find("if let Ok(Ok((stream, addr))) = hbb_common::timeout(1000, l.accept()).await {")
    allowed = re.sub(r"\s+", " ", fn_body(c.read("libs/base/src/lan.rs"), "pub fn is_allowed(ip: IpAddr) -> bool {") or "")
    c.fact("the Direct Link (21118) answers Tailscale and private-LAN addresses only, with no global whitelist",
           accept >= 0 and med.count(DIRECT_LAN_ONLY) == 1
           and 0 <= med.find(DIRECT_LAN_ONLY, accept) < med.find("crate::server::create_tcp_connection(", accept)
           and "(a == 100 && (b & 0xc0) == 64) || v4.is_private()" in allowed, allowed[:120])

    ui = c.read("src/ui_interface.rs")
    first = first_statement(ui, "pub async fn change_id_shared_(id: String, old_id: String) -> &'static str {")
    settings, mobile = c.read(rebrand.SETTINGS), c.read(rebrand.MOBILE_SERVER)
    c.fact("Change ID is off: hidden on desktop and mobile, refused if called (the Machine ID never changes)",
           rust_map(cfg, "BUILTIN_SETTINGS").get("disable-change-id") == "Y"
           and first is not None and first.startswith("if true { return INVALID_FORMAT; }")
           and "if (!isChangeIdDisabled())\n                  _Card(title: 'ID', children: [changeId()])," in settings
           and "            if (!isChangeIdDisabled())\n" in mobile
           and "bind.mainGetBuildinOption(key: kOptionDisableChangeId) == 'Y'" in c.read("flutter/lib/common.dart"),
           f"change_id_shared_ starts {first!r}")


def first_launch_checks(c):
    """Ticket 09: a Target without an app-generated Permanent password stays off the Hosted servers
    (its Machine ID is never registered) while Direct IP over the tailnet keeps working."""
    med = c.read("src/rendezvous_mediator.rs")
    ipc = c.read("src/ipc.rs")
    lock = strip_tests_and_comments(c.read("src/password_lock.rs"))
    body = fn_body(med, "pub async fn start_all() {") or ""
    flat = lambda sig: re.sub(r"\s+", "", fn_body(lock, sig) or "")
    gate = re.search(r"let servers = crate::password_lock::hosted_servers\(\s*Config::get_rendezvous_servers\(\),"
                     r"\s*crate::password_lock::hosted_on\(\),\s*\);", body)
    helper = flat("pub fn hosted_servers(servers: Vec<String>, password_set: bool) -> Vec<String> {")
    ready = flat("pub fn hosted_ready(marker: &str, has_password: bool) -> bool {")
    on = flat("pub fn hosted_on() -> bool {")
    spawn = re.search(r"let server_cloned = server\.clone\(\);\s*tokio::spawn\(async move \{\s*"
                      r"direct_server\(server_cloned\)\.await;\s*\}\);", body)
    loop = body.find("for host in servers.clone() {")
    c.fact("no app-generated Permanent password, no Hosted servers: the Target registers its Machine ID only once "
           "the generator's marker is set; Direct IP keeps listening (ticket 09)",
           gate is not None and 0 <= gate.end() < loop and body.count("Config::get_rendezvous_servers()") == 1
           and med.count("Self::start(server, host)") == 1 and helper == "ifpassword_set{servers}else{Vec::new()}"
           and ready == 'marker=="Y"&&has_password'
           and on == "hosted_ready(&Config::get_option(GENERATED_OPTION),Config::has_permanent_password())"
           and spawn is not None and spawn.start() < body.find("\n        loop {\n"),
           f"gate {gate is not None}, helper {helper!r}, ready {ready!r}, on {on!r}, Direct IP ungated {spawn is not None}")

    ticks = re.findall(r"_ = timer\.tick\(\) => \{\s*if SHOULD_EXIT\.load\(Ordering::SeqCst\) \{\s*break;\s*\}"
                       r"\s*if !crate::password_lock::hosted_on\(\) \{\s*break;", med)
    c.fact("a live Hosted registration ends within a tick once the generated password is gone, whatever removed it "
           "(ticket 09)", len(ticks) == 2 == med.count("_ = timer.tick() => {"), f"{len(ticks)} of 2 ticks")

    key = re.search(r'pub const GENERATED_CONFIG: &str = "([^"]+)";', lock)
    opt = re.search(r'pub const GENERATED_OPTION: &str = "([^"]+)";', lock)
    protected = str_array(c, lock, "PROTECTED_CONFIG", {"GENERATED_CONFIG": key and key.group(1)})
    arm = re.search(r"\} else if name == crate::password_lock::GENERATED_CONFIG \{\s*(?://[^\n]*\s*)?"
                    r"updated = crate::password_lock::set_generated\(&value\);\s*let ack = if updated", ipc)
    clear = re.search(r"updated = Config::set_permanent_password\(&value\);\s*if updated \{\s*"
                      r"crate::password_lock::clear_generated\(\);", ipc)
    setgen = fn_body(lock, "pub fn set_generated(password: &str) -> bool {") or ""
    order = [setgen.find(n) for n in ("if !generated_write_allowed(", "authed_sessions()",
                                      "Config::is_disable_change_permanent_password()",
                                      "if !Config::set_permanent_password(password) {",
                                      "Config::set_option(GENERATED_OPTION.to_owned(), \"Y\".to_owned());")]
    allowed = flat("pub fn generated_write_allowed(password: &str, remote_sessions: usize, change_disabled: bool) -> bool {")
    guard = fn_body(lock, "pub fn guard_options(") or ""
    pinned = guard.find("pin_option(&mut incoming, current, GENERATED_OPTION);")
    gen = flat("pub fn generate_and_set() -> String {")
    c.fact("only an app-generated password sets the Hosted marker: the daemon writes it with the password, any other "
           "password write clears it, and no Options write or remote session sets it (ticket 09)",
           key and opt and key.group(1) in protected and arm and clear
           and -1 not in order and order == sorted(order)
           and allowed == ("!change_disabled&&config_write_allowed(GENERATED_CONFIG,remote_sessions)"
                           "&&password.len()==LEN&&password.bytes().all(|b|ALPHABET.contains(&b))")
           and 0 <= pinned < guard.find("if remote_sessions == 0")
           and "ifsend_generated(pw.clone()){" in gen and "set_permanent_password" not in gen,
           f"protected {protected}, generated arm {arm is not None}, typed clears {clear is not None}, "
           f"set_generated order {order}, options pin {pinned}")

    home, setup = c.read(rebrand.HOME), c.read(SETUP_DART)
    panel = c.read("flutter/lib/desktop/kit/password.dart")
    dart_opt = re.search(r"const kBoringPasswordGenerated = '([^']+)';", panel)
    make = fn_body(panel, "  Future<void> _make() async {") or ""
    at = setup.find("List<_Screen> _screensFor(SetupPlatform p, {bool passwordOnly = false}) => [")
    screens = re.sub(r"\s+", " ", setup[at:setup.find("];", at) + 2]) if at >= 0 else ""
    why = []
    if not (rebrand.PASSWORD_SETUP_INIT in home and rebrand.PASSWORD_SETUP_BRANCH in home
            and home.find(rebrand.PASSWORD_SETUP_BRANCH) < home.find("    if ((isMacOS || isWindows) && _boringSetup) {\n")):
        why.append("the home page doesn't open Setup's password step for a computer with no password made here")
    if not (dart_opt and opt and dart_opt.group(1) == opt.group(1)):
        why.append("the Dart marker isn't the service's")
    if "generatePassword: () => bind.mainGeneratePermanentPassword()," not in home or "passwordOnly: passwordOnly," not in home:
        why.append("Setup doesn't run the generator")
    if "if (!passwordOnly) ...[" not in screens or not screens.endswith("], _Screen.password, ];"):
        why.append("the password-only run isn't Setup's own password step")
    if not 0 <= make.find("final pass = await widget.generate();") < make.find("_step = _Step.shown;") \
            or "if (pass.isEmpty) {" not in make:
        why.append("the panel doesn't show the generated password once, or shows a refusal as a password")
    if "_Step.confirm" not in (fn_body(panel, "  Widget build(BuildContext context) {") or ""):
        why.append("replacing a password doesn't ask first")
    c.fact("1.8.0 first launch: a computer with no password made here gets Setup's password step alone, which "
           "runs the generator (asking first if a password is set) and shows it once (ticket 09)",
           not why, "; ".join(why))


def our_code(c):
    """The Rust and Dart we add: our own modules and widgets, and the text rebrand.py inserts."""
    files, inserted = set(), []
    for rel, old, new, _ in rebrand.PATCHES:
        if not isinstance(old, str):
            continue
        added = new.replace(old, "", 1) if old in new else new
        if rel.endswith((".rs", ".dart")):
            inserted.append(added)
        if rel == "src/lib.rs":
            files |= {f"src/{m}.rs" for m in re.findall(r"\bmod (\w+);", added)}
        files |= {f"flutter/lib/desktop/widgets/{w}.dart"
                  for w in re.findall(r"package:flutter_hbb/desktop/widgets/(\w+)\.dart", added)}
    texts = {rel: strip_tests_and_comments(c.read(rel)) for rel in sorted(files)}
    texts["rebrand.py inserted text"] = "\n".join(inserted)
    return texts


def config_kept_checks(c, cfg):
    """Ticket 09: the 1.8.0 Update starts from the 1.7.x config, untouched."""
    org = re.search(r'static ref ORG: RwLock<String> = RwLock::new\("([^"]*)"', cfg)
    app = re.search(r'static ref APP_NAME: RwLock<String> = RwLock::new\("([^"]*)"', cfg)
    key = re.search(r'pub const KEY_OPTION: &str = "([^"]*)";', c.read("src/license_key.rs"))
    same = ((org and org.group(1), app and app.group(1), key and key.group(1))
            == (SHIPPED_ORG, SHIPPED_APP, SHIPPED_KEY_OPTION))
    script = c.read("src/platform/privileges_scripts/install-update.sh")
    removed = set(re.findall(r'\brm -r?f "([^"]+)"', script))
    script_ok = (script and not CONFIG_PATH.search(script)
                 and removed <= {"$STAGE", "$PREV", "$APP", "$OLD", "$f", "$SUPPORT/update-pending"})
    wipes = [f"{rel}: {m.group(0)}" for rel, text in our_code(c).items() for m in CONFIG_WIPE.finditer(text)]
    c.fact("the 1.8.0 Update keeps 1.7.x's config: same config dir and License key option, the update script "
           "never touches it, and nothing we add clears saved machines or settings (ticket 09)",
           same and script_ok and not wipes,
           f"identity {org and org.group(1)}.{app and app.group(1)} / {key and key.group(1)}, "
           f"script removes {sorted(removed)}, wipes {wipes[:5]}")


def run_checks(root):
    c = Check(root)
    workflow_guard(c)
    cfg = c.read(HBB)

    # identity
    m = re.search(r'static ref APP_NAME: RwLock<String> = RwLock::new\("([^"]*)"', cfg)
    app_name = m and m.group(1)
    c.fact(f"app name is {APP}", app_name == APP, app_name)
    try:
        info = plistlib.loads((c.root / "flutter/macos/Runner/Info.plist").read_bytes())
    except Exception:
        info = {}
    c.fact(f"app name shown as {SHOWN} on Mac", info.get("CFBundleDisplayName") == SHOWN)
    c.fact(f"app name shown as {SHOWN} on Windows",
           f'VALUE "ProductName", "{SHOWN}"' in c.read("flutter/windows/runner/Runner.rc"))
    ids = set(re.findall(r"PRODUCT_BUNDLE_IDENTIFIER = ([^;\s]+)",
                         c.read("flutter/macos/Runner.xcodeproj/project.pbxproj")
                         + c.read("flutter/macos/Runner/Configs/AppInfo.xcconfig")))
    c.fact(f"Mac bundle id is {AGENT}", ids == {AGENT}, str(ids))
    c.fact(f"LaunchAgent label is {AGENT}",
           plist_label(c, "src/platform/privileges_scripts/agent.plist") == AGENT)
    c.fact(f"LaunchDaemon label is {HOSTD}",
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
    c.fact(f"install script copies the real config dir, Preferences/{rebrand.ORG}.{APP}/",
           conf_dir == f"{rebrand.ORG}.{APP}" and dirs == {conf_dir}
           and tomls == {f"{APP}.toml", f"{APP}2.toml"}, f"config dir {conf_dir}, script {dirs} {tomls}")

    # servers and locked settings (ADR 0005: the Hosted servers, forced; no whitelist)
    locked = rust_map(cfg, "OVERWRITE_SETTINGS")
    hosted_checks(c, cfg, locked)
    c.fact("Direct IP locked on", locked.get("direct-server") == "Y")
    conn = c.read("src/server/connection.rs")
    ok, why = whitelist_enforced(conn, c.read("libs/hbb_common/src/lib.rs"))
    c.fact("a whitelist the buyer sets is still checked first on incoming connections", ok, why)
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
    password_lock_checks(c, locked)
    controller_key_checks(c, locked)
    stored_controller_key_checks(c)
    first_launch_checks(c)
    config_kept_checks(c, cfg)

    # sync, NAT test, updater
    for rel, sig, what in (
        ("src/common.rs", "pub fn test_nat_type() {", "NAT test"),
        ("src/common.rs", "pub fn check_software_update() {", "update check"),
        ("src/common.rs", "pub async fn do_check_software_update() -> hbb_common::ResultType<()> {",
         "update check request"),
        ("src/hbbs_http/sync.rs", "async fn start_hbbs_sync_async() {", "stats sync"),
        ("src/updater.rs", "fn start_auto_update_check_(rx_msg: Receiver<UpdateMsg>) {", "Windows updater"),
        ("src/updater.rs", "pub fn start_auto_update_macos() {", "Mac updater"),
        # lock bypasses: each of these writes past OVERWRITE_SETTINGS
        ("src/platform/windows.rs", "pub fn get_license_from_exe_name() -> ResultType<CustomServer> {",
         "Windows exe-name license (sets rendezvous and API server)"),
        ("src/common.rs", "pub fn read_custom_client(config: &str) {",
         "custom.txt reader (writes OVERWRITE_SETTINGS)"),
        ("src/common.rs", "fn get_api_server_(api: String, custom: String) -> String {",
         "API server lookup (none derived from the rendezvous server: no audit posts)"),
    ):
        first = first_statement(c.read(rel), sig)
        c.fact(f"{what} returns before doing anything",
               first is not None and re.match(r"(if true \{ )?(return\b|bail!)", first), f"{rel}: {first!r}")
    body = fn_body(cfg, "pub fn get_rendezvous_server() -> String {") or ""
    c.fact("no rendezvous server read from the config file",
           body and "rendezvous_server = CONFIG2" not in body and "get_rendezvous_servers()" in body)
    c.fact("auto update locked off", locked.get("allow-auto-update") == "N")
    c.fact("LAN discovery not locked off (ADR 0003)", locked.get("enable-lan-discovery", "Y") == "Y",
           locked.get("enable-lan-discovery"))
    first = first_statement(c.read("src/lan.rs"), "pub(super) fn start_listening() -> ResultType<()> {")
    c.fact("LAN discovery listener answers pings (ADR 0003)",
           first is not None and not re.match(r"(if true \{ )?(return\b|bail!)", first), repr(first))
    c.fact("update check locked off", rust_map(cfg, "OVERWRITE_LOCAL_SETTINGS").get("enable-check-update") == "N")
    lib = c.read("libs/hbb_common/src/lib.rs")
    c.fact("version check endpoint empty", 'const URL: &str = "";' in lib)

    updater_checks(c)
    root_bundle_checks(c)
    bundle_checks(c)  # v1.7 t17

    # The notice hooks into upstream files only through rebrand.py; each must have landed.
    hooks = [
        ("src/lib.rs", "mod update_notice;"), ("src/lib.rs", "mod update_notice_run;"),
        ("src/flutter_ffi.rs", "pub fn main_check_update_notice()"),
        (rebrand.HOME, "UpdateNoticeBanner("),
        (rebrand.HOME, "update_notice_banner.dart"),
        (rebrand.SETTINGS, "kBoringUpdateCheckOption"),
        (rebrand.SETTINGS, "update_notice_banner.dart"),
        ("src/lib.rs", "mod license_key;"), ("src/lib.rs", "mod license_key_run;"),
        ("src/flutter_ffi.rs", "pub fn main_set_license_key("),
        (rebrand.SETTINGS, "LicenseKeyField("),
        (rebrand.SETTINGS, "license_key_field.dart"),
        ("src/lib.rs", "mod update_install;"), ("src/lib.rs", "mod update_install_run;"),
        ("src/lib.rs", "mod update_rollback;"),
        ("src/flutter_ffi.rs", "pub fn main_install_update()"),
        ("src/core_main.rs", '"--boring-verify-package"'),
        (rebrand.HOME, "bind.mainInstallUpdate()"),
        (rebrand.HOME, "setKey: (k) => bind.mainSetLicenseKey(key: k),"),  # ticket 15
        (rebrand.HOME, "if (isMacOS || isWindows) return _buildBlock(child: buildBoringHome(context));"),  # v1.7 t01/t12
        (rebrand.HOME, "MacHome("), (rebrand.HOME, "Kit.theme()"),
        (rebrand.HOME, "lan: lanMacs.macs,"), (rebrand.HOME, "discover: () => bind.mainDiscover(),"),  # v1.7 t02
        ("libs/base/src/lan.rs", f'DEVICE_NAME_OPTION: &str = "{rebrand.BORING_MAC_NAME_OPTION}";'),
        ("src/lan.rs", rebrand.T02_PONG_NAME),  # LAN pong names this Mac as Settings does
        (rebrand.T07_TOOLBAR, "..add(buildBoringSessionToolbar(context, more));"),  # v1.7 t07
        (rebrand.T07_TOOLBAR, "SessionToolbar("),
        (rebrand.T07_TOOLBAR, "final link = linkStateFor(linkType.stream_type.value);"),  # v1.7 t03 Link Badge
        ("src/platform/privileges_scripts/install-update.sh", f'SERVICE_LABEL="{rebrand.HOSTD_ID}"'),        ("src/lib.rs", "mod activate_link;"),
        ("src/flutter_ffi.rs", "pub fn main_activate_link("),
        ("flutter/lib/common.dart", "bind.mainActivateLink(url: url)"),
    ]
    missing = [f"{rel}: {needle}" for rel, needle in hooks if needle not in c.read(rel)]
    c.fact("update hooks landed in upstream files (ADR 0004)", not missing, "; ".join(missing))
    bar = c.read("flutter/lib/desktop/kit/session_toolbar.dart")  # v1.7 t07
    c.fact("Session Toolbar uses kit tokens only",
           not re.search(r"\bColors\.|Color\(|MyTheme", bar))
    multi_window_checks(c, cfg)  # v1.7 t11
    activate_link_checks(c)
    simple_settings_checks(c)  # v1.7 t09
    trust_checks(c, cfg)  # v1.7 t04
    setup_checks(c)  # v1.7 t06
    switch_recovery_checks(c)  # v1.7 t31
    windows_checks(c)  # v1.7 t12
    high_efficiency_checks(c)  # v1.7 t05
    rust_hook_checks(c)  # v1.7 t02-t05
    support_checks(c)  # v1.7 t20
    lan_both_ways_checks(c)  # v1.7 t21
    fastest_lan_checks(c)  # v1.7 t25
    target_word_checks(c)  # v1.7 t26
    home_checks(c)  # v1.7 review: Home, Settings, copy
    transfer_speed_checks(c)  # v1.7 t27
    transfer_verify_checks(c)  # v1.7 t30
    ft = rebrand.FILE_MGR  # v1.7 t08
    ft_needles = ("TransferPane(", "TransferDraggable(", "boringTransferList()",
                  "_boringSend(model.remoteController)", "_boringSend(model.localController)")
    ft_missing = [n for n in ft_needles if n not in c.read(ft)]
    c.fact("v1.7 File Transfer kit wired into the file manager", not ft_missing, "; ".join(ft_missing))
    c.fact("File Transfer theme carries the extensions upstream's location bar reads (v1.7 t28)",
           "data: boringKitTheme," in c.read(ft) and "Kit.theme()" not in c.read(ft))
    c.fact("UI errors reach the app log (v1.7 t28)",
           "logUiErrors((text) => bind.mainLogUiError(text: text));" in c.read("flutter/lib/main.dart")
           and "pub fn main_log_ui_error(text: String)" in c.read("src/flutter_ffi.rs"))

    hits = []
    for base in ("src", "libs", "flutter/lib"):
        for p in sorted((c.root / base).rglob("*")):
            if p.suffix not in (".rs", ".dart") or not p.is_file() or "/lang/" in p.as_posix():
                continue
            code = strip_tests_and_comments(p.read_text(encoding="utf-8", errors="replace"))
            hits += [f"{p.relative_to(c.root)}: {h}" for h in PUBLIC_SERVER.findall(code)]
            hits += [f"{p.relative_to(c.root)}: RustDesk's server key" for _ in range(code.count(RUSTDESK_KEY))]
    c.fact("no shipped code names a RustDesk public server or its key", not hits, "; ".join(hits[:10]))

    # banned codecs and the Mac build flags (releases build locally: boring/release/build-mac)
    bad = []
    for p in sorted(c.root.rglob("*")):
        rel = p.relative_to(c.root).as_posix()
        if not p.is_file() or (rel.startswith(("boring/", ".git/", "target/")) and rel != RELEASE_SCRIPT):
            continue
        is_wf = rel.startswith(".github/workflows/")
        if not (is_wf or p.suffix in (".sh", ".ps1", ".bat", ".cmd", ".py") or p.name in ("Dockerfile", "build-mac")):
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
    mac_builds = [l for l in c.read(RELEASE_SCRIPT).splitlines()
                  if "build.py" in l and "--flutter" in l and "--portable" not in l]
    c.fact("Mac build has --unix-file-copy-paste",
           mac_builds and all("--unix-file-copy-paste" in l for l in mac_builds), str(mac_builds))
    # toolchain pins are checked against upstream's workflows by boring/pins.py; the app version is Cargo.toml's

    msi_checks(c)
    branding_checks(c)
    connect_checks(c)
    transfer_checks(c)  # v1.7 t29
    look_checks(c)  # v1.7 review: nothing left in the RustDesk look
    direct_first_checks(c)

    # protocol: every .proto in the tree is upstream's, byte for byte, except our two LoginRequest fields
    c.fact("protocol files are upstream's plus our two LoginRequest fields (boring/protocol.sha256)",
           *protocol_matches(c.root))

    print(f"rebrand check: {c.passed} passed, {c.failed} failed")
    return 1 if c.failed else 0


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = args[0] if args else pathlib.Path(__file__).resolve().parent.parent
    sys.exit(run_checks(root))
