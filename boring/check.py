#!/usr/bin/env python3
"""Rebrand check: prove a scripted tree is the Boring Remote Desk app.

Usage:  python3 boring/check.py [ROOT]

Reads the tree after boring/rebrand.py has run and asserts what the spec asks
for: name, bundle IDs, empty servers, Direct IP on, tailnet + private-LAN whitelist (ADR 0003), listener
on all interfaces, allow-only-conn-window-open available and off, sync / NAT
test / updater unreachable, LAN discovery on (ADR 0003) (ADR 0004: only the version file, its .sig and fulfillment /update), no RustDesk public server named in shipped code,
no hwcodec/vram in any build invocation, Mac build with file copy-paste, the
Windows MSI (name, exe, art sizes, license, icon, no RustDesk text, release on
tags), no RustDesk name, link or logo a person sees on Mac or Windows (strings,
translations, app metadata, every logo slot; AGPL notices in the Legal dialog, license and source link), that
the connect box takes an IP or a tailnet name and never reaches the ID/rendezvous
path, and that the protocol files are upstream's. It only reads the tree.
Idempotence is proved by test_rebrand.py and the CI clean-diff step.

Prints one PASS/FAIL line per fact, then
    rebrand check: <n> passed, <m> failed
and exits 1 if anything failed. Stdlib only.
"""
import base64
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
NO_OWNER = "nothing shipped names Monolith3 or Jason"
# Text that ships, or that the app is built from. boring/ and tests don't ship.
OWNER = re.compile(r"monolith3|jason|boringstories", re.I)
OWNER_DIRS = ("flutter/lib", "flutter/macos/Runner", "flutter/windows/runner", "flutter/assets", "src", "libs", "res")
OWNER_FILES = ("Cargo.toml", "flutter/pubspec.yaml", "flutter/macos/Runner.xcodeproj/project.pbxproj")
OWNER_EXTS = {".dart", ".rs", ".swift", ".cpp", ".cc", ".c", ".h", ".mm", ".m", ".plist", ".xcconfig", ".xib",
              ".rc", ".wxl", ".wxs", ".rtf", ".txt", ".toml", ".yaml", ".json", ".py", ".strings"}
NOT_THE_OWNER = "Copyright 2012 Jason Champion"  # libs/clipboard/src/windows/wf_cliprdr.c: upstream's header stays
LEGAL_ITEM = "onTap: () => showLegalDialog(context),"


def owner_hits(root):
    paths = [root / f for f in OWNER_FILES]
    for base in OWNER_DIRS:
        paths += [p for p in (root / base).rglob("*") if p.suffix in OWNER_EXTS]
    out = []
    for p in paths:
        if p.is_file() and not p.relative_to(root).as_posix().startswith("flutter/assets/LICENCE"):
            text = p.read_text(encoding="utf-8", errors="replace").replace(NOT_THE_OWNER, "")
            if OWNER.search(text):
                out.append(p.relative_to(root).as_posix())
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
                            "onLicence: () => showLegalDialog(context)," in c.read(rebrand.LOOK_INSTALL))) if not ok]
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
    """v1.7 t03: the connect box takes a name or IP for a Direct Link (own address, then
    Tailscale, ADR 0004), never an ID, and off Tailscale it is encrypted or refused (ADR 0005)."""
    client = c.read("src/client.rs")
    body = fn_body(client, "    async fn _start(\n") or ""
    guard = body.find(rebrand.DIRECT_LINK_CALL)
    pre = strip_tests_and_comments(body[:guard]) if guard >= 0 else ""
    block = strip_tests_and_comments(body[guard:guard + len(rebrand.DIRECT_LINK_CALL)]) if guard >= 0 else ""
    tops = [l.strip() for l in pre.splitlines() if l.startswith("        ") and not l.startswith("         ")]
    why = []
    if guard < 0:
        why.append("no unconditional Direct Link return in _start")
    if ROUTE_AROUND.search(pre):
        why.append(f"_start touches the ID path first: {ROUTE_AROUND.findall(pre)}")
    if "if config::is_incoming_only()" not in pre or any(not t.startswith(("if ", "}", "bail!")) for t in tops):
        why.append(f"only the incoming-only branch may come before the Direct Link: {tops}")
    if guard >= 0 and ("return Ok((" not in block or "else" in block or "?;" not in block):
        why.append("the Direct Link block does not always return")
    calls = [m.start() for m in re.finditer(r"Self::_start_inner\(", client)]
    start = client.find("    async fn _start(\n")
    if not calls or any(not (start < i < start + len(body) + 200) for i in calls) or \
            len(re.findall(r"::_start\(", client)) != 1:
        why.append("_start / _start_inner are called from somewhere else")
    c.fact("connect box never reaches the ID/rendezvous path", not why, "; ".join(why))

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
               "setPassword: (p) => bind.mainSetPermanentPasswordWithResult(password: p),",
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
        (home, "setPassword: (p) => bind.mainSetPermanentPasswordWithResult(password: p),"),
        (c.read(rebrand.SETTINGS), "onRunSetup: () =>"),
        (kit, "?Privacy_ScreenCapture'"),
        (kit, "?Privacy_Accessibility'"),
        (kit, "SimpleSettings.strongEnough("),
        (kit, "?Privacy_ListenEvent'"),  # t21: the third switch
        (home, "canMonitorInput: () => bind.mainIsCanInputMonitoring(prompt: false),"),
        (home, "welcome: setupNeeded(bind.mainGetLocalOption(key: kSetupDoneOption)),"),
        (home, "readyChecks: boringAccessChecks(),"),
        (kit, "const kSetupDownloadUrl = "),
    ]
    missing = [n for text, n in hooks if n not in text]
    c.fact("Setup wired: first launch, Settings, this Mac's name, System Settings panes (v1.7 t06)",
           not missing, "; ".join(missing))


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
    wf = c.read(".github/workflows/boring-build.yml")
    needles = [
        ("libs/base/src/update_feed.rs", feed, '#[cfg(target_os = "windows")]\npub const THIS: Platform = Platform::Windows;'),
        ("src/update_notice.rs", notice, "base::update_feed::release_for(body, base::update_feed::THIS)"),
        ("src/update_notice.rs", notice, "store.set(KEY_LAST_PKG_URL, package_url(&body));"),
        ("src/update_install_run.rs", run, "crate::platform::update_to(p)"),
        ("src/update_install_run.rs", run, "LocalConfig::get_option(crate::update_notice::KEY_LAST_PKG_URL)"),
        ("boring-build.yml", wf, "boring/min-version feed-out feed-out/BoringRemote-*-windows-x64*.msi"),
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
    # The trusted skip must sit inside the login decision, right before the approve-mode ask.
    i, j = conn.find(rebrand.T04_TRUSTED_SKIP), conn.find("if (password::approve_mode() == ApproveMode::Click")
    if i < 0 or conn[i + len(rebrand.T04_TRUSTED_SKIP):j].strip():
        missing.append("connection.rs: trusted skip is not right before the approve-mode ask")
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
        ("Allow and the Unattended Password map to lasting trust, everything else to this session",
         rebrand.T04_GRANT in conn and "_ => base::trust::SignIn::ThisSessionOnly," in rebrand.T04_GRANT),
        ("approve_into stores nothing for ThisSessionOnly", "Some(key) if how != SignIn::ThisSessionOnly => {" in grant),
    ] if not ok]
    c.fact("a one-time code lets a Controller in for that session only (ADR 0005)", not once, "; ".join(once))

    removed = [n for n, ok in [
        ("connection.rs sends a removed Controller to the ask before any password path",
         "if self.boring_trust.must_ask() {" in rebrand.T04_TRUSTED_SKIP and rebrand.T04_TRUSTED_SKIP in conn),
        ("approve_into re-trusts a removed Controller only on Allow",
         "if how != SignIn::Allowed {" in grant and "t.reinstate(key, name)" in grant),
        ("Remove in Settings keeps the entry, hidden, so the token is still known",
         "'removed': true" in (fn_body(dart, "String removeTrusted(") or "")),
    ] if not ok]
    c.fact(REMOVED_ASKS, not removed, "; ".join(removed))

    why = [f"rebrand map sets {k}" for d in (rebrand.LOCKED, rebrand.DEFAULTS, rebrand.LOCKED_LOCAL)
           for k in d if PASSWORDISH.search(k)]
    for name in ("DEFAULT_SETTINGS", "OVERWRITE_SETTINGS", "HARD_SETTINGS", "BUILTIN_SETTINGS",
                 "DEFAULT_LOCAL_SETTINGS", "OVERWRITE_LOCAL_SETTINGS"):
        m = re.search(rf"pub static ref {name}: RwLock<HashMap<String, String>> = (.*?);\n", cfg, re.S)
        if not m or PASSWORDISH.search(m.group(1)):
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
    reinstate = fn_body(trust, "String reinstateTrusted(String json, String key, {int? now}) {") or ""
    grant = fn_body(c.read(TRUST_RS), "    fn reinstate(") or ""
    bad = [n for n, ok in [
        ("Trusted Controllers lists removed ones with Allow", "removed: parseRemoved(" in settings
         and "onAllow: (c) async {" in settings and "child: const Text('Allow')," in trust),
        ("Allow there writes the server option (ipc to the service), never a local one",
         "await bind.mainSetOption(\n                            key: kTrustedControllersOption,\n"
         "                            value: reinstateTrusted(" in settings
         and "mainSetLocalOption(key: kTrustedControllersOption" not in settings),
        ("reinstateTrusted does what trust.rs reinstate does", "f.key != 'removed'" in reinstate
         and "'added': at" in reinstate and "t.removed = false;" in grant and "t.added = now();" in grant),
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
    if '("removed", prefix(k))' not in ask or '"new", self.pending' not in ask:
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
    for need in ("'Connect to a computer'", '"Type a computer\'s name"', "Text('Computers',",
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
    page = fn_body(c.read(rebrand.HOME), "Widget boringSetupPage({required VoidCallback onDone}) {") or ""
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
    wf = c.read(".github/workflows/boring-build.yml")
    bad = [n for n, ok in [
        (f"PRODUCT_NAME is {xc.get('PRODUCT_NAME')}", xc.get("PRODUCT_NAME") == SHOWN),
        (f"EXECUTABLE_NAME is {xc.get('EXECUTABLE_NAME')}", xc.get("EXECUTABLE_NAME") == APP),
        ("project's product path not quoted", f'path = "{bundle}";' in c.read("flutter/macos/Runner.xcodeproj/project.pbxproj")),
        ("scheme", set(re.findall(r'BuildableName = "([^"]*\.app)"', scheme)) == {bundle}),
        ("build.py service copy", f'"./build/macos/Build/Products/Release/{bundle}/Contents/MacOS/"' in c.read("build.py")),
        ("verify-dmg.sh", f'APP="{bundle}"' in c.read("boring/dmg/verify-dmg.sh")),
        ("workflow", f'"flutter/build/macos/Build/Products/Release/{bundle}"' in wf and f"Release/{old}" not in wf),
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
        ("Settings' Access section", "access: AccessSection(checks: boringAccessChecks())," in settings),
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
                           "child: boringKit(Scaffold(", "onLicence: () => showLegalDialog(context),")
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


def run_checks(root):
    c = Check(root)
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

    # servers and locked settings
    c.fact("rendezvous servers empty", re.search(r"RENDEZVOUS_SERVERS: &\[&str\] = &\[\s*\];", cfg))
    locked = rust_map(cfg, "OVERWRITE_SETTINGS")
    for key in ("custom-rendezvous-server", "relay-server", "api-server"):
        c.fact(f"{key} locked empty", key in locked and locked[key] == "", locked.get(key))
    c.fact("whitelist locked to Tailscale + private LAN, nothing public (ADR 0003)",
           whitelist_is_private(locked.get("whitelist", "")), locked.get("whitelist"))
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
    branding_checks(c)
    connect_checks(c)
    transfer_checks(c)  # v1.7 t29
    look_checks(c)  # v1.7 review: nothing left in the RustDesk look

    # protocol untouched: every .proto in the tree is upstream's, byte for byte
    c.fact("protocol files are upstream's (boring/protocol.sha256)", *protocol_matches(c.root))

    print(f"rebrand check: {c.passed} passed, {c.failed} failed")
    return 1 if c.failed else 0


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = args[0] if args else pathlib.Path(__file__).resolve().parent.parent
    sys.exit(run_checks(root))
