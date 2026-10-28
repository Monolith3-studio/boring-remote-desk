#!/usr/bin/env python3
"""Rebrand check: prove a scripted tree is the Boring Remote Desk app.

Usage:  python3 boring/check.py [ROOT]

Reads the tree after boring/rebrand.py has run and asserts what the spec asks
for: name, bundle IDs, empty servers, Direct IP on, tailnet whitelist, listener
on all interfaces, allow-only-conn-window-open available and off, sync / NAT
test / updater / LAN discovery unreachable (ADR 0004: only the version file, its .sig and fulfillment /update), no RustDesk public server named in shipped code,
no hwcodec/vram in any build invocation, Mac build with file copy-paste, the
Windows MSI (name, exe, art sizes, license, icon, no RustDesk text, release on
tags), no RustDesk name, link or logo a person sees on Mac or Windows (strings,
translations, app metadata, every logo slot; one AGPL line on the About page), that
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
                if s == rebrand.LEGAL_LINE:
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


def branding_checks(c):
    """No RustDesk name, link or logo a person sees in the Mac and Windows app."""
    hits, legal = ui_brand_hits(c.root)
    c.fact("no RustDesk name or link in the Mac and Windows app's strings", not hits, "; ".join(hits[:12]))
    c.fact("About page has the one plain AGPL legal line, crediting RustDesk with our source URL",
           legal == ["flutter/lib/desktop/pages/desktop_setting_page.dart"]
           and rebrand.FORK_URL in rebrand.LEGAL_LINE and "Purslane" in rebrand.LEGAL_LINE,
           f"legal line found in {legal}")
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


TAILNET_GUARD = ("        if true {\n            return Ok((\n                (\n"
                 "                    connect_tcp_local(boring_tailnet_addr(peer).await?, None, CONNECT_TIMEOUT)\n")
ROUTE_AROUND = re.compile(r"rendezvous|RENDEZVOUS|_start_inner|other_server|is_domain_port_str|get_lch")


def tailnet_exprs():
    """The Rust tests for rebrand.TAILNET's two ranges, derived from the CIDRs."""
    import ipaddress
    v4, v6 = (ipaddress.ip_network(n) for n in rebrand.TAILNET.split(","))
    assert v4.prefixlen == 10 and v6.prefixlen == 48, "boring_is_tailnet is written for a /10 and a /48"
    o = v4.network_address.packed
    mask = (0xFF << (16 - v4.prefixlen)) & 0xFF
    segs = ", ".join(f"0x{int.from_bytes(v6.network_address.packed[i:i + 2], 'big'):x}" for i in (0, 2, 4))
    return (f"ip.octets()[0] == {o[0]} && (ip.octets()[1] & 0x{mask:x}) == {o[1]}",
            f"ip.segments()[..3] == [{segs}]")


def connect_checks(c):
    """The connect box takes an IP or a tailnet name, never an ID."""
    client = c.read("src/client.rs")
    body = fn_body(client, "    async fn _start(\n") or ""
    guard = body.find(TAILNET_GUARD)
    pre = strip_tests_and_comments(body[:guard]) if guard >= 0 else ""
    block = body[guard:body.find("\n        }\n", guard)] if guard >= 0 else ""
    tops = [l.strip() for l in pre.splitlines() if l.startswith("        ") and not l.startswith("         ")]
    why = []
    if guard < 0:
        why.append("no unconditional tailnet return after the IP branch")
    if ROUTE_AROUND.search(pre):
        why.append(f"_start touches the ID path first: {ROUTE_AROUND.findall(pre)}")
    if "if hbb_common::is_ip_str(peer) {" not in pre or any(not t.startswith(("if ", "}")) for t in tops):
        why.append(f"only the incoming-only and IP branches may come first: {tops}")
    if guard >= 0 and ("return Ok((" not in block or "else" in block):
        why.append("the tailnet block does not always return")
    calls = [m.start() for m in re.finditer(r"Self::_start_inner\(", client)]
    start = client.find("    async fn _start(\n")
    if not calls or any(not (start < i < start + len(body) + 200) for i in calls) or \
            len(re.findall(r"::_start\(", client)) != 1:
        why.append("_start / _start_inner are called from somewhere else")
    c.fact("connect box never reaches the ID/rendezvous path", not why, "; ".join(why))

    resolver = fn_body(client, "async fn boring_tailnet_addr(peer: &str) -> ResultType<SocketAddr> {") or ""
    is_tailnet = fn_body(client, "fn boring_is_tailnet(addr: SocketAddr) -> bool {") or ""
    v4, v6 = tailnet_exprs()
    why = []
    if f'const BORING_NOT_FOUND: &str = "{rebrand.NOT_FOUND}";' not in client:
        why.append("error text is not rebrand.NOT_FOUND")
    for need in ("lookup_host(check_port(peer, RELAY_PORT + 1))", "_ => bail!(BORING_NOT_FOUND),",
                 "if addrs.is_empty() || !addrs.iter().all(|a| boring_is_tailnet(*a)) {\n        bail!(BORING_NOT_FOUND);"):
        if need not in resolver:
            why.append(f"resolver lost: {need.splitlines()[0]}")
    for need in ("hbb_common::try_into_v4(addr).ip()", f"V4(ip) => {v4},", f"V6(ip) => {v6},"):
        if need not in is_tailnet:
            why.append(f"tailnet test is not {need}")
    c.fact("names connect Direct IP only to Tailscale addresses, else the plain error", not why, "; ".join(why))

    key = f'("{rebrand.NOT_FOUND}", '
    langs = sorted((c.root / rebrand.LANG_DIR).glob("*.rs"))
    missing = [p.name for p in langs if p.read_text(encoding="utf-8").count(key) != 1]
    c.fact("plain not-found error is in every translation file", langs and not missing, ", ".join(missing))


# ADR 0004 (docs/adr/0004-in-app-updater.md, supersedes 0003): the app may fetch
# the signed version file and its .sig, and POST the license key to fulfillment
# /update. Nothing else in shipped code is an update endpoint, and the only thing
# run as root for an update is install-update.sh.
UPDATE_ENDPOINTS = {
    "VERSION_URL": ("src/update_notice.rs", "https://boringlabs.online/downloads/the-boring-remote-version.json"),
    "UPDATE_ENDPOINT": ("src/license_key.rs", "https://store-fulfillment.boringstories.workers.dev/update"),
}
UPDATEISH_URL = re.compile(r"https?://[^\s\"'`)<>]*(?:version|update|release|latest|download)[^\s\"'`)<>]*", re.I)
# Not app updates: (prefix, why).
NOT_UPDATE_URLS = (("https://api.telegram.org/bot{}/getUpdates", "2FA Telegram bot polling"),)
INSTALL_SCRIPT = "src/platform/privileges_scripts/install-update.sh"
# Every `with administrator privileges` site, as file or file:enclosing fn/const.
ROOT_CALLERS = {
    "src/update_install_run.rs:OSA": "runs Resources/boring-install-update.sh (slice 6), the one update path",
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
    c.fact("the only update endpoints are VERSION_URL, its .sig and fulfillment /update (ADR 0004)",
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

    updater_checks(c)

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
        ("src/platform/privileges_scripts/install-update.sh", f'SERVICE_LABEL="{rebrand.HOSTD_ID}"'),
    ]
    missing = [f"{rel}: {needle}" for rel, needle in hooks if needle not in c.read(rel)]
    c.fact("update hooks landed in upstream files (ADR 0004)", not missing, "; ".join(missing))

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

    # protocol untouched: every .proto in the tree is upstream's, byte for byte
    c.fact("protocol files are upstream's (boring/protocol.sha256)", *protocol_matches(c.root))

    print(f"rebrand check: {c.passed} passed, {c.failed} failed")
    return 1 if c.failed else 0


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = args[0] if args else pathlib.Path(__file__).resolve().parent.parent
    sys.exit(run_checks(root))
