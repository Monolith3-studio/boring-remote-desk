#!/usr/bin/env python3
"""Rebrand check: prove a scripted tree is the Boring Remote Desk app.

Usage:  python3 boring/check.py [ROOT]

Reads the tree after boring/rebrand.py has run and asserts what the spec asks
for: name, bundle IDs, the Hosted servers as the only servers with every override forced to
them, their key baked in from boring/server-key.pub (ADR 0005), no Tailscale whitelist,
Direct IP on, listener on all interfaces, allow-only-conn-window-open available and off, sync / NAT
test / updater / LAN discovery unreachable (ADR 0004: only the version file, its .sig and fulfillment /update), no RustDesk public server named in shipped code,
no GitHub Actions workflow, no hwcodec/vram in any build invocation, Mac build with
file copy-paste, the Windows MSI (name, exe, art sizes, license, icon, no RustDesk text), no RustDesk name, link or logo a person sees on Mac or Windows (strings,
translations, app metadata, every logo slot; one AGPL line on the About page), that
the connect box sends a Machine ID through the Hosted servers and any other name Direct IP
to a tailnet address, that the Target shows its Machine ID, that a saved Machine ID tries its
tailnet address first and then the Hosted servers (ticket 08), and that the protocol files are
upstream's. It only reads the tree.
Idempotence is proved by test_rebrand.py and build-mac's second-run step.

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
# ADR 0005, pinned here (not taken from rebrand.py): the one rendezvous/relay host the app
# knows, and the key file the build bakes. RustDesk's public servers' key never ships.
HOSTED = "rs.theboringremote.com"
SERVER_KEY = pathlib.Path(__file__).resolve().parent / "server-key.pub"
RUSTDESK_KEY = "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw="
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


# After the IP branch: anything but a Machine ID returns Direct IP to a tailnet address.
TAILNET_GUARD = ("        if !boring_is_machine_id(peer) {\n            return Ok((\n                (\n"
                 "                    connect_tcp_local(boring_tailnet_addr(peer).await?, None, CONNECT_TIMEOUT)\n")
# A Machine ID is digits only: never an address, a tailnet name or id@server (another server).
MACHINE_ID_TEST = "!peer.is_empty() && peer.len() <= 20 && peer.bytes().all(|b| b.is_ascii_digit())"
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
    """The connect box: a Machine ID goes through the Hosted servers; any other name connects
    Direct IP to a tailnet address and never reaches the rendezvous path (ADR 0005)."""
    client = c.read("src/client.rs")
    body = fn_body(client, "    async fn _start(\n") or ""
    guard = body.find(TAILNET_GUARD)
    pre = strip_tests_and_comments(body[:guard]) if guard >= 0 else ""
    block = body[guard:body.find("\n        }\n", guard)] if guard >= 0 else ""
    tops = [l.strip() for l in pre.splitlines() if l.startswith("        ") and not l.startswith("         ")]
    why = []
    if guard < 0:
        why.append("no tailnet return for everything but a Machine ID after the IP branch")
    if ROUTE_AROUND.search(pre):
        why.append(f"_start touches the ID path first: {ROUTE_AROUND.findall(pre)}")
    if "if hbb_common::is_ip_str(peer) {" not in pre or any(not t.startswith(("if ", "}")) for t in tops):
        why.append(f"only the incoming-only and IP branches may come first: {tops}")
    if guard >= 0 and ("return Ok((" not in block or "else" in block):
        why.append("the tailnet block does not always return")
    is_id = re.sub(r"\s+", " ", fn_body(client, "pub(crate) fn boring_is_machine_id(peer: &str) -> bool {") or "").strip()
    if is_id != MACHINE_ID_TEST:
        why.append(f"a Machine ID isn't digits only: {is_id!r}")
    calls = [m.start() for m in re.finditer(r"Self::_start_inner\(", client)]
    start = client.find("    async fn _start(\n")
    if not calls or any(not (start < i < start + len(body) + 200) for i in calls) or \
            len(re.findall(r"::_start\(", client)) != 1:
        why.append("_start / _start_inner are called from somewhere else")
    c.fact("connect box: only a Machine ID reaches the rendezvous path; names connect Direct IP", not why,
           "; ".join(why))

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
           and builtin is not None and builtin.group(1) == "Default::default()",
           f"label {'Machine ID' if rebrand.MACHINE_ID_LABEL in board else 'missing'}, get_id {get_id[:60]!r}")

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
    "UPDATE_ENDPOINT": ("src/license_key.rs", "https://boring-store-fulfillment.restless-term-7ead.workers.dev/update"),
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
# The one way decide() lets a login in unasked: right password, and the ID listed with the key it proved.
# The trust gate's key, written out here (not taken from rebrand.py): proven against this connection.
# Its own Machine ID counts only on a connection keyed to the Target's signed identity (ticket 07).
GATE_KEY = ("crate::trust_policy::login_key(\n                            &lr,\n"
            "                            &self.hash.challenge,\n                            self.stream.local_addr().ip(),\n"
            "                            &self.ip,\n                            &Config::get_id(),\n"
            "                            self.stream.is_secured(),\n                        )")
# Ticket 07, the Controller side: what a connection records and what the login signs with it.
VERIFIED_AT_START = ("interface.get_lch().write().unwrap().boring_verified_target =\n"
                     "                    crate::trust_policy::verified_target(peer, key, x.0 .2.as_deref(), x.0 .0.is_secured());")
VERIFIED_CLEARED = "interface.get_lch().write().unwrap().boring_verified_target = None;"
SIGN_CALL = "crate::trust_policy::sign_login(&mut lr, &self.hash.challenge, self.boring_verified_target.as_deref());"
# accepted() remembers only a new ID: a trusted one showing another key keeps the stored key.
REMEMBER_IF = "if password == Password::Right && remember && !trusted.has_id(controller) {"
TRUSTED_IF = "if password == Password::Right && key.map_or(false, |k| trusted.contains(controller, k)) {"


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
    gate = conn.find("if crate::trust_policy::on_login(\n                        self.inner.id(),\n"
                     "                        &lr.my_id,\n                        crate::trust_policy::Password::Right,", check)
    reset = conn.find("self.update_failure_with_scope(failure, true, 0, FailureScope::Default);", check)
    logon = conn.find("if !self." + LOGON + " {", check)
    ok = 0 <= check < gate < reset < logon and "LOGIN_MSG_PASSWORD_WRONG" in conn[check:gate]
    return conn[gate:reset] if ok else ""


def password_lock_checks(c, locked):
    """Ticket 05: permanent password only, refused without one, throttled, fixed during a session."""
    c.fact("one-time password off: only the permanent password is accepted",
           locked.get("verification-method") == "use-permanent-password", locked.get("verification-method"))
    c.fact("one-time password length pinned", locked.get("temporary-password-length") == "10",
           locked.get("temporary-password-length"))
    # The option only hides settings in the UI (common.dart canBeBlocked ignores it in full access
    # mode, and the home page's Set Password doesn't check it); the daemon's session guard holds them.
    c.fact("allow-remote-config-modification locked off (a UI hint; the session guard holds the settings)",
           locked.get("allow-remote-config-modification") == "N", locked.get("allow-remote-config-modification"))

    conn = c.read("src/server/connection.rs")
    lock = strip_tests_and_comments(c.read("src/password_lock.rs"))
    trust = strip_tests_and_comments(c.read("src/trust_policy.rs"))
    gate, click, unset = no_password_gate(conn)
    refuse = fn_body(lock, "pub fn refuse_login(verification_method: &str) -> bool {")
    live = "if crate::password_lock::refuse_login(&Config::get_option(keys::OPTION_VERIFICATION_METHOD)) {"
    c.fact("no permanent password: no unattended access, only a click on the Target (not remembered)",
           0 <= gate < click and conn[gate:].startswith(live) and "return false;" in conn[gate:click]
           and unset is not None
           and re.search(r"crate::trust_policy::on_login\(\s*self\.inner\.id\(\),\s*&lr\.my_id,\s*"
                         r"crate::trust_policy::Password::NotSet,\s*None,\s*\);", unset.group(1)) is not None
           and refuse is not None and refuse.strip() == "verification_method != PERMANENT_ONLY"
           and TRUSTED_IF in trust
           and REMEMBER_IF in trust,
           f"gate at {gate}, click branch at {click}, no-password click path {unset is not None}, "
           f"refuse_login {refuse!r}")

    throttle = fn_body(conn, "async fn check_failure_with_scope(") or ""
    ok = (THROTTLED_LOGIN.search(conn) is not None and conn.count("self.validate_password(") == 1
          and '"Too many wrong attempts"' in throttle and '"Please try 1 minute later"' in throttle
          and "let res = if failure.2 > 30 {" in throttle and "} else if time == failure.0 && failure.1 > 6 {" in throttle
          and "self.check_failure_with_scope(i, FailureScope::Default)"
          in (fn_body(conn, "async fn check_failure(&mut self, i: usize)") or ""))
    c.fact("wrong passwords are still throttled before and after every password check", ok)

    ipc = c.read("src/ipc.rs")
    arms = [re.search(rf'name == "{k}" \{{\s*if {re.escape(rebrand.IPC_GUARD)} \{{\s*log::warn!\(', ipc)
            for k in ("permanent-password", "salt", "unlock-pin")]
    options = re.search(r"let mut value = crate::password_lock::guard_options\(\s*value,\s*&Config::get_options\(\),"
                        r"\s*crate::password_lock::authed_sessions\(\),\s*\);", ipc)
    guard = fn_body(lock, "pub fn config_write_allowed(name: &str, remote_sessions: usize) -> bool {") or ""
    sessions = (fn_body(lock, "pub fn authed_sessions() -> usize {") or "").strip()
    key = re.search(r'pub const TRUSTED_OPTION: &str = "([^"]+)";', trust)
    guarded = str_array(c, lock, "SECURITY_OPTIONS", {"TRUSTED_OPTION": key and key.group(1)})
    protected = str_array(c, lock, "PROTECTED_CONFIG")
    need = ("approve-mode", "verification-method", "allow-remote-config-modification", "access-mode", "whitelist")
    c.fact("a remote session can't change the password, PIN or security options",
           all(arms) and ipc.count(rebrand.IPC_GUARD) == 3 and options is not None and "remote_sessions == 0" in guard
           and sessions == "crate::server::AUTHED_CONNS.lock().unwrap().len()"
           and set(protected) == {"permanent-password", "salt", "unlock-pin"}
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
    missing = [f"{p.name}: {k}" for p in langs for k in rebrand.UI_KEYS + [rebrand.MACHINE_ID_LABEL]
               if p.read_text(encoding="utf-8").count(f'("{k}", ') != 1]
    c.fact("new UI strings (tickets 05, 06, 07) have a key in every translation file", langs and not missing,
           ", ".join(missing[:5]))


def logon_sites(conn, locked):
    """Every way into a session: (count, [unexplained sites])."""
    sites = [m.start() for m in re.finditer(r"if !(?:self|conn)\." + re.escape(LOGON), conn)]
    why = {
        "Accept, after the trust gate's on_accept":
            lambda before: before[-1500:].rfind("if !crate::trust_policy::on_accept(conn.inner.id()) {")
            > before[-1500:].rfind("ipc::Data::Authorize => {") >= 0,
        "recent session: only a one-time password login records one, and that is locked off":
            lambda before: before.endswith("} else if self.is_recent_session(false) {\n                ")
            and locked.get("verification-method") == "use-permanent-password",
        "right password, after the trust gate":
            lambda before: before.rstrip().endswith("self.update_failure_with_scope(failure, true, 0, FailureScope::Default);")
            and before[-2500:].rfind("if crate::trust_policy::on_login(") > before[-2500:].rfind("if !self.validate_password(") >= 0,
        "2FA, only after a gated logon asked for it":
            lambda before: before[-1500:].rfind("if !self.awaiting_2fa {") > before[-1500:].rfind("message::Union::Auth2fa(tfa)") >= 0
            and conn.count("self.awaiting_2fa = true;") == 1
            and "self.awaiting_2fa = true;" in (fn_body(conn, "async fn send_logon_response_and_keep_alive(&mut self) -> bool {") or ""),
        "switch sides this computer asked for (uuid match)":
            lambda before: "if uuid == uuid_old {" in before[-1500:],
    }
    unexplained = [s for s in sites if sum(bool(ok(conn[:s])) for ok in why.values()) != 1]
    return len(sites), unexplained


def proof_checks(c, conn, trust, wait):
    """Trust binding (option B): the Controller signs each login with its own key pair; the Target
    trusts the ID only with the key stored for it and a valid signature over this very login."""
    squash = lambda s: re.sub(r"\s+", " ", s or "").strip()
    contains = squash(fn_body(trust, "pub fn contains(&self, id: &str, key: &Key) -> bool {"))
    entry = squash(fn_body(trust, "fn entry(s: &str) -> Option<(&str, Key)> {"))
    parse = squash(fn_body(trust, "pub fn parse(option: &str) -> Self {"))
    proven = squash(fn_body(trust, "pub fn proven_key("))
    names = squash(fn_body(trust, "pub fn target_name(arrived_on: IpAddr, from: &str) -> Option<String> {"))
    tailnet = squash(fn_body(trust, "fn is_tailnet(ip: IpAddr) -> bool {"))
    login_key = squash(fn_body(trust, "pub fn login_key("))
    all_names = squash(fn_body(trust, "pub fn target_names(arrived_on: IpAddr, from: &str, own_id: &str, secured: bool) -> Vec<String> {"))
    why = []
    if "pub struct Trusted(Vec<(String, Key)>);" not in trust:
        why.append("the list isn't ID + key")
    if contains != "storable(id) && self.0.iter().any(|(t, k)| t == id && k == key)":
        why.append(f"contains is {contains!r}")
    if entry != "let (id, key) = s.trim().split_once(':')?; Some((id, unhex(key)?))" or "filter_map(entry)" not in parse:
        why.append("parse keeps entries without a key")
    if proven != ("let key: Key = pk.try_into().ok()?; let want = login_message(challenge, target, controller)?; "
                  "let signed = sign::verify(sig, &sign::PublicKey(key)).ok()?; (signed == want).then_some(key)"):
        why.append("proven_key doesn't verify the signature over this login")
    if names != ("let from = ip_in(from)?; if !(is_tailnet(arrived_on) && is_tailnet(from)) { return None; } "
                 "Some(canonical(arrived_on).to_string())"):
        why.append("target_name isn't the tailnet address a tailnet peer arrived on (relay/LAN addresses relay)")
    if tailnet != "crate::client::boring_is_tailnet(SocketAddr::new(ip, 0))":
        why.append(f"is_tailnet is {tailnet!r}")
    if login_key != ("target_names(arrived_on, from, own_id, secured) .iter() .find_map(|target| "
                     "proven_key(&lr.my_id, &lr.boring_controller_pk, &lr.boring_login_sig, challenge, target))"):
        why.append(f"login_key is {login_key[:80]!r}")
    if all_names != ("let mut names: Vec<String> = target_name(arrived_on, from).into_iter().collect(); "
                     "if secured && crate::client::boring_is_machine_id(own_id) { names.push(own_id.to_owned()); } names"):
        why.append("the Target's Machine ID counts as its name on a connection not keyed to its signed identity")
    if f"crate::trust_policy::Password::Right,\n                        {GATE_KEY},\n" not in wait:
        why.append("the trust gate doesn't pass the key proven against this connection")
    c.fact("a trusted login needs the stored key's signature over this login; a known ID alone never skips the click",
           not why, "; ".join(why))

    client = c.read("src/client.rs")
    built = fn_body(client, "    fn create_login_msg(") or ""
    hash_fn = fn_body(client, "pub async fn handle_hash(") or ""
    signing = squash(fn_body(trust, "pub fn sign_login(lr: &mut LoginRequest, challenge: &str, verified: Option<&str>) {"))
    message = fn_body(trust, "pub fn login_message(challenge: &str, target: &str, controller: &str) -> Option<Vec<u8>> {") or ""
    resolver = fn_body(client, "async fn boring_tailnet_addr(peer: &str) -> ResultType<SocketAddr> {") or ""
    lib = c.read("src/lib.rs")
    why = []
    sign_at, sent_at = built.find(rebrand.SIGN_LOGIN), built.find("msg_out.set_login_request(lr);")
    if not 0 <= sign_at < sent_at:
        why.append("create_login_msg doesn't sign before sending")
    if rebrand.HASH_FIRST_NEW.split("    true\n")[0] not in hash_fn:
        why.append("handle_hash sends the login before it stores the challenge")
    dialed = squash(fn_body(trust, "pub fn dialed_target(peer: &str) -> Option<String> {"))
    if dialed != ("let ip = match ip_in(peer) { Some(ip) => ip, None => DIALED.lock().unwrap().iter()"
                  ".find(|(p, _)| p == peer)?.1, }; is_tailnet(ip).then(|| ip.to_string())"):
        why.append("the Controller signs a target other than a tailnet address it connected to")
    want = ('let Some(target) = signed_target(&lr.username, verified) else { return; }; '
            'if login_message(challenge, &target, &lr.my_id).is_none() { return; } '
            '#[cfg(any(target_os = "android", target_os = "ios"))] let pair = Some(Config::get_key_pair()); '
            '#[cfg(not(any(target_os = "android", target_os = "ios")))] let pair = Config::get_existing_key_pair(); '
            'let Some((sk, pk)) = pair else { return; }; '
            'if let Some(sig) = signature(challenge, &target, &lr.my_id, &sk) { lr.boring_controller_pk = pk.into(); '
            'lr.boring_login_sig = sig.into(); }')
    if signing != want:
        why.append("sign_login isn't the service's key pair over (challenge, dialed Target, own ID)")
    if SIGN_CALL not in built:
        why.append("the login isn't signed with this connection's verified Machine ID")
    if not re.search(r'const LOGIN_DOMAIN: &\[u8\] = b"\\0[^"]*";', trust):
        why.append("the signed login has no zero-led domain (could read as a SignedId)")
    if not re.search(r"let challenge_ok = !challenge\.is_empty\(\)\s*&& challenge\.len\(\) <= 64\s*"
                     r"&& challenge\.bytes\(\)\.all\(\|b\| b\.is_ascii_alphanumeric\(\)\);\s*if !challenge_ok \{\s*return None;",
                     message):
        why.append("the Controller would sign any challenge a Target sends")
    if "crate::trust_policy::note_dialed(peer, addr.ip());" not in resolver:
        why.append("a tailnet name's login isn't bound to the address it resolved to")
    if not re.search(r"(?<!Target side only\n)mod trust_policy;", lib):
        why.append("trust_policy is left out of iOS Controllers")
    c.fact("Controllers sign each login with their own key (this challenge, the Target they dialed, their ID)",
           not why, "; ".join(why))
    hosted_signing_checks(c, client, trust, squash)


def hosted_signing_checks(c, client, trust, squash):
    """Ticket 07: a Machine-ID login is signed only on a session that verified the Target against
    the baked server key: the servers' word on its key checked out under that key, and the
    Target signed this session's key exchange (upstream's plaintext fallback never counts)."""
    why = []
    verified = squash(fn_body(trust, "pub fn verified_target(peer: &str, key: &str, target_pk: Option<&[u8]>, secured: bool) -> Option<String> {"))
    if verified != ("let baked = key.is_empty() || key == hbb_common::config::RS_PUB_KEY; "
                    "(crate::client::boring_is_machine_id(peer) && baked && target_pk.is_some() && secured) "
                    ".then(|| peer.to_owned())"):
        why.append(f"verified_target is {verified[:90]!r}")
    signed = squash(fn_body(trust, "pub fn signed_target(peer: &str, verified: Option<&str>) -> Option<String> {"))
    # Or (ticket 08) the tailnet address this connection reached Direct IP: tailnet_first_checks.
    if signed != ("dialed_target(peer) .or_else(|| verified.filter(|v| *v == peer).map(str::to_owned)) "
                  ".or_else(|| verified.and_then(ip_in).filter(|ip| is_tailnet(*ip)).map(|ip| ip.to_string()))"):
        why.append(f"signed_target is {signed[:90]!r}")
    code = strip_tests_and_comments(client)
    start = fn_body(code, "    pub async fn start(\n") or ""
    clear, run, record = start.find(VERIFIED_CLEARED), start.find("Self::_start("), start.find(VERIFIED_AT_START)
    if not (0 <= clear < run < record and start[run:record].count("Ok(x) => {") == 1):
        why.append("Client::start doesn't clear, then record, the verified Machine ID on each connection")
    # Ticket 08 adds one write (start: the tailnet address) and two reads (that, and handle_peer_info).
    if code.count("boring_verified_target =") != 3 or code.count(".boring_verified_target") != 5:
        why.append("the verified Machine ID is written or read somewhere else")
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
    c.fact("Controllers sign a Machine-ID login only on a session that verified the Target against the baked server key",
           not why, "; ".join(why))


# Ticket 08, pinned here (not taken from rebrand.py).
TAILNET_FIRST = (
    "        if let Some((stream, addr)) = boring_tailnet_first(peer, interface.is_force_relay()).await {\n"
    "            interface.get_lch().write().unwrap().boring_tailnet_target = Some(addr);\n"
    "            return Ok(((stream, true, None, None, \"TCP\"), (0, \"\".to_owned()), false));\n"
    "        }\n")
TAILNET_DIAL = ("let options = PeerConfig::load(peer).options; "
                "let record = PeerRecord { id: peer, tailnet: options.get(TAILNET_OPTION).map(String::as_str) }; "
                "let reach = Reach { tailnet_up: crate::connect_plan::own_tailnet_addr().is_some(), relay_only }; "
                "for attempt in plan(&record, reach) { let Attempt::Tailnet(addr) = attempt else { break }; "
                "match connect_tcp_local(check_port(&addr, RELAY_PORT + 1), None, TAILNET_TIMEOUT_MS).await {")
TAILNET_PLAN = ("if !crate::client::boring_is_machine_id(peer.id) { return vec![Attempt::DirectIp(peer.id.to_owned())]; } "
                "let mut attempts = Vec::new(); "
                "let saved = peer.tailnet.and_then(|a| a.parse::<IpAddr>().ok()).filter(|ip| is_tailnet(*ip)); "
                "if let Some(ip) = saved { if reach.tailnet_up && !reach.relay_only { "
                "attempts.push(Attempt::Tailnet(ip.to_string())); } } "
                "attempts.push(Attempt::Hosted(peer.id.to_owned())); attempts")
TAILNET_CLEARED = "interface.get_lch().write().unwrap().boring_tailnet_target = None;"
TAILNET_TAKEN = ("let tailnet = interface.get_lch().write().unwrap().boring_tailnet_target.take();\n"
                 "                if tailnet.is_some() {\n"
                 "                    interface.get_lch().write().unwrap().boring_verified_target = tailnet;\n")
REMEMBERED = ("crate::connect_plan::remember_tailnet(\n            &mut config.options,\n            &self.id,\n"
              "            self.boring_verified_target.as_deref(),\n            &pi.platform_additions,\n        );")
TAILNET_REMEMBER_IF = "if verified != Some(id) || !crate::client::boring_is_machine_id(id) {"
HOSTED_DOWN = ("Can't reach the Boring Remote servers (rs.theboringremote.com). Check this computer's internet"
               " connection, or connect by Tailscale name or IP.")
HOSTED_DOWN_MAP = ("let mut socket = socket.map_err(|err| {\n"
                   '            log::warn!("Hosted servers unreachable: {err}");\n'
                   "            anyhow!(crate::connect_plan::HOSTED_DOWN)\n        })?;")
PATH_LABEL = "let stream_type = crate::connect_plan::stream_label(stream_type, direct, peer.local_addr().ip());"
INSECURE_SKIP = ("                    && !crate::common::is_direct_ip_access(&self.handler.get_id())\n"
                 "                    && stream_type != crate::connect_plan::TAILNET_STREAM")


def tailnet_first_checks(c):
    """Ticket 08 (spec slice 3): a saved Machine ID tries its tailnet address first (~3 s), then the
    Hosted servers; the login signs that address only on the connection that reached it; the
    address is learned only from a verified Target; a plain error when the Hosted servers are down;
    the session shows tailnet direct / direct / relayed."""
    squash = lambda s: re.sub(r"\s+", " ", s or "").strip()
    client, plan_rs = c.read("src/client.rs"), c.read("src/connect_plan.rs")
    code = strip_tests_and_comments(client)
    plan_code = strip_tests_and_comments(plan_rs)
    body = fn_body(client, "    async fn _start(\n") or ""
    guard = body.find(TAILNET_GUARD)
    first, rendezvous = body.find(TAILNET_FIRST), body.find("let other_server = interface.get_lch()")
    why = []
    if "mod connect_plan;" not in c.read("src/lib.rs"):
        why.append("no connect_plan module")
    if not (0 <= guard < first < rendezvous):
        why.append("_start doesn't try the tailnet address after the typed-name branch and before the Hosted servers")
    elif strip_tests_and_comments(body[guard:rendezvous]).count("return Ok((") != 2:
        why.append("something else returns between the tailnet attempt and the Hosted servers")
    dial = squash(fn_body(code, "async fn boring_tailnet_first(peer: &str, relay_only: bool) -> Option<(Stream, String)> {"))
    if TAILNET_DIAL not in dial or "Ok(stream) => return Some((stream, addr))," not in dial:
        why.append(f"boring_tailnet_first isn't Direct IP to the plan's tailnet address only: {dial[:80]!r}")
    if squash(fn_body(plan_code, "pub fn plan(peer: &PeerRecord, reach: Reach) -> Vec<Attempt> {")) != TAILNET_PLAN:
        why.append("plan isn't: typed names Direct IP only; a Machine ID's saved tailnet address, then the Hosted servers")
    if "pub const TAILNET_TIMEOUT_MS: u64 = 3_000;" not in plan_code:
        why.append("the tailnet attempt isn't ~3 s")
    c.fact("a saved Machine ID tries its tailnet address first (~3 s), then the Hosted servers (ticket 08)",
           not why, "; ".join(why))

    why = []
    start = fn_body(code, "    pub async fn start(\n") or ""
    clear, run, record = start.find(TAILNET_CLEARED), start.find("Self::_start("), start.find(VERIFIED_AT_START)
    taken = start.find(TAILNET_TAKEN)
    if not (0 <= clear < run < record < taken):
        why.append("Client::start doesn't clear the tailnet address, then move it into the login after 07's record")
    if code.count("boring_tailnet_target =") != 2 or code.count(".boring_tailnet_target") != 3:
        why.append("the tailnet address is written or read somewhere else")
    c.fact("a tailnet-first login signs only the address its own connection reached (ticket 08)",
           not why, "; ".join(why))

    remember = squash(fn_body(plan_code, "pub fn remember_tailnet("))
    peer_info = fn_body(code, "    pub fn handle_peer_info(&mut self, pi: &PeerInfo) {") or ""
    conn = c.read("src/server/connection.rs")
    reported = conn.find("crate::connect_plan::add_own_tailnet(&mut platform_additions);")
    c.fact("a saved Machine ID records a tailnet address only from its verified Target (ticket 08)",
           0 <= peer_info.find(REMEMBERED) < peer_info.find("self.save_config(config);")
           and f"{squash(TAILNET_REMEMBER_IF)} return; }}" in remember
           and plan_code.count("TAILNET_OPTION.to_owned()") == 1 and code.count("TAILNET_OPTION") == 2
           and 0 <= reported < conn.find("pi.platform_additions = serde_json::to_string(&platform_additions)"),
           remember[:80])

    inner = fn_body(code, "    async fn _start_inner(\n") or ""
    langs = sorted((c.root / rebrand.LANG_DIR).glob("*.rs"))
    missing = [p.name for p in langs for k in (HOSTED_DOWN, rebrand.TAILNET_LABEL)
               if p.read_text(encoding="utf-8").count(f'("{k}", ') != 1]
    c.fact(f"Hosted servers unreachable: a plain error naming {HOSTED} (ticket 08)",
           HOSTED_DOWN_MAP in inner and "socket?;" not in inner and HOSTED in HOSTED_DOWN
           and f'pub const HOSTED_DOWN: &str = "{HOSTED_DOWN}";' in plan_code and rebrand.HOSTED_DOWN == HOSTED_DOWN
           and bool(langs) and not missing, ", ".join(missing[:5]))

    io_loop = c.read("src/client/io_loop.rs")
    label = squash(fn_body(plan_code, "pub fn stream_label(stream_type: &'static str, direct: bool, local: IpAddr) -> &'static str {"))
    dart = fn_body(c.read(rebrand.DART_COMMON), "String getConnectionText(bool secure, bool direct, String streamType) {") or ""
    c.fact("the session shows tailnet direct, direct or relayed (ticket 08)",
           0 <= io_loop.find(PATH_LABEL) < io_loop.find(".set_connection_type(is_secured, direct, stream_type);")
           and label == "if direct && is_tailnet(local) { TAILNET_STREAM } else { stream_type }"
           and 'pub const TAILNET_STREAM: &str = "Tailnet";' in plan_code
           and INSECURE_SKIP in io_loop and io_loop.count("connect_plan::TAILNET_STREAM") == 1
           and dart.lstrip("\n ").split("\n")[1:3] == ["  if (streamType == 'Tailnet') {",
                                                     f"    return translate('{rebrand.TAILNET_LABEL}');"],
           label[:60])


def trust_checks(c, locked):
    """Ticket 06: a Controller needs the password and a click unless it proves, by signing this
    login with its own key, that it is a trusted one. The ID it reports is never enough alone."""
    c.fact("unknown Controllers need the password and a click on the Target (approve mode locked, prompt can't hide)",
           locked.get("approve-mode") == "" and "approve-mode" in locked and locked.get("allow-hide-cm") == "N",
           f"approve-mode {locked.get('approve-mode')!r}, allow-hide-cm {locked.get('allow-hide-cm')!r}")

    conn = c.read("src/server/connection.rs")
    trust = strip_tests_and_comments(c.read("src/trust_policy.rs"))
    decide = fn_body(trust, "pub fn decide(") or ""
    wait = trust_gate(conn)
    c.fact("a right password waits for a click on the Target unless the Controller proves a trusted key",
           "!= crate::trust_policy::Decision::Allow" in wait and re.search(CLICK_WAIT, wait) is not None
           and "mod trust_policy;" in c.read("src/lib.rs")
           and re.match(r"\s*" + re.escape(TRUSTED_IF) + r"\s*return Decision::Allow;\s*\}", decide)
           and "AtTarget::NotAsked => Decision::Ask," in decide and decide.count("Decision::Allow") == 2,
           f"trust gate {'found' if wait else 'missing or out of place'}")

    _, _, unset = no_password_gate(conn)
    authorize = conn.find("ipc::Data::Authorize => {")
    arm = conn[authorize:conn.find("ipc::Data::Close =>", authorize)] if authorize >= 0 else ""
    c.fact("every Accept prompt counts against the IP's failure budget; an approval clears it",
           unset is not None and re.match(r"\s*(?://[^\n]*\s*)*let \(failure, res\) = self\.check_failure\(0\)\.await;\s*"
                                          r"if !res \{\s*return true;\s*\}\s*" + BUMP, unset.group(1)) is not None
           and re.search(r"!= crate::trust_policy::Decision::Allow\s*\{\s*" + BUMP, wait) is not None
           and re.search(r"if !crate::trust_policy::on_accept\(conn\.inner\.id\(\)\) \{.*?\}\s*"
                         r"clear_failures\(&mut LOGIN_FAILURES\[0\]\.lock\(\)\.unwrap\(\), &conn\.failure_keys\(\)\);",
                         arm, re.S) is not None)

    accept = fn_body(trust, "pub fn on_accept(conn_id: i32) -> bool {") or ""
    take = re.sub(r"\s+", " ", fn_body(trust, "fn take(conn_id: i32) -> Option<Waiting> {") or "")
    loop = re.search(r"_ = login_deadline\(conn\.authorized, started\) => \{\s*conn\.on_close\(\"Timeout\", true\)\.await;"
                     r"\s*break;", conn)
    stray = re.search(r"if !crate::trust_policy::on_accept\(conn\.inner\.id\(\)\) \{\s*if conn\.authorized \{\s*continue;\s*\}"
                      r"\s*conn\.send_close_reason_no_retry\(\"\"\)\.await;\s*conn\.on_close\([^)]*\)\.await;\s*break;\s*\}", arm)
    c.fact("the Target's Accept only counts for a login waiting on it; a stray one ends the connection",
           stray is not None and arm.find("if !crate::trust_policy::on_accept(") < arm.find(LOGON)
           and conn.count("ipc::Data::Authorize") == 1
           and re.match(r"\s*let Some\(w\) = take\(conn_id\) else \{.{0,200}?return false;\s*\};", accept, re.S) is not None
           and "let i = pending.iter().position(|w| w.conn_id == conn_id)?;" in take
           and "PENDING.lock().unwrap().push(" in (fn_body(trust, "pub fn on_login(") or "")
           and "self.closed = true;\n        crate::trust_policy::forget(self.inner.id());" in conn
           and loop is not None,
           f"Authorize arm at {authorize}, stray Accept closes {stray is not None}, login timeout {'kept' if loop else 'gone'}")

    login = conn.find("if let Some(message::Union::LoginRequest(lr)) = msg.union {")
    swap = re.match(r"\s*(?://[^\n]*\s*)*if crate::trust_policy::forget\(self\.inner\.id\(\)\) \{\s*"
                    r"self\.send_login_error\([^)]*\)\.await;\s*return false;\s*\}\s*if !self\.check_login_scope",
                    conn[login + 70:]) if login >= 0 else None
    c.fact("a new login on a connection waiting on Accept ends it (the click can't land on another login)",
           swap is not None and "take(conn_id).is_some()" in (fn_body(trust, "pub fn forget(conn_id: i32) -> bool {") or ""))

    empty = re.search(r"\} else if lr\.password\.is_empty\(\) \{(.*?)\} else \{", conn, re.S)
    wrong = conn[conn.find("if !self.validate_password("):conn.find("if crate::trust_policy::on_login(\n                        self.inner.id(),\n                        &lr.my_id,\n                        crate::trust_policy::Password::Right")]
    c.fact("no Accept prompt for a login without the right password (empty or wrong)",
           empty is not None and "try_start_cm" not in empty.group(1) and "LOGIN_MSG_PASSWORD_WRONG" in wrong
           and "try_start_cm" not in wrong)

    count, unexplained = logon_sites(conn, locked)
    c.fact("exactly five ways into a session, each gated or explained", count == 5 and not unexplained,
           f"{count} logon calls, unexplained at {unexplained}")

    lock = strip_tests_and_comments(c.read("src/password_lock.rs"))
    key = re.search(r'pub const TRUSTED_OPTION: &str = "([^"]+)";', trust)
    remove_key = re.search(r'pub const REMOVE_OPTION: &str = "([^"]+)";', trust)
    guarded = str_array(c, lock, "SECURITY_OPTIONS", {"TRUSTED_OPTION": key and key.group(1)})
    ipc = c.read("src/ipc.rs")
    hook = re.search(r"let removed = crate::trust_policy::take_options\(&mut value, &Config::get_options\(\)\);\s*"
                     r"Config::set_options\(value\);\s*crate::trust_policy::close_removed\(&removed\);", ipc)
    c.fact("trusted Controllers live in the daemon's config; only an Accept with no other session open adds one",
           key is not None and key.group(1) in guarded and hook is not None
           and re.search(r"(?<!Local)Config::set_option\(TRUSTED_OPTION", trust) is not None
           and re.search(r"(?<!Local)Config::get_option\(TRUSTED_OPTION", trust) is not None
           and trust.count("Config::set_option(") == 1
           and "Config::set_option(TRUSTED_OPTION" in (fn_body(trust, "fn save(trusted: &Trusted) {") or "")
           and len(re.findall(r"\bsave\(&", trust)) == 2 and "save(&next);" in accept
           and re.search(r"if trusted\.to_option\(\) != stored \{[^}]*save\(&trusted\);\s*\}",
                         fn_body(trust, "fn load() -> Trusted {") or "") is not None
           and "let remember = crate::password_lock::authed_sessions() == 0;" in accept
           and REMEMBER_IF in trust
           and "LocalConfig" not in trust and "mod trust_policy;" in c.read("src/lib.rs"),
           f"key {key.group(1) if key else None}, options hook {hook is not None}")

    takes = fn_body(trust, "pub fn take_options(") or ""
    arm_close = re.search(r"Some\(data\) = rx_from_authed\.recv\(\) => \{\s*match data \{.*?"
                          r"ipc::Data::Close => \{\s*conn\.send_close_reason_no_retry\(\"\"\)\.await;"
                          r"\s*conn\.on_close\([^)]*\)\.await;\s*break;\s*\}", conn, re.S)
    widget = c.read("flutter/lib/desktop/widgets/trusted_controllers.dart")
    dart_remove = re.search(r"const kBoringTrustedControllersRemove = '([^']+)';", widget)
    c.fact("removing a trusted Controller works during a session and ends its sessions",
           hook is not None and arm_close is not None and rebrand.CLOSE_CONTROLLER in conn
           and "incoming.remove(REMOVE_OPTION)" in takes and "list.remove(id);" in takes
           and "crate::server::close_controller(id);" in (fn_body(trust, "pub fn close_removed(") or "")
           and remove_key is not None and dart_remove is not None and dart_remove.group(1) == remove_key.group(1)
           and "bind.mainSetOption(key: kBoringTrustedControllersRemove, value: ids)" in widget,
           f"options hook {hook is not None}, close arm {arm_close is not None}")

    proof_checks(c, conn, trust, wait)

    on_login = fn_body(trust, "pub fn on_login(") or ""
    c.fact("a Controller-supplied ID is logged throttled and only if storable",
           "hbb_common::throttled_log!(" in on_login and "if storable(controller) { controller }" in on_login
           and not re.search(r"\blog::\w+!", on_login))

    settings = c.read(rebrand.SETTINGS)
    unlock = settings.find("_lock(locked, 'Unlock Security Settings'")
    card = settings.find(rebrand.TRUST_CARD)
    dart_key = re.search(r"const kBoringTrustedControllers = '([^']+)';", widget)
    c.fact("Settings lists trusted Controllers with Remove, behind the security unlock",
           0 <= unlock < settings.find("preventMouseKeyBuilder(", unlock) < card
           and "import 'package:flutter_hbb/desktop/widgets/trusted_controllers.dart';" in settings
           and key is not None and dart_key is not None and dart_key.group(1) == key.group(1)
           and "translate('Remove')" in widget,
           f"unlock at {unlock}, card at {card}, widget key {dart_key.group(1) if dart_key else None}")


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
    maps = {name: rust_map(cfg, name) for name in ("OVERWRITE_SETTINGS", "DEFAULT_SETTINGS")}
    left = [f"{name} {k}" for name, m in maps.items() for k, v in m.items()
            if k == "whitelist" or tailnet & set(v.split(","))]
    c.fact("no Tailscale whitelist left (ADR 0005)", not left, ", ".join(left))


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
    trust_checks(c, locked)

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
        (rebrand.HOME, "setKey: (k) => bind.mainSetLicenseKey(key: k),"),  # ticket 15
        ("src/platform/privileges_scripts/install-update.sh", f'SERVICE_LABEL="{rebrand.HOSTD_ID}"'),        ("src/lib.rs", "mod activate_link;"),
        ("src/flutter_ffi.rs", "pub fn main_activate_link("),
        ("flutter/lib/common.dart", "bind.mainActivateLink(url: url)"),
    ]
    missing = [f"{rel}: {needle}" for rel, needle in hooks if needle not in c.read(rel)]
    c.fact("update hooks landed in upstream files (ADR 0004)", not missing, "; ".join(missing))
    activate_link_checks(c)

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
    tailnet_first_checks(c)

    # protocol: every .proto in the tree is upstream's, byte for byte, except our two LoginRequest fields
    c.fact("protocol files are upstream's plus our two LoginRequest fields (boring/protocol.sha256)",
           *protocol_matches(c.root))

    print(f"rebrand check: {c.passed} passed, {c.failed} failed")
    return 1 if c.failed else 0


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = args[0] if args else pathlib.Path(__file__).resolve().parent.parent
    sys.exit(run_checks(root))
