#!/usr/bin/env python3
"""Turn a clean RustDesk checkout into the Boring Remote Desk app.

Usage:  python3 boring/rebrand.py [ROOT]      (ROOT defaults to the repo root)

Run it on a fresh checkout with submodules initialised (`libs/hbb_common` is
patched in place, so no forked hbb_common repo is needed). It patches config,
not a mass find-replace: every change below names the file, the exact upstream
text it expects, and why. Running it twice changes nothing the second time.

If upstream moved a patch target (neither the upstream text nor our text is
there), the script stops with exit 2 and names every moved target. Fix the
entry here, never by hand-editing the tree.

Stdlib only. Checked by boring/check.py.
"""
import pathlib
import re
import sys

APP_NAME = "BoringRemote"        # internal name: paths, IPC, launchd, exe; no space on purpose
DISPLAY_NAME = "Boring Remote"   # what people read
AGENT_ID = "io.boringlabs.remote.agent"   # app bundle + LaunchAgent (TCC holder)
HOSTD_ID = "io.boringlabs.remote.hostd"   # root LaunchDaemon
ORG = "io.boringlabs"                      # Mac config dir: ~/Library/Preferences/io.boringlabs.BoringRemote
TAILNET = "100.64.0.0/10"

GUARD = "if true { return; } // boring-remote: stripped"
GUARD_OK = "if true { return Ok(()); } // boring-remote: stripped"

LOCKED = {  # OVERWRITE_SETTINGS: wins over the user's config file, UI shows them fixed
    "whitelist": TAILNET,
    "direct-server": "Y",
    "custom-rendezvous-server": "",
    "relay-server": "",
    "api-server": "",
    "allow-auto-update": "N",
    "enable-lan-discovery": "N",  # no answering LAN pings with ID, hostname, user, MAC
    "rendezvous-servers": "",     # a server list the config file could otherwise carry
}
DEFAULTS = {  # DEFAULT_SETTINGS: user can change
    "allow-only-conn-window-open": "N",
}
LOCKED_LOCAL = {  # OVERWRITE_LOCAL_SETTINGS
    "enable-check-update": "N",
}


def _rust_map(d):
    pairs = ", ".join(f'("{k}", "{v}")' for k, v in d.items())
    return (f"RwLock::new([{pairs}].iter()"
            ".map(|(k, v)| (k.to_string(), v.to_string())).collect())")


HBB = "libs/hbb_common/src/config.rs"

# (file, old, new, why). `old` may be a compiled regex. Every occurrence is replaced.
PATCHES = [
    # --- identity -----------------------------------------------------------
    (HBB, 'pub static ref APP_NAME: RwLock<String> = RwLock::new("RustDesk".to_owned());',
     f'pub static ref APP_NAME: RwLock<String> = RwLock::new("{APP_NAME}".to_owned());',
     "app name"),
    (HBB, 'pub static ref ORG: RwLock<String> = RwLock::new("com.carriez".to_owned());',
     f'pub static ref ORG: RwLock<String> = RwLock::new("{ORG}".to_owned());',
     "Mac config dir org"),
    ("flutter/macos/Runner/Configs/AppInfo.xcconfig", "PRODUCT_NAME = RustDesk\n",
     f"PRODUCT_NAME = {APP_NAME}\n", "Mac .app and executable name"),
    ("flutter/macos/Runner/Configs/AppInfo.xcconfig",
     "PRODUCT_BUNDLE_IDENTIFIER = com.carriez.flutterHbb",
     f"PRODUCT_BUNDLE_IDENTIFIER = {AGENT_ID}", "Mac bundle id (xcconfig)"),
    ("flutter/macos/Runner.xcodeproj/project.pbxproj",
     "PRODUCT_BUNDLE_IDENTIFIER = com.carriez.rustdesk;",
     f"PRODUCT_BUNDLE_IDENTIFIER = {AGENT_ID};", "Mac bundle id (project)"),
    ("flutter/macos/Runner.xcodeproj/project.pbxproj", "RustDesk.app", f"{APP_NAME}.app",
     "Mac product reference"),
    ("flutter/macos/Runner.xcodeproj/xcshareddata/xcschemes/Runner.xcscheme",
     'BuildableName = "RustDesk.app"', f'BuildableName = "{APP_NAME}.app"', "Mac scheme"),
    ("flutter/macos/Runner/Info.plist",
     "<key>CFBundleName</key>\n\t<string>$(PRODUCT_NAME)</string>",
     "<key>CFBundleName</key>\n\t<string>$(PRODUCT_NAME)</string>\n"
     f"\t<key>CFBundleDisplayName</key>\n\t<string>{DISPLAY_NAME}</string>",
     "Mac display name"),
    ("flutter/macos/Runner/Info.plist", "<string>com.carriez.rustdesk</string>",
     f"<string>{AGENT_ID}</string>", "Mac URL type name"),
    ("flutter/macos/Runner/Info.plist", "<string>rustdesk</string>\n\t\t\t</array>",
     f"<string>{APP_NAME.lower()}</string>\n\t\t\t</array>",
     "URL scheme matches get_uri_prefix()"),
    ("Cargo.toml", 'name = "RustDesk"\nidentifier = "com.carriez.rustdesk"',
     f'name = "{DISPLAY_NAME}"\nidentifier = "{AGENT_ID}"', "cargo-bundle metadata"),
    ("flutter/windows/CMakeLists.txt", 'set(BINARY_NAME "rustdesk")',
     f'set(BINARY_NAME "{APP_NAME}")', "Windows exe = <app name>.exe, as the app expects"),
    ("build.py", "-e ../../{flutter_build_dir_2}/rustdesk.exe",
     "-e ../../{flutter_build_dir_2}/" + APP_NAME + ".exe", "portable packer exe"),
    ("build.py", "./build/macos/Build/Products/Release/RustDesk.app/",
     f"./build/macos/Build/Products/Release/{APP_NAME}.app/", "Mac service binary copy"),
    ("flutter/windows/runner/Runner.rc", 'VALUE "FileDescription", "RustDesk Remote Desktop"',
     f'VALUE "FileDescription", "{DISPLAY_NAME}"', "Windows file description"),
    ("flutter/windows/runner/Runner.rc", 'VALUE "ProductName", "RustDesk"',
     f'VALUE "ProductName", "{DISPLAY_NAME}"', "Windows product name"),
    ("flutter/windows/runner/Runner.rc", 'VALUE "InternalName", "rustdesk"',
     f'VALUE "InternalName", "{APP_NAME}"', "Windows internal name"),
    ("flutter/windows/runner/Runner.rc", 'VALUE "OriginalFilename", "rustdesk.exe"',
     f'VALUE "OriginalFilename", "{APP_NAME}.exe"', "Windows original filename"),
    ("src/auth_2fa.rs", 'const ISSUER: &str = "RustDesk";',
     f'const ISSUER: &str = "{DISPLAY_NAME}";', "2FA issuer"),
    # --- Mac launchd labels: agent / hostd ----------------------------------
    ("src/platform/macos.rs", re.compile(r"(?:com\.carriez\.)?\{\}_server"),
     AGENT_ID + "{:.0}", "LaunchAgent label ({:.0} swallows the app-name arg)"),
    ("src/platform/macos.rs", re.compile(r"(?:com\.carriez\.)?\{\}_service"),
     HOSTD_ID + "{:.0}", "LaunchDaemon label"),
] + [
    (f"src/platform/privileges_scripts/{f}", old, new, "launchd label / prefs dir")
    for f, pairs in (
        ("agent.plist", ("agent", "assoc")),
        ("daemon.plist", ("hostd", "assoc")),
        ("install.scpt", ("agent", "hostd", "prefs")),
        ("uninstall.scpt", ("agent", "hostd")),
        ("update.scpt", ("agent", "hostd")),
    )
    for old, new in (
        {"agent": ("com.carriez.RustDesk_server", AGENT_ID),
         "hostd": ("com.carriez.RustDesk_service", HOSTD_ID),
         "assoc": ("<string>com.carriez.rustdesk</string>", f"<string>{AGENT_ID}</string>"),
         "prefs": ("Preferences/com.carriez.RustDesk/", f"Preferences/{ORG}.RustDesk/")}[p]
        for p in pairs)
] + [
    # --- servers: none ------------------------------------------------------
    (HBB, 'pub const RENDEZVOUS_SERVERS: &[&str] = &["rs-ny.rustdesk.com"];',
     "pub const RENDEZVOUS_SERVERS: &[&str] = &[];", "no public rendezvous server"),
    ("libs/hbb_common/src/lib.rs", 'const URL: &str = "https://api.rustdesk.com/version/latest";',
     'const URL: &str = "";', "no version check endpoint"),
    ("src/common.rs", '    "https://admin.rustdesk.com".to_owned()\n',
     '    "".to_owned()\n', "no default API server"),
    (HBB, "    pub fn get_rendezvous_servers() -> Vec<String> {\n",
     "    pub fn get_rendezvous_servers() -> Vec<String> {\n"
     "        if true { return Vec::new(); } // boring-remote: stripped\n",
     "no server list from the exe name, rendezvous-servers or the serial path"),
    (HBB, "            rendezvous_server = CONFIG2.read().unwrap().rendezvous_server.clone();\n",
     "            // boring-remote: no rendezvous server from the config file\n",
     "no rendezvous server from the config file"),
    ("src/client.rs",
     "            if other_server == PUBLIC_SERVER {\n"
     "                (\n"
     "                    check_port(RENDEZVOUS_SERVERS[0], RENDEZVOUS_PORT),\n"
     "                    RENDEZVOUS_SERVERS[1..]\n"
     "                        .iter()\n",
     "            if other_server == PUBLIC_SERVER {\n"
     "                // boring-remote: the list is empty, so id@public is an error, not a panic\n"
     "                let Some((first, rest)) = RENDEZVOUS_SERVERS.split_first() else {\n"
     '                    bail!("Boring Remote has no public server: connect by tailnet address");\n'
     "                };\n"
     "                (\n"
     "                    check_port(*first, RENDEZVOUS_PORT),\n"
     "                    rest.iter()\n",
     "id@public peer fails cleanly"),
    # --- lock bypasses: these write past OVERWRITE_SETTINGS ------------------
    ("src/platform/windows.rs", "pub fn get_license_from_exe_name() -> ResultType<CustomServer> {\n",
     "pub fn get_license_from_exe_name() -> ResultType<CustomServer> {\n"
     '    if true { bail!("no license in the exe name"); } // boring-remote: stripped\n',
     "exe name cannot set the rendezvous, API or relay server"),
    ("src/common.rs", "pub fn read_custom_client(config: &str) {\n",
     f"pub fn read_custom_client(config: &str) {{\n    {GUARD}\n",
     "custom.txt cannot rewrite OVERWRITE_SETTINGS (whitelist, servers)"),
    # --- locked settings ----------------------------------------------------
    (HBB, "pub static ref OVERWRITE_SETTINGS: RwLock<HashMap<String, String>> = Default::default();",
     "pub static ref OVERWRITE_SETTINGS: RwLock<HashMap<String, String>> = " + _rust_map(LOCKED) + ";",
     "whitelist, Direct IP, empty servers, no auto update, no LAN discovery"),
    (HBB, "pub static ref DEFAULT_SETTINGS: RwLock<HashMap<String, String>> = Default::default();",
     "pub static ref DEFAULT_SETTINGS: RwLock<HashMap<String, String>> = " + _rust_map(DEFAULTS) + ";",
     "allow-only-conn-window-open off by default"),
    (HBB, "pub static ref OVERWRITE_LOCAL_SETTINGS: RwLock<HashMap<String, String>> = Default::default();",
     "pub static ref OVERWRITE_LOCAL_SETTINGS: RwLock<HashMap<String, String>> = "
     + _rust_map(LOCKED_LOCAL) + ";", "no update check"),
    # --- strip sync, NAT test, updater --------------------------------------
    ("src/common.rs", "pub fn test_nat_type() {\n",
     f"pub fn test_nat_type() {{\n    {GUARD}\n", "NAT test"),
    ("src/common.rs", "pub fn check_software_update() {\n",
     f"pub fn check_software_update() {{\n    {GUARD}\n", "update check"),
    ("src/common.rs", "pub async fn do_check_software_update() -> hbb_common::ResultType<()> {\n",
     f"pub async fn do_check_software_update() -> hbb_common::ResultType<()> {{\n    {GUARD_OK}\n",
     "update check (network call)"),
    ("src/hbbs_http/sync.rs", "async fn start_hbbs_sync_async() {\n",
     f"async fn start_hbbs_sync_async() {{\n    {GUARD}\n", "stats sync"),
    ("src/updater.rs", "fn start_auto_update_check_(rx_msg: Receiver<UpdateMsg>) {\n",
     f"fn start_auto_update_check_(rx_msg: Receiver<UpdateMsg>) {{\n    {GUARD}\n", "Windows auto-updater"),
    ("src/updater.rs", "pub fn start_auto_update_macos() {\n",
     f"pub fn start_auto_update_macos() {{\n    {GUARD}\n", "Mac auto-updater"),
    ("src/lan.rs", "pub(super) fn start_listening() -> ResultType<()> {\n",
     f"pub(super) fn start_listening() -> ResultType<()> {{\n    {GUARD_OK}\n",
     "LAN discovery listener: never binds UDP 21119"),
    # --- banned codecs: hwcodec / vram --------------------------------------
    ("build.py", "    if args.hwcodec:\n        features.append('hwcodec')\n"
                 "    if args.vram:\n        features.append('vram')\n",
     "    if args.hwcodec or args.vram:\n"
     "        raise SystemExit('Boring Remote: hwcodec and vram are banned (no license)')\n",
     "build refuses the banned flags"),
    ("build.py", "./build.py --flutter --hwcodec\n", "./build.py --flutter\n", "linux docker helper"),
    ("flutter/build_fdroid.sh", "RUSTDESK_FEATURES='flutter,hwcodec'", "RUSTDESK_FEATURES='flutter'",
     "android helper"),
    ("flutter/ios_arm64.sh", "--features flutter,hwcodec", "--features flutter", "ios helper"),
    ("flutter/ndk_arm.sh", "--features flutter,hwcodec", "--features flutter", "android helper"),
    ("flutter/ndk_arm64.sh", "--features flutter,hwcodec", "--features flutter", "android helper"),
]

# --- Windows MSI (res/msi, WiX v4) ---------------------------------------------
# Internally the product stays APP_NAME: exe, install dir, service, registry keys
# and URL scheme are all $(var.Product), and the app finds itself by that name.
# Only what people read becomes DISPLAY_NAME. Upstream's preprocess.py still runs
# at build time; these patches set its defaults, so CI passes it only -d.
MSI = "res/msi/Package"
WXL = f"{MSI}/Language/Package.en-us.wxl"
PREPROCESS = "res/msi/preprocess.py"
MANUFACTURER = "Boring Labs"
UPSTREAM_ARP_LINKS = (
    '    "Contact": {\n        "msi": "ARPCONTACT",\n        "v": "https://github.com/rustdesk/rustdesk",\n    },\n'
    '    "HelpLink": {\n        "msi": "ARPHELPLINK",\n'
    '        "v": "https://github.com/rustdesk/rustdesk/issues/",\n    },\n'
    '    "ReadMe": {\n        "msi": "ARPREADME",\n        "v": "https://github.com/rustdesk/rustdesk",\n    },\n')
PATCHES += [
    (f"{MSI}/Package.wxs", '<Package Name="$(var.Product)"', f'<Package Name="{DISPLAY_NAME}"',
     "Apps list and installer title"),
    (f"{MSI}/Package.wxs", 'Description="$(var.Description)"', f'Description="{DISPLAY_NAME} Installer"',
     "MSI file properties"),
    (f"{MSI}/Components/Folders.wxs", '<Directory Id="App.StartMenu" Name="$(var.Product)" />',
     f'<Directory Id="App.StartMenu" Name="{DISPLAY_NAME}" />', "Start menu folder"),
    (f"{MSI}/UI/MyInstallDirDlg.wxs",
     '                <Control Id="ChkBoxInstallPrinter" Type="CheckBox" X="20" Y="180" Width="290" '
     'Height="17" Property="PRINTER" CheckBoxValue="1" Text="!(loc.MyInstallDirDlgPrinter)" />\n',
     "                <!-- boring-remote: no printer checkbox, no printer driver ships -->\n",
     "printer option hidden"),
    (f"{MSI}/Components/RustDesk.wxs",
     '\t\t\t<Custom Action="RemoveAmyuniIdd" Before="RemoveRuntimeGeneratedFiles"/>\n'
     '\t\t\t<Custom Action="RemoveAmyuniIdd.SetParam" Before="RemoveAmyuniIdd"/>\n',
     "\t\t\t<!-- boring-remote: no Amyuni driver ships, nothing to remove -->\n", "Amyuni dropped"),
    (PREPROCESS, '"--app-name", type=str, default="RustDesk"', f'"--app-name", type=str, default="{APP_NAME}"',
     "MSI Product is BoringRemote, so it installs BoringRemote.exe"),
    (PREPROCESS, 'default="Purslane Tech Pte. Ltd.",', f'default="{MANUFACTURER}",', "MSI manufacturer"),
    (PREPROCESS, UPSTREAM_ARP_LINKS, "    # boring-remote: no upstream support links in Apps & features\n",
     "Apps list support links"),
    (PREPROCESS, '    if app_name == "RustDesk":\n        return\n    license_file',
     "    if True:  # boring-remote: License.rtf comes from boring/msi and keeps its upstream credit\n"
     "        return\n    license_file", "license not rewritten"),
] + [
    (WXL, f'Value="{old}"', f'Value="{new}"', f"installer text: {new}")
    for old, new in (
        ("RustDesk", DISPLAY_NAME),  # AR_Comment, F_App, SC_Client (the Start menu shortcut)
        ("RustDesk - Main programs installations.", f"{DISPLAY_NAME}: the app and its service."),
        ("Uninstall RustDesk", f"Uninstall {DISPLAY_NAME}"),
        ("Removes RustDesk or parts of it from the computer", f"Removes {DISPLAY_NAME} from this computer"),
        ("Start RustDesk.", f"Start {DISPLAY_NAME}."),
        ("RustDesk Tray", f"{APP_NAME} Tray"),  # the app itself manages "<APP_NAME> Tray.lnk"
        ("Start RustDesk tray.", f"Start {DISPLAY_NAME} in the tray."),
        ("The server part of RustDesk. Provides the MediaLibrary and other services.",
         f"The {DISPLAY_NAME} service."),
        ("RustDesk Service", f"{DISPLAY_NAME} Service"),
        ("This service runs the RustDesk Server.", f"Runs {DISPLAY_NAME} in the background."),
        ("Install RustDesk Printer", f"Install {DISPLAY_NAME} Printer"),
    )
]

# (file under boring/, destination in the tree, why), copied byte for byte.
# The art comes from boring/msi/make_art.py: re-run it, never edit the outputs.
HERE = pathlib.Path(__file__).resolve().parent
COPIES = [
    ("msi/WixUIBannerBmp.bmp", f"{MSI}/Resources/WixUIBannerBmp.bmp", "MSI banner art, 493x58"),
    ("msi/WixUIDialogBmp.bmp", f"{MSI}/Resources/WixUIDialogBmp.bmp", "MSI dialog art, 493x312"),
    ("msi/License.rtf", f"{MSI}/License.rtf", "installer license: AGPL notice, not upstream's privacy policy"),
    ("msi/icon.ico", "res/icon.ico", "product icon (MSI, shortcuts, Apps list)"),
    ("msi/icon.ico", "flutter/windows/runner/resources/app_icon.ico", "exe icon"),
]

OUR_WORKFLOW_PREFIX = "boring-"


def apply(root):
    root = pathlib.Path(root)
    changed, moved = [], []
    texts = {}
    for rel, old, new, why in PATCHES:
        path = root / rel
        if rel not in texts:
            texts[rel] = path.read_text(encoding="utf-8") if path.is_file() else None
        text = texts[rel]
        if text is None:
            moved.append(f"{rel}: file missing ({why})")
            continue
        if isinstance(old, re.Pattern):
            text2, n = old.subn(new.replace("\\", "\\\\"), text)
        elif old in new:  # an insertion: applied once `new` is there
            n = 0 if new in text else text.count(old)
            text2 = text.replace(old, new)
        else:
            n = text.count(old)
            text2 = text.replace(old, new)
        if n:
            texts[rel] = text2
            changed.append(f"{rel}: {why}")
        elif new not in text:
            moved.append(f"{rel}: patch target moved ({why})")
    for rel, text in texts.items():
        if text is not None and (root / rel).read_text(encoding="utf-8") != text:
            (root / rel).write_text(text, encoding="utf-8")
    for src, rel, why in COPIES:
        data, dest = (HERE / src).read_bytes(), root / rel
        if not dest.is_file() or dest.read_bytes() != data:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            changed.append(f"{rel}: {why}")
    wf = root / ".github" / "workflows"
    if wf.is_dir():
        for f in sorted(wf.iterdir()):
            if f.suffix in (".yml", ".yaml") and not f.name.startswith(OUR_WORKFLOW_PREFIX):
                f.unlink()
                changed.append(f".github/workflows/{f.name}: removed upstream workflow")
    return changed, moved


def main(argv):
    root = argv[1] if len(argv) > 1 else pathlib.Path(__file__).resolve().parent.parent
    changed, moved = apply(root)
    for c in changed:
        print("patched", c)
    for m in moved:
        print("ERROR", m, file=sys.stderr)
    print(f"rebrand: {len(changed)} changed, {len(moved)} moved")
    return 2 if moved else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
