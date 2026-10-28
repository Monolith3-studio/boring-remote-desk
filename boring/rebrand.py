#!/usr/bin/env python3
"""Turn a clean RustDesk checkout into the Boring Remote Desk app.

Usage:  python3 boring/rebrand.py [ROOT]      (ROOT defaults to the repo root)

Run it on a fresh checkout with submodules initialised (`libs/hbb_common` is
patched in place, so no forked hbb_common repo is needed). It patches config,
not a mass find-replace: every change below names the file, the exact upstream
text it expects, and why. Running it twice changes nothing the second time.

If upstream moved a patch target (neither the upstream text nor our text is
there), the script stops with exit 2, names every moved target and writes
nothing: every target is checked before any file changes. Fix the entry here,
never by hand-editing the tree. Patched files keep their line endings.

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
FORK_URL = "https://github.com/Monolith3-studio/boring-remote-desk"  # our source; the only link we ship
# The one place RustDesk is named (AGPL attribution), as plain text on the About page.
LEGAL_LINE = f"Based on RustDesk, \u00a9 Purslane Tech Pte. Ltd., AGPL-3.0. Source: {FORK_URL}"
# Tailscale's address ranges, both tailnet-only: IPv4 CGNAT and the IPv6 ULA a
# MagicDNS AAAA answer points at. The listener is dual-stack, so v4 peers arrive
# as ::ffff:100.x and connection.rs normalises them with try_into_v4 first.
TAILNET = "100.64.0.0/10,fd7a:115c:a1e0::/48"

# What the connect box says when a name doesn't resolve to a tailnet
# address. It is also the translation key (src/lang/*.rs, English everywhere).
NOT_FOUND = "Couldn't find that machine. Type its Tailscale name or IP."
# Goes in src/client.rs before `impl Client`. The ranges are TAILNET's, written
# out (check.py derives them from TAILNET and compares).
TAILNET_RESOLVER = f"""
// boring-remote: connect by tailnet name. A name (with or without a port) goes
// through the system resolver, which covers MagicDNS, and connects Direct IP only
// if every address it resolves to is a Tailscale one. Anything else is refused.
const BORING_NOT_FOUND: &str = "{NOT_FOUND}";

fn boring_is_tailnet(addr: SocketAddr) -> bool {{
    match hbb_common::try_into_v4(addr).ip() {{
        std::net::IpAddr::V4(ip) => ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64,
        std::net::IpAddr::V6(ip) => ip.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    }}
}}

async fn boring_tailnet_addr(peer: &str) -> ResultType<SocketAddr> {{
    let lookup = hbb_common::tokio::time::timeout(
        std::time::Duration::from_millis(CONNECT_TIMEOUT),
        hbb_common::tokio::net::lookup_host(check_port(peer, RELAY_PORT + 1)),
    )
    .await;
    let addrs: Vec<SocketAddr> = match lookup {{
        Ok(Ok(addrs)) => addrs.collect(),
        _ => bail!(BORING_NOT_FOUND),
    }};
    if addrs.is_empty() || !addrs.iter().all(|a| boring_is_tailnet(*a)) {{
        bail!(BORING_NOT_FOUND);
    }}
    Ok(addrs.iter().find(|a| a.is_ipv4()).copied().unwrap_or(addrs[0]))
}}
"""

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
     f"<key>CFBundleName</key>\n\t<string>{DISPLAY_NAME}</string>\n"
     f"\t<key>CFBundleDisplayName</key>\n\t<string>{DISPLAY_NAME}</string>",
     "Mac display name (menu bar, About panel, Finder)"),
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
    (f"src/platform/privileges_scripts/{f}", old, new, why)
    for f, old, new, why in (
        ("agent.plist", "com.carriez.RustDesk_server", AGENT_ID, "LaunchAgent label"),
        ("agent.plist", "<string>com.carriez.rustdesk</string>", f"<string>{AGENT_ID}</string>", "agent bundle id"),
        ("daemon.plist", "com.carriez.RustDesk_service", HOSTD_ID, "LaunchDaemon label"),
        ("daemon.plist", "<string>com.carriez.rustdesk</string>", f"<string>{AGENT_ID}</string>", "daemon bundle id"),
        ("install.scpt", "com.carriez.RustDesk_server", AGENT_ID, "LaunchAgent label"),
        ("install.scpt", "com.carriez.RustDesk_service", HOSTD_ID, "LaunchDaemon label"),
        # the app's config dir is ~/Library/Preferences/<ORG>.<APP_NAME>, files <APP_NAME>.toml / 2.toml
        ("install.scpt", "Preferences/com.carriez.RustDesk/", f"Preferences/{ORG}.{APP_NAME}/", "config dir"),
        ("install.scpt", '(prefs_dir & "RustDesk.toml")', f'(prefs_dir & "{APP_NAME}.toml")', "config file"),
        ("install.scpt", '(prefs_dir & "RustDesk2.toml")', f'(prefs_dir & "{APP_NAME}2.toml")', "config file 2"),
        ("uninstall.scpt", "com.carriez.RustDesk_server", AGENT_ID, "LaunchAgent label"),
        ("uninstall.scpt", "com.carriez.RustDesk_service", HOSTD_ID, "LaunchDaemon label"),
        ("update.scpt", "com.carriez.RustDesk_server", AGENT_ID, "LaunchAgent label"),
        ("update.scpt", "com.carriez.RustDesk_service", HOSTD_ID, "LaunchDaemon label"),
        # ours (Install update, slice 6): same label as daemon.plist, from the same constant
        ("install-update.sh", 'SERVICE_LABEL="com.carriez.RustDesk_service"', f'SERVICE_LABEL="{HOSTD_ID}"',
         "LaunchDaemon label (install update)"),
    )
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
    # --- tailnet name: connect box takes a tailnet name, never an ID --------------
    ("src/client.rs", "\nimpl Client {\n    const CLIENT_CLIPBOARD_NAME",
     TAILNET_RESOLVER + "\nimpl Client {\n    const CLIENT_CLIPBOARD_NAME",
     "tailnet name resolver"),
    ("src/client.rs",
     "        // Allow connect to {domain}:{port}\n"
     "        if hbb_common::is_domain_port_str(peer) {\n"
     "            return Ok((\n"
     "                (\n"
     "                    connect_tcp_local(peer, None, CONNECT_TIMEOUT).await?,\n",
     "        // boring-remote: anything that is not an IP is a tailnet name, never an ID.\n"
     "        // There is no rendezvous server, so the ID path below can't be reached.\n"
     "        if true {\n"
     "            return Ok((\n"
     "                (\n"
     "                    connect_tcp_local(boring_tailnet_addr(peer).await?, None, CONNECT_TIMEOUT)\n"
     "                        .await?,\n",
     "names connect Direct IP to a tailnet address; no ID/rendezvous path"),
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

# --- branding: no RustDesk name, link or logo a person sees on Mac or Windows --
# Code names, crate names, IPC and config keys stay (boring/check.py INTERNAL says
# which and why). Every rustdesk.com / github.com/rustdesk link goes, or points at
# our fork. RustDesk is named once, as plain text: LEGAL_LINE on the About page.
SETTINGS = "flutter/lib/desktop/pages/desktop_setting_page.dart"
HOME = "flutter/lib/desktop/pages/desktop_home_page.dart"
CORAL, INK, PAPER = "FF5949", "0C0B11", "F0EFEB"  # Boring Labs kit
DART_COMMON = "flutter/lib/common.dart"
# (text, fill, where): every text-on-fill pair the patches below set; check.py wants >= 4.5:1.
TEXT_PAIRS = [
    ("FFFFFF", INK, "filled buttons, chat bubble, connection window buttons (light and dark)"),
    (INK, "FFFFFF", "accent text, light theme page"), (INK, "EFEFF2", "accent text, light theme card"),
    (PAPER, "18191E", "accent text, dark theme page"), (PAPER, "24252B", "accent text, dark theme card"),
]
ABOUT_OLD = "              InkWell(\n                  onTap: () {\n                    launchUrlString('https://rustdesk.com/privacy.html');\n                  },\n                  child: Text(\n                    translate('Privacy Statement'),\n                    style: linkStyle,\n                  ).marginSymmetric(vertical: 4.0)),\n              InkWell(\n                  onTap: () {\n                    launchUrlString('https://rustdesk.com');\n                  },\n                  child: Text(\n                    translate('Website'),\n                    style: linkStyle,\n                  ).marginSymmetric(vertical: 4.0)),\n              Container(\n                decoration: const BoxDecoration(color: Color(0xFF2c8cff)),\n                padding:\n                    const EdgeInsets.symmetric(vertical: 24, horizontal: 8),\n                child: SelectionArea(\n                    child: Row(\n                  children: [\n                    Expanded(\n                      child: Column(\n                        crossAxisAlignment: CrossAxisAlignment.start,\n                        children: [\n                          Text(\n                            'Copyright © ${DateTime.now().toString().substring(0, 4)} Purslane Tech Pte. Ltd.\\n$license',\n                            style: const TextStyle(color: Colors.white),\n                          ),\n                          Text(\n                            translate('Slogan_tip'),\n                            style: TextStyle(\n                                fontWeight: FontWeight.w800,\n                                color: Colors.white),\n                          )\n                        ],\n                      ),\n                    ),\n                  ],\n                )),\n              ).marginSymmetric(vertical: 4.0)\n"
ABOUT_NEW = ("              SelectionArea(\n"  # plain text, selectable, no link
             f"                  child: Text('{LEGAL_LINE}')\n"
             "                      .marginSymmetric(vertical: 4.0)),\n")
PATCHES += [
    # About page: one plain legal line, no logo, no links, no RustDesk blue
    (SETTINGS, "translate('About RustDesk')", f"'About {DISPLAY_NAME}'", "About title"),
    (SETTINGS, ABOUT_OLD, ABOUT_NEW, "About: privacy/website links and copyright block become the legal line"),
    # links: none to RustDesk; the few that need a target point at our fork
    ("flutter/lib/common.dart", "  if (bind.mainGetBuildinOption(key: \"hide-powered-by-me\") == 'Y') {\n",
     "  if (true) {  // boring-remote: no powered-by line\n", "no 'Powered by' line"),
    ("flutter/lib/common.dart", "        launchUrl(Uri.parse('https://rustdesk.com'));\n",
     f"        launchUrl(Uri.parse('{FORK_URL}'));\n", "powered-by link"),
    ("flutter/lib/common/widgets/toolbar.dart", "'https://github.com/rustdesk/rustdesk/issues/14586'",
     f"'{FORK_URL}'", "Wayland keyboard help link"),
    ("flutter/lib/desktop/pages/connection_page.dart", '"https://rustdesk.com/pricing"', f'"{FORK_URL}"',
     "public-server guide link"),
    (HOME, "'https://rustdesk.com/download'", f"'{FORK_URL}/releases'", "download link"),
    (HOME, "'https://github.com/rustdesk/rustdesk/releases/tag/${bind.mainGetNewVersion()}'",
     f"'{FORK_URL}/releases'", "changelog link"),
    (HOME, re.compile(r"'https://rustdesk\.com/docs/en/client/linux/#[a-z0-9-]+'"), f"'{FORK_URL}'",
     "Linux help links"),
    (HOME, ", help: 'Help', link: translate(\"doc_mac_permission\"));", ");",
     "Mac permission cards: no rustdesk.com help link"),
    ("flutter/lib/desktop/pages/install_page.dart", "'https://rustdesk.com/privacy.html'", f"'{FORK_URL}'",
     "installer licence link"),
    ("src/client.rs", '"https://rustdesk.com/docs/en/manual/linux/#x11-required"', '""', "X11 help link"),
    ("src/client.rs", '"https://rustdesk.com/docs/en/manual/linux/#login-screen"', '""', "login-screen help link"),
    # names a person reads
    ("flutter/lib/desktop/widgets/tabbar_widget.dart", '"RustDesk",', f"'{DISPLAY_NAME}',", "Windows title bar"),
    ("flutter/lib/common.dart", "  final name = bind.mainGetAppNameSync();\n",
     f"  final name = '{DISPLAY_NAME}';  // boring-remote: display name\n", "window titles"),
    ("flutter/lib/main.dart", "              : bind.mainGetAppNameSync(),\n", f"              : '{DISPLAY_NAME}',\n",
     "app title"),
    ("src/tray.rs", 'crate::get_app_name(),\n                translate("Service is running"',
     f'"{DISPLAY_NAME}",\n                translate("Service is running"', "tray tooltip"),
    ("src/tray.rs", 'crate::get_app_name(),\n                translate("Ready"',
     f'"{DISPLAY_NAME}",\n                translate("Ready"', "tray tooltip (sessions)"),
    ("src/whiteboard/macos.rs", '"RustDesk whiteboard"', f'"{DISPLAY_NAME} whiteboard"', "whiteboard title"),
    ("src/whiteboard/windows.rs", '"RustDesk whiteboard"', f'"{DISPLAY_NAME} whiteboard"', "whiteboard title"),
    ("src/platform/windows.rs", 'let caption = "RustDesk Output"', f'let caption = "{DISPLAY_NAME}"',
     "message box caption"),
    # translations: the lookup shows our name for any RustDesk left, keys included
    ("src/lang.rs", "        let mut s = s.to_string();\n",
     f'        let mut s = s.replace("RustDesk", "{DISPLAY_NAME}");  // boring-remote: every language\n',
     "translated text says Boring Remote"),
    # app metadata the OS shows
    ("flutter/macos/Runner/Configs/AppInfo.xcconfig",
     re.compile(r"PRODUCT_COPYRIGHT = Copyright © \d+ Purslane Tech Pte\. Ltd\. All rights reserved\."),
     f"PRODUCT_COPYRIGHT = {DISPLAY_NAME}, AGPL-3.0", "Get Info / About panel copyright"),
] + [
    ("flutter/macos/Runner/Base.lproj/MainMenu.xib", f'title="{verb}APP_NAME"', f'title="{verb}{DISPLAY_NAME}"',
     "Mac app menu and window title") for verb in ("", "About ", "Hide ", "Quit ")
] + [
    ("flutter/windows/runner/Runner.rc", 'VALUE "CompanyName", "Purslane Tech Pte. Ltd."',
     f'VALUE "CompanyName", "{MANUFACTURER}"', "exe properties: company"),
    ("flutter/windows/runner/Runner.rc",
     re.compile(r'VALUE "LegalCopyright", "Copyright © \d+ Purslane Tech Pte\. Ltd\. All rights reserved\."'),
     f'VALUE "LegalCopyright", "{DISPLAY_NAME}, AGPL-3.0"', "exe properties: copyright"),
    ("Cargo.toml", re.compile(r'LegalCopyright = "Copyright © \d+ Purslane Tech Pte\. Ltd\. All rights reserved\."\n'
                              r'ProductName = "RustDesk"\nFileDescription = "RustDesk Remote Desktop"\n'
                              r'OriginalFilename = "rustdesk\.exe"'),
     f'LegalCopyright = "{DISPLAY_NAME}, AGPL-3.0"\nProductName = "{DISPLAY_NAME}"\n'
     f'FileDescription = "{DISPLAY_NAME}"\nOriginalFilename = "{APP_NAME}.exe"', "dll properties"),
    # Boring Labs palette. Coral only where no text sits on it or in it: icons, borders,
    # selection, progress, the pointer. Text and filled buttons are ink and paper, so
    # every text pair clears 4.5:1 (TEXT_PAIRS, checked by check.py).
    (DART_COMMON, "static const Color accent = Color(0xFF0071FF);",
     f"static const Color accent = Color(0xFF{CORAL});", "accent: non-text only"),
    (DART_COMMON, "static const Color accent50 = Color(0x770071FF);",
     f"static const Color accent50 = Color(0x77{CORAL});", "accent 50%"),
    (DART_COMMON, "static const Color accent80 = Color(0xAA0071FF);",
     f"static const Color accent80 = Color(0xAA{CORAL});", "accent 80%"),
    (DART_COMMON, "static const Color button = Color(0xFF2C8CFF);\n",
     f"static const Color button = Color(0xFF{INK});\n"
     f"  static const Color ink = Color(0xFF{INK});  // boring-remote: text and filled buttons\n"
     f"  static const Color paper = Color(0xFF{PAPER});\n"
     "  static Color get accentText => currentThemeMode() == ThemeMode.dark ? paper : ink;\n",
     "filled buttons ink; accent text ink (light) or paper (dark)"),
    (DART_COMMON, "static const Color idColor = Color(0xFF00B6F0);",
     f"static const Color idColor = Color(0xFF{INK});", "ID text colour"),
    (DART_COMMON, "labelLarge: TextStyle(fontSize: 16.0, color: MyTheme.accent80)",
     "labelLarge: TextStyle(fontSize: 16.0, color: MyTheme.ink)", "light theme label text"),
    (DART_COMMON, "backgroundColor: MyTheme.accent,\n        shape:",
     "backgroundColor: MyTheme.ink,\n        foregroundColor: Colors.white,\n        shape:",
     "light theme filled buttons"),
    (DART_COMMON, "backgroundColor: MyTheme.accent,\n        foregroundColor: Colors.white,",
     "backgroundColor: MyTheme.ink,\n        foregroundColor: Colors.white,", "dark theme filled buttons"),
    (DART_COMMON, "style: const TextStyle(\n                                          color: MyTheme.accent)",
     "style: TextStyle(\n                                          color: MyTheme.accentText)", "dialog Cancel text"),
    (DART_COMMON, "style: TextStyle(color: MyTheme.accent),", "style: TextStyle(color: MyTheme.accentText),",
     "Retry text"),
    (SETTINGS, "style: const TextStyle(\n        color: _accentColor,",
     "style: TextStyle(\n        color: MyTheme.accentText,", "Settings title text"),
    (SETTINGS, "style: TextStyle(\n                  color: selected ? _accentColor : null,\n                  fontWeight",
     "style: TextStyle(\n                  color: selected ? MyTheme.accentText : null,\n                  fontWeight",
     "selected settings tab text"),
    ("flutter/lib/desktop/widgets/button.dart",
     "color: pressed.value\n                      ? MyTheme.accent\n                      : (widget.isOutline",
     "color: pressed.value\n                      ? MyTheme.button\n                      : (widget.isOutline",
     "pressed text button fill"),
    ("flutter/lib/desktop/widgets/button.dart",
     "color: pressed.value\n                  ? MyTheme.accent\n                  : (widget.isOutline",
     "color: pressed.value\n                  ? MyTheme.button\n                  : (widget.isOutline",
     "pressed icon-and-text button fill"),
    ("flutter/lib/desktop/pages/server_page.dart", " color: MyTheme.accent,\n", " color: MyTheme.button,\n",
     "connection window text buttons (buildButton, white text)"),
    ("flutter/lib/common/widgets/chat_page.dart", "isOwnMessage ? MyTheme.accent : Colors.blueGrey",
     "isOwnMessage ? MyTheme.button : Colors.blueGrey", "own chat bubble (white text)"),
] + [
    ("flutter/lib/desktop/pages/file_manager_page.dart",
     f"backgroundColor: MaterialStateProperty.all(\n{a}selectedItems.items.isEmpty\n{b}? MyTheme.accent80\n"
     f"{b}: MyTheme.accent,",
     f"backgroundColor: MaterialStateProperty.all(\n{a}selectedItems.items.isEmpty\n"
     f"{b}? MyTheme.ink.withOpacity(0.6)\n{b}: MyTheme.ink,", "file transfer send button (white text)")
    for a, b in ((" " * 26, " " * 30), (" " * 24, " " * 28))
]

# (file under boring/, destination in the tree, why), copied byte for byte.
# The art comes from boring/msi/make_art.py: re-run it, never edit the outputs.
HERE = pathlib.Path(__file__).resolve().parent
# --- update notice hooks (ADR 0003, docs/adr/0003-update-notice-not-updater.md) ---
# The new files (src/update_notice*.rs, update_notice_banner.dart) are ours; these
# patches only wire them into upstream. check.py asserts each hook landed.
NOTICE_IMPORT = "import 'package:flutter_hbb/desktop/widgets/update_notice_banner.dart';\n"
NOTICE_BANNER = (
    "      // boring-remote: update notice replaces upstream's stripped updater banner slot.\n"
    "      UpdateNoticeBanner(\n"
    "        check: () async => UpdateNotice.fromBridge(await bind.mainCheckUpdateNotice()),\n"
    "        isEnabled: () => mainGetLocalBoolOptionSync(kBoringUpdateCheckOption),\n"
    "        openUrl: (u) => launchUrl(u),\n"
    "      ),\n")
PATCHES += [
    ("src/lib.rs", "mod custom_server;\n",
     "mod custom_server;\nmod update_notice; // boring-remote: update notice (ADR 0003)\nmod update_notice_run;\n",
     "update notice modules"),
    ("src/flutter_ffi.rs", "pub fn main_get_local_option(key: String) -> SyncReturn<String> {\n",
     "/// boring-remote: update notice (ADR 0003). Blocking HTTP, so not Sync: the bridge runs it off the UI thread.\n"
     "/// Returns {\"version\",\"below_min\"} as JSON, or None. Notice only; nothing is downloaded.\n"
     "pub fn main_check_update_notice() -> Option<String> {\n"
     "    crate::update_notice_run::check_now()\n"
     "}\n\n"
     "pub fn main_get_local_option(key: String) -> SyncReturn<String> {\n",
     "update notice bridge call"),
    (HOME, "import 'package:flutter_hbb/desktop/widgets/update_progress.dart';\n",
     "import 'package:flutter_hbb/desktop/widgets/update_progress.dart';\n" + NOTICE_IMPORT,
     "update notice import (home)"),
    (HOME, "      if (!isOutgoingOnly) buildPasswordBoard(context),\n",
     "      if (!isOutgoingOnly) buildPasswordBoard(context),\n" + NOTICE_BANNER,
     "update notice banner on the home page"),
    (SETTINGS, "import 'package:flutter_hbb/desktop/widgets/remote_toolbar.dart';\n",
     "import 'package:flutter_hbb/desktop/widgets/remote_toolbar.dart';\n" + NOTICE_IMPORT,
     "update notice import (settings)"),
    (SETTINGS, "      if (!incomingOnly)\n        _OptionCheckBox(\n          context,\n",
     "      if (!isWeb)\n        _OptionCheckBox(context, 'Check for updates', kBoringUpdateCheckOption,\n"
     "            isServer: false),\n"
     "      if (!incomingOnly)\n        _OptionCheckBox(\n          context,\n",
     "update notice on/off switch in General settings"),
]

# --- License key hooks (in-app updater spec, slice 5) ----------------------------
# src/license_key*.rs and license_key_field.dart are ours; these wire them in.
PATCHES += [
    ("src/lib.rs", "mod update_notice_run;\n",
     "mod update_notice_run;\nmod license_key; // boring-remote: License key (slice 5)\nmod license_key_run;\n",
     "license key modules"),
    ("src/flutter_ffi.rs", "pub fn main_get_local_option(key: String) -> SyncReturn<String> {\n",
     "/// boring-remote: store the License key in `boring-license-key`, then check it with\n"
     "/// fulfillment. Blocking HTTP, so not Sync. Returns valid|revoked|refunded|unknown|busy|network|none.\n"
     "pub fn main_set_license_key(key: String) -> String {\n"
     "    crate::license_key_run::set_and_check(&key)\n"
     "}\n\n"
     "pub fn main_get_local_option(key: String) -> SyncReturn<String> {\n",
     "license key bridge call"),
    (SETTINGS, NOTICE_IMPORT,
     NOTICE_IMPORT + "import 'package:flutter_hbb/desktop/widgets/license_key_field.dart';\n",
     "license key import (settings)"),
    (SETTINGS, "      if (!isWeb)\n        _OptionCheckBox(context, 'Check for updates', kBoringUpdateCheckOption,\n",
     "      if (!isWeb)\n        LicenseKeyField(\n"
     "          initialKey: bind.mainGetLocalOption(key: kBoringLicenseKeyOption),\n"
     "          setKey: (k) => bind.mainSetLicenseKey(key: k),\n"
     "        ),\n"
     "      if (!isWeb)\n        _OptionCheckBox(context, 'Check for updates', kBoringUpdateCheckOption,\n",
     "license key field in General settings"),
]

# --- Install update hooks (ADR 0004, spec slices 5-6) ----------------------------
# src/update_install*.rs and privileges_scripts/install-update.sh are ours; these wire them in.
PATCHES += [
    ("src/lib.rs", "mod license_key_run;\n",
     "mod license_key_run;\nmod update_install; // boring-remote: Install update (ADR 0004)\nmod update_install_run;\n"
     "mod update_rollback;\n",
     "install update modules"),
    ("src/flutter_ffi.rs", "pub fn main_get_local_option(key: String) -> SyncReturn<String> {\n",
     "/// boring-remote: Install update (ADR 0004). Downloads, checks sha256 + sig, then runs the\n"
     "/// root install script (one admin prompt). Blocking, so not Sync. Returns ok or an error word.\n"
     "pub fn main_install_update() -> String {\n"
     "    crate::update_install_run::install_now()\n"
     "}\n\n"
     "pub fn main_get_local_option(key: String) -> SyncReturn<String> {\n",
     "install update bridge call"),
    ("src/core_main.rs", '        if args[0] == "--version" {\n',
     "        // boring-remote: the install script's own sig check (ADR 0004).\n"
     '        if args[0] == "--boring-verify-package" {\n'
     "            std::process::exit(crate::update_install::verify_cli(&args[1..]));\n"
     "        }\n"
     '        if args[0] == "--version" {\n',
     "install update --verify mode"),
    (HOME, NOTICE_IMPORT,
     NOTICE_IMPORT + "import 'package:flutter_hbb/desktop/widgets/license_key_field.dart';\n",
     "license key option name (home banner)"),
]

COPIES = [
    ("msi/WixUIBannerBmp.bmp", f"{MSI}/Resources/WixUIBannerBmp.bmp", "MSI banner art, 493x58"),
    ("msi/WixUIDialogBmp.bmp", f"{MSI}/Resources/WixUIDialogBmp.bmp", "MSI dialog art, 493x312"),
    ("msi/License.rtf", f"{MSI}/License.rtf", "installer license: AGPL notice, not upstream's privacy policy"),
    ("msi/icon.ico", "res/icon.ico", "product icon (MSI, shortcuts, Apps list)"),
    ("msi/icon.ico", "flutter/windows/runner/resources/app_icon.ico", "exe icon"),
] + [  # branding, from boring/art/make_app_art.py: every upstream logo slot (boring/upstream-logos.sha256)
    ("art/AppIcon.icns", "flutter/macos/Runner/AppIcon.icns", "Mac app and Dock icon (the Mac kit's, as-is)"),
    ("art/icon-1024.png", "res/icon.png", "app icon master"),
    ("art/icon-1024.png", "res/mac-icon.png", "Mac icon master"),
    ("art/icon-32.png", "res/32x32.png", "bundle icon"),
    ("art/icon-64.png", "res/64x64.png", "bundle icon"),
    ("art/icon-128.png", "res/128x128.png", "bundle icon"),
    ("art/icon-256.png", "res/128x128@2x.png", "bundle icon"),
    ("art/tray.ico", "res/tray-icon.ico", "Windows tray icon"),
    ("art/menubar-60.png", "res/mac-tray-dark-x2.png", "Mac menu-bar template glyph"),
    ("art/menubar-48.png", "res/mac-tray-light-x2.png", "Mac menu-bar template glyph"),
    ("art/icon.svg", "flutter/assets/icon.svg", "in-app icon: tab bar, connection window"),
    ("art/icon.svg", "res/logo.svg", "logo"),
]

OUR_WORKFLOW_PREFIX = "boring-"

# Translations: every value in src/lang/*.rs, every language. RustDesk becomes the
# display name; a value that is a RustDesk link becomes "" (the UI no longer shows those).
LANG_DIR = "src/lang"
LANG_VALUE = re.compile(r'(\(\s*"(?:[^"\\]|\\.)*",\s*")((?:[^"\\]|\\.)*)("\s*\))')
LANG_END = re.compile(r"\),?\n(\s*\]\.iter\(\)\.cloned\(\)\.collect\(\);)")  # the last entry
RUSTDESK_LINK = re.compile(r"rustdesk\.com|github\.com/rustdesk")


def _lang_value(m):
    value = "" if RUSTDESK_LINK.search(m.group(2)) else m.group(2).replace("RustDesk", DISPLAY_NAME)
    return m.group(1) + value + m.group(3)


def _read(path):
    """(text with LF endings, True if the file uses CRLF), or (None, False) if missing.

    Patches are written with LF; a CRLF checkout (Windows, text=auto) is matched
    on LF and written back as CRLF, so a patched file keeps its endings."""
    if not path.is_file():
        return None, False
    text = path.read_bytes().decode("utf-8")
    return text.replace("\r\n", "\n"), "\r\n" in text


def _patch(text, old, new):
    """(patched text, replacements made); 0 replacements if already applied."""
    if isinstance(old, re.Pattern):
        return old.subn(new.replace("\\", "\\\\"), text)
    if old in new:  # an insertion: applied once `new` is there
        return text.replace(old, new), (0 if new in text else text.count(old))
    return text.replace(old, new), text.count(old)


def plan(root):
    """Everything a run would do, without touching the tree.

    Returns (writes {rel: bytes}, deletes [rel], changed [msg], moved [msg])."""
    root = pathlib.Path(root)
    changed, moved, texts = [], [], {}
    for rel, old, new, why in PATCHES:
        if rel not in texts:
            texts[rel] = _read(root / rel)
        text, crlf = texts[rel]
        if text is None:
            moved.append(f"{rel}: file missing ({why})")
            continue
        text2, n = _patch(text, old, new)
        if n:
            texts[rel] = (text2, crlf)
            changed.append(f"{rel}: {why}")
        elif new not in text:
            moved.append(f"{rel}: patch target moved ({why})")
    langs = sorted((root / LANG_DIR).glob("*.rs")) if (root / LANG_DIR).is_dir() else []
    if not langs:
        moved.append(f"{LANG_DIR}: no translation files (translations)")
    for p in langs:
        rel = p.relative_to(root).as_posix()
        if rel not in texts:
            texts[rel] = _read(p)
        text, crlf = texts[rel]
        text2 = LANG_VALUE.sub(_lang_value, text)
        if f'("{NOT_FOUND}", ' not in text2:
            text2 = LANG_END.sub(f'),\n        ("{NOT_FOUND}", ""),\n\\1', text2, count=1)
        if text2 != text:
            texts[rel] = (text2, crlf)
            changed.append(f"{rel}: translations say {DISPLAY_NAME}, plain not-found error")
    writes, deletes = {}, []
    for rel, (text, crlf) in texts.items():
        if text is not None:
            data = (text.replace("\n", "\r\n") if crlf else text).encode("utf-8")
            if (root / rel).read_bytes() != data:
                writes[rel] = data
    for src, rel, why in COPIES:
        data, dest = (HERE / src).read_bytes(), root / rel
        if not dest.is_file() or dest.read_bytes() != data:
            writes[rel] = data
            changed.append(f"{rel}: {why}")
    wf = root / ".github" / "workflows"
    if wf.is_dir():
        for f in sorted(wf.iterdir()):
            if f.suffix in (".yml", ".yaml") and not f.name.startswith(OUR_WORKFLOW_PREFIX):
                deletes.append(f".github/workflows/{f.name}")
                changed.append(f".github/workflows/{f.name}: removed upstream workflow")
    return writes, deletes, changed, moved


def apply(root):
    """Patch the tree, all or nothing: if any target moved, nothing is written."""
    root = pathlib.Path(root)
    writes, deletes, changed, moved = plan(root)
    if moved:
        return [], moved
    for rel, data in writes.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(data)
    for rel in deletes:
        (root / rel).unlink()
    return changed, moved


def main(argv):
    root = argv[1] if len(argv) > 1 else pathlib.Path(__file__).resolve().parent.parent
    changed, moved = apply(root)
    for c in changed:
        print("patched", c)
    for m in moved:
        print("ERROR", m, file=sys.stderr)
    if moved:
        print(f"rebrand: nothing written, {len(moved)} moved")
        return 2
    print(f"rebrand: {len(changed)} changed, 0 moved")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
