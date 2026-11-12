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
# MagicDNS AAAA answer points at. The connect box sends a name Direct IP only when it
# resolves into them (a tailnet name). No longer a whitelist (ADR 0005).
TAILNET = "100.64.0.0/10,fd7a:115c:a1e0::/48"
# The Hosted servers (ADR 0005): our unmodified hbbs + hbbr. The only rendezvous host the app
# knows; the relay follows it. Their server key's public half is checked in next to this file,
# the same bytes as boring-remote-servers' keys/id_ed25519.pub, and baked in as RS_PUB_KEY.
HOSTED = "rs.theboringremote.com"
SERVER_KEY_FILE = pathlib.Path(__file__).resolve().parent / "server-key.pub"
RUSTDESK_PUB_KEY = "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw="  # RustDesk's public servers' key

# What the connect box says when a name doesn't resolve to a tailnet
# address. It is also the translation key (src/lang/*.rs, English everywhere).
NOT_FOUND = "Couldn't find that machine. Type its Tailscale name or IP."
# New UI strings (tickets 05, 06). Each is its own translation key: English text, "" in every
# language file until translated (AGENTS.md, Localization).
SESSION_SET_FAILED = "Couldn't set the password. If a remote session is open, end it and try again."
UI_KEYS = [
    "Generate", "Reset", "Copy", "New password", "Write it down or copy it now. It won't be shown again.",
    "I've saved it", "Replace", "Replace the password?", "Every Controller will need the new password.",
    "Also clear trusted Controllers", SESSION_SET_FAILED, "Trusted Controllers",
    "None yet. A computer connecting for the first time needs a click here.",
]
MACHINE_ID_LABEL = "Machine ID"  # the Target's ID on its home page (ticket 07, glossary)
LANG_KEYS = [NOT_FOUND, MACHINE_ID_LABEL] + UI_KEYS
# The login to a tailnet name signs the address it resolved to (ticket 06, src/trust_policy.rs).
NOTE_DIALED = "crate::trust_policy::note_dialed(peer, addr.ip());\n"
# Goes in src/client.rs before `impl Client`. The ranges are TAILNET's, written
# out (check.py derives them from TAILNET and compares).
TAILNET_RESOLVER = f"""
// boring-remote: connect by Machine ID or tailnet name (ADR 0005). A Machine ID (digits only)
// goes through the Hosted servers. Any other name (with or without a port) goes through the
// system resolver, which covers MagicDNS, and connects Direct IP only if every address it
// resolves to is a Tailscale one. Anything else is refused.
const BORING_NOT_FOUND: &str = "{NOT_FOUND}";

/// A Machine ID the Hosted servers issue: digits only. Never an address, a name or id@server.
pub(crate) fn boring_is_machine_id(peer: &str) -> bool {{
    !peer.is_empty() && peer.len() <= 20 && peer.bytes().all(|b| b.is_ascii_digit())
}}

pub(crate) fn boring_is_tailnet(addr: SocketAddr) -> bool {{
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
    let addr = addrs.iter().find(|a| a.is_ipv4()).copied().unwrap_or(addrs[0]);
    {NOTE_DIALED}    Ok(addr)
}}
"""

GUARD = "if true { return; } // boring-remote: stripped"
GUARD_OK = "if true { return Ok(()); } // boring-remote: stripped"
GUARD_EMPTY = 'if true { return "".to_owned(); } // boring-remote: no API server (spec slice 2)'
# First statements of hbb_common's two server getters (ADR 0005): every override (exe name,
# Settings, PROD_RENDEZVOUS_SERVER, the config file, rendezvous-servers, the serial path)
# is skipped, so the answer is always the Hosted servers.
FORCE_SERVERS = ("        if true { return RENDEZVOUS_SERVERS.iter().map(|x| x.to_string()).collect(); }"
                 " // boring-remote: the Hosted servers only\n")
FORCE_SERVER = ('        if true { return format!("{}:{RENDEZVOUS_PORT}", RENDEZVOUS_SERVERS[0]); }'
                " // boring-remote: the Hosted servers only\n")
# In Client::_start, after the IP branch: a Machine ID falls through to upstream's rendezvous
# path; anything else is a tailnet name and connects Direct IP (tailnet first: ticket 08).
MACHINE_ID_GUARD = (
    "        // boring-remote: a Machine ID goes through the Hosted servers (ADR 0005). Anything\n"
    "        // else that is not an IP is a tailnet name, never an ID or id@server.\n"
    "        if !boring_is_machine_id(peer) {\n")

LOCKED = {  # OVERWRITE_SETTINGS: wins over the user's config file, UI shows them fixed
    # Servers (ADR 0005): ours, forced, never blank. "key" (the baked server key) is added by
    # server_patches(). No whitelist: Machine-ID connections arrive from anywhere.
    "direct-server": "Y",  # the tailnet path: Direct IP to a tailnet address
    "custom-rendezvous-server": HOSTED,
    "relay-server": HOSTED,
    "api-server": "",  # no API server (spec slice 2); get_api_server_ derives none either
    "allow-auto-update": "N",
    "enable-lan-discovery": "N",  # no answering LAN pings with ID, hostname, user, MAC
    "rendezvous-servers": HOSTED,  # a server list the config file could otherwise carry
    # ticket 05: permanent password only; no one-time password, no Controller-side config edits
    "verification-method": "use-permanent-password",
    "temporary-password-length": "10",  # moot with the line above; pinned in case it goes
    "allow-remote-config-modification": "N",
    # ticket 06: password AND click. "" is RustDesk's "both": a right password from a trusted
    # Controller logs in, an unknown one also needs Accept on the Target (src/trust_policy.rs).
    # Not "password": that hides the Accept button. The prompt can't be hidden either.
    "approve-mode": "",
    "allow-hide-cm": "N",
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
    # --- servers: the Hosted servers only (ADR 0005) ------------------------
    (HBB, 'pub const RENDEZVOUS_SERVERS: &[&str] = &["rs-ny.rustdesk.com"];',
     f'pub const RENDEZVOUS_SERVERS: &[&str] = &["{HOSTED}"];', "the Hosted servers, no public one"),
    ("libs/hbb_common/src/lib.rs", 'const URL: &str = "https://api.rustdesk.com/version/latest";',
     'const URL: &str = "";', "no version check endpoint"),
    ("src/common.rs", '    "https://admin.rustdesk.com".to_owned()\n',
     '    "".to_owned()\n', "no default API server"),
    ("src/common.rs", "fn get_api_server_(api: String, custom: String) -> String {\n",
     f"fn get_api_server_(api: String, custom: String) -> String {{\n    {GUARD_EMPTY}\n",
     "no API server, none derived from the rendezvous server (no audit posts, no account calls)"),
    (HBB, "    pub fn get_rendezvous_servers() -> Vec<String> {\n",
     "    pub fn get_rendezvous_servers() -> Vec<String> {\n" + FORCE_SERVERS,
     "server list is ours: not from the exe name, rendezvous-servers or the serial path"),
    (HBB, "    pub fn get_rendezvous_server() -> String {\n",
     "    pub fn get_rendezvous_server() -> String {\n" + FORCE_SERVER,
     "rendezvous server is ours: not from the exe name, Settings, PROD or the config file"),
    (HBB, "            rendezvous_server = CONFIG2.read().unwrap().rendezvous_server.clone();\n",
     "            // boring-remote: no rendezvous server from the config file\n",
     "no rendezvous server from the config file"),
    # --- connect box: a Machine ID through the Hosted servers, else a tailnet name ----
    ("src/client.rs", "\nimpl Client {\n    const CLIENT_CLIPBOARD_NAME",
     TAILNET_RESOLVER + "\nimpl Client {\n    const CLIENT_CLIPBOARD_NAME",
     "Machine ID test and tailnet name resolver"),
    ("src/client.rs",
     "        // Allow connect to {domain}:{port}\n"
     "        if hbb_common::is_domain_port_str(peer) {\n"
     "            return Ok((\n"
     "                (\n"
     "                    connect_tcp_local(peer, None, CONNECT_TIMEOUT).await?,\n",
     MACHINE_ID_GUARD + "            return Ok((\n"
     "                (\n"
     "                    connect_tcp_local(boring_tailnet_addr(peer).await?, None, CONNECT_TIMEOUT)\n"
     "                        .await?,\n",
     "a Machine ID takes the Hosted path; any other name connects Direct IP to a tailnet address"),
    # --- lock bypasses: these write past OVERWRITE_SETTINGS ------------------
    ("src/platform/windows.rs", "pub fn get_license_from_exe_name() -> ResultType<CustomServer> {\n",
     "pub fn get_license_from_exe_name() -> ResultType<CustomServer> {\n"
     '    if true { bail!("no license in the exe name"); } // boring-remote: stripped\n',
     "exe name cannot set the rendezvous, API or relay server"),
    ("src/common.rs", "pub fn read_custom_client(config: &str) {\n",
     f"pub fn read_custom_client(config: &str) {{\n    {GUARD}\n",
     "custom.txt cannot rewrite OVERWRITE_SETTINGS (servers, key)"),
    # --- locked settings ----------------------------------------------------
    # OVERWRITE_SETTINGS (LOCKED plus the server key) is in server_patches().
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
    # Tickets 12/15: Install update and the inline License key field (same bridges as Settings).
    "        hasKey: () => bind.mainGetLocalOption(key: kBoringLicenseKeyOption).isNotEmpty,\n"
    "        install: () => bind.mainInstallUpdate(),\n"
    "        setKey: (k) => bind.mainSetLicenseKey(key: k),\n"
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

# --- Activate link (ticket 14) ----------------------------------------------------
# Rides upstream's URL scheme (already renamed to boringremote above). src/activate_link.rs
# and activate_link.dart are ours; these wire them in and stop upstream logging incoming
# links, since an activate link carries the License key.
PATCHES += [
    ("src/lib.rs", "mod license_key_run;\n",
     "mod license_key_run;\nmod activate_link; // boring-remote: boringremote://activate?key= (ticket 14)\n",
     "activate link module"),
    ("src/flutter_ffi.rs", "pub fn main_get_local_option(key: String) -> SyncReturn<String> {\n",
     "/// boring-remote: boringremote://activate?key=<License key>. Stores + checks the key like\n"
     "/// main_set_license_key; anything but a clean activate link returns `rejected`. Blocking.\n"
     "pub fn main_activate_link(url: String) -> String {\n"
     "    crate::license_key_run::activate_link(&url)\n"
     "}\n\n"
     "pub fn main_get_local_option(key: String) -> SyncReturn<String> {\n",
     "activate link bridge call"),
    ("flutter/lib/common.dart", "import 'package:flutter_hbb/utils/http_service.dart' as http;\n",
     "import 'package:flutter_hbb/utils/http_service.dart' as http;\n"
     "import 'package:flutter_hbb/desktop/widgets/activate_link.dart';\n",
     "activate link import"),
    ("flutter/lib/common.dart", '  } else if (uri.authority == "config") {\n',
     '  } else if (uri.authority == "activate") {\n'
     "    // boring-remote: one-click activate link (ticket 14). Rust parses and checks it.\n"
     "    final url = uri.toString();\n"
     "    Timer(Duration(seconds: 1), () async {\n"
     "      showActivateLinkResult(await bind.mainActivateLink(url: url));\n"
     "    });\n"
     "    return null;\n"
     '  } else if (uri.authority == "config") {\n',
     "activate link handler"),
    ("src/platform/delegate.rs", '            log::debug!("URL received: {}", theurl);\n', "",
     "don't log incoming links (they can carry a License key)"),
    ("flutter/lib/common.dart", '    debugPrint("A uri was received: $uri. handleByFlutter $handleByFlutter");\n', "",
     "don't log incoming links"),
    ("flutter/lib/common.dart", '    print("initialLink: $initialLink");\n', "", "don't log the cold-boot link"),
    ("flutter/lib/main.dart", '  debugPrint("launch args: $args");\n', "", "don't log launch args (may be a link)"),
]

# --- Permanent password only (ticket 05) ------------------------------------------
# src/password_lock.rs and generated_password.dart are ours; these wire them in.
# The locks themselves are in LOCKED (verification-method, allow-remote-config-modification).
# Shared by both gates below: upstream's click branch (Windows terminal OS-login prep, the
# version check before the wait message), so a gated login behaves like an upstream click login.
def _click_wait(indent):
    i = " " * indent
    return (
        f"{i}#[cfg(not(any(target_os = \"android\", target_os = \"ios\")))]\n"
        f"{i}if should_use_terminal_os_login_scope(self.terminal, &lr.os_login.username) {{\n"
        f"{i}    if let Some(keep_alive) = self.prepare_terminal_login_for_authorization().await {{\n"
        f"{i}        return keep_alive;\n"
        f"{i}    }}\n"
        f"{i}}}\n"
        f"{i}self.try_start_cm(lr.my_id, lr.my_name, false);\n"
        f"{i}if hbb_common::get_version_number(&lr.version)\n"
        f"{i}    >= hbb_common::get_version_number(\"1.2.0\")\n"
        f"{i}{{\n"
        f"{i}    self.send_login_error(crate::client::LOGIN_MSG_NO_PASSWORD_ACCESS).await;\n"
        f"{i}}}\n"
        f"{i}return true;\n")


NO_PASSWORD_GATE = (
    "            // boring-remote: permanent password only (ticket 05). None set yet: no unattended\n"
    "            // access, but someone at this computer can still click Accept, not remembered (ticket 06).\n"
    "            if crate::password_lock::refuse_login(&Config::get_option(keys::OPTION_VERIFICATION_METHOD)) {\n"
    "                self.send_login_error(crate::password_lock::LOCK_GONE_ERROR).await;\n"
    "                return false;\n"
    "            }\n"
    "            if !Config::has_permanent_password() {\n"
    "                // Every prompt counts against this IP's failure budget: no prompt spam.\n"
    "                let (failure, res) = self.check_failure(0).await;\n"
    "                if !res {\n"
    "                    return true;\n"
    "                }\n"
    "                self.update_failure_with_scope(failure, false, 0, FailureScope::Default);\n"
    "                crate::trust_policy::on_login(\n"
    "                    self.inner.id(),\n"
    "                    &lr.my_id,\n"
    "                    crate::trust_policy::Password::NotSet,\n"
    "                    None,\n"
    "                );\n"
    + _click_wait(16) +
    "            }\n")
GENERATE_BUTTON = (
    "        // boring-remote: Generate (ticket 05) sets a strong password and shows it once. Reset asks\n"
    "        // first and can clear the trusted Controllers too (ticket 06).\n"
    "        final generateButton = dialogButton(\n"
    "          permanentPasswordSet ? \"Reset\" : \"Generate\",\n"
    "          icon: Icon(Icons.casino_outlined),\n"
    "          onPressed: () async {\n"
    "            var clearTrusted = false;\n"
    "            if (permanentPasswordSet) {\n"
    "              final go = await confirmReplacePassword();\n"
    "              if (go == null) return;\n"
    "              clearTrusted = go;\n"
    "            }\n"
    "            final pass = await bind.mainGeneratePermanentPassword();\n"
    "            if (pass.isEmpty) {\n"
    "              setState(() {\n"
    f"                errMsg0 = '${{translate('Prompt')}}: ${{translate(\"{SESSION_SET_FAILED}\")}}';\n"
    "              });\n"
    "              return;\n"
    "            }\n"
    "            if (clearTrusted) clearTrustedControllers();\n"
    "            close();\n"
    "            notEmptyCallback?.call();\n"
    "            showGeneratedPasswordOnce(pass);\n"
    "          },\n"
    "        );\n")
IPC_GUARD = ("!crate::password_lock::config_write_allowed(&name, "
             "crate::password_lock::authed_sessions())")
SYNC_GUARD = (
    "            // boring-remote: no whole-config replace during a remote session (tickets 05, 06).\n"
    "            if crate::password_lock::authed_sessions() > 0 {\n"
    "                log::warn!(\"config sync refused during a remote session\");\n"
    "                return;\n"
    "            }\n")
OPTIONS_HOOK = (
    "                // boring-remote: security options stay put during a remote session (ticket 05).\n"
    "                let mut value = crate::password_lock::guard_options(\n"
    "                    value,\n"
    "                    &Config::get_options(),\n"
    "                    crate::password_lock::authed_sessions(),\n"
    "                );\n"
    "                // The trusted list is the daemon's; removing one ends its sessions (ticket 06).\n"
    "                let removed = crate::trust_policy::take_options(&mut value, &Config::get_options());\n"
    "                Config::set_options(value);\n"
    "                crate::trust_policy::close_removed(&removed);\n")
MOBILE_SERVER = "flutter/lib/mobile/pages/server_page.dart"
NON_IOS = '#[cfg(not(target_os = "ios"))] // boring-remote: Target side only\n'
PATCHES += [
    ("src/lib.rs", "mod lang;\n",
     "mod lang;\n" + NON_IOS + "mod password_lock; // boring-remote: permanent password only (ticket 05)\n",
     "password lock module (no Target side on iOS)"),
    ("src/flutter_ffi.rs", "pub fn main_get_local_option(key: String) -> SyncReturn<String> {\n",
     "/// boring-remote: set a generated permanent password (ticket 05) and return it once for the\n"
     "/// UI to show. Empty if the daemon refused it. Never logged, never readable again.\n"
     "pub fn main_generate_permanent_password() -> String {\n"
     "    #[cfg(not(target_os = \"ios\"))]\n"
     "    return crate::password_lock::generate_and_set();\n"
     "    #[cfg(target_os = \"ios\")]\n"
     "    String::new()\n"
     "}\n\n"
     "pub fn main_get_local_option(key: String) -> SyncReturn<String> {\n",
     "generate password bridge call"),
    ("src/server/connection.rs", "            if (password::approve_mode() == ApproveMode::Click && !allow_logon_screen_password)\n",
     NO_PASSWORD_GATE
     + "            if (password::approve_mode() == ApproveMode::Click && !allow_logon_screen_password)\n",
     "no permanent password refuses the login"),
    ("src/ipc.rs",
     '                } else if name == "permanent-password" {\n'
     "                    if Config::is_disable_change_permanent_password() {\n",
     '                } else if name == "permanent-password" {\n'
     f"                    if {IPC_GUARD} {{\n"
     '                        log::warn!("permanent password write refused during a remote session");\n'
     "                        updated = false;\n"
     "                    } else if Config::is_disable_change_permanent_password() {\n",
     "no password change during a remote session"),
    ("src/ipc.rs",
     '                } else if name == "salt" {\n                    Config::set_salt(&value);\n',
     '                } else if name == "salt" {\n'
     f"                    if {IPC_GUARD} {{\n"
     '                        log::warn!("salt write refused during a remote session");\n'
     "                        return;\n"
     "                    }\n"
     "                    Config::set_salt(&value);\n",
     "no salt change during a remote session"),
    ("src/ipc.rs",
     '                } else if name == "unlock-pin" {\n                    Config::set_unlock_pin(&value);\n',
     '                } else if name == "unlock-pin" {\n'
     f"                    if {IPC_GUARD} {{\n"
     '                        log::warn!("unlock PIN write refused during a remote session");\n'
     "                        return;\n"
     "                    }\n"
     "                    Config::set_unlock_pin(&value);\n",
     "no unlock PIN change during a remote session"),
    ("src/ipc.rs",
     "                Config::set_options(value);\n                allow_err!(stream.send(&Data::Options(None)).await);\n",
     OPTIONS_HOOK + "                allow_err!(stream.send(&Data::Options(None)).await);\n",
     "security options kept during a remote session; trusted list removals end sessions"),
    ("src/ipc.rs",
     "        Data::SyncConfig(Some(configs)) => {\n            let (config, config2) = *configs;\n",
     "        Data::SyncConfig(Some(configs)) => {\n" + SYNC_GUARD + "            let (config, config2) = *configs;\n",
     "no whole-config sync during a remote session"),
    (HOME, 'translate("One-time Password"),',
     'translate(showOneTime ? "One-time Password" : "Password"),',
     "no one-time password label when it is off"),
    (HOME, "import 'package:flutter_hbb/desktop/pages/desktop_tab_page.dart';\n",
     "import 'package:flutter_hbb/desktop/pages/desktop_tab_page.dart';\n"
     "import 'package:flutter_hbb/desktop/widgets/generated_password.dart';\n"
     "import 'package:flutter_hbb/desktop/widgets/trusted_controllers.dart';\n",
     "generated password + trusted list imports (home)"),
    (HOME, "    MinCharactersValidationRule(8),\n",
     "    MinCharactersValidationRule(16), // boring-remote: typed passwords 16+ (ticket 05)\n",
     "typed password needs 16+ characters"),
    (HOME, "          onPressed: canSubmit ? submit : null,\n        );\n",
     "          onPressed: canSubmit ? submit : null,\n          isOutline: true,\n        );\n",
     "OK is the secondary action; Generate/Reset is the main one"),
    (HOME, "        return [\n          cancelButton,\n          if (localPasswordSet) removeButton,\n          okButton,\n        ];\n",
     GENERATE_BUTTON
     + "        return [\n          cancelButton,\n          if (localPasswordSet) removeButton,\n          okButton,\n"
       "          generateButton,\n        ];\n",
     "Generate/Reset button in Set Password"),
    (MOBILE_SERVER, "                translate('One-time Password'),\n",
     "                translate(showOneTime ? 'One-time Password' : 'Password'),\n",
     "mobile: no one-time password label when it is off"),
    (MOBILE_SERVER, "            if (showPasswordOption)\n              PopupMenuItem(\n                value: kUse",
     "            if (showPasswordOption && !isOptionFixed(kOptionVerificationMethod))\n"
     "              PopupMenuItem(\n                value: kUse",
     "mobile: no verification method menu when it is locked"),
]

# --- Trusted Controllers (ticket 06) ----------------------------------------------
# src/trust_policy.rs and trusted_controllers.dart are ours; these wire them in. The
# approve-mode / allow-hide-cm locks are in LOCKED. Trust is bound to the Controller's own key:
# it signs each tailnet Direct IP login (SIGN_LOGIN, two LoginRequest fields in PROTO_PATCH), and
# the Target trusts an ID only with its stored key and a valid signature over this login on this
# connection (LOGIN_KEY). A known ID alone, a 1.7 Controller, LAN Direct IP and relayed logins
# always get the click.
# The key is proven against this connection: its challenge, the address it arrived on and the
# address it came from (both tailnet, or the login has no name to sign and clicks).
# The Target's own Machine ID counts as a signed name only on a connection keyed to its signed
# identity (ticket 07); the Controller signs it only on a session it verified (VERIFY_ON_START).
LOGIN_KEY = ("crate::trust_policy::login_key(\n"
             "                            &lr,\n"
             "                            &self.hash.challenge,\n"
             "                            self.stream.local_addr().ip(),\n"
             "                            &self.ip,\n"
             "                            &Config::get_id(),\n"
             "                            self.stream.is_secured(),\n"
             "                        )")
TRUST_GATE = (
    "                    // boring-remote: a Controller that doesn't prove a trusted key also needs\n"
    "                    // a click on this computer (ticket 06). Every prompt counts against this\n"
    "                    // IP's failure budget. Nobody answers: the login times out.\n"
    "                    if crate::trust_policy::on_login(\n"
    "                        self.inner.id(),\n"
    "                        &lr.my_id,\n"
    "                        crate::trust_policy::Password::Right,\n"
    f"                        {LOGIN_KEY},\n"
    "                    ) != crate::trust_policy::Decision::Allow\n"
    "                    {\n"
    "                        self.update_failure_with_scope(failure, false, 0, FailureScope::Default);\n"
    + _click_wait(24) +
    "                    }\n")
ACCEPT_GATE = (
    "                            // boring-remote: Accept counts only for a login waiting on it\n"
    "                            // (ticket 06). Before login, anything else ends the connection, so\n"
    "                            // the CM never shows a session that isn't there. An approval clears\n"
    "                            // the IP's prompt count.\n"
    "                            if !crate::trust_policy::on_accept(conn.inner.id()) {\n"
    "                                if conn.authorized {\n"
    "                                    continue;\n"
    "                                }\n"
    "                                conn.send_close_reason_no_retry(\"\").await;\n"
    "                                conn.on_close(\"connection manager\", true).await;\n"
    "                                break;\n"
    "                            }\n"
    "                            clear_failures(&mut LOGIN_FAILURES[0].lock().unwrap(), &conn.failure_keys());\n")
FORGET_ON_LOGIN = (
    "            // boring-remote: a new login while this one waits on Accept could swap the login\n"
    "            // the prompt approves, so it ends the connection (ticket 06).\n"
    "            if crate::trust_policy::forget(self.inner.id()) {\n"
    "                self.send_login_error(\"Connection not allowed\").await;\n"
    "                return false;\n"
    "            }\n")
CLOSE_CONTROLLER = (
    "/// boring-remote: end every authorised connection from this Controller ID (ticket 06).\n"
    "pub fn close_controller(peer_id: &str) {\n"
    "    for c in AUTHED_CONNS.lock().unwrap().iter() {\n"
    "        if c.session_key.peer_id == peer_id {\n"
    "            c.sender.send(ipc::Data::Close).ok();\n"
    "        }\n"
    "    }\n"
    "}\n\n")
CLOSE_ARM = (
    "                        // boring-remote: its Controller was removed from the trusted list (ticket 06).\n"
    "                        ipc::Data::Close => {\n"
    "                            conn.send_close_reason_no_retry(\"\").await;\n"
    "                            conn.on_close(\"trusted Controller removed\", true).await;\n"
    "                            break;\n"
    "                        }\n")
TRUST_CARD = "                _Card(title: 'Trusted Controllers', children: [TrustedControllers()]),\n"
# Upstream starts the CM (an Accept button) on these two paths too; Accept can't let them in,
# so they show nothing and the Controller asks for the password.
EMPTY_PASSWORD_CM = (
    "            } else if lr.password.is_empty() {\n"
    "                #[cfg(not(any(target_os = \"android\", target_os = \"ios\")))]\n"
    "                if should_use_terminal_os_login_scope(self.terminal, &lr.os_login.username) {\n"
    "                    if let Some(keep_alive) = self.prepare_terminal_login_for_authorization().await\n"
    "                    {\n"
    "                        return keep_alive;\n"
    "                    }\n"
    "                }\n"
    "                self.try_start_cm(lr.my_id, lr.my_name, false);\n"
    "            } else {\n")
EMPTY_PASSWORD_NO_CM = (
    "            } else if lr.password.is_empty() {\n"
    "                // boring-remote: no Accept for a login without the password (ticket 06).\n"
    "            } else {\n")
WRONG_PASSWORD_CM = (
    "                    self.send_login_error(crate::client::LOGIN_MSG_PASSWORD_WRONG)\n"
    "                        .await;\n"
    "                    self.try_start_cm(lr.my_id, lr.my_name, false);\n")
_PW_OK = ("                    self.update_failure_with_scope(failure, true, 0, FailureScope::Default);\n"
          "                    if !self.send_logon_response_and_keep_alive().await {\n")
_AUTHORIZE = ("                        ipc::Data::Authorize => {\n"
              "                            conn.set_conn_audit_primary_auth(ConnAuditPrimaryAuth::Click);\n")
_LOGIN = ("        if let Some(message::Union::LoginRequest(lr)) = msg.union {\n"
          "            if !self.check_login_scope(&lr).await {\n")
SIGN_LOGIN = ("        // boring-remote: sign this login for the Target's trusted list (tickets 06, 07).\n"
              "        crate::trust_policy::sign_login(&mut lr, &self.hash.challenge, self.boring_verified_target.as_deref());\n")
# Ticket 07: every connection records whether it verified the Target's Machine ID against the
# baked server key (src/trust_policy.rs verified_target); the login signs that ID only then.
# Cleared first, so a reconnect or a failed connect never keeps an older session's answer.
VERIFIED_FIELD = ("    pub other_server: Option<(String, String, String)>,\n"
                  "    /// boring-remote: the Machine ID this connection verified (ticket 07), else None.\n"
                  "    pub boring_verified_target: Option<String>,\n")
VERIFY_CLEAR = ("        interface.update_direct(None);\n"
                "        interface.update_received(false);\n"
                "        interface.get_lch().write().unwrap().boring_verified_target = None; // boring-remote (ticket 07)\n")
VERIFY_ON_START = (
    "            Ok(x) => {\n"
    "                // boring-remote: sign this Machine ID's login only if this connection verified\n"
    "                // the Target against the baked server key (ticket 07).\n"
    "                interface.get_lch().write().unwrap().boring_verified_target =\n"
    "                    crate::trust_policy::verified_target(peer, key, x.0 .2.as_deref(), x.0 .0.is_secured());\n")
_START_OK = "            Ok(x) => {\n                // Set x.2 to true only in the connect() function"
_LOGIN_BUILT = "        };\n        match self.conn_type {\n            ConnType::FILE_TRANSFER => lr.set_file_transfer(FileTransfer {\n"
# Upstream stores the Target's Hash only after sending the login; the signature needs it first.
HASH_FIRST_OLD = ("    send_login(lc.clone(), String::new(), String::new(), password, peer).await;\n"
                  "    lc.write().unwrap().hash = hash;\n    true\n}\n")
HASH_FIRST_NEW = ("    lc.write().unwrap().hash = hash; // boring-remote: the login signs its challenge (ticket 06)\n"
                  "    send_login(lc.clone(), String::new(), String::new(), password, peer).await;\n    true\n}\n")
# Two LoginRequest fields, numbered far from upstream's. A 1.7 Target or stock RustDesk ignores
# them; a 1.7 Controller leaves them empty. check.py undoes exactly this to compare the proto
# with upstream's pinned hash (boring/protocol.sha256, boring/REBASE.md).
PROTO_FIELDS = (
    "  // boring-remote: trusted Controllers (ticket 06). The Controller's own Ed25519 public key\n"
    "  // and its signature over this login (src/trust_policy.rs). Empty from older Controllers.\n"
    "  bytes boring_controller_pk = 1000;\n"
    "  bytes boring_login_sig = 1001;\n")
PROTO_PATCH = ("libs/base/protos/message.proto", "  string avatar = 17;\n}\n",
               "  string avatar = 17;\n" + PROTO_FIELDS + "}\n",
               "LoginRequest carries the Controller's key and login signature")
_AUTHED_TAIL = "                        _ => {}\n                    }\n                }\n                _ = second_timer.tick() => {\n"
PATCHES += [
    ("src/lib.rs", "mod password_lock; // boring-remote: permanent password only (ticket 05)\n",
     "mod password_lock; // boring-remote: permanent password only (ticket 05)\n"
     "mod trust_policy; // boring-remote: trusted Controllers (ticket 06); iOS Controllers sign too\n",
     "trust policy module (Controllers on every platform sign their logins)"),
    PROTO_PATCH,
    ("src/client.rs", _LOGIN_BUILT, _LOGIN_BUILT.replace("        match self", SIGN_LOGIN + "        match self", 1),
     "Controller signs each login with its own key"),
    ("src/client.rs", HASH_FIRST_OLD, HASH_FIRST_NEW, "the login knows the Target's challenge before it is built"),
    ("src/client.rs", VERIFIED_FIELD.split("    /// boring")[0], VERIFIED_FIELD,
     "the login config remembers the Machine ID its connection verified"),
    ("src/client.rs", VERIFY_CLEAR.rsplit("        interface.get_lch", 1)[0], VERIFY_CLEAR,
     "a new connection forgets the last one's verified Machine ID"),
    ("src/client.rs", _START_OK, _START_OK.replace("            Ok(x) => {\n", VERIFY_ON_START, 1),
     "a connection that verified the Target against the baked server key records its Machine ID"),
    (HOME, '                          translate("ID"),\n',
     f'                          translate("{MACHINE_ID_LABEL}"), // boring-remote (ticket 07)\n',
     "the Target shows its Machine ID"),
    ("src/server/connection.rs", _PW_OK, TRUST_GATE + _PW_OK,
     "unknown Controller waits for a click after the right password"),
    ("src/server/connection.rs", _AUTHORIZE,
     _AUTHORIZE.replace("                            conn.set_conn_audit", ACCEPT_GATE
                        + "                            conn.set_conn_audit", 1),
     "Accept only for a login waiting on it"),
    ("src/server/connection.rs", _LOGIN, _LOGIN.replace("            if !self.check_login_scope", FORGET_ON_LOGIN
                                                        + "            if !self.check_login_scope", 1),
     "a new login on a waiting connection ends it"),
    ("src/server/connection.rs", "        self.closed = true;\n",
     "        self.closed = true;\n        crate::trust_policy::forget(self.inner.id()); // boring-remote (ticket 06)\n",
     "a closed connection voids the wait"),
    ("src/server/connection.rs", EMPTY_PASSWORD_CM, EMPTY_PASSWORD_NO_CM, "no Accept prompt without a password"),
    ("src/server/connection.rs", WRONG_PASSWORD_CM, WRONG_PASSWORD_CM.replace(
        "                    self.try_start_cm(lr.my_id, lr.my_name, false);\n", ""),
     "no Accept prompt after a wrong password"),
    ("src/server/connection.rs", "#[cfg(windows)]\npub struct PortableState {\n",
     CLOSE_CONTROLLER + "#[cfg(windows)]\npub struct PortableState {\n", "close a removed Controller's sessions"),
    ("src/server/connection.rs", _AUTHED_TAIL, CLOSE_ARM + _AUTHED_TAIL, "removed Controller's session closes"),
    (SETTINGS, "import 'package:flutter_hbb/desktop/widgets/license_key_field.dart';\n",
     "import 'package:flutter_hbb/desktop/widgets/license_key_field.dart';\n"
     "import 'package:flutter_hbb/desktop/widgets/trusted_controllers.dart';\n",
     "trusted Controllers import (settings)"),
    (SETTINGS, "                _Card(title: '2FA', children: [tfa()]),\n",
     "                _Card(title: '2FA', children: [tfa()]),\n" + TRUST_CARD,
     "trusted Controllers list in Security settings"),
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


def read_server_key(path):
    """(the Hosted servers' public key as base64, None) or (None, why it can't be baked)."""
    import base64
    try:
        text = pathlib.Path(path).read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as e:
        return None, f"missing or unreadable ({e.__class__.__name__})"
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError:
        return None, "not base64"
    if len(raw) != 32 or base64.b64encode(raw).decode() != text:
        return None, f"not a 32-byte Ed25519 public key ({len(raw)} bytes)"
    if text == RUSTDESK_PUB_KEY:
        return None, "RustDesk's public servers' key, not ours"
    return text, None


def server_patches(key):
    """The patches that bake the server key: RS_PUB_KEY and the locked "key" option."""
    return [
        (HBB, f'pub const RS_PUB_KEY: &str = "{RUSTDESK_PUB_KEY}";', f'pub const RS_PUB_KEY: &str = "{key}";',
         "the Hosted servers' key, baked in (only Boring Remote builds use them)"),
        (HBB, "pub static ref OVERWRITE_SETTINGS: RwLock<HashMap<String, String>> = Default::default();",
         "pub static ref OVERWRITE_SETTINGS: RwLock<HashMap<String, String>> = "
         + _rust_map({**LOCKED, "key": key}) + ";",
         "servers and key forced to ours, Direct IP, no auto update, no LAN discovery, password + click"),
    ]


def _read(path):
    """(text with LF endings, True if the file uses CRLF), or (None, False) if missing.

    Patches are written with LF; a CRLF checkout (Windows, text=auto) is matched
    on LF and written back as CRLF, so a patched file keeps its endings."""
    if not path.is_file():
        return None, False
    text = path.read_bytes().decode("utf-8")
    return text.replace("\r\n", "\n"), "\r\n" in text


def _applied(text, old, new):
    """True if this patch's result is already in text. Bridge fns and mod lines share anchors,
    so a later insertion splits an earlier `new`; a multi-line inserted block already present
    also counts. (One-line GUARDs repeat across functions, so not those.)"""
    if new in text:
        return True
    added = new.replace(old, "", 1) if isinstance(old, str) and old in new else ""
    return added.count("\n") > 1 and added in text


def _patch(text, old, new):
    """(patched text, replacements made); 0 replacements if already applied."""
    if isinstance(old, re.Pattern):
        return old.subn(new.replace("\\", "\\\\"), text)
    if old in new:  # an insertion: applied once `new` is there
        return text.replace(old, new), (0 if _applied(text, old, new) else text.count(old))
    return text.replace(old, new), text.count(old)


def plan(root):
    """Everything a run would do, without touching the tree.

    Returns (writes {rel: bytes}, deletes [rel], changed [msg], moved [msg])."""
    root = pathlib.Path(root)
    changed, moved, texts = [], [], {}
    key, why_not = read_server_key(SERVER_KEY_FILE)
    if why_not:
        moved.append(f"{SERVER_KEY_FILE.name}: server key {why_not}")
    for rel, old, new, why in PATCHES + server_patches(key or "<no server key>"):
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
        elif not _applied(text, old, new):
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
        missing = "".join(f'        ("{k}", ""),\n' for k in LANG_KEYS if f'("{k}", ' not in text2)
        if missing:
            text2 = LANG_END.sub(lambda m: "),\n" + missing + m.group(1), text2, count=1)
        if text2 != text:
            texts[rel] = (text2, crlf)
            changed.append(f"{rel}: translations say {DISPLAY_NAME}, new keys (not-found error, tickets 05/06)")
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
