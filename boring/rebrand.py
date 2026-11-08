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
MAC_BUNDLE = f"{DISPLAY_NAME}.app"     # v1.7 t17: the Mac app file people see; its exe stays APP_NAME
OLD_MAC_BUNDLE = f"{APP_NAME}.app"     # 1.6.x's, moved once by libs/base/src/bundle_move.rs
WINDOWS_RULE = f"{DISPLAY_NAME} Service"  # t17: Windows firewall rule and service display name
AGENT_ID = "io.boringlabs.remote.agent"   # app bundle + LaunchAgent (TCC holder)
HOSTD_ID = "io.boringlabs.remote.hostd"   # root LaunchDaemon
ORG = "io.boringlabs"                      # Mac config dir: ~/Library/Preferences/io.boringlabs.BoringRemote
FORK_URL = "https://boringlabs.online/remote/source/"  # our source page: one tarball per version (AGPL 6, 13)
UPDATE_PAGE_URL = "https://boringlabs.online/remote/update"  # where buyers get a new version; update_notice_banner.dart
# Ticket 32. The one place RustDesk is named (AGPL 5(d)): this literal, in the kit's Legal dialog, opened from the
# plain Legal item on the About page. check.py wants the literal there and nowhere else.
LEGAL_DART = "flutter/lib/desktop/kit/legal.dart"
LEGAL_CREDIT = "Boring Remote is based on RustDesk, \u00a9 Purslane Tech Pte. Ltd."
LICENCE_ASSET = "flutter/assets/LICENCE.txt"  # the license text, bundled so Legal can show it with no network
# Tailscale's address ranges, both tailnet-only: IPv4 CGNAT and the IPv6 ULA a
# MagicDNS AAAA answer points at. The listener is dual-stack, so v4 peers arrive
# as ::ffff:100.x and connection.rs normalises them with try_into_v4 first.
TAILNET = "100.64.0.0/10,fd7a:115c:a1e0::/48"
# ADR 0003: the private LAN is allowed too (RFC 1918, IPv6 ULA and link-local),
# so Macs on the same network connect Direct. Public addresses stay blocked.
PRIVATE_LAN = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,fe80::/10"
WHITELIST = f"{TAILNET},{PRIVATE_LAN}"

# What the connect box says (v1.7 t03, ADRs 0004/0005), in plain words with one next step. The
# text lives in libs/base/src/direct_link.rs. boring-remote (v1.7 t26): the Target can be a Mac or a
# PC, so "computer" on both builds. These are the translation keys (src/lang/*.rs, English
# everywhere) and what check.py compares the Rust constants with.
NOT_FOUND = "Couldn't find a computer with that name. Pick it from the list, or check the spelling and try again."
NOT_ON_NETWORK = "Couldn't reach that computer. Make sure it's awake and on the same network as this one, then try again."
PLAINTEXT_REFUSED = "That computer needs the latest Boring Remote. Update Boring Remote on that computer, then try again."
IDENTITY_CHANGED = ("This isn't the computer you connected to before, so Boring Remote stopped. If that computer was "
                    "reinstalled, open Settings, click Trusted list, click Forget next to it, "
                    "then try again.")
NO_ADDRESS = ("Boring Remote doesn't know where that computer is yet. Type its name or address in the box, "
              "then try again.")
CONNECT_ERRORS = {"NOT_FOUND": NOT_FOUND, "NOT_ON_THIS_NETWORK": NOT_ON_NETWORK, "NO_ADDRESS": NO_ADDRESS,
                  "PLAINTEXT_REFUSED": PLAINTEXT_REFUSED, "IDENTITY_CHANGED": IDENTITY_CHANGED}
CONNECT_ERROR_KEYS = list(CONNECT_ERRORS.values())

# Replaces _start's IP and domain:port branches in src/client.rs. check.py looks for
# exactly this block and that nothing before it reaches the ID/rendezvous path.
DIRECT_LINK_CALL = (
    "        // boring-remote (v1.7 t03): every peer is a name or IP for a Direct Link, never an\n"
    "        // ID. base::direct_link dials the Target's own address, then its Tailscale address,\n"
    "        // else \"Not on this network\"; always encrypted or refused, Tailscale too (ADR 0004,\n"
    "        // 0005). There is no rendezvous server, so the ID path below can't be reached.\n"
    "        if true {\n"
    "            let (stream, path, pk) = base::direct_link::connect(peer, CONNECT_TIMEOUT).await?;\n"
    "            return Ok((\n"
    "                (stream, true, pk, None, path.stream_type()),\n"
    "                (0, \"\".to_owned()),\n"
    "                false,\n"
    "            ));\n"
    "        }\n")

GUARD = "if true { return; } // boring-remote: stripped"
GUARD_OK = "if true { return Ok(()); } // boring-remote: stripped"

LOCKED = {  # OVERWRITE_SETTINGS: wins over the user's config file, UI shows them fixed
    "whitelist": WHITELIST,
    "direct-server": "Y",
    "custom-rendezvous-server": "",
    "relay-server": "",
    "api-server": "",
    "allow-auto-update": "N",
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


# Audit H3: a bundle root runs is root:wheel and not group/other-writable (install.scpt,
# upstream's update.scpt and update_me; install-update.sh's lock_bundle is ours).
H3_BUNDLE_Q = f'quoted form of "/Applications/{MAC_BUNDLE}"'
H3_INSTALL_LOCK = (
    "  -- boring-remote (audit H3): the root daemon runs this bundle, so no user may change it.\n"
    f"  set bundle_q to {H3_BUNDLE_Q}\n"
    '  set sh0 to "chown -R root:wheel " & bundle_q & " && chmod -R go-w " & bundle_q & " || exit 1;"\n'
    "\n  set sh to sh0 & sh1 & sh2 & sh3 & sh4 & sh5\n")
H3_STAFF_SCPT = '" && chown -R " & quoted form of user & ":staff " & quoted form of app_bundle & "'
H3_ROOT_SCPT = '" && chown -R root:wheel " & quoted form of app_bundle & " && chmod -R go-w " & quoted form of app_bundle & "'
H3_STAFF_ME = '" && chown -R " & user_name_q & ":staff " & app_bundle_q & "'
H3_ROOT_ME = '" && chown -R root:wheel " & app_bundle_q & " && chmod -R go-w " & app_bundle_q & "'

HBB = "libs/hbb_common/src/config.rs"
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
     f"PRODUCT_NAME = {DISPLAY_NAME}\nEXECUTABLE_NAME = {APP_NAME}\nPRODUCT_MODULE_NAME = {APP_NAME}\n",
     "Mac .app is Boring Remote.app (t17); exe and Swift module keep the internal name"),
    ("flutter/macos/Runner/Configs/AppInfo.xcconfig",
     "PRODUCT_BUNDLE_IDENTIFIER = com.carriez.flutterHbb",
     f"PRODUCT_BUNDLE_IDENTIFIER = {AGENT_ID}", "Mac bundle id (xcconfig)"),
    ("flutter/macos/Runner.xcodeproj/project.pbxproj",
     "PRODUCT_BUNDLE_IDENTIFIER = com.carriez.rustdesk;",
     f"PRODUCT_BUNDLE_IDENTIFIER = {AGENT_ID};", "Mac bundle id (project)"),
    ("flutter/macos/Runner.xcodeproj/project.pbxproj", "path = RustDesk.app;", f'path = "{MAC_BUNDLE}";',
     "Mac product reference (quoted: the name has a space)"),
    ("flutter/macos/Runner.xcodeproj/project.pbxproj", "RustDesk.app", MAC_BUNDLE, "Mac product reference"),
    ("flutter/macos/Runner.xcodeproj/xcshareddata/xcschemes/Runner.xcscheme",
     'BuildableName = "RustDesk.app"', f'BuildableName = "{MAC_BUNDLE}"', "Mac scheme"),
    ("flutter/macos/Runner/Info.plist",
     "<key>CFBundleName</key>\n\t<string>$(PRODUCT_NAME)</string>",
     f"<key>CFBundleName</key>\n\t<string>{DISPLAY_NAME}</string>\n"
     f"\t<key>CFBundleDisplayName</key>\n\t<string>{DISPLAY_NAME}</string>",
     "Mac display name (menu bar, About panel, Finder)"),
    ("flutter/macos/Podfile", "    flutter_additional_macos_build_settings(target)\n",
     "    flutter_additional_macos_build_settings(target)\n"
     "    target.build_configurations.each { |c| c.build_settings['MACOSX_DEPLOYMENT_TARGET'] = '12.3' }\n",
     "pods at macOS 12.3 (Xcode 27 rejects pod targets below 12.0)"),
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
    ("build.py", "cp -rf ../target/release/service ./build/macos/Build/Products/Release/RustDesk.app/Contents/MacOS/",
     f'cp -rf ../target/release/service "./build/macos/Build/Products/Release/{MAC_BUNDLE}/Contents/MacOS/"',
     "Mac service binary copy"),
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
        # t17: the app file is "Boring Remote.app"; the exe in it keeps the internal name
        ("agent.plist", "/Applications/RustDesk.app/", f"/Applications/{MAC_BUNDLE}/", "agent runs Boring Remote.app"),
        ("agent.plist", "Contents/MacOS/RustDesk</string>", f"Contents/MacOS/{APP_NAME}</string>", "agent exe"),
        # t17: --server comes back after any exit; with SuccessfulExit=false, macOS's "Quit & Reopen"
        # (after granting Screen Recording) left it down for good
        ("agent.plist", "        <key>KeepAlive</key>\n        <dict>\n            <key>SuccessfulExit</key>\n"
         "            <false />\n            <key>AfterInitialDemand</key>\n            <false />\n        </dict>\n",
         "        <key>KeepAlive</key>\n        <true/>\n", "agent always comes back"),
        ("daemon.plist", "com.carriez.RustDesk_service", HOSTD_ID, "LaunchDaemon label"),
        ("daemon.plist", "<string>com.carriez.rustdesk</string>", f"<string>{AGENT_ID}</string>", "daemon bundle id"),
        # t17: run the service directly; through `sh -c` the space in the path splits the command
        ("daemon.plist", "        <string>/bin/sh</string>\n        <string>-c</string>\n"
         "        <string>/Applications/RustDesk.app/Contents/MacOS/service</string>\n",
         f"        <string>/Applications/{MAC_BUNDLE}/Contents/MacOS/service</string>\n", "hostd runs the service, no sh -c"),
        ("daemon.plist", "/Applications/RustDesk.app/", f"/Applications/{MAC_BUNDLE}/", "hostd working directory"),
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
        ("update.scpt", '"/Applications/RustDesk.app"', f'"/Applications/{MAC_BUNDLE}"', "upstream updater bundle path"),
        # audit H3: the root LaunchDaemon runs the bundle, so no user may write it. Installing the
        # daemon makes it root:wheel and not group/other-writable first, or installs nothing.
        ("install.scpt", "  set sh to sh1 & sh2 & sh3 & sh4 & sh5\n", H3_INSTALL_LOCK, "daemon install locks the bundle (audit H3)"),
        ("update.scpt", H3_STAFF_SCPT, H3_ROOT_SCPT, "upstream updater leaves the bundle root-owned (audit H3)"),
        # ours (Install update, slice 6): same label as daemon.plist, from the same constant
        ("install-update.sh", 'SERVICE_LABEL="com.carriez.RustDesk_service"', f'SERVICE_LABEL="{HOSTD_ID}"',
         "LaunchDaemon label (install update)"),
        ("install-update.sh", 'AGENT_LABEL="com.carriez.RustDesk_server"', f'AGENT_LABEL="{AGENT_ID}"',
         "LaunchAgent label (bundle move, t17)"),
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
    # --- Direct Link (v1.7 t03): the connect box takes a name or IP, never an ID ------
    ("src/client.rs",
     "        // to-do: remember the port for each peer, so that we can retry easier\n"
     "        if hbb_common::is_ip_str(peer) {\n"
     "            return Ok((\n"
     "                (\n"
     "                    connect_tcp_local(check_port(peer, RELAY_PORT + 1), None, CONNECT_TIMEOUT)\n"
     "                        .await?,\n"
     "                    true,\n"
     "                    None,\n"
     "                    None,\n"
     "                    \"TCP\",\n"
     "                ),\n"
     "                (0, \"\".to_owned()),\n"
     "                false,\n"
     "            ));\n"
     "        }\n"
     "        // Allow connect to {domain}:{port}\n"
     "        if hbb_common::is_domain_port_str(peer) {\n"
     "            return Ok((\n"
     "                (\n"
     "                    connect_tcp_local(peer, None, CONNECT_TIMEOUT).await?,\n"
     "                    true,\n"
     "                    None,\n"
     "                    None,\n"
     "                    \"TCP\",\n"
     "                ),\n"
     "                (0, \"\".to_owned()),\n"
     "                false,\n"
     "            ));\n"
     "        }\n",
     DIRECT_LINK_CALL,
     "every peer is a Direct Link: own address, then Tailscale, else Not on this network; no ID path"),
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
     "whitelist, Direct IP, empty servers, no auto update"),
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

# --- v1.7 t17: the Mac app file is "Boring Remote.app" ---------------------------
# What runs from /Applications names the new bundle; 1.6.x's bundle still counts as installed
# (and its exe as the user server) until libs/base/src/bundle_move.rs moves it. Upstream's
# updater (update_me, update_from_dmg_as_root, update_extracted) is dead code here and keeps
# its paths. Windows: only what people read changes; exe, install dir and service name stay.
MAC_INSTALLED = (
    "pub fn is_installed() -> bool {\n"
    "    if let Ok(p) = std::env::current_exe() {\n")
IPC_AUTH_OLD = (
    "    let expected_path = PathBuf::from(format!(\n"
    "        \"/Applications/{}.app/Contents/MacOS/{}\",\n"
    "        crate::get_app_name(),\n"
    "        crate::get_app_name()\n"
    "    ));\n"
    "    let Ok(expected_path) = fs::canonicalize(expected_path) else {\n"
    "        return false;\n"
    "    };\n"
    "    paths_refer_to_same_file(&peer_exe, &expected_path)\n")
WIN_SC_NAME = 'start= auto DisplayName= \\"{app_name} Service\\"'
WIN_FW_DELETE = '    netsh advfirewall firewall delete rule name=\\"{app_name} Service\\"\n'
PATCHES += [
    # 2026-11-02: Settings is a gear, not upstream's three-line menu icon (Mac and Windows tab bar).
    ("flutter/lib/desktop/pages/desktop_tab_page.dart", "                  icon: IconFont.menu,\n",
     "                  icon: Icons.settings_outlined, // boring-remote (v1.7 t17): a gear opens Settings\n",
     "Settings button is a gear"),
    ("src/platform/macos.rs", H3_STAFF_ME, H3_ROOT_ME, "upstream update_me leaves the bundle root-owned (audit H3)"),
    ("src/platform/macos.rs", MAC_INSTALLED,
     MAC_INSTALLED + f"        // boring-remote (v1.7 t17): {MAC_BUNDLE}; 1.6.x's name below counts until it moves.\n"
     f'        if p.starts_with("/Applications/{MAC_BUNDLE}") {{\n            return true;\n        }}\n',
     "the new bundle counts as installed"),
    ("src/platform/macos.rs", '.arg(&format!("/Applications/{}.app", crate::get_app_name()))',
     f'.arg("/Applications/{MAC_BUNDLE}")', "reopen the app from the new bundle"),
    ("src/ipc.rs", '.arg(&format!("/Applications/{}.app", crate::get_app_name()))',
     f'.arg("/Applications/{MAC_BUNDLE}")', "reopen the app from the new bundle"),
    ("src/ipc/auth.rs", IPC_AUTH_OLD,
     f"    // boring-remote (v1.7 t17): {MAC_BUNDLE}, or 1.6.x's bundle until bundle_move moves it.\n"
     f'    ["{MAC_BUNDLE}", "{OLD_MAC_BUNDLE}"].iter().any(|bundle| {{\n'
     '        fs::canonicalize(format!("/Applications/{}/Contents/MacOS/{}", bundle, crate::get_app_name()))\n'
     "            .is_ok_and(|expected_path| paths_refer_to_same_file(&peer_exe, &expected_path))\n"
     "    })\n",
     "the user server may run from the new bundle (or the old one until it moves)"),
    # v1.7 t05: encoder threads. Upstream caps them at free RAM GB / 2, so a PC with 3 GB free
    # encoded 3440x1440 VP9 on 1 thread (9 fps, device check 2026-11-03). A thread needs MBs, not GBs.
    ("libs/scrap/src/common/codec.rs", "    res = std::cmp::min(res, memory as usize / 2);",
     "    if memory < 1 { res = 1; } // boring-remote (v1.7 t05): RAM only limits threads when under 1 GB is free",
     "encoder threads follow the CPU, not free RAM"),
    ("libs/scrap/src/common/codec.rs",
     "        res = 0;\n        let percent = base::platform::windows::cpu_uage_one_minute();",
     "        res = max / 2; // boring-remote (v1.7 t05): no CPU sample yet (None) counts as idle, not 1 thread\n"
     "        let percent = base::platform::windows::cpu_uage_one_minute();",
     "encoder threads: no CPU sample yet on Windows counts as idle"),
    ("libs/scrap/src/common/codec.rs", "        _ if res >= 4 => 4,",
     "        _ if res >= 4 => res, // boring-remote (v1.7 t05): keep 4-7 threads, a 12-thread PC gets 6 not 4",
     "encoder threads: no rounding down from 6 to 4"),
    # Windows, what people read
    ("res/msi/CustomActions/FirewallRules.cpp", 'L"%ls Service", exeName);',
     f'L"{WINDOWS_RULE}"); // boring-remote (v1.7 t17): what people read, not the exe name',
     "MSI firewall rule display name"),
    ("res/msi/CustomActions/CustomActions.cpp", 'L"%ls Service", svcName);',
     f'L"{WINDOWS_RULE}"); // boring-remote (v1.7 t17): what people read, not the service name',
     "MSI service display name"),
    ("src/platform/windows.rs", 'firewall add rule name=\\"{app_name} Service\\"',
     f'firewall add rule name=\\"{WINDOWS_RULE}\\"', "self-install firewall rule display name"),
    ("src/platform/windows.rs", WIN_FW_DELETE,
     WIN_FW_DELETE + f'    netsh advfirewall firewall delete rule name=\\"{WINDOWS_RULE}\\"\n',
     "uninstall removes the rule under both names"),
    ("src/platform/windows.rs", WIN_SC_NAME, f'start= auto DisplayName= \\"{WINDOWS_RULE}\\"',
     "self-install service display name"),
    ("src/platform/windows.rs", 'reg add {subkey} /f /v DisplayName /t REG_SZ /d \\"{app_name}\\"',
     f'reg add {{subkey}} /f /v DisplayName /t REG_SZ /d \\"{DISPLAY_NAME}\\"', "Apps list name (self-install)"),
    ("src/platform/windows.rs", 'reg add {subkey} /f /v Publisher /t REG_SZ /d \\"{app_name}\\"',
     f'reg add {{subkey}} /f /v Publisher /t REG_SZ /d \\"{DISPLAY_NAME}\\"', "Apps list publisher (self-install)"),
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
# our source page. RustDesk is named once: LEGAL_CREDIT in the kit's Legal dialog.
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
ABOUT_NEW = ("              InkWell(\n"  # ticket 32: one plain item; the notices live in the dialog it opens
             "                  onTap: () => showLegalDialog(context),\n"
             "                  child: Text(\n"
             "                    LegalWords.title,\n"
             "                    style: linkStyle,\n"
             "                  ).marginSymmetric(vertical: 4.0)),\n")
PATCHES += [
    # About page: one plain Legal item, no logo, no other links, no RustDesk blue
    (SETTINGS, "translate('About RustDesk')", f"'About {DISPLAY_NAME}'", "About title"),
    (SETTINGS, ABOUT_OLD, ABOUT_NEW, "About: privacy/website links and copyright block become the Legal item"),
    (SETTINGS, "import '../../common/widgets/login.dart';\n",
     "import '../../common/widgets/login.dart';\nimport 'package:flutter_hbb/desktop/kit/legal.dart';\n",
     "Legal dialog import"),
    # links: none to RustDesk; the few that need a target point at our own pages
    ("flutter/lib/common.dart", "  if (bind.mainGetBuildinOption(key: \"hide-powered-by-me\") == 'Y') {\n",
     "  if (true) {  // boring-remote: no powered-by line\n", "no 'Powered by' line"),
    ("flutter/lib/common.dart", "        launchUrl(Uri.parse('https://rustdesk.com'));\n",
     f"        launchUrl(Uri.parse('{FORK_URL}'));\n", "powered-by link"),
    ("flutter/lib/common/widgets/toolbar.dart", "'https://github.com/rustdesk/rustdesk/issues/14586'",
     f"'{FORK_URL}'", "Wayland keyboard help link"),
    ("flutter/lib/desktop/pages/connection_page.dart", '"https://rustdesk.com/pricing"', f'"{FORK_URL}"',
     "public-server guide link"),
    (HOME, "'https://rustdesk.com/download'", f"'{UPDATE_PAGE_URL}'", "download link"),
    (HOME, "'https://github.com/rustdesk/rustdesk/releases/tag/${bind.mainGetNewVersion()}'",
     f"'{UPDATE_PAGE_URL}'", "changelog link"),
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

# --- Rust hooks for v1.7 (tickets 02-05; ADRs 0003-0006) ---------------------------
# Our logic lives in new files in libs/base/src (direct_link, trust, lan, high_efficiency,
# update_feed; their tests run from libs/base/tests/boring.rs). These patches only wire it into
# upstream: base's mod lines, the Direct Link listener and handshake (server side), the trust
# skip and grant, the High Efficiency marker and answer, the Controller's ask and badge, LAN
# Discovery's name and end of cycle. check.py asserts each hook text below landed.
BASE_LIB = "libs/base/src/lib.rs"
SERVER = "src/server.rs"
CONN = "src/server/connection.rs"
IO_LOOP = "src/client/io_loop.rs"
MEDIATOR = "src/rendezvous_mediator.rs"
BASE_MODS = ("// boring-remote (v1.7): ours, see libs/base/tests/boring.rs\n"
             "pub mod bundle_move;\npub mod direct_link;\npub mod high_efficiency;\npub mod lan;\npub mod trust;\npub mod update_feed;\n")
# Target: the direct listener asks for encryption on every Direct Link, Tailscale too (ADR 0005,
# 0004 amendment: a 100.64/10 address proves nothing about WireGuard) and marks it a Direct Link.
T03_LISTENER = (
    "                // boring-remote: every Direct Link is encrypted, Tailscale too (ADR 0005, 0004 amendment).\n"
    "                tokio::spawn(async move {\n"
    "                    allow_err!(\n"
    "                        crate::server::create_tcp_connection(\n"
    "                            server,\n"
    "                            hbb_common::Stream::from(stream, local_addr),\n"
    "                            addr,\n"
    "                            true,\n"
    "                            ConnectionMeta {\n"
    "                                direct_link: true,\n"
    "                                ..Default::default()\n"
    "                            }, // Direct connections don't have server-side user context.\n")
T03_META_FIELDS = (
    "    /// boring-remote: an encrypted Direct Link (v1.7 t03, ADR 0005), see base::direct_link.\n"
    "    pub direct_link: bool,\n"
    "    /// boring-remote: what the Direct Link trust exchange found (v1.7 t04), see base::trust.\n"
    "    pub trust: base::trust::Admission,\n")
# Target: announce + signed handshake + trust exchange, raced against eviction as upstream's was.
T03_HANDSHAKE_CALL = (
    "    let direct_link = meta.direct_link;\n"
    "    let trust = tokio::select! {\n"
    "        handshake = boring_direct_link_handshake(&mut stream, secure, direct_link) => handshake?,\n"
    "        _ = unauthorized.evicted() => {\n"
    "            bail!(\"evicted to make room for a newer unauthenticated connection\");\n"
    "        }\n"
    "    };\n"
    "    if direct_link {\n"
    "        base::direct_link::require_encrypted(addr.ip(), &stream)?;\n"
    "    }\n"
    "    let meta = ConnectionMeta { trust, ..meta };\n")
T03_HANDSHAKE_FN = (
    "/// boring-remote (v1.7 t03): a Direct Link first announces our identity key and Tailscale\n"
    "/// address (base::direct_link::announce), then runs the usual signed handshake, then the trust\n"
    "/// exchange inside the keyed stream (v1.7 t04, base::trust).\n"
    "async fn boring_direct_link_handshake(\n"
    "    stream: &mut Stream,\n"
    "    secure: bool,\n"
    "    direct_link: bool,\n"
    ") -> ResultType<base::trust::Admission> {\n"
    "    if direct_link {\n"
    "        // Listing interfaces blocks: off the async path, once per Direct Link.\n"
    "        let tailscale = tokio::task::spawn_blocking(boring_tailscale_ip).await.unwrap_or_default();\n"
    "        base::direct_link::announce(stream, &Config::get_key_pair().1, tailscale).await?;\n"
    "    }\n"
    "    identity_handshake(stream, secure).await?;\n"
    "    if direct_link && stream.is_secured() {\n"
    "        return base::trust::answer(stream, &base::trust::Trusted::load(), CONNECT_TIMEOUT).await;\n"
    "    }\n"
    "    Ok(Default::default())\n"
    "}\n"
    "\n"
    "fn boring_tailscale_ip() -> Option<std::net::IpAddr> {\n"
    "    default_net::get_interfaces()\n"
    "        .iter()\n"
    "        .flat_map(|i| i.ipv4.iter().map(|a| std::net::IpAddr::V4(a.addr)))\n"
    "        .find(|ip| base::direct_link::is_tailscale(*ip))\n"
    "}\n"
    "\n")
# "Always ask for password" (base::trust): a Trusted Controller switched on gets in by this Mac's
# Unattended Password and nothing else, whatever the approve mode. Click-only or Both: no ask is
# shown, so nobody here can click it in (a Trusted one skipped approve mode before, this only
# narrows that). A one-time code or a recent session is refused: validate_password tries the
# one-time code first, so only PermanentPassword counts. Wrong or none goes through upstream's
# per-address attempt limits and one-time-code rotation, exactly as its own password branch.
T04_ALWAYS_ASK = (
    "            // boring-remote: a Trusted Controller switched to \"Always ask for password\" gets in by\n"
    "            // this Mac's Unattended Password and nothing else, whatever the approve mode: not its\n"
    "            // token, a click here (no ask is shown), a one-time code or a recent session.\n"
    "            if self.boring_trust.always_ask() {\n"
    "                if !(password::permanent_enabled() || allow_logon_screen_password)\n"
    "                    || !Config::has_permanent_password()\n"
    "                {\n"
    "                    self.send_login_error(base::trust::NO_UNATTENDED_PASSWORD).await;\n"
    "                    sleep(1.).await;\n"
    "                    return false;\n"
    "                }\n"
    "                // None yet: the Controller is already asking its person for it (client.rs handle_hash).\n"
    "                if lr.password.is_empty() {\n"
    "                    return true;\n"
    "                }\n"
    "                let (failure, res) = self.check_failure(0).await;\n"
    "                if !res {\n"
    "                    return true;\n"
    "                }\n"
    "                if self.validate_password(allow_logon_screen_password)\n"
    "                    && self.conn_audit_primary_auth == ConnAuditPrimaryAuth::PermanentPassword\n"
    "                {\n"
    "                    self.update_failure_with_scope(failure, true, 0, FailureScope::Default);\n"
    "                    self.boring_trust.unattended_password_right();\n"
    "                    if !self.send_logon_response_and_keep_alive().await {\n"
    "                        return false;\n"
    "                    }\n"
    "                    self.try_start_cm(lr.my_id, lr.my_name, self.authorized);\n"
    "                } else {\n"
    "                    self.update_failure_with_scope(failure, false, 0, FailureScope::Default);\n"
    "                    self.check_update_temporary_password(false);\n"
    "                    self.send_login_error(crate::client::LOGIN_MSG_PASSWORD_WRONG)\n"
    "                        .await;\n"
    "                }\n"
    "                return true;\n"
    "            }\n")
# The last word before any sign-in lets a session in (Admission::may_let_in): an always-ask one
# that has not given the Unattended Password stays out, whatever got it there (Authorize from a
# click, switch sides, a sign-in path upstream adds later).
T04_ALWAYS_ASK_GATE = (
    "        // boring-remote: an always-ask Trusted Controller gets in only once its Unattended\n"
    "        // Password checked out, whatever brought it here (base::trust::Admission::may_let_in).\n"
    "        if !self.boring_trust.may_let_in() {\n"
    "            self.send_login_error(base::trust::ASKS_EVERY_TIME).await;\n"
    "            sleep(1.).await;\n"
    "            return false;\n"
    "        }\n")
T04_ALWAYS_ASK_GATE_AT = ("    async fn send_logon_response_and_keep_alive(&mut self) -> bool {\n"
                          "        if self.authorized {\n            return true;\n        }\n")
# Target: tells a Boring Remote Controller it always asks, so it keeps no password for it. Any
# other Controller ignores the key; nothing in the protocol changes (protocol.sha256 holds).
T04_ALWAYS_ASK_MARK = (
    "        // boring-remote: tells a Boring Remote Controller this Mac always asks it for the\n"
    "        // Unattended Password, so it keeps none (base::trust::ALWAYS_ASK_MARKER).\n"
    "        #[cfg(any(target_os = \"linux\", target_os = \"windows\", target_os = \"macos\"))]\n"
    "        if self.boring_trust.always_ask() {\n"
    "            platform_additions.insert(base::trust::ALWAYS_ASK_MARKER.into(), json!(true));\n"
    "        }\n")
# Controller: no password kept for a Target that always asks, typed with Remember on or saved
# before the switch; the next connect asks its person again.
T04_ALWAYS_ASK_FORGET = (
    "        // boring-remote: the Target always asks this computer for its Unattended Password\n"
    "        // (base::trust::ALWAYS_ASK_MARKER), so none is kept for it, remembered or not.\n"
    "        if base::trust::asks_every_time(&pi.platform_additions) {\n"
    "            config.password = Default::default();\n"
    "        }\n")
T04_ALWAYS_ASK_FORGET_AT = "        if let Some((_, b, c)) = self.other_server.as_ref() {\n            if b != PUBLIC_SERVER {\n"
# Review follow-up L1: a Controller switched to always ask while it is in, without having given
# the Unattended Password, is let go at the next second (base::trust::Admission::lost_trust).
T04_ALWAYS_ASK_KICK_AT = "                _ = second_timer.tick() => {\n"
T04_ALWAYS_ASK_KICK = (
    "                    // boring-remote: switched to always ask in Settings after it got in without the\n"
    "                    // Unattended Password: this session ends now (base::trust).\n"
    "                    if conn.authorized && conn.boring_trust.lost_trust() {\n"
    "                        conn.send_close_reason_no_retry(base::trust::ASKS_EVERY_TIME).await;\n"
    "                        conn.on_close(\"always ask for password\", true).await;\n"
    "                        break;\n"
    "                    }\n")
# Review re-check: an IP tunnel runs in its own loop (try_port_forward_loop), not the session
# loop above, so it gets the same check, once a second, and closes.
T04_ALWAYS_ASK_TUNNEL_TIMER_AT = "            let mut hbbs_rx = crate::hbbs_http::sync::signal_receiver();\n            loop {\n"
T04_ALWAYS_ASK_TUNNEL_TIMER = (
    "            // boring-remote: a tunnel switched to always ask is closed too (base::trust).\n"
    "            let mut boring_trust_check = crate::rustdesk_interval(time::interval(Duration::from_secs(1)));\n")
T04_ALWAYS_ASK_TUNNEL_AT = "                    _ = self.timer.tick() => {\n                        if last_recv_time.elapsed() >= H1 {\n"
T04_ALWAYS_ASK_TUNNEL = (
    "                    // boring-remote: switched to always ask after it got in without the Unattended\n"
    "                    // Password: the tunnel closes, as a session does (base::trust).\n"
    "                    _ = boring_trust_check.tick() => {\n"
    "                        if self.boring_trust.lost_trust() {\n"
    "                            bail!(\"{}\", base::trust::ASKS_EVERY_TIME);\n"
    "                        }\n"
    "                    }\n")
# Review follow-up L2: the Trusted list has one writer, the service. Settings' Remove, Allow and
# Always ask go over ipc as an edit (base::trust::edit, one locked read-modify-write on the live
# list) and wait for its answer; a settings window's whole-options write never carries its stale
# copy of the list (keep_trusted_list).
T04_EDIT_IPC_AT = ('                    allow_err!(stream.send(&Data::Config((name.clone(), Some(ack)))).await);\n'
                   '                } else if name == "salt" {\n')
T04_EDIT_IPC = (
    "                } else if name == base::trust::EDIT_CONFIG {\n"
    "                    // boring-remote: Settings' Remove, Allow and \"Always ask for password\", one locked\n"
    "                    // edit of the Trusted list here in the service; its answer goes back (base::trust).\n"
    "                    let answer = base::trust::edit(&value);\n"
    "                    allow_err!(stream.send(&Data::Config((name.clone(), Some(answer)))).await);\n")
T04_KEEP_LIST_OLD = "                Config::set_options(value);\n                allow_err!(stream.send(&Data::Options(None)).await);\n"
T04_KEEP_LIST = (
    "                // boring-remote: the Trusted list in a settings window's whole-options write is its\n"
    "                // stale copy; the service's own stays (base::trust::keep_trusted_list).\n"
    "                Config::set_options(base::trust::keep_trusted_list(value));\n"
    "                allow_err!(stream.send(&Data::Options(None)).await);\n")
T04_EDIT_ASK_AT = '#[tokio::main(flavor = "current_thread")]\npub async fn set_permanent_password_with_ack('
T04_EDIT_ASK = (
    "/// boring-remote: Settings' Trusted list edit, done by the service (base::trust::edit): its\n"
    "/// answer, or a refusal saying it didn't answer. The edit can carry a password: never logged.\n"
    "#[tokio::main(flavor = \"current_thread\")]\n"
    "pub async fn boring_trust_edit(edit: String) -> String {\n"
    "    match boring_trust_edit_async(edit).await {\n"
    "        Ok(answer) => {\n"
    "            // Always ask turned the salt over: the user config's copy follows, as after a\n"
    "            // password change.\n"
    "            if let Err(err) = sync_permanent_password_storage_from_daemon_async().await {\n"
    "                log::warn!(\"Failed to sync permanent password storage from daemon: {err}\");\n"
    "            }\n"
    "            answer\n"
    "        }\n"
    "        Err(err) => {\n"
    "            log::warn!(\"Trusted list edit: no answer from the service: {err}\");\n"
    "            serde_json::json!({ \"ok\": false, \"error\": base::trust::NO_SERVICE }).to_string()\n"
    "        }\n"
    "    }\n"
    "}\n"
    "\n"
    "async fn boring_trust_edit_async(edit: String) -> ResultType<String> {\n"
    "    let ms_timeout = 5_000;\n"
    "    let mut c = connect(ms_timeout, \"\").await?;\n"
    "    c.send_config(base::trust::EDIT_CONFIG, edit).await?;\n"
    "    if let Some(Data::Config((name, Some(answer)))) = c.next_timeout(ms_timeout).await? {\n"
    "        if name == base::trust::EDIT_CONFIG {\n"
    "            return Ok(answer);\n"
    "        }\n"
    "    }\n"
    "    bail!(\"no answer\")\n"
    "}\n"
    "\n")
T04_EDIT_FFI = (
    "/// boring-remote: Settings' Remove, Allow and \"Always ask for password\" (base::trust::edit),\n"
    "/// done by the service; returns its answer. Blocking ipc, so it runs on a bridge worker.\n"
    "pub fn boring_trust_edit(edit: String) -> String {\n"
    "    #[cfg(not(any(target_os = \"android\", target_os = \"ios\")))]\n"
    "    return crate::ipc::boring_trust_edit(edit);\n"
    "    #[cfg(any(target_os = \"android\", target_os = \"ios\"))]\n"
    "    return base::trust::edit(&edit);\n"
    "}\n\n")
T04_TRUSTED_SKIP = T04_ALWAYS_ASK + (
    "            // boring-remote (v1.7 t04): only a token this Mac issued skips the ask (ADR 0005).\n"
    "            if self.boring_trust.is_trusted() {\n"
    "                if !self.send_logon_response_and_keep_alive().await {\n"
    "                    return false;\n"
    "                }\n"
    "                self.try_start_cm(lr.my_id, lr.my_name, self.authorized);\n"
    "                return true;\n"
    "            }\n"
    "            // A Controller removed from Trusted Controllers waits for Allow here, whatever\n"
    "            // password it brings: Remove is not undone quietly (device check A2 step 5).\n"
    "            if self.boring_trust.must_ask() {\n"
    "                self.try_start_cm(lr.my_id, lr.my_name, false);\n"
    "                self.send_login_error(crate::client::LOGIN_MSG_NO_PASSWORD_ACCESS)\n"
    "                    .await;\n"
    "                return true;\n"
    "            }\n")
# ADR 0005: Allow here or the Unattended Password makes a Controller Trusted; a one-time code
# (or the recent-session password) lets it in for this session only.
T04_GRANT = (
    "        // boring-remote (v1.7 t04): Allow or the Unattended Password = Trusted; a one-time code\n"
    "        // is this session only (ADR 0005).\n"
    "        self.boring_trust.approve(\n"
    "            match self.conn_audit_primary_auth {\n"
    "                ConnAuditPrimaryAuth::Click => base::trust::SignIn::Allowed,\n"
    "                ConnAuditPrimaryAuth::PermanentPassword => base::trust::SignIn::UnattendedPassword,\n"
    "                _ => base::trust::SignIn::ThisSessionOnly,\n"
    "            },\n"
    "            &self.lr.my_name,\n"
    "        );\n")
T05_MARKER = (
    "        // boring-remote (v1.7 t05): tells a Boring Remote Controller this Target is one too\n"
    "        // (base::high_efficiency::MARKER); upstream RustDesk never sends the key.\n"
    "        #[cfg(any(target_os = \"linux\", target_os = \"windows\", target_os = \"macos\"))]\n"
    "        platform_additions.insert(base::high_efficiency::MARKER.into(), json!(crate::VERSION));\n")
T05_ANSWER = (
    "                            // boring-remote (v1.7 t05): tell a Boring Remote Controller its\n"
    "                            // High Efficiency ask took; only then does its badge say so.\n"
    "                            if let Some(answer) = base::high_efficiency::ack_for(&o) {\n"
    "                                // A Retina Mac on a software codec encodes its points size, a\n"
    "                                // quarter of the pixels (ADR 0006 amendment, device check A3).\n"
    "                                #[cfg(target_os = \"macos\")]\n"
    "                                if base::high_efficiency::captures_points(matches!(\n"
    "                                    scrap::codec::Encoder::negotiated_codec(),\n"
    "                                    scrap::CodecFormat::H264 | scrap::CodecFormat::H265\n"
    "                                )) {\n"
    "                                    base::high_efficiency::POINTS_CAPTURE.hold(self.inner.id());\n"
    "                                    if let Some(s) = self.server.upgrade() {\n"
    "                                        s.write().unwrap().update_enable_retina();\n"
    "                                    }\n"
    "                                }\n"
    "                                self.send(answer).await;\n"
    "                            }\n")
# Target (macOS): upstream's Retina rule (points while two displays stream) plus High Efficiency's.
T05_RETINA_OLD = "        *scrap::quartz::ENABLE_RETINA.lock().unwrap() = video_service_count < 2;\n"
T05_RETINA = (
    "        // boring-remote (ADR 0006 amendment): High Efficiency on a software codec captures points.\n"
    "        *scrap::quartz::ENABLE_RETINA.lock().unwrap() = base::high_efficiency::POINTS_CAPTURE\n"
    "            .retina(video_service_count, self.connections.keys().copied());\n")
T05_LINK_FIELD = (
    "    // boring-remote (v1.7 t05): this round's path until the Target answers High Efficiency.\n"
    "    boring_link: Option<base::high_efficiency::Link>,\n")
T05_LINK_SET = "                self.boring_link = Some(base::high_efficiency::Link::new(stream_type, is_secured, direct)); // v1.7 t05\n"
T05_ASK_FN = (
    "    /// boring-remote (v1.7 t05, ADR 0006): on a Local Direct Link to another Boring Remote, ask\n"
    "    /// the Target for 60 fps, best quality and the best shared software codec for this session\n"
    "    /// (base::high_efficiency). The badge waits for the Target's answer.\n"
    "    async fn ask_high_efficiency(&mut self, pi: &PeerInfo, peer: &mut Stream) {\n"
    "        let ours = self.handler.lc.read().unwrap().get_supported_decoding();\n"
    "        let ask = match self.boring_link.as_mut() {\n"
    "            Some(link) if self.handler.is_default() => link.ask(pi, ours),\n"
    "            _ => None,\n"
    "        };\n"
    "        if let Some(ask) = ask {\n"
    "            if let Err(e) = peer.send(&ask).await {\n"
    "                log::warn!(\"High Efficiency not asked: {}\", e);\n"
    "            }\n"
    "        }\n"
    "    }\n"
    "\n")
T05_ASK_CALL = "                        self.ask_high_efficiency(&pi, peer).await; // v1.7 t05\n"
T05_BADGE = (
    "                    Some(misc::Union::Option(o)) => {\n"
    "                        // boring-remote (v1.7 t05): the Target applied High Efficiency.\n"
    "                        if let Some(link) = self.boring_link.as_mut() {\n"
    "                            if link.answered(&o) {\n"
    "                                self.handler.set_connection_type(\n"
    "                                    link.secured,\n"
    "                                    link.direct,\n"
    "                                    base::high_efficiency::STREAM_TYPE,\n"
    "                                );\n"
    "                            }\n"
    "                        }\n"
    "                    }\n")
T02_PONG_NAME = (
    "                                    hostname: base::lan::advertised_name(\n"
    "                                        &Config::get_option(base::lan::DEVICE_NAME_OPTION),\n"
    "                                        hostname,\n"
    "                                    ),\n")
T02_END_CYCLE = "    base::lan::end_cycle(&peers); // v1.7 t02: Home drops Macs that left; the list keeps them\n"
T02_HOME_IP = "                (\"ip\", base::lan::peer_ip(peer)), // v1.7 t02: Home's address, \"\" once it left\n"
CONTROLLER_NAME = (
    "        // boring-remote (v1.7): the Target's approval prompt names this computer, as Setup named it.\n"
    "        let mut display_name = base::lan::advertised_name(\n"
    "            &crate::ui_interface::get_option(base::lan::DEVICE_NAME_OPTION),\n"
    "            crate::common::hostname(),\n"
    "        );\n")
PATCHES += [
    (BASE_LIB, "pub mod protos;\n", "pub mod protos;\n" + BASE_MODS, "base: our v1.7 modules"),
    (MEDIATOR,
     "    ConnectionMeta {\n        control_permissions,\n        controlled_context,\n    }\n",
     "    ConnectionMeta {\n        control_permissions,\n        controlled_context,\n"
     "        ..Default::default() // boring-remote: Direct Link fields stay off here (v1.7 t03)\n    }\n",
     "rendezvous sessions are never a Direct Link"),
    (MEDIATOR,
     "                tokio::spawn(async move {\n"
     "                    allow_err!(\n"
     "                        crate::server::create_tcp_connection(\n"
     "                            server,\n"
     "                            hbb_common::Stream::from(stream, local_addr),\n"
     "                            addr,\n"
     "                            false,\n"
     "                            ConnectionMeta::default(), // Direct connections don't have server-side user context.\n",
     T03_LISTENER, "direct listener: every Direct Link encrypted (ADR 0005, 0004 amendment)"),
    (SERVER, "    pub controlled_context: Option<ControlledContext>,\n",
     "    pub controlled_context: Option<ControlledContext>,\n" + T03_META_FIELDS, "Direct Link + trust on ConnectionMeta"),
    (SERVER,
     "    tokio::select! {\n"
     "        handshake = identity_handshake(&mut stream, secure) => handshake?,\n"
     "        _ = unauthorized.evicted() => {\n"
     "            bail!(\"evicted to make room for a newer unauthenticated connection\");\n"
     "        }\n"
     "    }\n",
     T03_HANDSHAKE_CALL, "Direct Link handshake + trust exchange, still raced against eviction"),
    (SERVER, "/// Our signed identity goes out and, when `secure`, the controller's reply keys `stream`.\n",
     T03_HANDSHAKE_FN + "/// Our signed identity goes out and, when `secure`, the controller's reply keys `stream`.\n",
     "Direct Link handshake (announce, sign, trust)"),
    (CONN, "    tx_to_cm: mpsc::UnboundedSender<ipc::Data>,\n    authorized: bool,\n",
     "    tx_to_cm: mpsc::UnboundedSender<ipc::Data>,\n    authorized: bool,\n"
     "    // boring-remote: the Direct Link trust exchange (v1.7 t04, base::trust).\n"
     "    boring_trust: base::trust::Admission,\n", "trust on the connection"),
    (CONN, "            control_permissions,\n            controlled_context,\n        } = meta;\n",
     "            control_permissions,\n            controlled_context,\n            trust: boring_trust,\n            ..\n        } = meta;\n",
     "trust from ConnectionMeta"),
    (CONN, "            controlled_context,\n            lr: Default::default(),\n",
     "            controlled_context,\n            boring_trust,\n            lr: Default::default(),\n", "trust on the connection"),
    (CONN, "        self.authorized = true;\n        self.unauthorized_id = None;\n",
     "        self.authorized = true;\n        self.unauthorized_id = None;\n" + T04_GRANT, "Trusted by Allow or the Unattended Password only"),
    (CONN, "        #[cfg(any(target_os = \"linux\", target_os = \"windows\", target_os = \"macos\"))]\n"
           "        if !platform_additions.is_empty() {\n",
     T05_MARKER + "        #[cfg(any(target_os = \"linux\", target_os = \"windows\", target_os = \"macos\"))]\n"
                  "        if !platform_additions.is_empty() {\n", "Boring Remote marker in PeerInfo"),
    (CONN, "        #[cfg(any(target_os = \"linux\", target_os = \"windows\", target_os = \"macos\"))]\n"
           "        if !platform_additions.is_empty() {\n",
     T04_ALWAYS_ASK_MARK + "        #[cfg(any(target_os = \"linux\", target_os = \"windows\", target_os = \"macos\"))]\n"
                           "        if !platform_additions.is_empty() {\n", "always ask: tell the Controller in PeerInfo"),
    (CONN, T04_ALWAYS_ASK_GATE_AT, T04_ALWAYS_ASK_GATE_AT + T04_ALWAYS_ASK_GATE,
     "always ask: no sign-in lets it in without the Unattended Password"),
    ("src/client.rs", T04_ALWAYS_ASK_FORGET_AT, T04_ALWAYS_ASK_FORGET + T04_ALWAYS_ASK_FORGET_AT,
     "always ask: the Controller keeps no password for that Target"),
    (CONN, T04_ALWAYS_ASK_KICK_AT, T04_ALWAYS_ASK_KICK_AT + T04_ALWAYS_ASK_KICK,
     "always ask: a session that got in without the password ends when switched on"),
    (CONN, T04_ALWAYS_ASK_TUNNEL_TIMER_AT,
     T04_ALWAYS_ASK_TUNNEL_TIMER_AT.replace("            loop {\n", T04_ALWAYS_ASK_TUNNEL_TIMER + "            loop {\n"),
     "always ask: a tunnel's own check timer"),
    (CONN, T04_ALWAYS_ASK_TUNNEL_AT, T04_ALWAYS_ASK_TUNNEL + T04_ALWAYS_ASK_TUNNEL_AT,
     "always ask: a tunnel that got in without the password closes when switched on"),
    ("src/ipc.rs", T04_EDIT_IPC_AT, T04_EDIT_IPC_AT.replace('                } else if name == "salt"', T04_EDIT_IPC + '                } else if name == "salt"'),
     "Trusted list: Settings' edits, one locked write in the service"),
    ("src/ipc.rs", T04_KEEP_LIST_OLD, T04_KEEP_LIST, "Trusted list: a settings window's stale copy is never stored"),
    ("src/ipc.rs", T04_EDIT_ASK_AT, T04_EDIT_ASK + T04_EDIT_ASK_AT, "Trusted list: Settings waits for the service's answer"),
    ("src/flutter_ffi.rs", "pub fn main_get_local_option(key: String) -> SyncReturn<String> {\n",
     T04_EDIT_FFI + "pub fn main_get_local_option(key: String) -> SyncReturn<String> {\n", "Trusted list edit bridge call"),
    (CONN, "            if (password::approve_mode() == ApproveMode::Click && !allow_logon_screen_password)\n",
     T04_TRUSTED_SKIP + "            if (password::approve_mode() == ApproveMode::Click && !allow_logon_screen_password)\n",
     "a Trusted Controller skips the ask"),
    (CONN, "                    Some(misc::Union::Option(o)) => {\n"
           "                        if self.authed_conn_type() == Some(AuthConnType::Remote) {\n"
           "                            self.update_options(&o).await;\n",
     "                    Some(misc::Union::Option(o)) => {\n"
     "                        if self.authed_conn_type() == Some(AuthConnType::Remote) {\n"
     "                            self.update_options(&o).await;\n" + T05_ANSWER, "answer the High Efficiency ask"),
    (SERVER, T05_RETINA_OLD, T05_RETINA, "High Efficiency on a software codec captures points"),
    (IO_LOOP, "    is_connected: bool,\n", "    is_connected: bool,\n" + T05_LINK_FIELD, "High Efficiency link state"),
    (IO_LOOP, "            is_connected: false,\n", "            is_connected: false,\n            boring_link: None,\n",
     "High Efficiency link state"),
    (IO_LOOP, "                    .set_connection_type(is_secured, direct, stream_type); // flutter -> connection_ready\n",
     "                    .set_connection_type(is_secured, direct, stream_type); // flutter -> connection_ready\n" + T05_LINK_SET,
     "remember this round's path"),
    (IO_LOOP, "    async fn handle_msg_from_peer(&mut self, data: &[u8], peer: &mut Stream) -> bool {\n",
     T05_ASK_FN + "    async fn handle_msg_from_peer(&mut self, data: &[u8], peer: &mut Stream) -> bool {\n",
     "High Efficiency ask"),
    (IO_LOOP, "                        self.handler.handle_peer_info(pi);\n",
     T05_ASK_CALL + "                        self.handler.handle_peer_info(pi);\n", "ask on the first PeerInfo"),
    (IO_LOOP, "                    Some(misc::Union::FollowCurrentDisplay(d_idx)) => {\n"
              "                        self.handler.set_current_display(d_idx);\n"
              "                    }\n",
     "                    Some(misc::Union::FollowCurrentDisplay(d_idx)) => {\n"
     "                        self.handler.set_current_display(d_idx);\n"
     "                    }\n" + T05_BADGE, "badge once the Target answered"),
    ("src/lan.rs", "                                    hostname,\n                                    username: crate::platform::get_active_username(),\n",
     T02_PONG_NAME + "                                    username: crate::platform::get_active_username(),\n",
     "LAN Discovery answers with this Mac's name"),
    ("src/lan.rs", "\n    config::LanPeers::store(&peers);\n    #[cfg(feature = \"flutter\")]\n"
                   "    crate::flutter_ffi::main_load_lan_peers();\n    Ok(())\n}\n",
     "\n" + T02_END_CYCLE + "    config::LanPeers::store(&peers);\n    #[cfg(feature = \"flutter\")]\n"
     "    crate::flutter_ffi::main_load_lan_peers();\n    Ok(())\n}\n", "end of a discovery cycle"),
    ("src/ui_interface.rs", "                (\"platform\", peer.platform.clone()),\n            ])\n",
     "                (\"platform\", peer.platform.clone()),\n" + T02_HOME_IP + "            ])\n", "Home's address for a LAN Mac"),
    ("src/client.rs", "        let mut display_name = get_builtin_option(keys::OPTION_DISPLAY_NAME);\n",
     CONTROLLER_NAME, "the approval prompt names the Controller computer"),
]

# --- LAN Discovery both ways (v1.7 ticket 21) --------------------------------------
# Upstream lists a computer only if this one's broadcast reached it and its reply came back in the
# same cycle. Broadcast is what Wi-Fi drops, so Tori's Wi-Fi laptop lost the wired PC (M1-D2) for
# good while the wired Studio kept it. Each cycle now also asks every computer seen before or heard
# from directly (base::lan::send_pings), and the listener notes who pinged it (heard_ping), so if
# either side's broadcast gets through both list each other. Loopback and Tailscale's /32 get no
# ping: those sends only failed (errors 49 and 65 every 6 s in the Studio's log).
T21_LISTENER_OLD = ("                            if p.id == id {\n"
                    "                                continue;\n"
                    "                            }\n")
T21_HEARD = "                            base::lan::heard_ping(addr.ip()); // v1.7 t21: ask it directly next cycle\n"
T21_SEND_OLD = ("    let maddr = SocketAddr::from(([255, 255, 255, 255], get_broadcast_port()));\n"
                "    for socket in &sockets {\n"
                "        allow_err!(socket.send_to(&out, maddr));\n"
                "    }\n")
T21_SEND = ("    // boring-remote (v1.7 t21): each interface's own broadcast, and a direct ask to every computer\n"
            "    // seen before or heard from (base::lan). Nothing to loopback or Tailscale: those only fail.\n"
            "    #[cfg(not(target_os = \"ios\"))]\n"
            "    let locals: Vec<(Ipv4Addr, u8)> = default_net::get_interfaces()\n"
            "        .into_iter()\n"
            "        .flat_map(|i| i.ipv4.into_iter().map(|n| (n.addr, n.prefix_len)))\n"
            "        .collect();\n"
            "    #[cfg(target_os = \"ios\")]\n"
            "    let locals: Vec<(Ipv4Addr, u8)> = Vec::new();\n"
            "    base::lan::send_pings(&sockets, &out, get_broadcast_port(), &config::LanPeers::load().peers, &locals);\n")
PATCHES += [
    ("src/lan.rs", T21_LISTENER_OLD, T21_LISTENER_OLD + T21_HEARD, "the listener notes who pinged it (t21)"),
    ("src/lan.rs", T21_SEND_OLD, T21_SEND, "discovery asks known computers directly, skips unusable interfaces (t21)"),
]

# --- Every LAN address, fastest first (v1.7 ticket 25) -------------------------------
# A computer with Ethernet and Wi-Fi on one network answered discovery from whichever its routing
# picked, so Home listed Tori's Wi-Fi .79 and sessions crawled over it. The pong now lists every LAN
# address with link type and speed in PeerDiscovery.misc (upstream never fills it, so the protocol
# files stay upstream's; an old peer sends none, an old Controller ignores it). The logic and the
# public-address filter live in base::lan; these wire the interface list in and out.
T25_NICS = (
    "/// boring-remote (v1.7 t25): this computer's IPv4 addresses with link type and speed, for base::lan.\n"
    "fn boring_nics() -> Vec<base::lan::Nic> {\n"
    "    #[cfg(target_os = \"ios\")]\n"
    "    let nics = Vec::new();\n"
    "    #[cfg(not(target_os = \"ios\"))]\n"
    "    let nics = default_net::get_interfaces()\n"
    "        .into_iter()\n"
    "        .flat_map(|i| {\n"
    "            use default_net::interface::InterfaceType as T;\n"
    "            let link = match i.if_type {\n"
    "                T::Wireless80211 => base::lan::LinkKind::WiFi,\n"
    "                T::Ethernet | T::Ethernet3Megabit | T::FastEthernetT | T::FastEthernetFx | T::GigabitEthernet => {\n"
    "                    base::lan::LinkKind::Wired\n"
    "                }\n"
    "                _ => base::lan::LinkKind::Other,\n"
    "            };\n"
    "            let label = format!(\"{} {}\", i.friendly_name.unwrap_or_default(), i.description.unwrap_or_default());\n"
    "            let mbps = base::lan::mbps_from_bps(i.transmit_speed);\n"
    "            let name = i.name;\n"
    "            i.ipv4.into_iter().map(move |n| base::lan::Nic {\n"
    "                name: name.clone(),\n"
    "                label: label.clone(),\n"
    "                ip: n.addr,\n"
    "                prefix: n.prefix_len,\n"
    "                link,\n"
    "                mbps,\n"
    "            })\n"
    "        })\n"
    "        .collect();\n"
    "    base::lan::with_live_media(nics)\n"
    "}\n\n")
T25_PONG_OLD = "                                    platform: whoami::platform().to_string(),\n"
T25_PONG = T25_PONG_OLD + "                                    misc: base::lan::advert(&boring_nics()), // v1.7 t25: every LAN address\n"
T25_STORE_OLD = ("                                    ip_mac: HashMap::from([\n"
                 "                                        (addr.ip().to_string(), p.mac.clone(),)\n"
                 "                                    ]),\n")
T25_STORE = ("                                    // boring-remote (v1.7 t25): where it answered from, and every address it listed.\n"
             "                                    ip_mac: base::lan::pong_addresses(&p.id, addr.ip(), &p.mac, &p.misc),\n")
T25_LOCAL_OLD = "    log::info!(\"discover ping sent\");\n"
T25_LOCAL = "    base::lan::set_local_nics(boring_nics()); // v1.7 t25: Home ranks and connect dials from these\n" + T25_LOCAL_OLD
PATCHES += [
    ("src/lan.rs", "#[inline]\nfn get_broadcast_port() -> u16 {\n", T25_NICS + "#[inline]\nfn get_broadcast_port() -> u16 {\n",
     "this computer's addresses with link type and speed (t25)"),
    ("src/lan.rs", T25_PONG_OLD, T25_PONG, "the pong lists every LAN address (t25)"),
    ("src/lan.rs", T25_STORE_OLD, T25_STORE, "discovery keeps every address a pong listed (t25)"),
    ("src/lan.rs", T25_LOCAL_OLD, T25_LOCAL, "discovery notes this computer's own addresses (t25)"),
    ("src/lan.rs", "    collections::{HashMap, HashSet},\n", "    collections::HashSet,\n", "the store line no longer builds a HashMap here (t25)"),
]

# --- Mac Home (v1.7 ticket 01) ----------------------------------------------------
# The kit (desktop/kit/kit.dart) and Mac Home (desktop/kit/mac_home.dart) are ours and
# bridge-free; these wire them to bind. Mac only: other platforms keep the old home for now.
# No numeric ID on Home: "Connect from outside the building" gives this computer's Tailscale
# address (ADR 0004; desktop/kit/tailscale.dart reads it from the network interfaces).
MAC_HOME_METHOD = (
    "  // boring-remote: v1.7 Mac Home. Recents by name; outside the building is Tailscale (ADR 0004), never the ID.\n"
    "  Widget buildBoringHome(BuildContext context) {\n"
    "    final recents = gFFI.recentPeersModel;\n"
    "    String name(Peer p) => p.alias.isNotEmpty\n"
    "        ? p.alias\n"
    "        : (p.hostname.isNotEmpty ? p.hostname : KitWords.unnamed);\n"
    "    // boring-remote (v1.7 t26): each machine once, newest address. Home's view only: nothing leaves disk.\n"
    "    List<MacEntry> usedBefore() {\n"
    "      final who = identitiesFromKnown(bind.mainGetLocalOption(key: kDirectLinkKnownOption));\n"
    "      return oneEntryPerMachine(\n"
    "          [for (final p in recents.peers) MacEntry(name: name(p), target: p.id, identity: who[p.id] ?? '')]);\n"
    "    }\n"
    "    return Theme(\n"
    "      data: Kit.theme(),\n"
    "      child: Material(\n"
    "        color: Kit.ink,\n"
    "        child: ListenableBuilder(\n"
    "          listenable: Listenable.merge([recents, lanMacs]),\n"
    "          builder: (context, _) => MacHome(\n"
    "            macs: usedBefore(),\n"
    "            tailscaleAddress: thisTailscaleAddress,\n"
    "            lan: lanMacs.macs,\n"
    "            discover: () => bind.mainDiscover(),\n"
    "            onConnect: (t) => connect(context, t),\n"
    "            // boring-remote (v1.7 t29): File Transfer alone, same dial and trust as a session.\n"
    "            onTransferFiles: (t) => connect(context, t, isFileTransfer: true),\n"
    "            notices: [\n"
    "              AccessSummary(checks: boringAccessChecks()), // v1.7 t17: not ready yet, and its Fix\n"
    + NOTICE_BANNER +
    "            ],\n"
    "          ),\n"
    "        ),\n"
    "      ),\n"
    "    );\n"
    "  }\n\n")
PATCHES += [
    (HOME, "import 'package:flutter_hbb/consts.dart';\n",
     "import 'package:flutter_hbb/consts.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/kit.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/lan_macs_model.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/mac_home.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/tailscale.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/trust.dart';\n"
     "import 'package:flutter_hbb/models/peer_model.dart';\n",
     "Mac Home imports"),
    (HOME, "    super.build(context);\n",
     "    super.build(context);\n"
     "    if (isMacOS) return _buildBlock(child: buildBoringHome(context));\n",
     "Mac Home replaces the RustDesk home on Mac"),
    (HOME, "  Widget _buildBlock({required Widget child}) {\n",
     MAC_HOME_METHOD + "  Widget _buildBlock({required Widget child}) {\n",
     "Mac Home wiring"),
    (HOME, "  void initState() {\n    super.initState();\n",
     "  void initState() {\n    super.initState();\n"
     "    if (isMacOS) bind.mainLoadRecentPeers(); // Mac Home lists recents\n",
     "Mac Home loads recents"),
]

# --- File Transfer (v1.7 ticket 08) ----------------------------------------------
# Two kit panes (This Mac / That Mac), rows drag across both ways, kit job list with
# progress / done / error. desktop/kit/file_transfer.dart is ours and bridge-free; these
# wire it to the unchanged engine (FileController.sendFiles, the Send button's path).
FILE_MGR = "flutter/lib/desktop/pages/file_manager_page.dart"
FILE_MGR_METHODS = (
    "  // boring-remote: v1.7 File Transfer. A drop on one pane sends the other pane's selection.\n"
    "  void _boringSend(FileController from) {\n"
    "    if (!SelectedItems.valid(from.selectedItems.items)) return;\n"
    "    from.sendFiles(from.selectedItems, from.getOtherSideDirectoryData());\n"
    "    from.selectedItems.clear();\n"
    "  }\n\n"
    "  final _boringClock = TransferClock(); // boring-remote (v1.7 t27)\n\n"
    "  Widget boringTransferList() => Obx(() => TransferList(\n"
    "        jobs: [\n"
    "          for (final j in jobController.jobTable)\n"
    "            if (j.type != JobType.none)\n"
    "              TransferJob.fromEngine(\n"
    "                  id: j.id,\n"
    "                  path: j.jobName,\n"
    "                  remoteToLocal: j.isRemoteToLocal,\n"
    "                  state: j.state.name,\n"
    "                  finished: j.finishedSize,\n"
    "                  total: j.totalSize,\n"
    "                  err: j.err,\n"
    "                  delete: j.type != JobType.transfer, // deletes are listed too (v1.7 review)\n"
    "                  speed: j.speed, // boring-remote (v1.7 t27)\n"
    "                  averageSpeed: _boringClock.observe(\n"
    "                      j.id, j.state.name, j.finishedSize, j.totalSize, DateTime.now())),\n"
    "        ],\n"
    "        onCancel: (id) {\n"
    "          jobController.jobTable.removeWhere((j) => j.id == id);\n"
    "          jobController.cancelJob(id);\n"
    "        },\n"
    "        onResume: (id) => jobController.resumeJob(id),\n"
    "        onRemove: (id) => jobController.jobTable.removeWhere((j) => j.id == id),\n"
    "      ));\n\n")
PATCHES += [
    (FILE_MGR, "import 'package:flutter_hbb/models/file_model.dart';\n",
     "import 'package:flutter_hbb/models/file_model.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/kit.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/file_transfer.dart';\n",
     "File Transfer kit imports"),
    (FILE_MGR,
     "          backgroundColor: Theme.of(context).scaffoldBackgroundColor,\n"
     "          body: Row(\n"
     "            children: [\n"
     "              if (!isWeb)\n"
     "                Flexible(\n"
     "                    flex: 3,\n"
     "                    child: dropArea(FileManagerView(\n"
     "                        model.localController, _ffi, _mouseFocusScope))),\n"
     "              Flexible(\n"
     "                  flex: 3,\n"
     "                  child: dropArea(FileManagerView(\n"
     "                      model.remoteController, _ffi, _mouseFocusScope))),\n"
     "              Flexible(flex: 2, child: statusList())\n"
     "            ],\n"
     "          ),\n",
     "          backgroundColor: Kit.ink,\n"
     "          body: Theme(\n"
     "            // boring-remote (v1.7 t28): upstream's location bar reads MyTheme.tabbar. A theme without\n"
     "            // those extensions throws there and the release build draws grey blocks.\n"
     "            data: boringKitTheme,\n"
     "            child: Row(\n"
     "              children: [\n"
     "                if (!isWeb)\n"
     "                  Flexible(\n"
     "                      flex: 3,\n"
     "                      child: TransferPane(\n"
     "                          side: TransferSide.thisMac,\n"
     "                          onDropFromOther: () => _boringSend(model.remoteController),\n"
     "                          child: dropArea(FileManagerView(\n"
     "                              model.localController, _ffi, _mouseFocusScope)))),\n"
     "                Flexible(\n"
     "                    flex: 3,\n"
     "                    child: TransferPane(\n"
     "                        side: TransferSide.thatMac,\n"
     "                        onDropFromOther: () => _boringSend(model.localController),\n"
     "                        child: dropArea(FileManagerView(\n"
     "                            model.remoteController, _ffi, _mouseFocusScope)))),\n"
     "                Flexible(flex: 2, child: boringTransferList())\n"
     "              ],\n"
     "            ),\n"
     "          ),\n",
     "File Transfer: kit panes and job list"),
    (FILE_MGR, "  Widget dropArea(FileManagerView fileView) {\n",
     FILE_MGR_METHODS + "  Widget dropArea(FileManagerView fileView) {\n",
     "File Transfer: drop-to-send and job list wiring"),
    (FILE_MGR,
     "          return Padding(\n"
     "            padding: EdgeInsets.symmetric(vertical: 1),\n"
     "            child: Obx(() => Container(\n",
     "          return TransferDraggable(\n"
     "            side: isLocal ? TransferSide.thisMac : TransferSide.thatMac,\n"
     "            label: selectedItems.items.contains(entry) && selectedItems.items.length > 1\n"
     "                ? '${selectedItems.items.length} items'\n"
     "                : entry.name,\n"
     "            onDragStarted: () {\n"
     "              if (selectedItems.items.contains(entry)) return;\n"
     "              selectedItems.clear();\n"
     "              selectedItems.add(entry);\n"
     "            },\n"
     "            child: Padding(\n"
     "            padding: EdgeInsets.symmetric(vertical: 1),\n"
     "            child: Obx(() => Container(\n",
     "File Transfer: rows drag to the other pane"),
    (FILE_MGR, "                ))),\n          );\n        });\n\n        return Column(\n",
     "                ))),\n          ));\n        });\n\n        return Column(\n",
     "File Transfer: close the row drag wrapper"),
    (FILE_MGR,
     "                  color: selectedItems.items.contains(entry)\n"
     "                      ? MyTheme.button\n",
     "                  color: selectedItems.items.contains(entry)\n"
     "                      ? Kit.line\n",
     "File Transfer: selected row in kit grey"),
]

# --- File Transfer page test + UI error log (v1.7 t28) ------------------------------
# flutter/test/file_transfer_page_test.dart pumps the real page, which reaches the bridge through
# PlatformFFI's private field, so the test needs a setter. kit/ui_error_log.dart is ours and
# bridge-free; these send what it catches to the app log, since a release build logs nothing else.
PATCHES += [
    ("flutter/lib/models/native_model.dart", "  RustdeskImpl get ffiBind => _ffiBind;\n",
     "  RustdeskImpl get ffiBind => _ffiBind;\n"
     "  // boring-remote (v1.7 t28): lets a widget test pump a page against a fake bridge.\n"
     "  @visibleForTesting\n"
     "  set ffiBindForTest(RustdeskImpl b) => _ffiBind = b;\n",
     "File Transfer page test: fake bridge setter"),
    ("flutter/lib/main.dart", "import 'package:flutter_hbb/desktop/pages/desktop_tab_page.dart';\n",
     "import 'package:flutter_hbb/desktop/kit/ui_error_log.dart';\n"
     "import 'package:flutter_hbb/desktop/pages/desktop_tab_page.dart';\n",
     "UI error log import"),
    ("flutter/lib/main.dart", "  kBootArgs = List.from(args);\n",
     "  // boring-remote (v1.7 t28): a grey block in a release build leaves a line in the app log.\n"
     "  logUiErrors((text) => bind.mainLogUiError(text: text));\n"
     "  kBootArgs = List.from(args);\n",
     "UI errors reach the app log"),
    ("src/flutter_ffi.rs", "pub fn main_is_login_wayland() -> SyncReturn<bool> {\n",
     "/// boring-remote (v1.7 t28): a widget failed to build or lay out. Release Flutter logs nothing itself.\n"
     "pub fn main_log_ui_error(text: String) {\n"
     "    log::error!(\"UI error: {}\", text);\n"
     "}\n\n"
     "pub fn main_is_login_wayland() -> SyncReturn<bool> {\n",
     "UI error log bridge call"),
]

# --- Session Toolbar (v1.7 ticket 07) --------------------------------------------
# desktop/kit/session_toolbar.dart is ours and bridge-free; this wires it on Mac. Five
# actions up front (Link Badge, Send files, display, quality, Disconnect); every other
# RustDesk menu moves behind More. The Link Badge shows the path Rust reports (t03).
T07_TOOLBAR = "flutter/lib/desktop/widgets/remote_toolbar.dart"
T07_METHOD = (
    "  // boring-remote: v1.7 Session Toolbar. Five actions up front, RustDesk's menus behind More.\n"
    "  Widget buildBoringSessionToolbar(BuildContext context, List<Widget> more) {\n"
    "    final ffi = widget.ffi;\n"
    "    final current = CurrentDisplayState.find(widget.id);\n"
    "    final linkType = ConnectionTypeState.find(widget.id);\n"
    "    return Obx(() {\n"
    "      final displays = pi.displaysCount.value;\n"
    "      final link = linkStateFor(linkType.stream_type.value); // v1.7 t03: the path Rust took\n"
    "      final display = current.value < 0 ? 0 : current.value;\n"
    "      return FutureBuilder<String?>(\n"
    "        future: bind.sessionGetImageQuality(sessionId: ffi.sessionId),\n"
    "        builder: (context, q) => SessionToolbar(\n"
    "          link: link,\n"
    "          onSendFiles: () => connect(context, widget.id,\n"
    "              isFileTransfer: true,\n"
    "              connToken: bind.sessionGetConnToken(sessionId: ffi.sessionId)),\n"
    "          displays: displays < 1 ? 1 : displays,\n"
    "          display: display,\n"
    "          onPickDisplay: (i) {\n"
    "            if (i != current.value) openMonitorInTheSameTab(i, ffi, pi);\n"
    "          },\n"
    "          quality: q.data ?? kRemoteImageQualityBalanced,\n"
    "          qualities: const {\n"
    "            kRemoteImageQualityBalanced: 'Auto',\n"
    "            kRemoteImageQualityBest: 'Best picture',\n"
    "            kRemoteImageQualityLow: 'Fastest',\n"
    "          },\n"
    "          onQuality: (v) async {\n"
    "            await bind.sessionSetImageQuality(sessionId: ffi.sessionId, value: v);\n"
    "            // v1.7 review: a hand pick replaces High Efficiency, so the badge goes back to Local.\n"
    "            linkType.setStreamType(streamTypeAfterQualityPick(linkType.stream_type.value));\n"
    "            if (mounted) setState(() {});\n"
    "          },\n"
    "          onDisconnect: () async {\n"
    "            if (await showConnEndAuditDialogCloseCanceled(ffi: ffi)) return;\n"
    "            closeConnection(id: widget.id);\n"
    "          },\n"
    "          more: more,\n"
    "        ),\n"
    "      );\n"
    "    });\n"
    "  }\n\n")
PATCHES += [
    (T07_TOOLBAR, "import 'package:flutter_hbb/consts.dart';\n",
     "import 'package:flutter_hbb/consts.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/session_toolbar.dart';\n",
     "Session Toolbar import"),
    (T07_TOOLBAR, "    toolbarItems.add(_CloseMenu(id: widget.id, ffi: widget.ffi));\n",
     "    toolbarItems.add(_CloseMenu(id: widget.id, ffi: widget.ffi));\n"
     "    if (isMacOS) {\n"
     "      // Everything but Close goes behind More; the kit toolbar has its own Disconnect.\n"
     "      final more = toolbarItems.sublist(0, toolbarItems.length - 1);\n"
     "      toolbarItems\n"
     "        ..clear()\n"
     "        ..add(buildBoringSessionToolbar(context, more));\n"
     "    }\n",
     "Session Toolbar replaces the RustDesk toolbar row on Mac"),
    (T07_TOOLBAR, "  ThemeData themeData() {\n",
     T07_METHOD + "  ThemeData themeData() {\n",
     "Session Toolbar wiring"),
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

# --- Multi-window sessions, each full screen (v1.7 ticket 11) ---------------------
# New sessions open in their own window: the tabs option defaults off (new installs and
# upgrades; a stored "Y" from someone who ticked it keeps tabs). The checkbox stays on the
# full settings page (kOptionOpenNewConnInTabs) = Advanced; ticket 09's simple page links there.
# A full-screen session remembers its monitor per Target: desktop/kit/session_window.dart is
# the bridge-free decision, these hooks feed it the live frame and screens, and restore moves
# the window to that monitor before going full screen on Mac too.
T11_TABS_OPTION = "enable-open-new-connections-in-tabs"
DEFAULTS_LOCAL = {  # DEFAULT_LOCAL_SETTINGS: user can change
    T11_TABS_OPTION: "N",
}
T11_COMMON = "flutter/lib/common.dart"
PATCHES += [
    (HBB, "pub static ref DEFAULT_LOCAL_SETTINGS: RwLock<HashMap<String, String>> = Default::default();",
     "pub static ref DEFAULT_LOCAL_SETTINGS: RwLock<HashMap<String, String>> = "
     + _rust_map(DEFAULTS_LOCAL) + ";", "new sessions open in windows, not tabs"),
    (T11_COMMON, "import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';\n",
     "import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/session_window.dart';\n",
     "session window kit import"),
    (T11_COMMON,
     "      final wc = WindowController.fromWindowId(windowId!);\n"
     "      isMaximized = await wc.isMaximized();\n",
     "      final wc = WindowController.fromWindowId(windowId!);\n"
     "      isMaximized = await wc.isMaximized();\n"
     "      // boring-remote: the live frame says which monitor a full-screen window is on.\n"
     "      try {\n"
     "        _boringLiveFrame = await wc.getFrame();\n"
     "      } catch (_) {\n"
     "        _boringLiveFrame = null;\n"
     "      }\n",
     "full-screen session saves its live frame"),
    (T11_COMMON,
     "Future _saveSessionWindowPosition(WindowType windowType, int windowId,\n",
     "Rect? _boringLiveFrame;\n\n"
     "Future _saveSessionWindowPosition(WindowType windowType, int windowId,\n",
     "live frame holder"),
    (T11_COMMON,
     "  final remoteList = await DesktopMultiWindow.invokeMethod(\n"
     "      windowId, kWindowEventGetRemoteList, null);\n",
     "  final remoteList = await DesktopMultiWindow.invokeMethod(\n"
     "      windowId, kWindowEventGetRemoteList, null);\n"
     "  final screens = (isMaximized || isFullscreen)\n"
     "      ? (await window_size.getScreenList()).map((s) => s.frame).toList()\n"
     "      : const <Rect>[];\n",
     "screens for the full-screen monitor"),
    (T11_COMMON,
     "    if (isMaximized || isFullscreen) {\n"
     "      final peerPos = bind.mainGetPeerFlutterOptionSync(\n"
     "          id: peerId, k: windowFramePrefix + windowType.name);\n"
     "      var lpos = LastWindowPosition.loadFromString(peerPos);\n"
     "      return LastWindowPosition(\n"
     "              lpos?.width ?? pos.offsetWidth,\n"
     "              lpos?.height ?? pos.offsetHeight,\n"
     "              lpos?.offsetWidth ?? pos.offsetWidth,\n"
     "              lpos?.offsetHeight ?? pos.offsetHeight,\n"
     "              isMaximized,\n"
     "              isFullscreen)\n"
     "          .toString();\n",
     "    if (isMaximized || isFullscreen) {\n"
     "      // boring-remote: remember the monitor this Target is full screen on.\n"
     "      return peerFrameWhileFull(\n"
     "          peerSaved: bind.mainGetPeerFlutterOptionSync(\n"
     "              id: peerId, k: windowFramePrefix + windowType.name),\n"
     "          live: _boringLiveFrame,\n"
     "          screens: screens,\n"
     "          fallback: pos.toJson(),\n"
     "          fullscreen: isFullscreen,\n"
     "          maximized: isMaximized);\n",
     "full-screen Target keeps its monitor"),
    (T11_COMMON,
     "        if (!isMacOS) {\n"
     "          await restoreFrame();\n"
     "        }\n",
     "        // boring-remote: Mac too, so full screen lands on the Target's monitor.\n"
     "        await restoreFrame();\n",
     "reopen a Target on its monitor before full screen"),
]

# --- Extras in the kit + one simple Settings page (v1.7 ticket 09) ----------------
# desktop/kit/simple_settings.dart and kit_extras.dart are ours and bridge-free; these wire them
# in. Port forward, terminal and camera view get the kit theme and kit tokens (check.py:
# EXTRAS_PAGES). Settings on Mac opens on SimpleSettings; the full tabs sit behind Advanced.
PORT_FWD = "flutter/lib/desktop/pages/port_forward_page.dart"
TERMINAL = "flutter/lib/desktop/pages/terminal_page.dart"
CAMERA = "flutter/lib/desktop/pages/view_camera_page.dart"
KIT_IMPORTS = ("import 'package:flutter_hbb/desktop/kit/kit.dart';\n"
               "import 'package:flutter_hbb/desktop/kit/kit_extras.dart';\n")
BORING_MAC_NAME_OPTION = "boring-device-name"  # server-side: the LAN listener answers with it (t02/t06)
SIMPLE_SETTINGS_METHOD = (
    "  // boring-remote: v1.7 Settings. One simple page on Mac; the full tabs are Advanced.\n"
    "  bool _boringAdvanced = false;\n\n"
    "  void _boringOpenAdvanced(SettingsTabKey tab) {\n"
    "    setState(() => _boringAdvanced = true);\n"
    "    WidgetsBinding.instance.addPostFrameCallback((_) {\n"
    "      final i = DesktopSettingPage.tabKeys.indexOf(tab);\n"
    "      if (i >= 0 && controller.hasClients) controller.jumpToPage(i);\n"
    "    });\n"
    "  }\n\n"
    "  Widget buildBoringSettings(BuildContext context) {\n"
    f"    const nameKey = '{BORING_MAC_NAME_OPTION}';\n"
    "    final name = bind.mainGetOptionSync(key: nameKey);\n"
    "    return Theme(\n"
    "      data: Kit.theme(),\n"
    "      child: Material(\n"
    "        color: Kit.ink,\n"
    "        child: SimpleSettings(\n"
    "          macName: name.isNotEmpty ? name : Platform.localHostname.replaceAll('.local', ''),\n"
    "          onRename: (n) => bind.mainSetOption(key: nameKey, value: n),\n"
    "          passwordSet: bind.mainGetCommonSync(key: 'permanent-password-set') == 'true',\n"
    "          setPassword: (p) => bind.mainSetPermanentPasswordWithResult(password: p),\n"
    "          // Remote access = the service is installed and not stopped. Off stops it (it stays off\n"
    "          // across restarts until turned back on). v1.7 t17: its own switch, never tied to login.\n"
    "          remoteAccess: bind.mainIsInstalledDaemon(prompt: false) &&\n"
    "              !mainGetBoolOptionSync(kOptionStopService),\n"
    "          onRemoteAccess: (on) async {\n"
    "            if (on) bind.mainIsInstalledDaemon(prompt: true);\n"
    "            await mainSetBoolOption(kOptionStopService, !on);\n"
    "            setState(() {});\n"
    "          },\n"
    "          // Open at login (Mac): the user's own LaunchAgent opens the window; remote access never depends on it.\n"
    "          openAtLogin: isMacOS\n"
    "              ? File(openAtLoginPath(Platform.environment['HOME'] ?? '')).existsSync()\n"
    "              : null,\n"
    "          onOpenAtLogin: (on) {\n"
    "            final f = File(openAtLoginPath(Platform.environment['HOME'] ?? ''));\n"
    "            try {\n"
    f"              on ? (f..createSync(recursive: true)).writeAsStringSync(openAtLoginPlist('{AGENT_ID}')) : f.deleteSync();\n"
    "            } catch (e) {\n"
    "              debugPrint('Settings: open at login: $e');\n"
    "            }\n"
    "          },\n"
    "          access: AccessSection(checks: boringAccessChecks(), clearSwitches: isMacOS ? boringClearSwitches : null), // v1.7 t17, t31\n"
    "          // v1.7 t04: whoever is waiting right now, Allow / Don't allow (kit/approval.dart)\n"
    "          waiting: WaitingApprovals(\n"
    "            waiting: ApprovalDesk.waitingNow,\n"
    "            onDecide: (id, allow) => ApprovalDesk.main?.decide(id, allow),\n"
    "          ),\n"
    "          checkUpdates: mainGetLocalBoolOptionSync(kBoringUpdateCheckOption),\n"
    "          onCheckUpdates: (on) async {\n"
    "            await mainSetLocalBoolOption(kBoringUpdateCheckOption, on);\n"
    "            setState(() {});\n"
    "          },\n"
    "          openUrl: (u) => launchUrlString(u), // Download Boring Remote (ticket 15)\n"
    "          advanced: [\n"
    "            // boring-remote: v1.7 t04 adds Trusted Controllers here.\n"
    "            SettingsLink(\n"
    "              label: 'Sessions open in windows or tabs',\n"
    "              onTap: () => _boringOpenAdvanced(SettingsTabKey.general), // v1.7 t11 owns this choice\n"
    "            ),\n"
    "            SettingsLink(\n"
    "              label: 'All settings',\n"
    "              onTap: () => _boringOpenAdvanced(DesktopSettingPage.tabKeys.first),\n"
    "            ),\n"
    "          ],\n"
    "        ),\n"
    "      ),\n"
    "    );\n"
    "  }\n\n")
PATCHES += [
    # Settings
    (SETTINGS, "import 'package:flutter_hbb/desktop/pages/desktop_tab_page.dart';\n",
     "import 'package:flutter_hbb/desktop/pages/desktop_tab_page.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/kit.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/simple_settings.dart';\n",
     "simple Settings imports"),
    (SETTINGS, "    super.build(context);\n    return Scaffold(\n"
     "      backgroundColor: Theme.of(context).colorScheme.background,\n      body: _buildBlock(\n",
     "    super.build(context);\n"
     "    if (isMacOS && !_boringAdvanced) {\n"
     "      return _buildBlock(children: [Expanded(child: buildBoringSettings(context))]);\n"
     "    }\n"
     "    return Scaffold(\n"
     "      backgroundColor: Theme.of(context).colorScheme.background,\n      body: _buildBlock(\n",
     "Mac Settings opens on the simple page"),
    (SETTINGS, "  Widget _header(BuildContext context) {\n",
     SIMPLE_SETTINGS_METHOD + "  Widget _header(BuildContext context) {\n",
     "simple Settings wiring"),
    (SETTINGS, "        const Spacer(),\n      ],\n",
     "        const Spacer(),\n"
     "        if (isMacOS)\n"
     "          TextButton(\n"
     "            onPressed: () => setState(() => _boringAdvanced = false),\n"
     "            child: const Text('Back to Settings'),\n"
     "          ).marginOnly(right: 20, top: 10),\n"
     "      ],\n",
     "Advanced goes back to the simple page"),
    # Port forward
    (PORT_FWD, "import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';\n",
     "import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';\n" + KIT_IMPORTS, "port forward: kit imports"),
    (PORT_FWD, "    super.build(context);\n    return Scaffold(\n"
     "      backgroundColor: Theme.of(context).scaffoldBackgroundColor,\n      body: FutureBuilder(",
     "    super.build(context);\n    return Theme(\n      data: kitThemeKeeping(context),\n      child: Scaffold(\n"
     "      backgroundColor: Kit.ink,\n      body: FutureBuilder(",
     "port forward: kit theme"),
    (PORT_FWD, "        return const Offstage();\n      }),\n    );\n  }\n",
     "        return const Offstage();\n      }),\n    ));\n  }\n", "port forward: close kit theme"),
    (PORT_FWD, "color: MyTheme.border", "color: Kit.line", "port forward: kit border"),
    (PORT_FWD, "color: const Color(0xFF007F00),", "color: Kit.panel,", "port forward: listening bar"),
    (PORT_FWD, "style: const TextStyle(fontSize: 16, color: Colors.white),",
     "style: const TextStyle(fontSize: 16, color: Kit.paper),", "port forward: listening text"),
    (PORT_FWD, "fontSize: 10, color: Color(0xFFDDDDDD), height: 1.2),",
     "fontSize: 12, color: Kit.muted, height: 1.2),", "port forward: listening tip, 12px floor"),
    (PORT_FWD, "              ? MyTheme.currentThemeMode() == ThemeMode.dark\n"
     "                  ? const Color(0xFF202020)\n                  : const Color(0xFFF4F5F6)\n"
     "              : Theme.of(context).colorScheme.background),",
     "              ? Kit.glass\n              : Kit.panel),", "port forward: kit row stripes"),
    # Terminal
    (TERMINAL, "import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';\n",
     "import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';\n" + KIT_IMPORTS, "terminal: kit imports"),
    (TERMINAL, "    super.build(context);\n    return Scaffold(\n"
     "      backgroundColor: Theme.of(context).scaffoldBackgroundColor,\n      body: LayoutBuilder(",
     "    super.build(context);\n    return Theme(\n      data: kitThemeKeeping(context),\n      child: Scaffold(\n"
     "      backgroundColor: Kit.ink,\n      body: LayoutBuilder(",
     "terminal: kit theme"),
    (TERMINAL, "        },\n      ),\n    );\n  }\n\n  @override\n  bool get wantKeepAlive => true;",
     "        },\n      ),\n    ));\n  }\n\n  @override\n  bool get wantKeepAlive => true;",
     "terminal: close kit theme"),
    ("flutter/lib/models/terminal_mouse_handler.dart", "import 'package:xterm/xterm.dart';\n",
     "import 'package:xterm/xterm.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/kit_extras.dart';\n", "terminal: kit terminal theme import"),
    ("flutter/lib/models/terminal_mouse_handler.dart", "        backgroundOpacity: widget.backgroundOpacity,\n",
     "        theme: kitTerminalTheme,\n        backgroundOpacity: widget.backgroundOpacity,\n",
     "terminal: kit terminal colours"),
    # Camera view
    (CAMERA, "import '../widgets/tabbar_widget.dart';\n",
     "import '../widgets/tabbar_widget.dart';\n" + KIT_IMPORTS, "camera: kit imports"),
    (CAMERA, "    return Scaffold(\n      backgroundColor: Theme.of(context).colorScheme.background,\n"
     "      body: Obx(() {\n",
     "    return Theme(\n      data: kitThemeKeeping(context),\n      child: Scaffold(\n"
     "      backgroundColor: Kit.ink,\n      body: Obx(() {\n",
     "camera: kit theme"),
    (CAMERA, "          return bodyWidget();\n        }\n      }),\n    );\n  }\n",
     "          return bodyWidget();\n        }\n      }),\n    ));\n  }\n", "camera: close kit theme"),
    (CAMERA, "color: kColorCanvas,", "color: Kit.ink,", "camera: kit canvas"),
    (CAMERA, "thumbColor: Colors.grey,", "thumbColor: Kit.muted,", "camera: kit scrollbars"),
]

# --- LAN trust (v1.7 ticket 04, ADRs 0002, 0005) -----------------------------------
# libs/base/src/trust.rs holds the token exchange; desktop/kit/trust.dart is ours and bridge-free.
# These wire the kit in: Trusted Controllers (and "Forget" for t03's pinned keys)
# under Settings → Advanced, and the plain-words approval prompt in the connection window.
T04_HOOK = "            // boring-remote: v1.7 t04 adds Trusted Controllers here.\n"
T04_SETTINGS_LINK = (
    "            // boring-remote: v1.7 t04 Trusted Controllers (base::trust, kit/trust.dart).\n"
    "            SettingsLink(\n"
    "              label: kTrustedTitle,\n"
    "              onTap: () => Navigator.of(context).push(MaterialPageRoute(\n"
    "                builder: (_) => Theme(\n"
    "                  data: Kit.theme(),\n"
    "                  child: Scaffold(\n"
    "                    backgroundColor: Kit.ink,\n"
    "                    appBar: AppBar(backgroundColor: Kit.ink),\n"
    "                    body: TrustedControllersPage(\n"
    "                      trusted: parseTrusted(bind.mainGetOptionSync(key: kTrustedControllersOption)),\n"
    "                      known: parseKnown(bind.mainGetLocalOption(key: kDirectLinkKnownOption)),\n"
    "                      // Every change to the list is the service's, one locked edit there (base::trust::edit);\n"
    "                      // each returns null once saved, else why not.\n"
    "                      onRemove: (k) async =>\n"
    "                          trustEditError(await bind.boringTrustEdit(edit: trustEdit('remove', k))),\n"
    "                      // Always ask for password: on carries the Unattended Password typed here.\n"
    "                      onAlwaysAsk: (k, on, pw) async => trustEditError(\n"
    "                          await bind.boringTrustEdit(edit: trustEdit('always_ask', k, on: on, password: pw))),\n"
    "                      newAlwaysAsk: bind.mainGetOptionSync(key: kNewAlwaysAskOption) == 'Y',\n"
    "                      onNewAlwaysAsk: (on) => bind.mainSetOption(key: kNewAlwaysAskOption, value: on ? 'Y' : ''),\n"
    "                      onForget: (id) async {\n"
    "                        for (final o in [kDirectLinkKnownOption, kTrustTokensOption]) {\n"
    "                          await bind.mainSetLocalOption(\n"
    "                              key: o, value: forgetId(bind.mainGetLocalOption(key: o), id));\n"
    "                        }\n"
    "                      },\n"
    "                      // Allow here = Allow on the prompt: Trusted again (the service's edit, as Remove),\n"
    "                      // and a live ask from it is let in (kit/approval.dart).\n"
    "                      removed: parseRemoved(bind.mainGetOptionSync(key: kTrustedControllersOption)),\n"
    "                      onAllow: (c) async {\n"
    "                        final error = trustEditError(await bind.boringTrustEdit(edit: trustEdit('allow', c.key)));\n"
    "                        if (error != null) return error;\n"
    "                        // Only the ask that presented its token, never one using its name (audit H1).\n"
    "                        for (final id in waitingFrom(c, ApprovalDesk.waitingNow.value)) {\n"
    "                          ApprovalDesk.main?.decide(id, true);\n"
    "                        }\n"
    "                        return null;\n"
    "                      },\n"
    "                      waiting: WaitingApprovals(\n"
    "                        waiting: ApprovalDesk.waitingNow,\n"
    "                        onDecide: (id, allow) => ApprovalDesk.main?.decide(id, allow),\n"
    "                      ),\n"
    "                    ),\n"
    "                  ),\n"
    "                ),\n"
    "              )),\n"
    "            ),\n")
T04_PROMPT = (
    "    // boring-remote (v1.7 t04): on Mac the ask is plain words: who, Allow or Don't allow.\n"
    "    if (isMacOS && showAccept) {\n"
    "      return Theme(\n"
    "        data: Kit.theme(),\n"
    "        child: Material(\n"
    "          color: Kit.ink,\n"
    "          child: ApprovalPrompt(\n"
    "            name: client.name,\n"
    "            trust: client.boringTrust,\n"
    "            ip: client.boringIp,\n"
    "            files: client.type_() == ClientType.file, // v1.7 t29: says transfer, not control\n"
    "            onAllow: () {\n"
    "              handleAccept(context);\n"
    "              windowManager.minimize();\n"
    "            },\n"
    "            onDeny: handleDisconnect,\n"
    "          ),\n"
    "        ),\n"
    "      );\n"
    "    }\n")
CM_PAGE = "flutter/lib/desktop/pages/server_page.dart"
# t09 left a marked hook line in its Settings method; t04 fills it inside that same patch (see
# _fold_v17), so a second rebrand run still finds t09's text and stays a no-op.
PATCHES += [
    (SETTINGS, "import 'package:flutter_hbb/desktop/kit/simple_settings.dart';\n",
     "import 'package:flutter_hbb/desktop/kit/simple_settings.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/trust.dart';\n",
     "Trusted Controllers import"),
    (CM_PAGE, "import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';\n",
     "import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/kit.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/trust.dart';\n",
     "approval prompt imports"),
    (CM_PAGE, "    final showAccept = model.approveMode != 'password';\n",
     "    final showAccept = model.approveMode != 'password';\n" + T04_PROMPT,
     "approval prompt in plain words"),
]

# --- Allow in the main window (v1.7 t04 follow-up) ---------------------------------
# On a real Mac the ask in the small connection window was cut off. The connection window runs in
# its own process (--cm), so src/boring_approval.rs (ours) carries ask / done to the main window
# over ipc `_boring_approval` (opening the main window if it is not running) and the answer back
# over `_cm`; desktop/kit/approval.dart (ours, bridge-free) shows the ask in the middle of the main
# window. The connection window then runs its own Allow / Don't allow, so trust is granted exactly
# as a click there does (T04_GRANT, ADR 0005). Settings lists who is waiting and who was removed,
# each with Allow. The connection window stays as the fallback and scrolls instead of clipping.
T04B_MOD = ("#[cfg(not(any(target_os = \"android\", target_os = \"ios\")))]\n"
            "mod boring_approval; // boring-remote: Allow in the main window (v1.7 t04)\n")
T04B_FFI = (
    "/// boring-remote (v1.7 t04): Allow / Don't allow between the connection window and the main\n"
    "/// window (src/boring_approval.rs). Blocking ipc, so it runs on its own thread.\n"
    "pub fn boring_approval_send(msg: String) {\n"
    "    #[cfg(not(any(target_os = \"android\", target_os = \"ios\")))]\n"
    "    std::thread::spawn(move || crate::boring_approval::send(msg));\n"
    "}\n\n")
T04B_LISTEN = (
    "pub fn start_global_event_stream(s: StreamSink<String>, app_type: String) -> ResultType<()> {\n"
    "    // boring-remote (v1.7 t04): the main window listens for the connection window's asks.\n"
    "    #[cfg(not(any(target_os = \"android\", target_os = \"ios\")))]\n"
    "    if app_type == crate::flutter::APP_TYPE_MAIN {\n"
    "        crate::boring_approval::listen_once();\n"
    "    }\n"
    "    super::flutter::start_global_event_stream(s, app_type)\n"
    "}\n")
T04B_CM_IPC = (
    "                                // boring-remote (v1.7 t04): the main window's Allow / Don't allow,\n"
    "                                // handed to this window's page, which runs its own (boring_approval.rs).\n"
    "                                #[cfg(feature = \"flutter\")]\n"
    "                                Data::UrlLink(msg) if msg.starts_with(crate::boring_approval::ANSWER) => {\n"
    "                                    crate::boring_approval::to_page(crate::flutter::APP_TYPE_CM, &msg);\n"
    "                                }\n")
T04B_EVENT = (
    "      } else if (name == kApprovalEvent) {\n"
    "        // boring-remote (v1.7 t04): Allow / Don't allow in the middle of the main window too.\n"
    "        final m = parseApproval(evt['msg'].toString());\n"
    "        final sm = parent.target?.serverModel;\n"
    "        if (m != null && m.kind == ApprovalKind.answer) {\n"
    "          // The connection window: its own Allow / Don't allow (server_page.dart, T04_PROMPT).\n"
    "          for (final c in [...?sm?.clients]) {\n"
    "            if (c.id == m.id && !c.authorized) {\n"
    "              if (m.allow) {\n"
    "                sm!.sendLoginResponse(c, true);\n"
    "              } else {\n"
    "                bind.cmCloseConnection(connId: c.id);\n"
    "              }\n"
    "              break;\n"
    "            }\n"
    "          }\n"
    "        } else if (m != null) {\n"
    "          (ApprovalDesk.main ??= ApprovalDesk(\n"
    "            overlay: () => globalKey.currentState?.overlay,\n"
    "            toFront: () => windowOnTop(null),\n"
    "            answer: (id, allow) => bind.boringApprovalSend(msg: approvalAnswer(id, allow)),\n"
    "          ))\n"
    "              .take(m);\n"
    "        }\n")
T04B_GATE = "(isMacOS || isWindows) && desktopType == DesktopType.cm"
T04B_ASK = (
    "      // boring-remote (v1.7 t04): the ask also goes to the middle of the main window.\n"
    f"      if ({T04B_GATE}) {{\n"
    "        bind.boringApprovalSend(\n"
    "            msg: !client.authorized && approveMode != 'password'\n"
    "                ? approvalAsk(client.id, client.name,\n"
    "                    files: client.type_() == ClientType.file, // v1.7 t29\n"
    "                    trust: client.boringTrust, key: client.boringKey, ip: client.boringIp)\n"
    "                : approvalDone(client.id));\n"
    "      }\n")
T04B_DONE_REMOVE = (
    "      // boring-remote (v1.7 t04): settled here, so the main window drops its ask.\n"
    f"      if ({T04B_GATE}) bind.boringApprovalSend(msg: approvalDone(id));\n")
T04B_DONE_LOGIN = (
    "    // boring-remote (v1.7 t04): settled here, so the main window drops its ask.\n"
    f"    if ({T04B_GATE}) bind.boringApprovalSend(msg: approvalDone(client.id));\n")
T04B_CARD = ("                client.disconnected ||\n"
             "                // boring-remote (v1.7 t04): the ask gets the whole card, nothing clipped.\n"
             "                ((isMacOS || isWindows) && !client.authorized)\n"
             "            ? Offstage()\n")
SERVER_MODEL = "flutter/lib/models/server_model.dart"
FFI_MODEL = "flutter/lib/models/model.dart"
APPROVAL_IMPORT = "import 'package:flutter_hbb/desktop/kit/approval.dart';\n"
PATCHES += [
    ("src/lib.rs", "mod update_rollback;\n", "mod update_rollback;\n" + T04B_MOD, "approval module"),
    ("src/flutter_ffi.rs", "pub fn main_get_local_option(key: String) -> SyncReturn<String> {\n",
     T04B_FFI + "pub fn main_get_local_option(key: String) -> SyncReturn<String> {\n", "approval bridge call"),
    ("src/flutter_ffi.rs",
     "pub fn start_global_event_stream(s: StreamSink<String>, app_type: String) -> ResultType<()> {\n"
     "    super::flutter::start_global_event_stream(s, app_type)\n}\n",
     T04B_LISTEN, "main window listens for approvals"),
    ("src/ui_cm_interface.rs",
     "                                Data::Close => {\n"
     "                                    log::info!(\"cm ipc connection closed from connection request\");\n",
     T04B_CM_IPC +
     "                                Data::Close => {\n"
     "                                    log::info!(\"cm ipc connection closed from connection request\");\n",
     "connection window takes the main window's answer"),
    (FFI_MODEL, "import 'platform_model.dart';\n", "import 'platform_model.dart';\n" + APPROVAL_IMPORT,
     "approval import (events)"),
    (FFI_MODEL, "      } else if (name == 'on_url_scheme_received') {\n",
     T04B_EVENT + "      } else if (name == 'on_url_scheme_received') {\n", "approval events, both windows"),
    (SERVER_MODEL, "import '../common.dart';\n", "import '../common.dart';\n" + APPROVAL_IMPORT,
     "approval import (connection window)"),
    (SERVER_MODEL, "      final client = Client.fromJson(jsonDecode(evt[\"client\"]));\n",
     "      final client = Client.fromJson(jsonDecode(evt[\"client\"]));\n" + T04B_ASK,
     "connection window sends its ask to the main window"),
    (SERVER_MODEL, "      final id = int.parse(evt['id'] as String);\n",
     "      final id = int.parse(evt['id'] as String);\n" + T04B_DONE_REMOVE, "ask gone: tell the main window"),
    (SERVER_MODEL, "  void sendLoginResponse(Client client, bool res) async {\n",
     "  void sendLoginResponse(Client client, bool res) async {\n" + T04B_DONE_LOGIN,
     "ask answered here: tell the main window"),
    (SETTINGS, "import 'package:url_launcher/url_launcher.dart';\n",
     "import 'package:url_launcher/url_launcher.dart';\n" + APPROVAL_IMPORT, "approval import (settings)"),
    (CM_PAGE, "                client.disconnected\n            ? Offstage()\n", T04B_CARD,
     "connection window: the ask gets the whole card"),
]

# --- Audit H1: the ask carries who it is, Settings matches by key ------------------
# The Target's trust exchange knows whether a waiting Controller is new or removed (and its key);
# the connection window and the main window only saw the name the Controller picked. These carry
# base::trust::AskInfo (new / removed, a key prefix, the address) from try_start_cm through the
# connection window's Data::Login and client JSON to Flutter's Client, then into the ask.
CM_IFACE = "src/ui_cm_interface.rs"
H1_ASK_INFO = "    pub boring: base::trust::AskInfo, // boring-remote: audit H1 (boring_trust, _key, _ip)\n"
H1_LOGIN_FIELD = "        #[serde(default)]\n        boring: base::trust::AskInfo, // boring-remote: audit H1\n"
H1_LOGIN_SEND = "            boring: self.boring_trust.ask_info(&self.ip), // boring-remote: audit H1\n"
H1_CLIENT_FIELDS = (
    "  // boring-remote (audit H1): new / removed, its trust key and address (base::trust::AskInfo).\n"
    "  String boringTrust = '';\n  String boringKey = '';\n  String boringIp = '';\n")
H1_CLIENT_JSON = (
    "    boringTrust = json['boring_trust'] ?? '';\n"
    "    boringKey = json['boring_key'] ?? '';\n"
    "    boringIp = json['boring_ip'] ?? '';\n")
PATCHES += [
    ("src/ipc.rs", "        from_switch: bool,\n    },\n    ChatMessage {\n",
     "        from_switch: bool,\n" + H1_LOGIN_FIELD + "    },\n    ChatMessage {\n", "ask info on Data::Login"),
    (CONN, "            from_switch: self.from_switch,\n        });\n",
     "            from_switch: self.from_switch,\n" + H1_LOGIN_SEND + "        });\n", "ask info to the connection window"),
    (CM_IFACE, "    pub from_switch: bool,\n    pub in_voice_call: bool,\n",
     "    pub from_switch: bool,\n    #[serde(flatten)]\n" + H1_ASK_INFO + "    pub in_voice_call: bool,\n",
     "ask info in the client JSON"),
    (CM_IFACE, "        from_switch: bool,\n        #[cfg(not(any(target_os = \"ios\")))] tx: mpsc::UnboundedSender<Data>,\n",
     "        from_switch: bool,\n        boring: base::trust::AskInfo,\n"
     "        #[cfg(not(any(target_os = \"ios\")))] tx: mpsc::UnboundedSender<Data>,\n", "ask info into add_connection"),
    (CM_IFACE, "            from_switch,\n            #[cfg(not(any(target_os = \"ios\")))]\n            tx,\n",
     "            from_switch,\n            boring,\n            #[cfg(not(any(target_os = \"ios\")))]\n            tx,\n",
     "ask info on the client"),
    (CM_IFACE, "privacy_mode, from_switch} => {\n", "privacy_mode, from_switch, boring} => {\n", "ask info from Data::Login"),
    (CM_IFACE, "privacy_mode, from_switch, self.tx.clone());\n", "privacy_mode, from_switch, boring, self.tx.clone());\n",
     "ask info into add_connection (desktop)"),
    (CM_IFACE, "                    from_switch,\n                    tx.clone(),\n                );\n",
     "                    from_switch,\n                    Default::default(), // boring-remote: audit H1, no ask info here\n"
     "                    tx.clone(),\n                );\n", "ask info into add_connection (Android)"),
    (SERVER_MODEL, "  bool incomingVoiceCall = false;\n\n  RxInt unreadChatMessageCount",
     "  bool incomingVoiceCall = false;\n" + H1_CLIENT_FIELDS + "\n  RxInt unreadChatMessageCount", "ask info on Client"),
    (SERVER_MODEL, "    incomingVoiceCall = json['incoming_voice_call'];\n  }\n",
     "    incomingVoiceCall = json['incoming_voice_call'];\n" + H1_CLIENT_JSON + "  }\n", "ask info from the client JSON"),
]

# --- One firewall rule each way after an upgrade (v1.7 t12/t17) --------------------
# Before t17 the rules were named "<exe> Service" ("BoringRemote Service"); t17 names them
# WINDOWS_RULE. An MSI upgrade over a pre-t17 install added the new pair and left the old pair.
# Install, upgrade, uninstall and self-install now drop the old-name rules (and any already under
# today's name) before adding, so one rule is left each way (ticket 12: no duplicates).
FW_CPP = "res/msi/CustomActions/FirewallRules.cpp"
FW_HELPERS = (
    "// boring-remote (v1.7 t17): drop every rule called `name` (INetFwRules::Remove takes one at a time).\n"
    "static void BoringRemoveRulesNamed(INetFwPolicy2* pNetFwPolicy2, LPCWSTR name)\n"
    "{\n"
    "    INetFwRules* rules = NULL;\n"
    "    if (FAILED(pNetFwPolicy2->get_Rules(&rules)) || rules == NULL) {\n"
    "        return;\n"
    "    }\n"
    "    BSTR b = SysAllocString(name);\n"
    "    int n = 0;\n"
    "    for (; b != NULL && n < 16; n++) {\n"
    "        INetFwRule* r = NULL;\n"
    "        if (FAILED(rules->Item(b, &r)) || r == NULL) {\n"
    "            break;\n"
    "        }\n"
    "        r->Release();\n"
    "        if (FAILED(rules->Remove(b))) {\n"
    "            break;\n"
    "        }\n"
    "    }\n"
    "    WcaLog(LOGMSG_STANDARD, \"Removed %d firewall rule(s) \\\"%ls\\\"\\n\", n, name);\n"
    "    SysFreeString(b);\n"
    "    rules->Release();\n"
    "}\n"
    "\n"
    "// boring-remote (v1.7 t17): the rules before t17 (\"BoringRemote Service\", the exe's name) and\n"
    "// any already under today's name go first, so install and upgrade leave one rule each way.\n"
    "static void BoringRemoveOldRules(INetFwPolicy2* pNetFwPolicy2, LPWSTR exeName)\n"
    "{\n"
    "    WCHAR old[STRING_BUFFER_SIZE] = L\"\";\n"
    "    if (SUCCEEDED(StringCchPrintfW(old, STRING_BUFFER_SIZE, L\"%ls%ls\", exeName, L\" Service\"))) {\n"
    "        BoringRemoveRulesNamed(pNetFwPolicy2, old);\n"
    "    }\n"
    f"    BoringRemoveRulesNamed(pNetFwPolicy2, L\"{WINDOWS_RULE}\");\n"
    "}\n"
    "\n")
FW_CALL = "    BoringRemoveOldRules(pNetFwPolicy2, exeName); // boring-remote (v1.7 t17)\n"
WIN_FW_ADD = f'    netsh advfirewall firewall add rule name=\\"{WINDOWS_RULE}\\" dir=out'
WIN_FW_CLEAN = (
    '    rem boring-remote (v1.7 t17): the rules before t17, and any under today\'s name, go first\n'
    '    netsh advfirewall firewall delete rule name=\\"{app_name} Service\\"\n'
    f'    netsh advfirewall firewall delete rule name=\\"{WINDOWS_RULE}\\"\n')
PATCHES += [
    (FW_CPP, "bool AddFirewallRule(bool add, LPWSTR exeName, LPWSTR exeFile)\n",
     FW_HELPERS + "bool AddFirewallRule(bool add, LPWSTR exeName, LPWSTR exeFile)\n",
     "MSI: firewall helpers drop the pre-t17 rules"),
    (FW_CPP, "    if (add) {\n", FW_CALL + "    if (add) {\n", "MSI: old-name rules go before the new ones are added"),
    ("src/platform/windows.rs", WIN_FW_ADD, WIN_FW_CLEAN + WIN_FW_ADD,
     "self-install: old-name rules go before the new ones are added"),
]

# --- Three-screen Setup (v1.7 ticket 06) -------------------------------------------
# desktop/kit/setup.dart is ours and bridge-free; these wire it in. First launch on Mac opens
# Setup in place of Home until it is finished once (local option boring-setup-done); Settings
# opens it again. Screen 1 writes the same name option Settings and LAN Discovery use.
T06_SETUP_PAGE = (
    "// boring-remote: v1.7 t06 Setup (name, see + control, Unattended Password).\n"
    "Widget boringSetupPage({required VoidCallback onDone}) {\n"
    f"  const nameKey = '{BORING_MAC_NAME_OPTION}';\n"
    "  final name = bind.mainGetOptionSync(key: nameKey);\n"
    "  final screens = SetupFlow.screenCount(SetupPlatform.mac);\n"
    "  return Theme(\n"
    "    data: Kit.theme(),\n"
    "    child: Material(\n"
    "      color: Kit.ink,\n"
    "      child: SetupFlow(\n"
    "        platform: SetupPlatform.mac,\n"
    "        computerName: name.isNotEmpty\n"
    "            ? Future.value(name)\n"
    "            : isWindows // v1.7 review: Windows' own computer name; scutil is Mac only\n"
    "                ? Future.value(windowsComputerName(Platform.environment, Platform.localHostname))\n"
    "            : Process.run('scutil', ['--get', 'ComputerName'])\n"
    "                .then((r) => r.exitCode == 0 ? '${r.stdout}'.trim() : '')\n"
    "                .catchError((_) => '')\n"
    "                .then((n) => n.isNotEmpty ? n : Platform.localHostname.replaceAll('.local', '')),\n"
    "        onName: (n) => bind.mainSetOption(key: nameKey, value: n),\n"
    "        canSeeScreen: () => bind.mainIsCanScreenRecording(prompt: false),\n"
    "        canMonitorInput: () => bind.mainIsCanInputMonitoring(prompt: false), // v1.7 t21: the third switch\n"
    "        canControl: () => bind.mainIsProcessTrusted(prompt: false),\n"
    "        switchesNow: boringServeWatch.switchesNow, // v1.7 t31: reads macOS now, and keeps --server caught up\n"
    "        clearSwitches: isMacOS ? boringClearSwitches : null,\n"
    "        openPane: (url) {\n"
    "          // Asking once puts Boring Remote in the pane's list; then open the pane itself.\n"
    "          if (url == kScreenRecordingPane) bind.mainIsCanScreenRecording(prompt: true);\n"
    "          if (url == kAccessibilityPane) bind.mainIsProcessTrusted(prompt: true);\n"
    "          if (url == kInputMonitoringPane) bind.mainIsCanInputMonitoring(prompt: true);\n"
    "          launchUrl(Uri.parse(url));\n"
    "        },\n"
    "        passwordSet: bind.mainGetCommonSync(key: 'permanent-password-set') == 'true',\n"
    "        setPassword: (p) => bind.mainSetPermanentPasswordWithResult(password: p),\n"
    "        startStep: setupStartStep(bind.mainGetLocalOption(key: kSetupStepOption), screens),\n"
    "        // v1.7 t21: a welcome on first launch only; Ready is Settings' Access line, green when it is.\n"
    "        welcome: setupNeeded(bind.mainGetLocalOption(key: kSetupDoneOption)),\n"
    "        readyChecks: boringAccessChecks(),\n"
    "        onStep: (i) => bind.mainSetLocalOption(key: kSetupStepOption, value: '$i'),\n"
    "        onDone: () async {\n"
    "          await bind.mainSetLocalOption(key: kSetupStepOption, value: '');\n"
    "          await bind.mainSetLocalOption(key: kSetupDoneOption, value: 'Y');\n"
    "          onDone();\n"
    "        },\n"
    "      ),\n"
    "    ),\n"
    "  );\n"
    "}\n\n")
T06_FIRST_LAUNCH = (
    "    if (isMacOS && _boringSetup) {\n"
    "      return _buildBlock(child: boringSetupPage(onDone: () => setState(() => _boringSetup = false)));\n"
    "    }\n")
T06_RUN_AGAIN = (
    "          onRunSetup: () => Navigator.of(context).push(MaterialPageRoute(\n"
    "            builder: (ctx) => Scaffold(\n"
    "              backgroundColor: Kit.ink,\n"
    "              appBar: AppBar(backgroundColor: Kit.ink, foregroundColor: Kit.paper),\n"
    "              body: boringSetupPage(onDone: () => Navigator.of(ctx).pop()),\n"
    "            ),\n"
    "          )).then((_) => bind.mainSetLocalOption(key: kSetupStepOption, value: '')), // t31: left Setup on purpose\n")
# The import, the first-launch branch and the Settings button land inside t01's and t09's own
# patches (as t04 did, see _fold_v17), so a second rebrand still finds their text whole and stays a no-op.
T06_FOLDS = {
    (HOME, "Mac Home imports"): ("import 'package:flutter_hbb/desktop/kit/mac_home.dart';\n",
                                "import 'package:flutter_hbb/desktop/kit/mac_home.dart';\n"
                                "import 'package:flutter_hbb/desktop/kit/setup.dart';\n"),
    (HOME, "Mac Home replaces the RustDesk home on Mac"): (
        "    if (isMacOS) return _buildBlock(child: buildBoringHome(context));\n",
        T06_FIRST_LAUNCH + "    if (isMacOS) return _buildBlock(child: buildBoringHome(context));\n"),
    (SETTINGS, "simple Settings wiring"): ("          advanced: [\n", T06_RUN_AGAIN + "          advanced: [\n"),
}
PATCHES += [
    (HOME, "class _DesktopHomePageState extends State<DesktopHomePage>\n",
     T06_SETUP_PAGE + "class _DesktopHomePageState extends State<DesktopHomePage>\n",
     "Setup wiring"),
    (HOME, "  // boring-remote: v1.7 Mac Home. Recents by name; outside the building is Tailscale (ADR 0004), never the ID.\n",
     "  bool _boringSetup = false; // v1.7 t06: first launch shows Setup until it is finished\n\n"
     "  // boring-remote: v1.7 Mac Home. Recents by name; outside the building is Tailscale (ADR 0004), never the ID.\n",
     "Setup state"),
    (HOME, "    if (isMacOS) bind.mainLoadRecentPeers(); // Mac Home lists recents\n",
     "    if (isMacOS) bind.mainLoadRecentPeers(); // Mac Home lists recents\n"
     "    if (isMacOS) _boringSetup = setupNeeded(bind.mainGetLocalOption(key: kSetupDoneOption));\n"
     "    // v1.7 t31: macOS's Quit & Reopen killed Setup partway, also when Settings opened it again.\n"
     "    if (isMacOS && bind.mainGetLocalOption(key: kSetupStepOption).isNotEmpty) _boringSetup = true;\n",
     "Setup on first launch only"),
]

# --- Windows gets the v1.7 UI (v1.7 ticket 12, ADRs 0006, 0007) -------------------
# Every Mac-only gate the v1.7 tickets added now also opens on Windows: Home + LAN list (t01/t02),
# Session Toolbar + Link Badge (t07/t03/t05), Settings (t09), trust prompt (t04), Setup (t06).
# The rewrite runs over the earlier blocks' own patch text (old and new alike), as t04/t06 did, so
# a second rebrand still finds each block whole and stays a no-op. Setup's screen 2 on Windows is
# "let other computers reach this one": the MSI's app rule (any port, every network type) covers
# Direct Link 21118 and LAN Discovery 21119; Allow adds the same rule if it is missing. The kit
# says "computer" for "this Mac" on Windows (KitWords, set once in main()).
T12_GATES = [
    "    if (isMacOS) return _buildBlock(child: buildBoringHome(context));\n",  # t01 Home
    "    if (isMacOS) bind.mainLoadRecentPeers(); // Mac Home lists recents\n",  # t01
    "    if (isMacOS) _boringSetup = setupNeeded(",  # t06 first launch
    "    if (isMacOS && _boringSetup) {\n",  # t06
    "    if (isMacOS) {\n      // Everything but Close goes behind More;",  # t07 toolbar
    "    if (isMacOS && !_boringAdvanced) {\n",  # t09 Settings
    "        if (isMacOS)\n          TextButton(\n            onPressed: () => setState(() => _boringAdvanced = false),",  # t09
    "    if (isMacOS && showAccept) {\n",  # t04 approval prompt
]
T12_EDITS = [(g, g.replace("if (isMacOS)", "if (isMacOS || isWindows)", 1)
               .replace("if (isMacOS &&", "if ((isMacOS || isWindows) &&", 1)) for g in T12_GATES] + [
    ("  final screens = SetupFlow.screenCount(SetupPlatform.mac);\n",  # t06 Setup
     "  final platform = isWindows ? SetupPlatform.windows : SetupPlatform.mac; // v1.7 t12\n"
     "  final screens = SetupFlow.screenCount(platform);\n"),
    ("        platform: SetupPlatform.mac,\n", "        platform: platform,\n"),
    ("        canControl: () => bind.mainIsProcessTrusted(prompt: false),\n",
     "        canControl: () => bind.mainIsProcessTrusted(prompt: false),\n"
     "        // v1.7 t12 (Windows): the installer's app rule is there for this exe; Allow adds it (Windows asks once).\n"
     "        canBeReached: () => Process.run('netsh', windowsRuleShowArgs())\n"
     "            .then((r) => r.exitCode == 0 && windowsRuleAllowsExe('${r.stdout}', Platform.resolvedExecutable))\n"
     "            .catchError((_) => false),\n"
     "        // A failure shows as the green check staying off (Setup checks again and says so).\n"
     "        allowReach: () => Process.run('powershell', windowsRuleAddArgs(Platform.resolvedExecutable))\n"
     "            .then<void>((r) {\n"
     "              if (r.exitCode != 0) debugPrint('Setup: adding the Windows rule failed: ${r.stderr}');\n"
     "            }).catchError((e) => debugPrint('Setup: could not run powershell: $e')),\n"),
]


def _t12(text):
    if not isinstance(text, str):
        return text
    for a, b in T12_EDITS:
        text = text.replace(a, b)
    return text


def _require(ok, why):
    """A structural guard on this script's own patch list; unlike assert, it survives python -O."""
    if not ok:
        raise RuntimeError(f"rebrand.py patch list is inconsistent: {why}")


def _fold_v17(rel, old, new, why):
    """The later v1.7 tickets write into earlier blocks' own patch text, in ticket order: t04's
    Trusted Controllers link into t09's Settings hook line, t06's folds into t01/t09, then t12's
    Mac-only gates opened to Windows, old and new alike."""
    if rel == SETTINGS and isinstance(new, str):
        new = new.replace(T04_HOOK, T04_SETTINGS_LINK)
    if (rel, why) in T06_FOLDS:
        new = new.replace(*T06_FOLDS[rel, why])
    return rel, _t12(old), _t12(new), why


PATCHES[:] = [_fold_v17(*p) for p in PATCHES]
_require(any(T04_SETTINGS_LINK in new for rel, _, new, _ in PATCHES if rel == SETTINGS), "t09's t04 hook line moved")
_require(all(any(r == rel and w == why and _t12(T06_FOLDS[rel, why][1]) in new for r, _, new, w in PATCHES)
             for rel, why in T06_FOLDS), "t01/t09 patch text moved under t06")
_require(all(any(b in new for _, _, new, _ in PATCHES) for _, b in T12_EDITS), "a v1.7 Mac gate moved under t12")
PATCHES += [
    ("flutter/lib/main.dart", "import 'package:flutter_hbb/common/widgets/overlay.dart';\n",
     "import 'package:flutter_hbb/common/widgets/overlay.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/kit.dart';\n",
     "kit words import"),
    ("flutter/lib/main.dart", "  kBootArgs = List.from(args);\n",
     "  kBootArgs = List.from(args);\n"
     "  if (isWindows) KitWords.windows(); // v1.7 t12: the kit says computer, not Mac, on Windows\n",
     "the kit says computer on Windows (every window runs main)"),
]

# --- v1.7 review: RustDesk look leftovers ------------------------------------------
# Spec Decision 5: nothing left in the RustDesk look. desktop/kit/kit_look.dart,
# connection_window.dart and install.dart are ours and bridge-free; these wire them into the
# upstream surfaces Mac and Windows still show: every overlay dialog (password prompt, connecting,
# errors in plain words with one next step), the session toolbar and the menus behind More, All
# settings, the connection window (and Allow no longer minimises it), the Windows install screen.
# common.dart's boringKit() puts a surface in the kit, with the theme extensions upstream code
# reads (MyTheme.color, MyTheme.tabbar) in kit tokens. The kit has no light variant, so Mac and
# Windows always run dark and the Theme card goes. The toolbar's own palette (_ToolbarTheme) moves
# to kit tokens on every desktop, as the MyTheme palette above does.
LOOK_TAB_PAGE = "flutter/lib/desktop/pages/desktop_tab_page.dart"
LOOK_INSTALL = "flutter/lib/desktop/pages/install_page.dart"
LOOK_DIALOGS = "flutter/lib/common/widgets/dialog.dart"
LOOK_CHAT = "flutter/lib/common/widgets/chat_page.dart"
LOOK_REMOTE_PAGES = ("flutter/lib/desktop/pages/remote_page.dart", "flutter/lib/desktop/pages/view_camera_page.dart")
LOOK_GATE = "(isMacOS || isWindows)"
LOOK_COMMON = (
    "// boring-remote: v1.7 review. The kit for the upstream surfaces Mac and Windows still show,\n"
    "// with the theme extensions upstream code reads (MyTheme.color, MyTheme.tabbar) in kit tokens.\n"
    "final ThemeData boringKitTheme = kitLook(Kit.theme()).copyWith(extensions: const <ThemeExtension<dynamic>>[\n"
    "  ColorThemeExtension(\n"
    "      border: Kit.line,\n"
    "      border2: Kit.line,\n"
    "      border3: Kit.line,\n"
    "      highlight: Kit.glass,\n"
    "      drag_indicator: Kit.muted,\n"
    "      shadow: Kit.ink,\n"
    "      errorBannerBg: Kit.glass,\n"
    "      me: Kit.ok,\n"
    "      toastBg: Kit.glass,\n"
    "      toastText: Kit.paper,\n"
    "      divider: Kit.line),\n"
    "  TabbarTheme(\n"
    "      selectedTabIconColor: Kit.paper,\n"
    "      unSelectedTabIconColor: Kit.muted,\n"
    "      selectedTextColor: Kit.paper,\n"
    "      unSelectedTextColor: Kit.muted,\n"
    "      selectedIconColor: Kit.paper,\n"
    "      unSelectedIconColor: Kit.muted,\n"
    "      dividerColor: Kit.line,\n"
    "      hoverColor: Kit.glass,\n"
    "      closeHoverColor: Kit.line,\n"
    "      selectedTabBackgroundColor: Kit.glass),\n"
    "]);\n\n"
    "/// [child] in the kit on Mac and Windows; other platforms keep the upstream look.\n"
    "Widget boringKit(Widget child, {Key? key}) =>\n"
    f"    {LOOK_GATE} ? Theme(key: key, data: boringKitTheme, child: child) : child;\n\n")
LOOK_MESSAGE = (
    f"  if {LOOK_GATE} {{\n"
    "    // boring-remote: v1.7 review: plain words, the next step on an error, no RustDesk icons.\n"
    "    final plain = kitMessageWords(type, title, text);\n"
    "    return KitMessage(\n"
    "      title: plain?.title ?? translate(title),\n"
    "      body: plain?.body ?? translateText(text),\n"
    "      next: plain?.next,\n"
    "      waiting: kitMessageWaits(type, text),\n"
    "    );\n"
    "  }\n")
LOOK_CM_HEADER = (
    f"    if {LOOK_GATE} {{\n"
    "      // boring-remote: v1.7 review: who is in, in the kit. No ID, no blue card.\n"
    "      final kind = switch (client.type_()) {\n"
    "        ClientType.file => ConnectedKind.files,\n"
    "        ClientType.camera => ConnectedKind.camera,\n"
    "        ClientType.terminal => ConnectedKind.terminal,\n"
    "        ClientType.portForward => ConnectedKind.forward,\n"
    "        ClientType.remote => ConnectedKind.control,\n"
    "      };\n"
    "      final canChat = client.authorized &&\n"
    "          (kind == ConnectedKind.control || kind == ConnectedKind.files || kind == ConnectedKind.camera);\n"
    "      return Obx(() => ConnectedHeader(\n"
    "            name: client.name,\n"
    "            kind: kind,\n"
    "            allowed: client.authorized,\n"
    "            ended: client.disconnected,\n"
    "            connectedFor: Duration(seconds: _time.value),\n"
    "            chatIsFiles: kind == ConnectedKind.files,\n"
    "            onChat: !canChat\n"
    "                ? null\n"
    "                : () => checkClickTime(client.id, () {\n"
    "                      if (kind == ConnectedKind.files) {\n"
    "                        gFFI.chatModel.toggleCMFilePage();\n"
    "                      } else {\n"
    "                        gFFI.chatModel.toggleCMChatPage(MessageKey(client.peerId, client.id));\n"
    "                      }\n"
    "                    }),\n"
    "          ));\n"
    "    }\n")
LOOK_CM_PERMISSIONS = (
    "  // boring-remote: v1.7 review: what the other side may do, as plain switches in the kit.\n"
    "  Widget _boringPermissions(bool canModify) {\n"
    "    final c = client;\n"
    "    final values = c.type_() == ClientType.camera\n"
    "        ? {'audio': c.audio, 'recording': c.recording}\n"
    "        : {\n"
    "            'keyboard': c.keyboard,\n"
    "            'clipboard': c.clipboard,\n"
    "            'audio': c.audio,\n"
    "            'file': c.file,\n"
    "            'restart': c.restart,\n"
    "            'recording': c.recording,\n"
    "            if (isWindows) 'block_input': c.blockInput,\n"
    "            if (bind.mainSupportedPrivacyModeImpls() != '[]') 'privacy_mode': c.privacyMode,\n"
    "          };\n"
    "    return PermissionSwitches(\n"
    "      values: values,\n"
    "      canChange: canModify,\n"
    "      onChanged: (name, on) => checkClickTime(c.id, () {\n"
    "        bind.cmSwitchPermission(connId: c.id, name: name, enabled: on);\n"
    "        setState(() {\n"
    "          switch (name) {\n"
    "            case 'keyboard':\n"
    "              c.keyboard = on;\n"
    "            case 'clipboard':\n"
    "              c.clipboard = on;\n"
    "            case 'audio':\n"
    "              c.audio = on;\n"
    "            case 'file':\n"
    "              c.file = on;\n"
    "            case 'restart':\n"
    "              c.restart = on;\n"
    "            case 'recording':\n"
    "              c.recording = on;\n"
    "            case 'block_input':\n"
    "              c.blockInput = on;\n"
    "            case 'privacy_mode':\n"
    "              c.privacyMode = on;\n"
    "          }\n"
    "        });\n"
    "      }),\n"
    "    );\n"
    "  }\n\n")
LOOK_CM_BUTTON = (
    f"    if {LOOK_GATE} {{\n"
    "      // boring-remote: v1.7 review: connection window buttons in the kit.\n"
    "      final kitButton = CmButton(\n"
    "        label: translate(text),\n"
    "        icon: icon is Icon ? icon.icon : null,\n"
    "        primary: CmButton.primaryKeys.contains(text),\n"
    "        onTap: () {\n"
    "          if (onClick != null) checkClickTime(client.id, onClick);\n"
    "        },\n"
    "        onTapDown: (details) {\n"
    "          if (onTapDown != null) checkClickTime(client.id, () => onTapDown(details));\n"
    "        },\n"
    "      );\n"
    "      return tooltip != null ? Tooltip(message: translate(tooltip), child: kitButton) : kitButton;\n"
    "    }\n")
LOOK_INSTALL_METHOD = (
    "  // boring-remote: v1.7 review. The install screen in the kit: plain words, one Install button.\n"
    "  Widget boringInstallScreen() => Obx(() => InstallScreen(\n"
    "        path: controller,\n"
    "        onChangePath: selectInstallPath,\n"
    "        startMenu: startmenu.value,\n"
    "        onStartMenu: (v) => startmenu.value = v,\n"
    "        desktopIcon: desktopicon.value,\n"
    "        onDesktopIcon: (v) => desktopicon.value = v,\n"
    "        printer: printer.value,\n"
    "        onPrinter: (v) => printer.value = v,\n"
    "        installing: showProgress.value || !btnEnabled.value,\n"
    "        canTryWithoutInstalling: !bind.installShowRunWithoutInstall(),\n"
    "        onInstall: install,\n"
    "        onCancel: () => windowManager.close(),\n"
    "        onTryWithoutInstalling: () => bind.installRunWithoutInstall(),\n"
    # this.context: path.dart's top-level context would win over State's otherwise
    "        onLicence: () => showLegalDialog(this.context),\n"
    "      ));\n\n")
# Allow keeps the connection window up (review: minimising was not asked for). t04's prompt is
# folded in its own patch, as t04 and t06 did, so a second rebrand still finds it whole.
LOOK_ALLOW = ("            onAllow: () {\n"
              "              handleAccept(context);\n"
              "              windowManager.minimize();\n"
              "            },\n",
              "            // Allow keeps this window up: the card shows who is in and how to end it.\n"
              "            onAllow: () => handleAccept(context),\n")
PATCHES[:] = [(rel, old, new.replace(*LOOK_ALLOW) if rel == CM_PAGE and isinstance(new, str) else new, why)
              for rel, old, new, why in PATCHES]
if not any(rel == CM_PAGE and LOOK_ALLOW[1] in new for rel, _, new, _ in PATCHES):
    raise SystemExit("rebrand: t04's approval prompt moved; the v1.7 review fold for Allow found nothing")
PATCHES += [
    # the kit for upstream surfaces, and Mac and Windows always dark
    (DART_COMMON, "import 'package:flutter_hbb/desktop/widgets/refresh_wrapper.dart';\n",
     "import 'package:flutter_hbb/desktop/widgets/refresh_wrapper.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/kit.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/kit_look.dart';\n", "kit look imports"),
    (DART_COMMON, "class MyTheme {\n  MyTheme._();\n", LOOK_COMMON + "class MyTheme {\n  MyTheme._();\n",
     "boringKit: an upstream surface in the kit"),
    (DART_COMMON, "  static ThemeMode getThemeModePreference() {\n    return themeModeFromString(",
     "  static ThemeMode getThemeModePreference() {\n"
     f"    if {LOOK_GATE} return ThemeMode.dark; // boring-remote: the kit is dark (v1.7 review)\n"
     "    return themeModeFromString(", "Mac and Windows always run the dark kit"),
    (SETTINGS, "  Widget theme() {\n    final current = MyTheme.getThemeModePreference().toShortString();\n",
     "  Widget theme() {\n"
     f"    if {LOOK_GATE} return const Offstage(); // boring-remote: the kit is always dark\n"
     "    final current = MyTheme.getThemeModePreference().toShortString();\n", "no Theme card on Mac and Windows"),
    # dialogs: every overlay dialog in the kit, connection messages in plain words
    (DART_COMMON, "                  onPointerUp: (_) => innerClicked = true,\n"
     "                  child: builder(setState, close, overlayState.context),\n",
     "                  onPointerUp: (_) => innerClicked = true,\n"
     "                  // boring-remote: v1.7 review: every dialog in the kit on Mac and Windows.\n"
     "                  child: boringKit(builder(setState, close, overlayState.context)),\n",
     "dialogs in the kit"),
    (DART_COMMON, "  return Row(\n    children: [\n      msgboxIcon(type),\n",
     LOOK_MESSAGE + "  return Row(\n    children: [\n      msgboxIcon(type),\n", "connection messages in plain words"),
    (LOOK_DIALOGS, "import 'package:flutter_hbb/models/peer_tab_model.dart';\n",
     "import 'package:flutter_hbb/models/peer_tab_model.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/kit_look.dart';\n", "password prompt words import"),
    (LOOK_DIALOGS, "      title: Row(\n        mainAxisAlignment: MainAxisAlignment.center,\n        children: [\n"
     "          Icon(Icons.password_rounded, color: MyTheme.accent),\n"
     "          Text(translate('Password Required')).paddingOnly(left: 10),\n        ],\n      ),\n",
     f"      title: {LOOK_GATE}\n"
     "          ? Text(KitPasswordWords.title) // boring-remote: v1.7 review, plain words\n"
     "          : Row(\n              mainAxisAlignment: MainAxisAlignment.center,\n              children: [\n"
     "                Icon(Icons.password_rounded, color: MyTheme.accent),\n"
     "                Text(translate('Password Required')).paddingOnly(left: 10),\n              ],\n            ),\n",
     "password prompt title"),
    (LOOK_DIALOGS, "          descWidget(translate('verify_rustdesk_password_tip')),\n",
     f"          descWidget({LOOK_GATE}\n"
     "              ? KitPasswordWords.body\n"
     "              : translate('verify_rustdesk_password_tip')),\n", "password prompt body"),
    (LOOK_DIALOGS, "          rememberWidget(\n            translate('Remember password'),\n",
     "          rememberWidget(\n"
     f"            {LOOK_GATE} ? KitPasswordWords.remember : translate('Remember password'),\n",
     "password prompt remember box"),
    # session toolbar and every menu behind More
    (T07_TOOLBAR, "import 'package:flutter_hbb/models/state_model.dart';\n",
     "import 'package:flutter_hbb/models/state_model.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/kit.dart';\n", "toolbar palette import"),
    (T07_TOOLBAR, "  static const Color blueColor = MyTheme.button;\n"
     "  static const Color hoverBlueColor = MyTheme.accent;\n"
     "  static Color inactiveColor = Colors.grey[800]!;\n"
     "  static Color hoverInactiveColor = Colors.grey[850]!;\n\n"
     "  static const Color redColor = Colors.redAccent;\n"
     "  static const Color hoverRedColor = Colors.red;\n",
     "  // boring-remote: v1.7 review: toolbar and More icons in kit tokens (a coral fill marks\n"
     "  // recording or a call to end; it never sits under text).\n"
     "  static const Color blueColor = Kit.glass;\n"
     "  static const Color hoverBlueColor = Kit.line;\n"
     "  static Color inactiveColor = Kit.panel;\n"
     "  static Color hoverInactiveColor = Kit.glass;\n\n"
     "  static const Color redColor = Kit.coral;\n"
     "  static const Color hoverRedColor = Kit.coral;\n", "toolbar palette in kit tokens"),
] + [
    p for page in LOOK_REMOTE_PAGES for p in (
        (page, "    remoteToolbar(BuildContext context) => RemoteToolbar(\n",
         "    // boring-remote: v1.7 review: the toolbar and every menu behind More in the kit.\n"
         "    remoteToolbar(BuildContext context) => boringKit(RemoteToolbar(\n", "toolbar in the kit"),
        (page, "          setRemoteState: setState,\n        );\n\n    bodyWidget() {\n",
         "          setRemoteState: setState,\n        ));\n\n    bodyWidget() {\n", "toolbar in the kit (close)"),
    )
] + [
    # All settings: kit theme, kit sections and tab list
    (LOOK_TAB_PAGE, "          page: DesktopSettingPage(\n            key: const ValueKey(kTabLabelSettingPage),\n"
     "            initialTabkey: initialPage,\n          )));\n",
     "          // boring-remote: v1.7 review: All settings in the kit on Mac and Windows.\n"
     "          page: boringKit(\n              DesktopSettingPage(\n"
     "                key: const ValueKey(kTabLabelSettingPage),\n                initialTabkey: initialPage,\n"
     "              ),\n              key: const ValueKey(kTabLabelSettingPage))));\n", "All settings in the kit"),
    (SETTINGS, "import 'package:flutter_hbb/models/printer_model.dart';\n",
     "import 'package:flutter_hbb/models/printer_model.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/kit_look.dart';\n", "All settings kit import"),
    (SETTINGS, "Widget _Card(\n    {required String title,\n    required List<Widget> children,\n"
     "    List<Widget>? title_suffix}) {\n  return Row(\n",
     "Widget _Card(\n    {required String title,\n    required List<Widget> children,\n"
     "    List<Widget>? title_suffix}) {\n"
     f"  if {LOOK_GATE} {{\n"
     "    // boring-remote: v1.7 review: All settings' sections in the kit.\n"
     "    return KitSection(title: translate(title), trailing: title_suffix ?? const [], children: children);\n"
     "  }\n  return Row(\n", "All settings sections in the kit"),
    (SETTINGS, "      bool selected = tab.key == selectedTab.value;\n      return SizedBox(\n"
     "        width: _kTabWidth,\n        height: _kTabHeight,\n",
     "      bool selected = tab.key == selectedTab.value;\n"
     f"      if {LOOK_GATE} {{\n"
     "        // boring-remote: v1.7 review: All settings' tab list in the kit.\n"
     "        return KitTabRow(\n"
     "          label: translate(tab.label),\n"
     "          icon: selected ? tab.selected : tab.unselected,\n"
     "          selected: selected,\n"
     "          onTap: () {\n"
     "            if (selectedTab.value != tab.key) {\n"
     "              final index = DesktopSettingPage.tabKeys.indexOf(tab.key);\n"
     "              if (index == -1) return;\n"
     "              controller.jumpToPage(index);\n"
     "            }\n"
     "            selectedTab.value = tab.key;\n"
     "          },\n"
     "        );\n"
     "      }\n"
     "      return SizedBox(\n        width: _kTabWidth,\n        height: _kTabHeight,\n",
     "All settings tab list in the kit"),
    # connection window after Allow: who is in, plain switches, kit buttons, kit chat bubbles
    (CM_PAGE, "import 'package:flutter_hbb/utils/platform_channel.dart';\n",
     "import 'package:flutter_hbb/utils/platform_channel.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/connection_window.dart';\n", "connection window kit import"),
    (CM_PAGE, "          final body = Scaffold(\n            backgroundColor: Theme.of(context).colorScheme.background,\n"
     "            body: ConnectionManager(),\n          );\n",
     "          // boring-remote: v1.7 review: the connection window in the kit on Mac and Windows.\n"
     "          final body = boringKit(Scaffold(\n"
     f"            backgroundColor: {LOOK_GATE} ? Kit.ink : Theme.of(context).colorScheme.background,\n"
     "            body: ConnectionManager(),\n          ));\n", "connection window in the kit"),
    (CM_PAGE, "    super.build(context);\n    return Container(\n      decoration: BoxDecoration(\n"
     "        borderRadius: BorderRadius.circular(10.0),\n        gradient: LinearGradient(\n",
     "    super.build(context);\n" + LOOK_CM_HEADER + "    return Container(\n      decoration: BoxDecoration(\n"
     "        borderRadius: BorderRadius.circular(10.0),\n        gradient: LinearGradient(\n",
     "connection window: who is in"),
    (CM_PAGE, "  @override\n  Widget build(BuildContext context) {\n    final crossAxisCount = 4;\n",
     LOOK_CM_PERMISSIONS + "  @override\n  Widget build(BuildContext context) {\n    final crossAxisCount = 4;\n",
     "connection window: plain permission switches"),
    (CM_PAGE, "            'N';\n    return Container(\n      width: double.infinity,\n      height: 160.0,\n",
     "            'N';\n"
     f"    if {LOOK_GATE} return _boringPermissions(canModifyPermission);\n"
     "    return Container(\n      width: double.infinity,\n      height: 160.0,\n",
     "connection window: switches replace the RustDesk grid"),
    (CM_PAGE, "    assert(!(onClick == null && onTapDown == null));\n    Widget textWidget;\n",
     "    assert(!(onClick == null && onTapDown == null));\n" + LOOK_CM_BUTTON + "    Widget textWidget;\n",
     "connection window buttons in the kit"),
    (LOOK_CHAT, "import 'package:flutter_hbb/models/chat_model.dart';\n",
     "import 'package:flutter_hbb/models/chat_model.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/kit.dart';\n", "chat kit import"),
    (LOOK_CHAT, "                          color:\n                              isOwnMessage ? MyTheme.button : Colors.blueGrey,\n",
     f"                          color: {LOOK_GATE} // boring-remote: v1.7 review, kit bubbles\n"
     "                              ? (isOwnMessage ? Kit.glass : Kit.line)\n"
     "                              : isOwnMessage ? MyTheme.button : Colors.blueGrey,\n", "chat bubbles in the kit"),
    (LOOK_CHAT, "                              style: TextStyle(\n                                color: Colors.white,\n"
     "                                fontSize: 8,\n",
     "                              style: TextStyle(\n"
     f"                                color: {LOOK_GATE} ? Kit.muted : Colors.white,\n"
     f"                                fontSize: {LOOK_GATE} ? 12 : 8,\n", "chat time 12px floor"),
    # Windows install screen
    (LOOK_INSTALL, "import 'package:flutter_hbb/models/state_model.dart';\n",
     "import 'package:flutter_hbb/models/state_model.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/kit.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/install.dart';\n"
     "import 'package:flutter_hbb/desktop/kit/legal.dart';\n", "install screen imports"),
    (LOOK_INSTALL, "        child: Scaffold(\n            backgroundColor: Theme.of(context).colorScheme.background,\n"
     "            body: DesktopTab(controller: tabController)),\n",
     "        child: boringKit(Scaffold(\n"
     f"            backgroundColor: {LOOK_GATE} ? Kit.ink : Theme.of(context).colorScheme.background,\n"
     "            body: DesktopTab(controller: tabController))),\n", "install window in the kit"),
    (LOOK_INSTALL, "  @override\n  Widget build(BuildContext context) {\n    final double em = 13;\n",
     LOOK_INSTALL_METHOD + "  @override\n  Widget build(BuildContext context) {\n"
     f"    if {LOOK_GATE} return boringInstallScreen();\n    final double em = 13;\n",
     "install screen in the kit"),
]

# --- v1.7 t17 follow-up: Access (Settings) and "not ready" (Home) --------------------------
# kit/access.dart is ours and bridge-free; this is the one place its checks meet the bridge.
# Each check is something that has to hold for the process that serves sessions (--server)
# before another computer can connect. Fix asks macOS first (so Boring Remote shows in the list),
# then opens the exact pane.
T17_ACCESS_CHECKS = (
    "// boring-remote: v1.7 t17. What has to be true before another computer can connect.\n"
    "Future<String>? _boringUid;\n"
    "Future<String> _boringUidNow() => _boringUid ??= Process.run('id', ['-u']).then((r) => '${r.stdout}'.trim());\n"
    "// v1.7 t31: Ready means what --server can do. It answers for itself over IPC; a new copy of the exe\n"
    "// reads the switches, since macOS can keep a running process's answer until it restarts.\n"
    "final boringServeWatch = ServeWatch(\n"
    "    askServer: () => bind.cmGetConfig(name: kServeAccessConfig).then<MacAccess?>(MacAccess.parse).catchError((_) => null),\n"
    "    askFresh: () => Process.run(Platform.resolvedExecutable, const [kFreshCheckArg])\n"
    "        .then<MacAccess?>((r) => r.exitCode == 0 ? MacAccess.parse('${r.stdout}') : null)\n"
    "        .catchError((_) => null),\n"
    "    askWindow: () => MacAccess(\n"
    "        screen: bind.mainIsCanScreenRecording(prompt: false),\n"
    "        control: bind.mainIsProcessTrusted(prompt: false),\n"
    "        input: bind.mainIsCanInputMonitoring(prompt: false)),\n"
    "    restart: () async => restartAgent(Process.run, await _boringUidNow()),\n"
    "    mayRestart: () => !mainGetBoolOptionSync(kOptionStopService));\n"
    "// \"Switch is on but still not working?\": clears ours (kit/access.dart), restarts --server so it holds no\n"
    "// old answer, asks macOS again and opens the first pane. Only ever from a click.\n"
    "Future<bool> boringClearSwitches() async {\n"
    "  // Only --server itself: with the window standing in, starting --server makes it close the window.\n"
    "  final up = await boringServeWatch.answering();\n"
    "  final ok = await clearSwitches(Process.run);\n"
    "  boringServeWatch.forget();\n"
    "  if (ok) {\n"
    "    bind.mainIsCanScreenRecording(prompt: true);\n"
    "    launchUrl(Uri.parse(kScreenRecordingPane));\n"
    "  }\n"
    "  if (up && !await restartAgent(Process.run, await _boringUidNow())) debugPrint('Access: --server still down');\n"
    "  return ok;\n"
    "}\n"
    "List<AccessCheck> boringAccessChecks() {\n"
    "  Future<bool> listening() => Socket.connect('127.0.0.1', kDirectLinkPort, timeout: const Duration(seconds: 1))\n"
    "      .then((s) {\n"
    "        s.destroy();\n"
    "        return true;\n"
    "      }).catchError((_) => false);\n"
    "  bool stopped() => mainGetBoolOptionSync(kOptionStopService);\n"
    "  Future<void> turnOn() async {\n"
    "    if (stopped()) await mainSetBoolOption(kOptionStopService, false);\n"
    "    if (!bind.mainIsInstalledDaemon(prompt: false)) bind.mainIsInstalledDaemon(prompt: true);\n"
    "  }\n"
    "  final on = AccessCheck(\n"
    "      label: AccessWords.on,\n"
    "      why: AccessWords.onWhy,\n"
    "      read: () async => bind.mainIsInstalledDaemon(prompt: false) && !stopped(),\n"
    "      fix: turnOn);\n"
    "  if (isWindows) {\n"
    "    Future<bool> running() => Process.run('sc', ['query', 'BoringRemote'])\n"
    "        .then((r) => '${r.stdout}'.contains('RUNNING'))\n"
    "        .catchError((_) => false);\n"
    "    return [\n"
    "      AccessCheck(\n"
    "          label: AccessWords.reach,\n"
    "          why: AccessWords.reachWhy,\n"
    "          read: () => Process.run('netsh', windowsRuleShowArgs())\n"
    "              .then((r) => r.exitCode == 0 && windowsRuleAllowsExe('${r.stdout}', Platform.resolvedExecutable))\n"
    "              .catchError((_) => false),\n"
    "          fix: () => Process.run('powershell', windowsRuleAddArgs(Platform.resolvedExecutable))\n"
    "              .then<void>((_) {}).catchError((e) => debugPrint('Access: $e'))),\n"
    "      on,\n"
    "      AccessCheck(label: AccessWords.running, why: AccessWords.runningWhy, read: running, fix: turnOn),\n"
    "      AccessCheck(label: AccessWords.listening, why: AccessWords.listeningWhy, read: listening, fix: turnOn),\n"
    "    ];\n"
    "  }\n"
    "  Future<String> uid() => _boringUidNow();\n"
    "  Future<bool> running() async =>\n"
    "      await Process.run('launchctl', ['print', 'gui/${await uid()}/$kAgentLabel'])\n"
    "          .then((r) => r.exitCode == 0 && agentRunning('${r.stdout}'))\n"
    "          .catchError((_) => false) &&\n"
    "      await boringServeWatch.answering(); // t31: up and answering for itself\n"
    "  // kickstart, and bootout + bootstrap when launchd holds the job at spawn failed (kit/access.dart).\n"
    "  Future<void> startAgent() async {\n"
    "    await turnOn();\n"
    "    if (!await restartAgent(Process.run, await uid())) debugPrint('Access: --server still down');\n"
    "  }\n"
    "  void pane(String url) {\n"
    "    boringServeWatch.forget(); // t31: a Fix click gets --server another try\n"
    "    launchUrl(Uri.parse(url));\n"
    "  }\n"
    "  return [\n"
    "    AccessCheck(\n"
    "        label: AccessWords.screen,\n"
    "        why: AccessWords.screenWhy,\n"
    "        read: () => boringServeWatch.serves((a) => a.screen), // t31: --server's own answer\n"
    "        fix: () async {\n"
    "          bind.mainIsCanScreenRecording(prompt: true); // CGRequestScreenCaptureAccess: macOS asks, and lists us\n"
    "          pane(kScreenRecordingPane);\n"
    "        }),\n"
    "    AccessCheck(\n"
    "        label: AccessWords.control,\n"
    "        why: AccessWords.controlWhy,\n"
    "        read: () => boringServeWatch.serves((a) => a.control),\n"
    "        fix: () async {\n"
    "          bind.mainIsProcessTrusted(prompt: true);\n"
    "          pane(kAccessibilityPane);\n"
    "        }),\n"
    "    AccessCheck(\n"
    "        label: AccessWords.input,\n"
    "        why: AccessWords.inputWhy,\n"
    "        read: () => boringServeWatch.serves((a) => a.input),\n"
    "        fix: () async {\n"
    "          bind.mainIsCanInputMonitoring(prompt: true);\n"
    "          pane(kInputMonitoringPane);\n"
    "        }),\n"
    "    on,\n"
    "    AccessCheck(label: AccessWords.running, why: AccessWords.runningWhy, read: running, fix: startAgent),\n"
    "    AccessCheck(label: AccessWords.listening, why: AccessWords.listeningWhy, read: listening, fix: startAgent),\n"
    "  ];\n"
    "}\n\n")
T17_ACCESS_IMPORT = "import 'package:flutter_hbb/desktop/kit/access.dart';\n"
# v1.7 t31: --server says what it can do, in its own process, over the IPC config call the window
# already uses (bind.cmGetConfig). A new copy of the exe prints the same line and exits before any
# window or log opens: macOS can keep a running process's Screen Recording answer until it restarts.
T31_ACCESS_LINE = (
    "/// boring-remote (v1.7 t31): what this process can do, as macOS tells it. kit/access.dart reads\n"
    "/// this line (MacAccess.parse). Remote sessions, so an automatic restart never drops one.\n"
    "pub fn boring_access_line() -> String {\n"
    "    let yn = |on: bool| if on { \"Y\" } else { \"N\" };\n"
    "    let sessions = crate::server::AUTHED_CONNS\n"
    "        .lock()\n"
    "        .unwrap()\n"
    "        .iter()\n"
    "        .filter(|x| x.conn_type == crate::server::AuthConnType::Remote)\n"
    "        .count();\n"
    "    format!(\n"
    "        \"server={} screen={} control={} input={} sessions={}\",\n"
    "        yn(crate::is_server()),\n"
    "        yn(is_can_screen_recording(false)),\n"
    "        yn(is_process_trusted(false)),\n"
    "        yn(is_can_input_monitoring(false)),\n"
    "        sessions\n"
    "    )\n"
    "}\n\n")
T31_IPC = (
    '                } else if name == "boring-serve-access" {\n'
    "                    // boring-remote (v1.7 t31): Ready asks --server, not the window.\n"
    '                    #[cfg(target_os = "macos")]\n'
    "                    {\n"
    "                        value = Some(crate::platform::macos::boring_access_line());\n"
    "                    }\n"
    '                    #[cfg(not(target_os = "macos"))]\n'
    "                    {\n"
    "                        value = None;\n"
    "                    }\n")
T31_FRESH = (
    '        } else if args[0] == "--boring-access" {\n'
    "            // boring-remote (v1.7 t31): a new process's read of the switches, for Setup and Access.\n"
    '            #[cfg(target_os = "macos")]\n'
    '            println!("{}", crate::platform::macos::boring_access_line());\n'
    "            return None;\n")
PATCHES += [
    ("src/platform/macos.rs", "pub fn is_can_screen_recording(prompt: bool) -> bool {\n",
     T31_ACCESS_LINE + "pub fn is_can_screen_recording(prompt: bool) -> bool {\n", "what this process can do (t31)"),
    ("src/ipc.rs", '                } else if name == "trusted-devices" {\n',
     T31_IPC + '                } else if name == "trusted-devices" {\n', "--server answers for itself (t31)"),
    ("src/core_main.rs", '        } else if args[0] == "--build-date" {\n',
     T31_FRESH + '        } else if args[0] == "--build-date" {\n', "a new process reads the switches (t31)"),
]
PATCHES += [
    (HOME, "class _DesktopHomePageState extends State<DesktopHomePage>\n",
     T17_ACCESS_CHECKS + "class _DesktopHomePageState extends State<DesktopHomePage>\n", "Access checks (t17)"),
    (HOME, "import 'package:flutter_hbb/consts.dart';\n", "import 'package:flutter_hbb/consts.dart';\n" + T17_ACCESS_IMPORT,
     "Access import (home)"),
    (SETTINGS, "import 'package:flutter_hbb/desktop/kit/trust.dart';\n",
     "import 'package:flutter_hbb/desktop/kit/trust.dart';\n" + T17_ACCESS_IMPORT, "Access import (settings)"),
]

# --- Save a support file and crash files (v1.7 ticket 20) ---------------------------------
# libs/base/src/support.rs (zip, redaction, panic hook, crash notice) and desktop/kit/support.dart
# (bridge-free) are ours; these wire them in. Every process that logs installs the panic hook right
# after init_log, so crash-<time>.txt lands next to that process's log. Settings → Help saves the
# zip on the Desktop; Home offers it once after a crash. Nothing is uploaded.
T20_MOD = "pub mod support; // v1.7 t20: support file, crash files\n"
T20_HOOK_CORE = "    base::support::install_panic_hook(&log_name, crate::VERSION); // boring-remote (v1.7 t20): crash files\n"
T20_HOOK_FFI = "        base::support::install_panic_hook(\"flutter_ffi\", crate::VERSION); // boring-remote (v1.7 t20)\n"
T20_HOOK_SERVICE = "    base::support::install_panic_hook(\"service\", librustdesk::VERSION); // boring-remote (v1.7 t20)\n"
T20_FFI = (
    "/// boring-remote (v1.7 t20): Save a support file on the Desktop (base::support). `access` is the\n"
    "/// Access rows as Settings shows them. File work, so not Sync. Returns the zip's path, or \"\".\n"
    "pub fn main_boring_save_support_file(access: String) -> String {\n"
    "    let enc = scrap::codec::Encoder::supported_encoding();\n"
    "    let codecs = format!(\n"
    "        \"encode: VP8 {}, VP9 true, AV1 {}, H.264 {}, H.265 {}\\nhardware decode: {}\",\n"
    "        enc.vp8,\n"
    "        enc.av1,\n"
    "        enc.h264,\n"
    "        enc.h265,\n"
    "        main_supported_hwdecodings().0\n"
    "    );\n"
    "    let rows = [\n"
    "        (\"Version\", format!(\"{} (built {})\", crate::VERSION, crate::BUILD_DATE)),\n"
    "        (\"Displays\", main_get_displays().0),\n"
    "        (\"Codecs\", codecs),\n"
    "        (\"Access\", access),\n"
    "    ];\n"
    "    match base::support::save(&rows) {\n"
    "        Ok(p) => p.to_string_lossy().into_owned(),\n"
    "        Err(e) => {\n"
    "            log::error!(\"support file not saved: {}\", e);\n"
    "            String::new()\n"
    "        }\n"
    "    }\n"
    "}\n\n"
    "/// boring-remote (v1.7 t20): Boring Remote closed unexpectedly since Home last offered the file.\n"
    "pub fn main_boring_crash_to_offer() -> SyncReturn<bool> {\n"
    "    SyncReturn(base::support::crash_to_offer())\n"
    "}\n\n"
    "/// boring-remote (v1.7 t20): Home's notice was answered; these crashes aren't offered again.\n"
    "pub fn main_boring_crash_offered() {\n"
    "    base::support::crash_offered()\n"
    "}\n\n")
T20_SAVE_FN = (
    "// boring-remote: v1.7 t20. Save a support file on the Desktop, with the Access rows as Settings shows them.\n"
    "Future<String> boringSaveSupportFile() async =>\n"
    "    bind.mainBoringSaveSupportFile(access: await accessReport(boringAccessChecks()));\n\n")
T20_NOTICE = (
    "              CrashNotice( // v1.7 t20: closed unexpectedly last time, offer the support file once\n"
    "                  crashed: () => bind.mainBoringCrashToOffer(),\n"
    "                  save: boringSaveSupportFile,\n"
    "                  onDone: () => bind.mainBoringCrashOffered()),\n")
T20_HELP = "          help: SupportSection(save: boringSaveSupportFile), // v1.7 t20\n"
T20_IMPORT = "import 'package:flutter_hbb/desktop/kit/support.dart';\n"
PATCHES += [
    (BASE_LIB, "pub mod update_feed;\n", "pub mod update_feed;\n" + T20_MOD, "base: support module (t20)"),
    ("src/core_main.rs", "    hbb_common::init_log(false, &log_name);\n",
     "    hbb_common::init_log(false, &log_name);\n" + T20_HOOK_CORE, "crash files: every core_main process (t20)"),
    ("src/flutter_ffi.rs", "        hbb_common::init_log(false, \"flutter_ffi\");\n",
     "        hbb_common::init_log(false, \"flutter_ffi\");\n" + T20_HOOK_FFI, "crash files: the window (t20)"),
    ("src/service.rs", "    hbb_common::init_log(false, \"service\");\n",
     "    hbb_common::init_log(false, \"service\");\n" + T20_HOOK_SERVICE, "crash files: the Mac service (t20)"),
    ("src/flutter_ffi.rs", "pub fn main_get_local_option(key: String) -> SyncReturn<String> {\n",
     T20_FFI + "pub fn main_get_local_option(key: String) -> SyncReturn<String> {\n", "support file bridge calls (t20)"),
    (HOME, "class _DesktopHomePageState extends State<DesktopHomePage>\n",
     T20_SAVE_FN + "class _DesktopHomePageState extends State<DesktopHomePage>\n", "save a support file (t20)"),
    (HOME, T17_ACCESS_IMPORT, T17_ACCESS_IMPORT + T20_IMPORT, "support import (home)"),
    (SETTINGS, T17_ACCESS_IMPORT, T17_ACCESS_IMPORT + T20_IMPORT, "support import (settings)"),
]
# Home's notices and Settings' slots live inside t01's and t09's own blocks, so t20 writes into
# that patch text (as t04/t06/t12 do) rather than patching over it.
T20_FOLDS = [
    (HOME, "              AccessSummary(checks: boringAccessChecks()), // v1.7 t17: not ready yet, and its Fix\n",
     T20_NOTICE + "              AccessSummary(checks: boringAccessChecks()), // v1.7 t17: not ready yet, and its Fix\n"),
    (SETTINGS, "          access: AccessSection(checks: boringAccessChecks(), clearSwitches: isMacOS ? boringClearSwitches : null), // v1.7 t17, t31\n",
     "          access: AccessSection(checks: boringAccessChecks(), clearSwitches: isMacOS ? boringClearSwitches : null), // v1.7 t17, t31\n" + T20_HELP),
]
_require(all(sum(r == rel and a in new for r, _, new, _ in PATCHES) == 1 for rel, a, _ in T20_FOLDS),
         "t20's Home notice or Settings Help anchor moved")


def _fold_t20(r, old, new, why):
    for rel, a, b in T20_FOLDS:
        if r == rel and isinstance(new, str):
            new = new.replace(a, b)
    return r, old, new, why


PATCHES[:] = [_fold_t20(*p) for p in PATCHES]

# --- File transfer at whatever the slowest link is (v1.7 ticket 27) -----------------------
# libs/base/src/file_speed.rs and desktop/kit/file_transfer.dart are ours; these wire them in.
# Sending: the 1 ms tick arm sends for up to a 2 ms slice instead of one block, so the socket sets
# the pace and the other arms still run between slices. Target writing: the connection stops
# reading the peer while 32 MiB is queued for its CM, and the CM acks what it wrote; upstream's queue
# is unbounded. Windows Target reading (through the CM): the same window the other way, on a 1 ms tick
# instead of 5 ms. A Controller keeps upstream's pace for a Target that doesn't say it can take more.
# secretbox is about 450 MiB/s per core and the wire format is fixed, so TCP streams seal a run of
# blocks, and open big frames already in the buffer, on several cores with the same nonces in the
# same order. Small frames (input, most video, every old peer's handshake) take upstream's path.
HBB_TCP = "libs/hbb_common/src/tcp.rs"
HBB_STREAM = "libs/hbb_common/src/stream.rs"
BASE_BUILD = "libs/base/build.rs"
FS_RS = "libs/base/src/fs.rs"
UI_CM = "src/ui_cm_interface.rs"
IPC = "src/ipc.rs"
T27_BUILD = (
    "    // boring-remote (v1.7 t27): this tree's hbb_common has Stream::send_run. A raw checkout's doesn't.\n"
    "    println!(\"cargo:rustc-check-cfg=cfg(boring_stream_run)\");\n"
    "    println!(\"cargo:rustc-cfg=boring_stream_run\");\n")
T27_READY = (
    "/// boring-remote (v1.7 t27): frames opened ahead, which `next` hands out in order.\n"
    "#[derive(Default)]\n"
    "struct BoringReady(std::collections::VecDeque<Result<BytesMut, Error>>);\n\n"
    "impl Clone for BoringReady {\n"
    "    fn clone(&self) -> Self {\n"
    "        Self::default()\n"
    "    }\n"
    "}\n\n"
    "/// boring-remote (v1.7 t27): how many big frames open together, what counts as big, and on how\n"
    "/// many cores. secretbox is about 450 MiB/s per core and the wire format isn't ours to change.\n"
    "const BORING_RUN: usize = 8;\n"
    "const BORING_RUN_FROM: usize = 64 * 1024;\n"
    "const BORING_CORES: usize = 4;\n\n"
    "fn boring_each<T: Send>(items: &mut [T], f: impl Fn(usize, &mut T) + Sync) {\n"
    "    if items.len() < 2 {\n"
    "        items.iter_mut().enumerate().for_each(|(i, item)| f(i, item));\n"
    "        return;\n"
    "    }\n"
    "    let per = (items.len() + BORING_CORES - 1) / BORING_CORES;\n"
    "    let f = &f;\n"
    "    std::thread::scope(|s| {\n"
    "        for (c, chunk) in items.chunks_mut(per).enumerate() {\n"
    "            s.spawn(move || {\n"
    "                for (i, item) in chunk.iter_mut().enumerate() {\n"
    "                    f(c * per + i, item);\n"
    "                }\n"
    "            });\n"
    "        }\n"
    "    });\n"
    "}\n\n")
T27_ENC_RUN = (
    "    /// boring-remote (v1.7 t27): the nonces `enc` would use one at a time, on several cores.\n"
    "    fn enc_run(&mut self, mut msgs: Vec<Vec<u8>>) -> Vec<Vec<u8>> {\n"
    "        let (first, key) = (self.1, &self.0);\n"
    "        boring_each(&mut msgs, |i, m| {\n"
    "            *m = secretbox::seal(m, &FramedStream::get_nonce(first + 1 + i as u64), key);\n"
    "        });\n"
    "        self.1 += msgs.len() as u64;\n"
    "        msgs\n"
    "    }\n\n"
    "    /// boring-remote (v1.7 t27): what `dec` does to each frame, on several cores, into the ready queue.\n"
    "    fn open_run(&mut self, frames: Vec<BytesMut>) {\n"
    "        let mut run: Vec<_> = frames\n"
    "            .into_iter()\n"
    "            .map(|frame| {\n"
    "                let nonce = (frame.len() > 1).then(|| {\n"
    "                    self.2 += 1;\n"
    "                    FramedStream::get_nonce(self.2)\n"
    "                });\n"
    "                (nonce, Ok(frame))\n"
    "            })\n"
    "            .collect();\n"
    "        let key = self.3.as_ref().unwrap_or(&self.0);\n"
    "        boring_each(&mut run, |_, (nonce, res): &mut (Option<Nonce>, Result<BytesMut, Error>)| {\n"
    "            if let (Some(nonce), Ok(frame)) = (nonce.as_ref(), res.as_ref()) {\n"
    "                *res = secretbox::open(frame, nonce, key)\n"
    "                    .map(|opened| BytesMut::from(&opened[..]))\n"
    "                    .map_err(|()| Error::new(ErrorKind::Other, \"decryption error\"));\n"
    "            }\n"
    "        });\n"
    "        self.4 .0.extend(run.into_iter().map(|(_, res)| res));\n"
    "    }\n\n")
T27_SEND_RUN = (
    "    /// boring-remote (v1.7 t27): messages in order, sealed together. The same bytes on the wire.\n"
    "    pub async fn send_run(&mut self, msgs: Vec<Vec<u8>>) -> ResultType<()> {\n"
    "        let msgs = match self.2.as_mut() {\n"
    "            Some(key) => key.enc_run(msgs),\n"
    "            None => msgs,\n"
    "        };\n"
    "        for msg in msgs {\n"
    "            self.send_bytes(Bytes::from(msg)).await?;\n"
    "        }\n"
    "        Ok(())\n"
    "    }\n\n")
T27_NEXT = (
    "    pub async fn next(&mut self) -> Option<Result<BytesMut, Error>> {\n"
    "        // boring-remote (v1.7 t27): big frames already here open together, on several cores.\n"
    "        if let Some(ready) = self.2.as_mut().and_then(|key| key.4 .0.pop_front()) {\n"
    "            return Some(ready);\n"
    "        }\n"
    "        let mut res = self.0.next().await;\n"
    "        if self.2.is_some() && matches!(&res, Some(Ok(frame)) if frame.len() >= BORING_RUN_FROM) {\n"
    "            let mut frames: Vec<BytesMut> = res.and_then(Result::ok).into_iter().collect();\n"
    "            let mut failed = None;\n"
    "            while frames.len() < BORING_RUN {\n"
    "                // Nothing is awaited from here on, so a select dropping this future loses nothing.\n"
    "                match futures::FutureExt::now_or_never(self.0.next()) {\n"
    "                    Some(Some(Ok(frame))) => frames.push(frame),\n"
    "                    Some(Some(Err(err))) => {\n"
    "                        failed = Some(err);\n"
    "                        break;\n"
    "                    }\n"
    "                    _ => break, // the end of the stream comes round again on the next call\n"
    "                }\n"
    "            }\n"
    "            let key = self.2.as_mut()?;\n"
    "            key.open_run(frames);\n"
    "            key.4 .0.extend(failed.map(Err));\n"
    "            return key.4 .0.pop_front();\n"
    "        }\n")
T27_STREAM_RUN = (
    "    /// boring-remote (v1.7 t27): messages in order. TCP seals them together.\n"
    "    pub async fn send_run(&mut self, msgs: Vec<Vec<u8>>) -> ResultType<()> {\n"
    "        if let Stream::Tcp(s) = self {\n"
    "            return s.send_run(msgs).await;\n"
    "        }\n"
    "        for msg in msgs {\n"
    "            self.send_raw(msg).await?;\n"
    "        }\n"
    "        Ok(())\n"
    "    }\n\n")
T27_MOD = "pub mod file_speed; // boring-remote (v1.7 t27): full-speed file transfer\n"
T27_COMPRESS = (
    "            // boring-remote (v1.7 t27): not media, and not a file that has stopped shrinking.\n"
    "            if matches!(self.data_source, DataSource::FilePath(_))\n"
    "                && !is_compressed_file(name)\n"
    "                && self.boring_compress.should_try(file_num, name)\n"
    "            {\n"
    "                let tmp = compress(&buf);\n"
    "                self.boring_compress.saw(buf.len(), tmp.len());\n")
T27_CONN_ARM = (
    "                        // boring-remote (v1.7 t27): send for a slice, not one block per tick. The log\n"
    "                        // to the CM was per tick, and now keeps a person's pace.\n"
    "                        if conn.boring_file_log.ready(base::file_speed::LOG_EVERY) {\n"
    "                            conn.send_to_cm(ipc::Data::FileTransferLog((\"transfer\".to_string(), fs::serialize_transfer_jobs(&conn.read_jobs))));\n"
    "                        }\n"
    "                        match base::file_speed::pump_read_jobs(&mut conn.read_jobs, &mut conn.stream).await {\n")
T27_CONN_GUARD = (
    "                // boring-remote (v1.7 t27): while the CM is 32 MiB behind, leave blocks in the socket so\n"
    "                // the sender feels the disk. Other arms keep running; each ack wakes this loop.\n"
    "                res = conn.stream.next(), if conn.boring_cm_window.has_room() => {\n")
T27_CONN_ACK = (
    "                        ipc::Data::FileWriteAck(bytes) => {\n"
    "                            // boring-remote (v1.7 t27): the guard on conn.stream.next() stops\n"
    "                            // last_recv_time moving, and a disk writing isn't an idle peer.\n"
    "                            conn.boring_cm_window.refund(bytes);\n"
    "                            last_recv_time = Instant::now();\n"
    "                        }\n")
T27_CONN_SPEND = (
    "                        // boring-remote (v1.7 t27): acked by the CM's IPC task, on desktop only.\n"
    "                        #[cfg(not(any(target_os = \"android\", target_os = \"ios\")))]\n"
    "                        self.boring_cm_window.spend(block.data.len());\n")
T27_MARKER = (
    "        // boring-remote (v1.7 t27): this Target pushes back on a sender (base::file_speed::CmWindow).\n"
    "        #[cfg(any(target_os = \"linux\", target_os = \"windows\", target_os = \"macos\"))]\n"
    "        platform_additions.insert(base::file_speed::FULL_SPEED_KEY.into(), json!(true));\n")
T27_READ_ACK = (
    "        // boring-remote (v1.7 t27): every block, stale ones too, or the CM's window stays spent. The\n"
    "        // send below finishes before this loop takes the next block.\n"
    "        self.send_to_cm(ipc::Data::FileReadAck(data.len()));\n")
T27_IPC = (
    "    /// boring-remote (v1.7 t27): CM to connection, bytes it has written or taken off the queue.\n"
    "    FileWriteAck(usize),\n"
    "    /// boring-remote (v1.7 t27): connection to CM, bytes it has sent on from a CM read job.\n"
    "    FileReadAck(usize),\n")
T27_CM_STATE = (
    "        // boring-remote (v1.7 t27): the two windows between this CM and its connection, and a\n"
    "        // person's pace for the progress log.\n"
    "        let mut boring_acks = base::file_speed::AckBatch::default();\n"
    "        let mut boring_read_window = base::file_speed::CmWindow::default();\n"
    "        let mut boring_write_log = base::file_speed::Every::default();\n"
    "        let mut boring_read_log = base::file_speed::Every::default();\n")
T27_CM_TICK = (
    "                        let conn_id = self.conn_id;\n"
    "                        // boring-remote (v1.7 t27): read for a slice while the connection keeps up.\n"
    "                        // self.tx is unbounded, so the window is what stops a whole file landing in\n"
    "                        // memory.\n"
    "                        let boring_started = Instant::now();\n"
    "                        while boring_read_window.has_room() {\n"
    "                            let before = base::file_speed::progress(&self.read_jobs);\n"
    "                            if let Err(e) = handle_read_jobs_tick(&mut self.read_jobs, &self.tx, conn_id).await {\n"
    "                                log::error!(\"Error processing read jobs: {}\", e);\n"
    "                            }\n"
    "                            let after = base::file_speed::progress(&self.read_jobs);\n"
    "                            boring_read_window.spend(after.1.saturating_sub(before.1) as usize);\n"
    "                            if after == before || boring_started.elapsed() >= base::file_speed::SLICE {\n"
    "                                break;\n"
    "                            }\n"
    "                        }\n"
    "                        if boring_read_log.ready(base::file_speed::LOG_EVERY) || self.read_jobs.is_empty() {\n"
    "                            let log = fs::serialize_transfer_jobs(&self.read_jobs);\n"
    "                            self.cm.ui_handler.file_transfer_log(\"transfer\", &log);\n"
    "                        }\n")
T27_IO_ARM = (
    "                                // boring-remote (v1.7 t27): send for a slice, not one block per tick,\n"
    "                                // unless this Target would only queue them in memory.\n"
    "                                let boring_sent = if self.boring_full_speed {\n"
    "                                    base::file_speed::pump_read_jobs(&mut self.read_jobs, &mut peer).await\n"
    "                                } else {\n"
    "                                    fs::handle_read_jobs(&mut self.read_jobs, &mut peer).await\n"
    "                                };\n"
    "                                if let Err(err) = boring_sent {\n")
T27_IO_PEER = "                        self.boring_full_speed = base::file_speed::target_takes_full_speed(&pi.platform_additions); // boring-remote (v1.7 t27)\n"
T27_IO_SPEED = (
    "        // boring-remote (v1.7 t27): file bytes, so a job's speed agrees with its percentage on\n"
    "        // compressed blocks too, and nothing until the second look, since a resumed job starts high.\n"
    "        let transferred = job.finished_size();\n"
    "        let last_transferred = last_update_jobs_status.1.get(&job.id()).copied();\n"
    "        last_update_jobs_status.1.insert(job.id(), transferred);\n"
    "        let speed = last_transferred.map_or(0., |last| {\n"
    "            transferred.saturating_sub(last) as f64 / (elapsed as f64 / 1000.)\n"
    "        });\n")
T27_DRIVES = (
    "  // boring-remote (v1.7 t27): one click to any drive on this side; the location bar still takes a path.\n"
    "  Future<List<TransferDrive>> _boringLoadDrives() async {\n"
    "    var platform = isLocal\n"
    "        ? (isWindows ? kPeerPlatformWindows : (isMacOS ? kPeerPlatformMacOS : ''))\n"
    "        : _ffi.ffiModel.pi.platform;\n"
    "    // The other computer's platform arrives with its PeerInfo, just after this view builds.\n"
    "    for (var i = 0; platform.isEmpty && !isLocal && i < 100; i++) {\n"
    "      await Future.delayed(const Duration(milliseconds: 200));\n"
    "      platform = _ffi.ffiModel.pi.platform;\n"
    "    }\n"
    "    final root = transferDriveRoot(platform);\n"
    "    if (root == null) return const [];\n"
    "    final fd = await controller.fileFetcher.fetchDirectory(root, isLocal, false);\n"
    "    return transferDrivesFrom(platform, [\n"
    "      for (final e in fd.entries)\n"
    "        (name: e.name, directory: e.isDirectory || e.isDrive, link: e.entryType == 2)\n"
    "    ]);\n"
    "  }\n\n")
T27_BLOCK_OLD = (
    "                    Some(file_response::Union::Block(block)) => {\n"
    "                        self.send_fs(ipc::FS::WriteBlock {\n")
PATCHES += [
    (BASE_LIB, T20_MOD, T20_MOD + T27_MOD, "base: file_speed module (t27)"),
    (BASE_BUILD, "fn main() {\n", "fn main() {\n" + T27_BUILD, "base knows its hbb_common has send_run (t27)"),
    (HBB_TCP, "pub struct Encrypt(pub Key, pub u64, pub u64, Option<Key>);\n",
     "pub struct Encrypt(pub Key, pub u64, pub u64, Option<Key>, BoringReady);\n\n" + T27_READY,
     "Encrypt holds frames opened ahead (t27)"),
    (HBB_TCP, "        let Encrypt(send, _, _, recv) = Encrypt::new_split(key.clone(), true, &t).unwrap();\n",
     "        let Encrypt(send, _, _, recv, _) = Encrypt::new_split(key.clone(), true, &t).unwrap();\n",
     "upstream's Encrypt test, one more field (t27)"),
    (HBB_TCP, "        let Encrypt(send, _, _, recv) = Encrypt::new_split(key, true, &t).unwrap();\n",
     "        let Encrypt(send, _, _, recv, _) = Encrypt::new_split(key, true, &t).unwrap();\n",
     "upstream's other Encrypt test, one more field (t27)"),
    (HBB_TCP, "        Self(key, 0, 0, None)\n", "        Self(key, 0, 0, None, Default::default())\n", "Encrypt::new (t27)"),
    (HBB_TCP, "            Self(initiator, 0, 0, Some(responder))\n",
     "            Self(initiator, 0, 0, Some(responder), Default::default())\n", "Encrypt::new_split, initiator (t27)"),
    (HBB_TCP, "            Self(responder, 0, 0, Some(initiator))\n",
     "            Self(responder, 0, 0, Some(initiator), Default::default())\n", "Encrypt::new_split, responder (t27)"),
    (HBB_TCP, "    pub fn dec(&mut self, bytes: &mut BytesMut) -> Result<(), Error> {\n",
     T27_ENC_RUN + "    pub fn dec(&mut self, bytes: &mut BytesMut) -> Result<(), Error> {\n", "seal and open a run (t27)"),
    (HBB_TCP, "    #[inline]\n    pub async fn send_bytes(&mut self, bytes: Bytes) -> ResultType<()> {\n",
     T27_SEND_RUN + "    #[inline]\n    pub async fn send_bytes(&mut self, bytes: Bytes) -> ResultType<()> {\n",
     "FramedStream::send_run (t27)"),
    (HBB_TCP, "    pub async fn next(&mut self) -> Option<Result<BytesMut, Error>> {\n        let mut res = self.0.next().await;\n",
     T27_NEXT, "FramedStream::next opens big frames together (t27)"),
    (HBB_STREAM, "    #[inline]\n    pub async fn send_raw(&mut self, bytes: Vec<u8>) -> ResultType<()> {\n",
     T27_STREAM_RUN + "    #[inline]\n    pub async fn send_raw(&mut self, bytes: Vec<u8>) -> ResultType<()> {\n",
     "Stream::send_run (t27)"),
    (FS_RS, "    #[serde(skip_serializing)]\n    digest: FileDigest,\n}\n",
     "    #[serde(skip_serializing)]\n    digest: FileDigest,\n"
     "    // boring-remote (v1.7 t27)\n    #[serde(skip_serializing)]\n"
     "    boring_compress: crate::file_speed::CompressGate,\n"
     "    #[serde(skip_serializing)]\n"
     "    boring_ahead: crate::file_speed::ReadAhead,\n}\n",
     "a job remembers whether its file still shrinks, and reads ahead (t27)"),
    (FS_RS, "    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {\n",
     "    // boring-remote (v1.7 t27): a run of blocks per thread hop instead of one.\n"
     "    async fn read_ahead(\n"
     "        &mut self,\n"
     "        ahead: &mut crate::file_speed::ReadAhead,\n"
     "        out: &mut [u8],\n"
     "    ) -> std::io::Result<usize> {\n"
     "        if ahead.is_empty() {\n"
     "            let n = self.read(ahead.space()).await?;\n"
     "            ahead.filled(n);\n"
     "        }\n"
     "        Ok(ahead.take(out))\n"
     "    }\n\n"
     "    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {\n",
     "read-ahead on the data stream (t27)"),
    (FS_RS,
     "                .ok_or(anyhow!(\"data stream is None\"))?\n"
     "                .read(&mut buf[offset..])\n"
     "                .await\n",
     "                .ok_or(anyhow!(\"data stream is None\"))?\n"
     "                .read_ahead(&mut self.boring_ahead, &mut buf[offset..])\n"
     "                .await\n",
     "the job's reads go through the read-ahead (t27)"),
    (FS_RS, "        log::debug!(\"skip file {} in job {}\", self.file_num, self.id);\n        self.data_stream.take();\n",
     "        log::debug!(\"skip file {} in job {}\", self.file_num, self.id);\n"
     "        self.boring_ahead.clear(); // boring-remote (v1.7 t27)\n"
     "        self.data_stream.take();\n",
     "a skip drops what was read ahead (t27)"),
    (FS_RS, "            if f.seek(std::io::SeekFrom::Start(offset)).await.is_ok() {\n",
     "            self.boring_ahead.clear(); // boring-remote (v1.7 t27)\n"
     "            if f.seek(std::io::SeekFrom::Start(offset)).await.is_ok() {\n",
     "a seek on resume drops what was read ahead (t27)"),
    (FS_RS,
     "            if matches!(self.data_source, DataSource::FilePath(_)) && !is_compressed_file(name) {\n"
     "                let tmp = compress(&buf);\n",
     T27_COMPRESS, "no zstd on media, or on a file that stopped shrinking (t27)"),
    (CONN, "    read_jobs: Vec<fs::TransferJob>,\n",
     "    read_jobs: Vec<fs::TransferJob>,\n"
     "    boring_file_log: base::file_speed::Every, // boring-remote (v1.7 t27)\n"
     "    boring_cm_window: base::file_speed::CmWindow, // boring-remote (v1.7 t27)\n", "transfer fields (t27)"),
    (CONN, "            read_jobs: Vec::new(),\n",
     "            read_jobs: Vec::new(),\n"
     "            boring_file_log: Default::default(),\n"
     "            boring_cm_window: Default::default(),\n", "transfer field defaults (t27)"),
    (CONN,
     "                        conn.send_to_cm(ipc::Data::FileTransferLog((\"transfer\".to_string(), fs::serialize_transfer_jobs(&conn.read_jobs))));\n"
     "                        match fs::handle_read_jobs(&mut conn.read_jobs, &mut conn.stream).await {\n",
     T27_CONN_ARM, "Target sends until the socket pushes back (t27)"),
    (CONN, "                res = conn.stream.next() => {\n", T27_CONN_GUARD, "Target stops reading while its CM is behind (t27)"),
    (CONN, "                        ipc::Data::FileBlockFromCM { id, file_num, data, compressed, conn_id } => {\n",
     T27_CONN_ACK + "                        ipc::Data::FileBlockFromCM { id, file_num, data, compressed, conn_id } => {\n",
     "the CM's acks open the window (t27)"),
    (CONN, T27_BLOCK_OLD,
     "                    Some(file_response::Union::Block(block)) => {\n" + T27_CONN_SPEND
     + "                        self.send_fs(ipc::FS::WriteBlock {\n", "blocks to the CM spend the window (t27)"),
    (CONN, T05_MARKER, T27_MARKER + T05_MARKER, "Target says it takes full speed (t27)"),
    (CONN, "        // Check if the job is still valid (not cancelled)\n"
           "        if !self.cm_read_job_ids.contains(&id) {\n"
           "            log::debug!(\n"
           "                \"Dropping file block for cancelled/unknown job id={}, file_num={}\",\n",
     T27_READ_ACK
     + "        // Check if the job is still valid (not cancelled)\n"
       "        if !self.cm_read_job_ids.contains(&id) {\n"
       "            log::debug!(\n"
       "                \"Dropping file block for cancelled/unknown job id={}, file_num={}\",\n",
     "blocks from a CM read job open its window (t27)"),
    (IPC, "    /// Response to ReadAllFiles: recursive directory listing\n",
     T27_IPC + "    /// Response to ReadAllFiles: recursive directory listing\n", "IPC: window acks (t27)"),
    (UI_CM, "        const MILLI5: Duration = Duration::from_millis(5);\n",
     "        const BORING_FILE_TICK: Duration = Duration::from_millis(1); // boring-remote (v1.7 t27): was 5 ms\n",
     "CM read job tick (t27)"),
    (UI_CM, "                                        file_timer = crate::rustdesk_interval(time::interval(MILLI5));\n",
     "                                        file_timer = crate::rustdesk_interval(time::interval(BORING_FILE_TICK));\n",
     "CM read job tick in use (t27)"),
    (UI_CM, "        // for tmp use, without real conn id\n        let mut write_jobs: Vec<fs::TransferJob> = Vec::new();\n",
     T27_CM_STATE + "        // for tmp use, without real conn id\n        let mut write_jobs: Vec<fs::TransferJob> = Vec::new();\n",
     "CM transfer state (t27)"),
    (UI_CM,
     "                                Data::FS(mut fs) => {\n"
     "                                    if let ipc::FS::WriteBlock { id, file_num, data: _, compressed } = fs {\n"
     "                                        if let Ok(bytes) = self.stream.next_raw().await {\n"
     "                                            fs = ipc::FS::WriteBlock{id, file_num, data:bytes.into(), compressed};\n"
     "                                            handle_fs(fs, &mut write_jobs, &mut self.read_jobs, &self.tx, Some(&tx_log), self.conn_id).await;\n"
     "                                        }\n",
     "                                Data::FileReadAck(bytes) => boring_read_window.refund(bytes), // boring-remote (v1.7 t27)\n"
     "                                Data::FS(mut fs) => {\n"
     "                                    let boring_block = matches!(fs, ipc::FS::WriteBlock { .. }); // boring-remote (v1.7 t27)\n"
     "                                    if let ipc::FS::WriteBlock { id, file_num, data: _, compressed } = fs {\n"
     "                                        if let Ok(bytes) = self.stream.next_raw().await {\n"
     "                                            let boring_bytes = bytes.len();\n"
     "                                            fs = ipc::FS::WriteBlock{id, file_num, data:bytes.into(), compressed};\n"
     "                                            handle_fs(fs, &mut write_jobs, &mut self.read_jobs, &self.tx, Some(&tx_log), self.conn_id).await;\n"
     "                                            // boring-remote (v1.7 t27): written, so the connection may\n"
     "                                            // read the peer again. Every block, even for a gone job.\n"
     "                                            if let Some(n) = boring_acks.add(boring_bytes) {\n"
     "                                                allow_err!(self.tx.send(Data::FileWriteAck(n)));\n"
     "                                            }\n"
     "                                        }\n",
     "CM acks what it wrote (t27)"),
    (UI_CM,
     "                                    let log = fs::serialize_transfer_jobs(&write_jobs);\n"
     "                                    self.cm.ui_handler.file_transfer_log(\"transfer\", &log);\n"
     "                                }\n"
     "                                Data::FileTransferLog((action, log)) => {\n",
     "                                    // boring-remote (v1.7 t27): this was every block.\n"
     "                                    if !boring_block || boring_write_log.ready(base::file_speed::LOG_EVERY) {\n"
     "                                        let log = fs::serialize_transfer_jobs(&write_jobs);\n"
     "                                        self.cm.ui_handler.file_transfer_log(\"transfer\", &log);\n"
     "                                    }\n"
     "                                }\n"
     "                                Data::FileTransferLog((action, log)) => {\n",
     "CM logs writes at a person's pace (t27)"),
    (UI_CM,
     "                        let conn_id = self.conn_id;\n"
     "                        if let Err(e) = handle_read_jobs_tick(&mut self.read_jobs, &self.tx, conn_id).await {\n"
     "                            log::error!(\"Error processing read jobs: {}\", e);\n"
     "                        }\n"
     "                        let log = fs::serialize_transfer_jobs(&self.read_jobs);\n"
     "                        self.cm.ui_handler.file_transfer_log(\"transfer\", &log);\n",
     T27_CM_TICK, "CM read jobs: a slice per tick, inside the window (t27)"),
    (IO_LOOP, "    read_jobs: Vec<fs::TransferJob>,\n",
     "    read_jobs: Vec<fs::TransferJob>,\n    boring_full_speed: bool, // boring-remote (v1.7 t27)\n", "Controller's pace field (t27)"),
    (IO_LOOP, "            read_jobs: Vec::new(),\n",
     "            read_jobs: Vec::new(),\n            boring_full_speed: false,\n", "Controller's pace starts at upstream's (t27)"),
    (IO_LOOP, "                                if let Err(err) = fs::handle_read_jobs(&mut self.read_jobs, &mut peer).await {\n",
     T27_IO_ARM, "Controller sends until the socket pushes back (t27)"),
    (IO_LOOP, T05_ASK_CALL, T27_IO_PEER + T05_ASK_CALL, "Controller reads what the Target can take (t27)"),
    (IO_LOOP,
     "        let transferred = job.transferred();\n"
     "        let last_transferred = {\n"
     "            if let Some(v) = last_update_jobs_status.1.get(&job.id()) {\n"
     "                v.to_owned()\n"
     "            } else {\n"
     "                0\n"
     "            }\n"
     "        };\n"
     "        last_update_jobs_status.1.insert(job.id(), transferred);\n"
     "        let speed = (transferred - last_transferred) as f64 / (elapsed as f64 / 1000.);\n",
     T27_IO_SPEED, "the speed a person sees (t27)"),
    (FILE_MGR, "  Widget headTools() {\n", T27_DRIVES + "  Widget headTools() {\n", "drive list loader (t27)"),
    (FILE_MGR, "        children: [\n          headTools(),\n",
     "        children: [\n          headTools(),\n"
     "          TransferDrives(load: _boringLoadDrives, onOpen: controller.openDirectory), // boring-remote (v1.7 t27)\n",
     "drive list on each side (t27)"),
]

# --- File transfer proves every file (v1.7 ticket 30) -------------------------------------
# libs/base/src/file_verify.rs is ours; these wire it in. The sender hashes with BLAKE3 as it reads,
# the receiver reads the `.download` back off the disk, and only a match gets the real name. Hashes
# and metadata travel in Misc::plugin_request, an upstream message nothing else uses, after a
# handshake only a Boring Remote answers: an old peer sees none of it and the job says so.
BASE_TOML = "libs/base/Cargo.toml"
CARGO_LOCK = "Cargo.lock"
FILE_MODEL = "flutter/lib/models/file_model.dart"
UI_SESSION = "src/ui_session_interface.rs"
FLUTTER_RS = "src/flutter.rs"
T30_MOD = "pub mod file_verify; // boring-remote (v1.7 t30): every file proved\n"
T30_DEP = "blake3 = \"=1.8.2\" # boring-remote (v1.7 t30): file_verify. 1.8.2 is the last on Rust 1.81 without a newer constant_time_eq.\n"
T30_LOCK_BLAKE3 = (
    "[[package]]\n"
    "name = \"blake3\"\n"
    "version = \"1.8.2\"\n"
    "source = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
    "checksum = \"3888aaa89e4b2a40fca9848e400f6a658a5a3978de7be858e209cafa8be9a4a0\"\n"
    "dependencies = [\n"
    " \"arrayref\",\n"
    " \"arrayvec\",\n"
    " \"cc\",\n"
    " \"cfg-if 1.0.0\",\n"
    " \"constant_time_eq 0.3.1\",\n"
    "]\n\n")
T30_LOCK_CTE = (
    "[[package]]\n"
    "name = \"constant_time_eq\"\n"
    "version = \"0.3.1\"\n"
    "source = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
    "checksum = \"7c74b8349d32d297c9134b8c88677813a227df8f779daa29bfc29c183fe3dca6\"\n\n")
T30_HOOKS = (
    "// boring-remote (v1.7 t30): the job's end of crate::file_verify, here for the private fields.\n"
    "async fn boring_file_stamp(stream: &Option<DataStream>) -> crate::file_verify::FileStamp {\n"
    "    match stream {\n"
    "        Some(DataStream::FileStream(file)) => match file.metadata().await {\n"
    "            Ok(m) => (m.len(), m.modified().ok()),\n"
    "            Err(_) => Default::default(),\n"
    "        },\n"
    "        _ => Default::default(),\n"
    "    }\n"
    "}\n\n"
    "impl TransferJob {\n"
    "    /// Before a read job's next read: what never gets read is listed, and a file that came back\n"
    "    /// wrong goes again, once the first pass is over. It doesn't ask about overwriting again.\n"
    "    pub async fn boring_tick(&mut self) {\n"
    "        if !self.boring.sending() {\n"
    "            return;\n"
    "        }\n"
    "        let DataSource::FilePath(root) = &self.data_source else {\n"
    "            return;\n"
    "        };\n"
    "        let root = root.clone();\n"
    "        let len = self.files.len() as i32;\n"
    "        if self.data_stream.is_none() {\n"
    "            while self.file_num < len {\n"
    "                let path = Self::join(&root, &self.files[self.file_num as usize].name);\n"
    "                if !self.boring.refuse(self.file_num, &path) {\n"
    "                    break;\n"
    "                }\n"
    "                self.file_num += 1;\n"
    "            }\n"
    "        }\n"
    "        if self.file_num < len || self.data_stream.is_some() {\n"
    "            return;\n"
    "        }\n"
    "        let Some(n) = self.boring.next_resend() else {\n"
    "            return;\n"
    "        };\n"
    "        let entry = &self.files[n as usize];\n"
    "        let (path, size) = (Self::join(&root, &entry.name), entry.size);\n"
    "        match File::open(&path).await {\n"
    "            Ok(file) => {\n"
    "                self.boring_ahead.clear();\n"
    "                self.boring.resend_started();\n"
    "                self.data_stream = Some(DataStream::FileStream(file));\n"
    "                self.file_num = n;\n"
    "                self.file_confirmed = true;\n"
    "                self.file_is_waiting = false;\n"
    "                self.finished_size = self.finished_size.saturating_sub(size);\n"
    "            }\n"
    "            Err(err) => self.boring.resend_failed(n, &path, &err.to_string()),\n"
    "        }\n"
    "    }\n\n"
    "    #[inline]\n"
    "    pub fn boring_holds_done(&self) -> bool {\n"
    "        self.boring.holds_done(self.file_num, self.files.len() as i32)\n"
    "    }\n\n"
    "    fn boring_after_read(&mut self, file_num: usize, err: Option<String>) {\n"
    "        let DataSource::FilePath(root) = &self.data_source else {\n"
    "            return;\n"
    "        };\n"
    "        let Some(entry) = self.files.get(file_num) else {\n"
    "            return;\n"
    "        };\n"
    "        let path = Self::join(root, &entry.name);\n"
    "        let (n, next, len) = (file_num as i32, self.file_num, self.files.len() as i32);\n"
    "        self.file_num = match err {\n"
    "            None => self.boring.sent_eof(n, &path, next, len),\n"
    "            Some(err) => self.boring.read_failed(n, &path, &err, next, len),\n"
    "        };\n"
    "    }\n\n"
    "    /// Whether the open file changed under the read, or the read stopped short of it.\n"
    "    async fn boring_file_changed(&mut self) -> Option<String> {\n"
    "        if !self.boring.sending() {\n"
    "            return None;\n"
    "        }\n"
    "        let now = boring_file_stamp(&self.data_stream).await;\n"
    "        self.boring.stamp_closed(now)\n"
    "    }\n\n"
    "    pub async fn write(&mut self, block: FileTransferBlock) -> ResultType<()> {\n"
    "        let (end_of_file, file_num) = (block.data.is_empty() && !block.compressed, block.file_num);\n"
    "        if self.boring.refuses_file(file_num) {\n"
    "            return Ok(());\n"
    "        }\n"
    "        let counted = self.boring.rewind(file_num);\n"
    "        self.finished_size = self.finished_size.saturating_sub(counted);\n"
    "        let res = self.boring_write(block).await;\n"
    "        if !self.boring.receiving() {\n"
    "            return res;\n"
    "        }\n"
    "        // A write that failed shows up in the read-back, which is what sends it again.\n"
    "        if let Err(err) = res {\n"
    "            self.boring.write_failed(file_num, &err.to_string());\n"
    "        }\n"
    "        if end_of_file {\n"
    "            if let Some(DataStream::FileStream(mut file)) = self.data_stream.take() {\n"
    "                if let Err(err) = file.flush().await {\n"
    "                    self.boring.write_failed(file_num, &err.to_string());\n"
    "                }\n"
    "            }\n"
    "            crate::file_verify::file_closed(self, file_num);\n"
    "        }\n"
    "        Ok(())\n"
    "    }\n\n"
    "    /// What a disk failing part way through a file looks like: the next real read is an error.\n"
    "    #[cfg(test)]\n"
    "    pub fn boring_break_stream(&mut self, dir: &Path) {\n"
    "        let dir = std::fs::File::open(dir).unwrap();\n"
    "        self.data_stream = Some(DataStream::FileStream(File::from_std(dir)));\n"
    "    }\n"
    "}\n\n")
T30_READ_GUARD = (
    "        // boring-remote (v1.7 t30): a file that wouldn't open is listed, and the next call moves on.\n"
    "        if self.boring.sending() && self.data_stream.is_none() {\n"
    "            return Ok(None);\n"
    "        }\n"
    "        if self.boring.wants_stamp() {\n"
    "            let stamp = boring_file_stamp(&self.data_stream).await;\n"
    "            self.boring.stamp_opened(stamp);\n"
    "        }\n")
T30_TICK = (
    "    // boring-remote (v1.7 t30): seals and manifests go out between blocks, in order.\n"
    "    for job in jobs.iter_mut().filter(|j| !j.is_last_job) {\n"
    "        job.boring_tick().await;\n"
    "        for msg in job.boring.take_outgoing() {\n"
    "            stream.send(&msg).await?;\n"
    "        }\n"
    "    }\n")
T30_IO_ON_WIRE = (
    "    /// boring-remote (v1.7 t30): a message from the other computer about a job's files.\n"
    "    fn boring_on_wire(&mut self, content: &[u8]) {\n"
    "        use base::file_verify::{self as verify, Wire};\n"
    "        let Some(wire) = Wire::from_json(content) else {\n"
    "            return;\n"
    "        };\n"
    "        if let Wire::Report { id, report } = wire {\n"
    "            let receiving_here = fs::get_job(id, &mut self.write_jobs).is_some();\n"
    "            if verify::report_is_wanted(self.boring_verify_os.is_some(), receiving_here) {\n"
    "                self.boring_reports.insert(id, report);\n"
    "            }\n"
    "            return;\n"
    "        }\n"
    "        let Some(id) = wire.job_id() else {\n"
    "            return;\n"
    "        };\n"
    "        let sender = self.sender.clone();\n"
    "        let outbox: verify::Outbox = Arc::new(move |msg| {\n"
    "            sender.send(Data::Message(msg)).ok();\n"
    "        });\n"
    "        if let Some(job) = fs::get_job(id, &mut self.write_jobs) {\n"
    "            verify::on_wire(job, wire, Some(&outbox));\n"
    "        } else if let Some(job) = fs::get_job(id, &mut self.read_jobs) {\n"
    "            verify::on_wire(job, wire, None);\n"
    "        }\n"
    "    }\n\n")
T30_IO_PEER = (
    "                        // boring-remote (v1.7 t30): only a Boring Remote says this, and only one hears hello.\n"
    "                        if self.handler.is_file_transfer() && base::file_verify::peer_says_verified(&pi.platform_additions) {\n"
    "                            self.boring_verify_os = Some(base::file_verify::os_from_platform(&pi.platform));\n"
    "                            let hello = base::file_verify::Wire::Hello { os: base::file_verify::this_os().to_string() };\n"
    "                            allow_err!(peer.send(&hello.to_message()).await);\n"
    "                        }\n")
T30_IO_MISC = (
    "                    Some(misc::Union::PluginRequest(p)) if p.id == base::file_verify::WIRE_ID => {\n"
    "                        self.boring_on_wire(&p.content); // boring-remote (v1.7 t30)\n"
    "                    }\n")
T30_IO_REPORT = (
    "                                fs::JobType::Generic => {\n"
    "                                    // boring-remote (v1.7 t30): the job says what happened, in plain words. Ours\n"
    "                                    // if this side received, the other side's if it did.\n"
    "                                    let report = if boring_received { boring_report } else { self.boring_reports.remove(&d.id) };\n"
    "                                    self.handler.boring_job_report(\n"
    "                                        d.id,\n"
    "                                        base::file_verify::job_words(report.as_ref(), self.boring_verify_os.is_some()),\n"
    "                                    );\n")
T30_CONN_ON_WIRE = (
    "    /// boring-remote (v1.7 t30): a message from the Controller about a job's files. A job read here\n"
    "    /// handles it here; a CM's job, which is every write and a Windows read, gets it over IPC.\n"
    "    fn boring_on_wire(&mut self, content: &[u8]) {\n"
    "        use base::file_verify::{self as verify, Wire};\n"
    "        let Some(wire) = Wire::from_json(content) else {\n"
    "            return;\n"
    "        };\n"
    "        if let Wire::Hello { os } = wire {\n"
    "            self.boring_verify_os = Some(os);\n"
    "            return;\n"
    "        }\n"
    "        let Some(id) = wire.job_id() else {\n"
    "            return;\n"
    "        };\n"
    "        if let Some(job) = fs::get_job(id, &mut self.read_jobs) {\n"
    "            verify::on_wire(job, wire, None);\n"
    "        } else {\n"
    "            self.send_fs(ipc::FS::BoringWire(wire.to_json()));\n"
    "        }\n"
    "    }\n\n")
T30_CONN_MISC = (
    "                    Some(misc::Union::PluginRequest(p)) if p.id == base::file_verify::WIRE_ID => {\n"
    "                        self.boring_on_wire(&p.content); // boring-remote (v1.7 t30)\n"
    "                    }\n")
T30_CONN_SCOPE = (
    "        // boring-remote (v1.7 t30): the proof of a transfer belongs to the transfer.\n"
    "        if matches!(misc.union.as_ref(), Some(misc::Union::PluginRequest(p)) if p.id == base::file_verify::WIRE_ID) {\n"
    "            return true;\n"
    "        }\n")
T30_MARKER = (
    "        // boring-remote (v1.7 t30): this Target proves files (base::file_verify). Upstream never sends the key.\n"
    "        // Not on Linux, which ships nothing and whose read-back would come from the cache.\n"
    "        #[cfg(any(target_os = \"windows\", target_os = \"macos\"))]\n"
    "        platform_additions.insert(base::file_verify::MARKER.into(), json!(true));\n")
T30_CONN_ENABLE = (
    "        // boring-remote (v1.7 t30)\n"
    "        if let Some(os) = self.boring_verify_os.clone() {\n"
    "            base::file_verify::enable_send(&mut job, &os);\n"
    "        }\n")
T30_CONN_CM_ENABLE = (
    "                                            // boring-remote (v1.7 t30): the CM's read job proves its files too.\n"
    "                                            if let Some(os) = self.boring_verify_os.clone() {\n"
    "                                                self.send_fs(ipc::FS::BoringWire(\n"
    "                                                    base::file_verify::Wire::StartRead { id, os }.to_json(),\n"
    "                                                ));\n"
    "                                            }\n")
T30_CM_WIRE = (
    "        // boring-remote (v1.7 t30): about a write job here, or a read job on a Windows Target.\n"
    "        ipc::FS::BoringWire(json) => {\n"
    "            use base::file_verify::{self as verify, Wire};\n"
    "            if let Some((wire, id)) =\n"
    "                Wire::from_json(json.as_bytes()).and_then(|w| w.job_id().map(|id| (w, id)))\n"
    "            {\n"
    "                let tx = tx.clone();\n"
    "                let outbox: verify::Outbox = std::sync::Arc::new(move |msg| send_raw(msg, &tx));\n"
    "                if let Some(job) = fs::get_job(id, write_jobs) {\n"
    "                    verify::on_wire(job, wire, Some(&outbox));\n"
    "                } else if let Some(job) = fs::get_job(id, read_jobs) {\n"
    "                    verify::on_wire(job, wire, None);\n"
    "                }\n"
    "            }\n"
    "        }\n")
T30_CM_DONE = (
    "                // boring-remote (v1.7 t30): the job's words go ahead of Done, on the same path.\n"
    "                if let Some(report) = base::file_verify::finish(&job) {\n"
    "                    send_raw(base::file_verify::Wire::Report { id, report }.to_message(), tx);\n"
    "                }\n")
T30_CM_ROOM = (
    "            // boring-remote (v1.7 t30): don't start what can't fit.\n"
    "            if let Err(e) = base::file_verify::check_room(&job) {\n"
    "                send_raw(fs::new_error(id, e, file_num), tx);\n"
    "                return;\n"
    "            }\n")
T30_CM_TICK = (
    "        // boring-remote (v1.7 t30): seals and manifests go out between blocks, in order.\n"
    "        job.boring_tick().await;\n"
    "        for msg in job.boring.take_outgoing() {\n"
    "            send_raw(msg, tx);\n"
    "        }\n\n")
T30_TRAIT = (
    "    /// boring-remote (v1.7 t30): what a finished transfer proved, in plain words.\n"
    "    fn boring_job_report(&self, _id: i32, _words: String) {}\n")
T30_FLUTTER = (
    "    // boring-remote (v1.7 t30)\n"
    "    fn boring_job_report(&self, id: i32, words: String) {\n"
    "        self.push_event(\"boring_job_report\", &[(\"id\", &id.to_string()), (\"words\", &words)], &[]);\n"
    "    }\n\n")
T30_DART_MODEL = (
    "      } else if (name == 'boring_job_report') {\n"
    "        // boring-remote (v1.7 t30)\n"
    "        parent.target?.fileModel.jobController.boringJobReport(evt);\n")
T30_DART_JOB = (
    "  /// boring-remote (v1.7 t30): what the job proved, kept for the transfer list. job_done follows it.\n"
    "  void boringJobReport(Map<String, dynamic> evt) {\n"
    "    final jobIndex = getJob(int.tryParse(evt['id']?.toString() ?? '') ?? -1);\n"
    "    if (jobIndex == -1 || jobTable[jobIndex].type != JobType.transfer) return;\n"
    "    jobTable[jobIndex].err = evt['words']?.toString() ?? '';\n"
    "  }\n\n")
PATCHES += [
    (BASE_LIB, T27_MOD, T27_MOD + T30_MOD, "base: file_verify module (t30)"),
    (BASE_TOML, "anyhow = \"1.0\"\n", "anyhow = \"1.0\"\n" + T30_DEP, "base depends on blake3 (t30)"),
    (CARGO_LOCK, " \"anyhow\",\n \"backtrace\",\n \"bytes\",\n \"filetime\",\n \"hbb_common\",\n",
     " \"anyhow\",\n \"backtrace\",\n \"blake3\",\n \"bytes\",\n \"filetime\",\n \"hbb_common\",\n", "lock: base uses blake3 (t30)"),
    (CARGO_LOCK, "[[package]]\nname = \"block\"\nversion = \"0.1.6\"\n",
     T30_LOCK_BLAKE3 + "[[package]]\nname = \"block\"\nversion = \"0.1.6\"\n", "lock: blake3 (t30)"),
    (CARGO_LOCK, "[[package]]\nname = \"core-foundation\"\nversion = \"0.7.0\"\n",
     T30_LOCK_CTE + "[[package]]\nname = \"core-foundation\"\nversion = \"0.7.0\"\n", "lock: blake3's constant_time_eq (t30)"),
    (CARGO_LOCK, " \"constant_time_eq\",\n", " \"constant_time_eq 0.2.6\",\n", "lock: two constant_time_eq now, so totp-rs says which (t30)"),
    (FS_RS, "    default_overwrite_strategy: Option<bool>,\n",
     "    default_overwrite_strategy: Option<bool>,\n"
     "    // boring-remote (v1.7 t30)\n    #[serde(skip_serializing)]\n"
     "    pub boring: crate::file_verify::JobVerify,\n",
     "a job carries its verification (t30)"),
    (FS_RS, "impl TransferJob {\n    #[allow(clippy::too_many_arguments)]\n    pub fn new_write(\n",
     T30_HOOKS + "impl TransferJob {\n    #[allow(clippy::too_many_arguments)]\n    pub fn new_write(\n",
     "the job's hooks (t30)"),
    (FS_RS, "    pub fn modify_time(&self) {\n        if self.r#type == JobType::Printer {\n",
     "    pub fn modify_time(&self) {\n"
     "        // boring-remote (v1.7 t30): when verifying, the name comes only after the read-back.\n"
     "        if self.r#type == JobType::Printer || self.boring.receiving() {\n",
     "no real name before the read-back (t30)"),
    (FS_RS, "    pub async fn write(&mut self, block: FileTransferBlock) -> ResultType<()> {\n        if block.id != self.id {\n",
     "    async fn boring_write(&mut self, block: FileTransferBlock) -> ResultType<()> {\n        if block.id != self.id {\n",
     "upstream's write goes behind the hook (t30)"),
    (FS_RS,
     "                            self.file_num += 1;\n"
     "                            self.file_confirmed = false;\n"
     "                            self.file_is_waiting = false;\n"
     "                            return Err(err.into());\n",
     "                            self.file_num += 1;\n"
     "                            self.file_confirmed = false;\n"
     "                            self.file_is_waiting = false;\n"
     "                            // boring-remote (v1.7 t30): listed and tried again, not the end of the job.\n"
     "                            if self.boring.sending() {\n"
     "                                let path = Self::join(p, &self.files[file_num].name);\n"
     "                                let len = self.files.len() as i32;\n"
     "                                self.file_num = self.boring.read_failed(\n"
     "                                    file_num as i32,\n"
     "                                    &path,\n"
     "                                    &err.to_string(),\n"
     "                                    self.file_num,\n"
     "                                    len,\n"
     "                                );\n"
     "                                return Ok(true);\n"
     "                            }\n"
     "                            return Err(err.into());\n",
     "a file that won't open doesn't end the job (t30)"),
    (FS_RS, "                    self.data_stream = Some(DataStream::FileStream(File::create(&path).await?));\n",
     "                    // boring-remote (v1.7 t30): a link under this name is refused, not written through.\n"
     "                    self.data_stream = Some(DataStream::FileStream(crate::file_verify::create_work_file(&path).await?));\n",
     "a copy never writes through a link (t30)"),
    (FS_RS, "                        std::fs::write(dp, json!(self.digest).to_string()).ok();\n",
     "                        crate::file_verify::write_work_file(dp, &json!(self.digest).to_string()).ok(); // boring-remote (v1.7 t30)\n",
     "a digest never writes through a link (t30)"),
    (FS_RS, "            let digest_path = format!(\"{}.digest\", &file_path);\n\n            let mut f = if Path::new(&download_path).exists()",
     "            let digest_path = format!(\"{}.digest\", &file_path);\n\n"
     "            // boring-remote (v1.7 t30): a resume never reopens a link.\n"
     "            if crate::file_verify::is_link(Path::new(&download_path)) {\n"
     "                log::warn!(\"A link is in the way of {}, not resuming\", download_path);\n"
     "                return;\n"
     "            }\n"
     "            let mut f = if Path::new(&download_path).exists()",
     "a resume never reopens a link (t30)"),
    (FS_RS, "        const BUF_SIZE: usize = 128 * 1024;\n", T30_READ_GUARD + "        const BUF_SIZE: usize = 128 * 1024;\n", "a read waits for the next file (t30)"),
    (FS_RS,
     "                    self.file_num += 1;\n"
     "                    self.data_stream = None;\n"
     "                    self.file_confirmed = false;\n"
     "                    self.file_is_waiting = false;\n"
     "                    return Err(err.into());\n",
     "                    self.file_num += 1;\n"
     "                    self.data_stream = None;\n"
     "                    self.file_confirmed = false;\n"
     "                    self.file_is_waiting = false;\n"
     "                    // boring-remote (v1.7 t30): listed and tried again, not the end of the job.\n"
     "                    if self.boring.sending() {\n"
     "                        self.boring_ahead.clear();\n"
     "                        self.boring_after_read(file_num, Some(err.to_string()));\n"
     "                        // Ends the receiver's stream, so a resend starts the file over.\n"
     "                        return Ok(Some(FileTransferBlock {\n"
     "                            id: self.id,\n"
     "                            file_num: file_num as _,\n"
     "                            ..Default::default()\n"
     "                        }));\n"
     "                    }\n"
     "                    return Err(err.into());\n",
     "a read error doesn't end the job (t30)"),
    (FS_RS, "        unsafe { buf.set_len(offset) };\n",
     "        unsafe { buf.set_len(offset) };\n"
     "        self.boring.sent_bytes(&buf); // boring-remote (v1.7 t30)\n",
     "the sender hashes what it read (t30)"),
    (FS_RS,
     "            self.file_num += 1;\n"
     "            self.data_stream = None;\n"
     "            self.file_confirmed = false;\n"
     "            self.file_is_waiting = false;\n"
     "        } else {\n",
     "            let boring_changed = self.boring_file_changed().await; // boring-remote (v1.7 t30)\n"
     "            self.file_num += 1;\n"
     "            self.data_stream = None;\n"
     "            self.file_confirmed = false;\n"
     "            self.file_is_waiting = false;\n"
     "            self.boring_after_read(file_num, boring_changed); // boring-remote (v1.7 t30)\n"
     "        } else {\n",
     "the seal follows a file's last block (t30)"),
    (FS_RS, "        if self.job_skipped() {\n            return Some(\"skipped\".to_string());\n",
     "        // boring-remote (v1.7 t30): when verifying, a skip is in the job's report instead.\n"
     "        if self.job_skipped() && !self.boring.active() {\n            return Some(\"skipped\".to_string());\n",
     "a skip goes in the report (t30)"),
    (FS_RS, "        self.file_num += 1;\n        self.file_skipped = true;\n",
     "        // boring-remote (v1.7 t30): nothing goes across, so the two ends compare what they have.\n"
     "        if let (DataSource::FilePath(p), Some(entry)) = (&self.data_source, self.files.get(self.file_num as usize)) {\n"
     "            let path = Self::join(p, &entry.name);\n"
     "            self.boring.skipped(self.file_num, &path);\n"
     "        }\n"
     "        self.file_num += 1;\n        self.file_skipped = true;\n",
     "a skip is compared (t30)"),
    (FS_RS, "            self.boring_ahead.clear(); // boring-remote (v1.7 t27)\n            if f.seek(std::io::SeekFrom::Start(offset)).await.is_ok() {\n",
     "            self.boring.stream_moved(); // boring-remote (v1.7 t30)\n"
     "            self.boring_ahead.clear(); // boring-remote (v1.7 t27)\n"
     "            if f.seek(std::io::SeekFrom::Start(offset)).await.is_ok() {\n",
     "a resume hashes the whole file (t30)"),
    (FS_RS, ") -> ResultType<String> {\n    init_jobs(jobs, stream).await?;\n",
     ") -> ResultType<String> {\n" + T30_TICK + "    init_jobs(jobs, stream).await?;\n", "seals go out from the read loop (t30)"),
    (FS_RS, "                if job.job_completed() {\n                    job_log = serialize_transfer_job(job, true, false, \"\");\n",
     "                // boring-remote (v1.7 t30): Done waits for the last verdict.\n"
     "                if !job.boring_holds_done() && job.job_completed() {\n                    job_log = serialize_transfer_job(job, true, false, \"\");\n",
     "Done waits for the last verdict (t30)"),
    (IPC, "pub enum FS {\n    ReadEmptyDirs {\n",
     "pub enum FS {\n"
     "    /// boring-remote (v1.7 t30): connection to CM, a base::file_verify::Wire message as JSON.\n"
     "    BoringWire(String),\n"
     "    ReadEmptyDirs {\n", "IPC: verification messages (t30)"),
    (UI_CM, "        ipc::FS::CancelWrite { id } => {\n", T30_CM_WIRE + "        ipc::FS::CancelWrite { id } => {\n", "CM handles verification messages (t30)"),
    (UI_CM, "            if let Some(job) = fs::remove_job(id, write_jobs) {\n                job.modify_time();\n                send_raw(fs::new_done(id, file_num), tx);\n",
     "            if let Some(job) = fs::remove_job(id, write_jobs) {\n                job.modify_time();\n" + T30_CM_DONE + "                send_raw(fs::new_done(id, file_num), tx);\n",
     "CM sends the report (t30)"),
    (UI_CM, "            job.total_size = total_size;\n            job.conn_id = conn_id;\n            write_jobs.push(job);\n",
     "            job.total_size = total_size;\n            job.conn_id = conn_id;\n" + T30_CM_ROOM + "            write_jobs.push(job);\n",
     "CM checks free space first (t30)"),
    (UI_CM, "        // Initialize data stream if needed (opens file, sends digest for overwrite detection)\n",
     T30_CM_TICK + "        // Initialize data stream if needed (opens file, sends digest for overwrite detection)\n",
     "CM's read jobs send their seals (t30)"),
    (UI_CM, "            Ok(None) => {\n                if job.job_completed() {\n                    finished.push(job.id);\n",
     "            Ok(None) => {\n"
     "                // boring-remote (v1.7 t30): Done waits for the last verdict.\n"
     "                if !job.boring_holds_done() && job.job_completed() {\n                    finished.push(job.id);\n",
     "CM's Done waits for the last verdict (t30)"),
    (CONN, "    boring_cm_window: base::file_speed::CmWindow, // boring-remote (v1.7 t27)\n",
     "    boring_cm_window: base::file_speed::CmWindow, // boring-remote (v1.7 t27)\n"
     "    boring_verify_os: Option<String>, // boring-remote (v1.7 t30): set once the Controller says hello\n", "verify field (t30)"),
    (CONN, "            boring_cm_window: Default::default(),\n",
     "            boring_cm_window: Default::default(),\n            boring_verify_os: None,\n", "verify field default (t30)"),
    (CONN, T27_MARKER, T30_MARKER + T27_MARKER, "Target says it proves files (t30)"),
    (CONN, "    fn is_file_transfer_scoped_misc(misc: &Misc) -> bool {\n",
     "    fn is_file_transfer_scoped_misc(misc: &Misc) -> bool {\n" + T30_CONN_SCOPE, "the proof is in scope for a transfer (t30)"),
    (CONN, "                    Some(misc::Union::SwitchDisplay(s)) => {\n                        self.handle_switch_display(s).await;\n",
     T30_CONN_MISC + "                    Some(misc::Union::SwitchDisplay(s)) => {\n                        self.handle_switch_display(s).await;\n",
     "Target hears the proof (t30)"),
    (CONN, "    async fn process_new_read_job(&mut self, mut job: fs::TransferJob, path: String) {\n",
     T30_CONN_ON_WIRE + "    async fn process_new_read_job(&mut self, mut job: fs::TransferJob, path: String) {\n", "Target routes the proof (t30)"),
    (CONN, "        job.conn_id = self.inner.id();\n        self.read_jobs.push(job);\n",
     "        job.conn_id = self.inner.id();\n" + T30_CONN_ENABLE + "        self.read_jobs.push(job);\n", "Target's read job proves its files (t30)"),
    (CONN, "                                                overwrite_detection: od,\n                                            });\n",
     "                                                overwrite_detection: od,\n                                            });\n" + T30_CONN_CM_ENABLE,
     "a CM read job proves its files (t30)"),
    (IO_LOOP, "    boring_full_speed: bool, // boring-remote (v1.7 t27)\n",
     "    boring_full_speed: bool, // boring-remote (v1.7 t27)\n"
     "    boring_verify_os: Option<String>, // boring-remote (v1.7 t30): set once the Target says it can\n"
     "    boring_reports: HashMap<i32, base::file_verify::Report>, // boring-remote (v1.7 t30): reports from the Target\n",
     "Controller's verify fields (t30)"),
    (IO_LOOP, "            boring_full_speed: false,\n",
     "            boring_full_speed: false,\n            boring_verify_os: None,\n            boring_reports: Default::default(),\n",
     "Controller's verify field defaults (t30)"),
    (IO_LOOP, T27_IO_PEER, T30_IO_PEER + T27_IO_PEER, "Controller says hello to a Target that proves files (t30)"),
    (IO_LOOP, "                                // boring-remote (v1.7 t27): send for a slice, not one block per tick,\n",
     "                                base::file_verify::enable_sends(&mut self.read_jobs, self.boring_verify_os.as_deref()); // boring-remote (v1.7 t30)\n"
     "                                // boring-remote (v1.7 t27): send for a slice, not one block per tick,\n",
     "Controller's read jobs prove their files (t30)"),
    (IO_LOOP, "    fn handle_job_status(&mut self, id: i32, file_num: i32, err: Option<String>) {\n",
     T30_IO_ON_WIRE + "    fn handle_job_status(&mut self, id: i32, file_num: i32, err: Option<String>) {\n", "Controller routes the proof (t30)"),
    (IO_LOOP, "                Some(message::Union::Misc(misc)) => match misc.union {\n                    Some(misc::Union::AudioFormat(f)) => {\n",
     "                Some(message::Union::Misc(misc)) => match misc.union {\n" + T30_IO_MISC + "                    Some(misc::Union::AudioFormat(f)) => {\n",
     "Controller hears the proof (t30)"),
    (IO_LOOP, "            Data::SendFiles((id, r#type, path, to, file_num, include_hidden, is_remote)) => {\n",
     "            Data::SendFiles((id, r#type, path, to, file_num, _, is_remote)) => {\n"
     "                let include_hidden = true; // boring-remote (v1.7 t30): a copy takes everything, whatever the pane shows\n",
     "a copy takes hidden files (t30)"),
    (IO_LOOP, "            Data::AddJob((id, r#type, path, to, file_num, include_hidden, is_remote)) => {\n",
     "            Data::AddJob((id, r#type, path, to, file_num, _, is_remote)) => {\n"
     "                let include_hidden = true; // boring-remote (v1.7 t30)\n",
     "a queued copy takes hidden files (t30)"),
    (IO_LOOP, "                                if let Err(err) = job.set_files(entries) {\n",
     "                                // boring-remote (v1.7 t30): don't start what can't fit.\n"
     "                                if let Err(err) = job.set_files(entries).and_then(|_| {\n"
     "                                    base::file_verify::check_room(job).map_err(|e| hbb_common::anyhow::anyhow!(e))\n"
     "                                }) {\n",
     "Controller checks free space first (t30)"),
    (IO_LOOP, "                            let mut printer_data = None;\n                            if let Some(job) = fs::remove_job(d.id, &mut self.write_jobs) {\n                                job.modify_time();\n",
     "                            let mut printer_data = None;\n"
     "                            let (mut boring_report, mut boring_received) = (None, false); // boring-remote (v1.7 t30)\n"
     "                            if let Some(job) = fs::remove_job(d.id, &mut self.write_jobs) {\n                                job.modify_time();\n"
     "                                boring_report = base::file_verify::finish(&job);\n"
     "                                boring_received = true;\n",
     "Controller finishes a job it received (t30)"),
    (IO_LOOP, "                                fs::JobType::Generic => {\n                                    self.handle_job_status(d.id, d.file_num, err);\n",
     T30_IO_REPORT + "                                    self.handle_job_status(d.id, d.file_num, err);\n", "the job says what happened (t30)"),
    (UI_SESSION, "    fn job_done(&self, id: i32, file_num: i32);\n", "    fn job_done(&self, id: i32, file_num: i32);\n" + T30_TRAIT, "report reaches the UI (t30)"),
    (FLUTTER_RS, "    // unused in flutter\n    fn clear_all_jobs(&self) {}\n", T30_FLUTTER + "    // unused in flutter\n    fn clear_all_jobs(&self) {}\n", "report reaches Flutter (t30)"),
    (FFI_MODEL, "      } else if (name == 'job_error') {\n", T30_DART_MODEL + "      } else if (name == 'job_error') {\n", "report event (t30)"),
    (FILE_MODEL, "  void jobError(Map<String, dynamic> evt) {\n", T30_DART_JOB + "  void jobError(Map<String, dynamic> evt) {\n", "the job keeps its report (t30)"),
    (FILE_MODEL, "          await fileFetcher.readEmptyDirs(item.path, isLocal, showHidden);\n",
     "          await fileFetcher.readEmptyDirs(item.path, isLocal, true); // boring-remote (v1.7 t30): old peers too\n",
     "empty folders include hidden ones (t30)"),
]

COPIES = [
    ("msi/WixUIBannerBmp.bmp", f"{MSI}/Resources/WixUIBannerBmp.bmp", "MSI banner art, 493x58"),
    ("msi/WixUIDialogBmp.bmp", f"{MSI}/Resources/WixUIDialogBmp.bmp", "MSI dialog art, 493x312"),
    ("msi/License.rtf", f"{MSI}/License.rtf", "installer license: AGPL notice, not upstream's privacy policy"),
    ("../LICENCE", LICENCE_ASSET, "the license text, bundled: Legal shows it (AGPL 5(d))"),
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


# Anchors that must be in their file exactly once (review L5): a second copy would put a trust
# hook in twice, or somewhere the checks don't look. A count over one is a moved target.
ONCE = {
    "a Trusted Controller skips the ask",
    "Trusted by Allow or the Unattended Password only",
    "always ask: tell the Controller in PeerInfo",
    "always ask: no sign-in lets it in without the Unattended Password",
    "always ask: the Controller keeps no password for that Target",
    "always ask: a session that got in without the password ends when switched on",
    "always ask: a tunnel's own check timer",
    "always ask: a tunnel that got in without the password closes when switched on",
    "Trusted list: Settings' edits, one locked write in the service",
    "Trusted list: a settings window's stale copy is never stored",
    "Trusted list: Settings waits for the service's answer",
    "Trusted list edit bridge call",
}


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
        if n > 1 and why in ONCE:
            moved.append(f"{rel}: patch anchor not unique, {n} copies ({why})")
            continue
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
        for msg in CONNECT_ERROR_KEYS:
            if f'("{msg}", ' not in text2:
                text2 = LANG_END.sub(f'),\n        ("{msg}", ""),\n\\1', text2, count=1)
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
