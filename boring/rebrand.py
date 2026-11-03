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
FORK_URL = "https://github.com/Monolith3-studio/boring-remote-desk"  # our source; the only link we ship
# The one place RustDesk is named (AGPL attribution), as plain text on the About page.
LEGAL_LINE = f"Based on RustDesk, \u00a9 Purslane Tech Pte. Ltd., AGPL-3.0. Source: {FORK_URL}"
# Tailscale's address ranges, both tailnet-only: IPv4 CGNAT and the IPv6 ULA a
# MagicDNS AAAA answer points at. The listener is dual-stack, so v4 peers arrive
# as ::ffff:100.x and connection.rs normalises them with try_into_v4 first.
TAILNET = "100.64.0.0/10,fd7a:115c:a1e0::/48"
# ADR 0003: the private LAN is allowed too (RFC 1918, IPv6 ULA and link-local),
# so Macs on the same network connect Direct. Public addresses stay blocked.
PRIVATE_LAN = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,fe80::/10"
WHITELIST = f"{TAILNET},{PRIVATE_LAN}"

# What the connect box says (v1.7 t03, ADRs 0004/0005), in plain words with one next step. The
# text lives in libs/base/src/direct_link.rs, once per platform: the Mac build says "Mac", the
# Windows build "computer" (as the kit's KitWords do). These are the translation keys
# (src/lang/*.rs, English everywhere) and what check.py compares the Rust constants with.
NOT_FOUND = "Couldn't find a Mac with that name. Pick it from the list, or check the spelling and try again."
NOT_ON_NETWORK = "Couldn't reach that Mac. Make sure it's awake and on the same network as this one, then try again."
PLAINTEXT_REFUSED = "That Mac needs the latest Boring Remote. Update Boring Remote on that Mac, then try again."
IDENTITY_CHANGED = ("This isn't the Mac you connected to before, so Boring Remote stopped. If that Mac was "
                    "reinstalled, open Settings, click Trusted Controllers, click Forget next to it, "
                    "then try again.")
NO_ADDRESS = ("Boring Remote doesn't know where that Mac is yet. Type its name or address in the box, "
              "then try again.")
CONNECT_ERRORS = {"NOT_FOUND": NOT_FOUND, "NOT_ON_THIS_NETWORK": NOT_ON_NETWORK, "NO_ADDRESS": NO_ADDRESS,
                  "PLAINTEXT_REFUSED": PLAINTEXT_REFUSED, "IDENTITY_CHANGED": IDENTITY_CHANGED}


def on_windows(text):
    """The Windows build's wording of a buyer-facing line: computer, not Mac (KitWords)."""
    return text.replace("Macs", "computers").replace("Mac", "computer")


CONNECT_ERROR_KEYS = [t for v in CONNECT_ERRORS.values() for t in (v, on_windows(v))]

# Replaces _start's IP and domain:port branches in src/client.rs. check.py looks for
# exactly this block and that nothing before it reaches the ID/rendezvous path.
DIRECT_LINK_CALL = (
    "        // boring-remote (v1.7 t03): every peer is a name or IP for a Direct Link, never an\n"
    "        // ID. base::direct_link dials the Target's own address, then its Tailscale address,\n"
    "        // else \"Not on this network\"; off Tailscale it is encrypted or refused (ADR 0004,\n"
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
    # Jason (2026-11-02): Settings is a gear, not upstream's three-line menu icon (Mac and Windows tab bar).
    ("flutter/lib/desktop/pages/desktop_tab_page.dart", "                  icon: IconFont.menu,\n",
     "                  icon: Icons.settings_outlined, // boring-remote (v1.7 t17): a gear opens Settings\n",
     "Settings button is a gear"),
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
    # Windows, what people read
    ("res/msi/CustomActions/FirewallRules.cpp", 'L"%ls Service", exeName);',
     f'L"{WINDOWS_RULE}"); // boring-remote (v1.7 t17): what people read, not the exe name',
     "MSI firewall rule display name"),
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
# Target: the direct listener asks for encryption off Tailscale (ADR 0005) and marks the Direct Link.
T03_LISTENER = (
    "                // boring-remote: encrypted everywhere but Tailscale (v1.7 t03, ADR 0005).\n"
    "                let encrypt = base::direct_link::must_encrypt(hbb_common::try_into_v4(addr).ip());\n"
    "                tokio::spawn(async move {\n"
    "                    allow_err!(\n"
    "                        crate::server::create_tcp_connection(\n"
    "                            server,\n"
    "                            hbb_common::Stream::from(stream, local_addr),\n"
    "                            addr,\n"
    "                            encrypt,\n"
    "                            ConnectionMeta {\n"
    "                                direct_link: encrypt,\n"
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
T04_TRUSTED_SKIP = (
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
     T03_LISTENER, "direct listener: encrypted Direct Link off Tailscale (ADR 0005)"),
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
    "        : (p.hostname.isNotEmpty ? p.hostname : 'Unnamed Mac');\n"
    "    return Theme(\n"
    "      data: Kit.theme(),\n"
    "      child: Material(\n"
    "        color: Kit.ink,\n"
    "        child: ListenableBuilder(\n"
    "          listenable: Listenable.merge([recents, lanMacs]),\n"
    "          builder: (context, _) => MacHome(\n"
    "            macs: [for (final p in recents.peers) MacEntry(name: name(p), target: p.id)],\n"
    "            tailscaleAddress: thisTailscaleAddress,\n"
    "            lan: lanMacs.macs,\n"
    "            discover: () => bind.mainDiscover(),\n"
    "            onConnect: (t) => connect(context, t),\n"
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
    "                  delete: j.type != JobType.transfer), // deletes are listed too (v1.7 review)\n"
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
     "            data: Kit.theme().copyWith(cardColor: Kit.panel),\n"
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
    "          access: AccessSection(checks: boringAccessChecks()), // v1.7 t17\n"
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
    "              label: 'Trusted Controllers',\n"
    "              onTap: () => Navigator.of(context).push(MaterialPageRoute(\n"
    "                builder: (_) => Theme(\n"
    "                  data: Kit.theme(),\n"
    "                  child: Scaffold(\n"
    "                    backgroundColor: Kit.ink,\n"
    "                    appBar: AppBar(backgroundColor: Kit.ink),\n"
    "                    body: TrustedControllersPage(\n"
    "                      trusted: parseTrusted(bind.mainGetOptionSync(key: kTrustedControllersOption)),\n"
    "                      known: parseKnown(bind.mainGetLocalOption(key: kDirectLinkKnownOption)),\n"
    "                      onRemove: (k) => bind.mainSetOption(\n"
    "                          key: kTrustedControllersOption,\n"
    "                          value: removeTrusted(bind.mainGetOptionSync(key: kTrustedControllersOption), k)),\n"
    "                      onForget: (id) async {\n"
    "                        for (final o in [kDirectLinkKnownOption, kTrustTokensOption]) {\n"
    "                          await bind.mainSetLocalOption(\n"
    "                              key: o, value: forgetId(bind.mainGetLocalOption(key: o), id));\n"
    "                        }\n"
    "                      },\n"
    "                      // Allow here = Allow on the prompt: Trusted again (the server option, over ipc to\n"
    "                      // the service, as Remove), and a live ask from it is let in (kit/approval.dart).\n"
    "                      removed: parseRemoved(bind.mainGetOptionSync(key: kTrustedControllersOption)),\n"
    "                      onAllow: (c) async {\n"
    "                        await bind.mainSetOption(\n"
    "                            key: kTrustedControllersOption,\n"
    "                            value: reinstateTrusted(bind.mainGetOptionSync(key: kTrustedControllersOption), c.key));\n"
    "                        for (final w in ApprovalDesk.waitingNow.value) {\n"
    "                          if (w.name.trim() == c.name.trim()) ApprovalDesk.main?.decide(w.id, true);\n"
    "                        }\n"
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
    "                ? approvalAsk(client.id, client.name)\n"
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
    "        canControl: () => bind.mainIsProcessTrusted(prompt: false),\n"
    "        openPane: (url) {\n"
    "          // Asking once puts Boring Remote in the pane's list; then open the pane itself.\n"
    "          if (url == kScreenRecordingPane) bind.mainIsCanScreenRecording(prompt: true);\n"
    "          if (url == kAccessibilityPane) bind.mainIsProcessTrusted(prompt: true);\n"
    "          launchUrl(Uri.parse(url));\n"
    "        },\n"
    "        passwordSet: bind.mainGetCommonSync(key: 'permanent-password-set') == 'true',\n"
    "        setPassword: (p) => bind.mainSetPermanentPasswordWithResult(password: p),\n"
    "        startStep: setupStartStep(bind.mainGetLocalOption(key: kSetupStepOption), screens),\n"
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
    "          )),\n")
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
     "    if (isMacOS) _boringSetup = setupNeeded(bind.mainGetLocalOption(key: kSetupDoneOption));\n",
     "Setup on first launch only"),
]

# --- Windows gets the v1.7 UI (v1.7 ticket 12, ADRs 0006, 0007) -------------------
# Every Mac-only gate the v1.7 tickets added now also opens on Windows: Home + LAN list (t01/t02),
# Session Toolbar + Link Badge (t07/t03/t05), Settings (t09), trust prompt (t04), Setup (t06).
# The rewrite runs over the earlier blocks' own patch text (old and new alike), as t04/t06 did, so
# a second rebrand still finds each block whole and stays a no-op. Setup's screen 2 on Windows is
# "let other computers reach this one": the MSI's app rule (any port, every network type) covers
# Direct Link 21118 and LAN Discovery 21119; Allow adds the same rule if it is missing. The kit
# says "computer" for "Mac" on Windows (KitWords, set once in main()).
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
    ("'Unnamed Mac'", "'Unnamed ${KitWords.one}'"),  # t01 Home
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
    f"        onLicence: () => launchUrlString('{FORK_URL}'),\n"
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
     "import 'package:flutter_hbb/desktop/kit/install.dart';\n", "install screen imports"),
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
    "  Future<String> uid() => _boringUid ??= Process.run('id', ['-u']).then((r) => '${r.stdout}'.trim());\n"
    "  Future<bool> running() async => Process.run('launchctl', ['print', 'gui/${await uid()}/$kAgentLabel'])\n"
    "      .then((r) => r.exitCode == 0 && agentRunning('${r.stdout}'))\n"
    "      .catchError((_) => false);\n"
    "  // kickstart, and bootout + bootstrap when launchd holds the job at spawn failed (kit/access.dart).\n"
    "  Future<void> startAgent() async {\n"
    "    await turnOn();\n"
    "    if (!await restartAgent(Process.run, await uid())) debugPrint('Access: --server still down');\n"
    "  }\n"
    "  void pane(String url) => launchUrl(Uri.parse(url));\n"
    "  return [\n"
    "    AccessCheck(\n"
    "        label: AccessWords.screen,\n"
    "        why: AccessWords.screenWhy,\n"
    "        read: () async => bind.mainIsCanScreenRecording(prompt: false),\n"
    "        fix: () async {\n"
    "          bind.mainIsCanScreenRecording(prompt: true); // CGRequestScreenCaptureAccess: macOS asks, and lists us\n"
    "          pane(kScreenRecordingPane);\n"
    "        }),\n"
    "    AccessCheck(\n"
    "        label: AccessWords.control,\n"
    "        why: AccessWords.controlWhy,\n"
    "        read: () async => bind.mainIsProcessTrusted(prompt: false),\n"
    "        fix: () async {\n"
    "          bind.mainIsProcessTrusted(prompt: true);\n"
    "          pane(kAccessibilityPane);\n"
    "        }),\n"
    "    AccessCheck(\n"
    "        label: AccessWords.input,\n"
    "        why: AccessWords.inputWhy,\n"
    "        read: () async => bind.mainIsCanInputMonitoring(prompt: false),\n"
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
PATCHES += [
    (HOME, "class _DesktopHomePageState extends State<DesktopHomePage>\n",
     T17_ACCESS_CHECKS + "class _DesktopHomePageState extends State<DesktopHomePage>\n", "Access checks (t17)"),
    (HOME, "import 'package:flutter_hbb/consts.dart';\n", "import 'package:flutter_hbb/consts.dart';\n" + T17_ACCESS_IMPORT,
     "Access import (home)"),
    (SETTINGS, "import 'package:flutter_hbb/desktop/kit/trust.dart';\n",
     "import 'package:flutter_hbb/desktop/kit/trust.dart';\n" + T17_ACCESS_IMPORT, "Access import (settings)"),
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
