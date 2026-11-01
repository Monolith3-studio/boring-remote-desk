#!/usr/bin/env python3
"""Seam 2: the rebrand script against a clean copy of this checkout.

Run:  python3 -m unittest boring/test_rebrand.py -v
Needs git and an initialised libs/hbb_common submodule. Each test exports a
fresh tree (committed HEAD of the repo and of the submodule) into a temp dir,
so your working tree is never touched.
"""
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check  # noqa: E402  (shares the installer-string reader with check.py)
import rebrand  # noqa: E402

REPO = HERE.parent
WIN_UI = "v1.7 Home, Setup, Settings, toolbar and trust prompt open on Windows too (t12)"
WIN_SETUP = "Windows Setup step 2 lets other computers reach this one, through the installer's rule (t12)"
WIN_RULE = "installer's app rule lets other computers reach Direct Link 21118: any port, every network type (t12)"
WIN_UPDATE = "Windows reads its own signed feed entry and installs the checked MSI (ADR 0007)"
CONNECT_DIRECT = "connect box never reaches the ID/rendezvous path"
CONNECT_TAILNET = "connect box dials only Tailscale or private-LAN addresses, else the plain error"
CONNECT_ENCRYPTED = "Direct Link is encrypted off Tailscale; plaintext refused both ends (ADR 0005)"
NOT_FOUND_TRANSLATED = "every connect error, Mac and Windows wording, is in every translation file"
CONNECT_PIN = "Direct Link pins the Target on the address dialled and on its ID (identity changed otherwise)"
ONE_TIME_CODE = "a one-time code lets a Controller in for that session only (ADR 0005)"
HE_WIRED = "High Efficiency wired: Target marks itself and answers the ask, badge waits for the answer"
RUST_HOOKS = "v1.7 Rust hooks landed: base modules, Direct Link meta, LAN end of cycle, Controller name"
NO_DEFAULT_PASSWORD = "no default or blank password ships (ADR 0002)"
TRUST_WIRED = "LAN trust wired: token exchange both ends, approval prompt, Trusted Controllers (v1.7 t04)"
TRUST_TOKENS = "trust tokens: 256-bit, constant-time, option names agree in Rust and Dart"
REBRAND = HERE / "rebrand.py"
CHECK = HERE / "check.py"


def export_clean_tree(dest):
    for sub, out in (("", dest), ("libs/hbb_common", dest / "libs/hbb_common")):
        out.mkdir(parents=True, exist_ok=True)
        archive = subprocess.run(["git", "-C", str(REPO / sub), "archive", "HEAD"],
                                 check=True, capture_output=True).stdout
        subprocess.run(["tar", "-x", "-C", str(out)], input=archive, check=True)
    # Our own workflows come from the working tree, so the tests see what you are editing.
    wf = dest / ".github/workflows"
    wf.mkdir(parents=True, exist_ok=True)
    for ours in (REPO / ".github/workflows").glob("boring-*.yml"):
        shutil.copy2(ours, wf / ours.name)
    # An unpatched upstream tree still has its own workflows; put one back so the
    # tree under test looks like a fresh upstream checkout.
    (wf / "flutter-build.yml").write_text(
        "jobs:\n  b:\n    steps:\n      - run: ./build.py --flutter --hwcodec --unix-file-copy-paste\n")


def run(script, root, *extra):
    return subprocess.run([sys.executable, str(script), str(root), *extra],
                          capture_output=True, text=True)


def tree_hashes(root):
    import hashlib
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


class RebrandSeam(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="rebrand-"))
        self.root = self.tmp / "tree"
        export_clean_tree(self.root)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def rebrand(self):
        r = run(REBRAND, self.root)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r

    def test_check_fails_on_clean_upstream_tree(self):
        r = run(CHECK, self.root)
        self.assertNotEqual(r.returncode, 0)
        for fact in ("rendezvous servers empty", "whitelist", "app name", "hwcodec",
                     "MSI product name", "MSI banner art"):
            self.assertIn(fact, r.stdout)
        for fact in ("no RustDesk name or link in the Mac and Windows app's strings",
                     "About page has the one plain AGPL legal line",
                     "no RustDesk name or link in any translation",
                     "no RustDesk in app metadata", "window titles and tray tooltip say Boring Remote",
                     "no upstream RustDesk logo or icon ships", "every logo slot holds Boring Remote art",
                     "Mac menu-bar icon res/mac-tray-dark-x2.png is a template glyph",
                     CONNECT_DIRECT, NOT_FOUND_TRANSLATED, CONNECT_ENCRYPTED, TRUST_WIRED, ONE_TIME_CODE,
                     HE_WIRED, RUST_HOOKS):
            self.assertIn(f"FAIL {fact}", r.stdout)

    def test_check_passes_after_rebrand(self):
        self.rebrand()
        r = run(CHECK, self.root)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertRegex(r.stdout, r"rebrand check: \d+ passed, 0 failed")

    def test_second_run_is_noop(self):
        self.rebrand()
        before = tree_hashes(self.root)
        r = self.rebrand()
        self.assertIn("rebrand: 0 changed, 0 moved", r.stdout)
        self.assertEqual(before, tree_hashes(self.root))

    def test_banned_codec_in_a_workflow_fails_check(self):
        self.rebrand()
        (self.root / ".github/workflows/boring-sneaky.yml").write_text(
            "jobs:\n  b:\n    steps:\n      - run: python3 build.py --flutter --vram\n")
        r = run(CHECK, self.root)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("boring-sneaky.yml", r.stdout)

    def test_build_py_refuses_banned_codecs(self):
        self.rebrand()
        for flag in ("--hwcodec", "--vram"):
            r = subprocess.run([sys.executable, "build.py", "--flutter", flag, "--print-features"],
                               cwd=self.root, capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0, flag)
            self.assertIn("banned", r.stdout + r.stderr)

    def preprocess_msi(self):
        """Run upstream's own res/msi/preprocess.py the way CI does, on a fake dist."""
        dist = self.tmp / "dist"
        (dist / "data").mkdir(parents=True)
        (dist / "data/app.so").write_bytes(b"x")
        exe = dist / "BoringRemote.exe"  # preprocess asks the exe for its version and build date
        exe.write_text('#!/bin/sh\ncase "$1" in --version) echo 1.5.0;; '
                       '--build-date) echo "2026-10-22 12:00";; esac\n')
        exe.chmod(0o755)
        r = subprocess.run([sys.executable, "preprocess.py", "-d", str(dist)],
                           cwd=self.root / "res/msi", capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return self.root / "res/msi/Package"

    def test_msi_sources_are_boring_remote_after_preprocess(self):
        self.rebrand()
        pkg = self.preprocess_msi()
        inc = (pkg / "Includes.wxi").read_text()
        self.assertIn('<?define Product="BoringRemote" ?>', inc)        # installs BoringRemote.exe
        self.assertIn('<?define Manufacturer="Boring Labs" ?>', inc)
        wxs = (pkg / "Package.wxs").read_text()
        self.assertIn('<Package Name="Boring Remote"', wxs)              # Apps list name
        self.assertIn('<WixVariable Id="WixUIBannerBmp" Value="Resources\\WixUIBannerBmp.bmp" />', wxs)
        self.assertIn('<WixVariable Id="WixUIDialogBmp" Value="Resources\\WixUIDialogBmp.bmp" />', wxs)
        for name, size in (("WixUIBannerBmp", (493, 58)), ("WixUIDialogBmp", (493, 312))):
            head = (pkg / f"Resources/{name}.bmp").read_bytes()[:30]
            self.assertEqual(head[:2], b"BM", name)
            self.assertEqual((int.from_bytes(head[18:22], "little"),
                              int.from_bytes(head[22:26], "little", signed=True)), size, name)
        seen = check.installer_strings(pkg)  # every string a person can read in the installer
        self.assertEqual([s for s in seen if "rustdesk" in s.split(": ", 1)[1].lower()], [])
        self.assertIn("Package.en-us.wxl: Boring Remote", seen)           # Start menu shortcut
        lic = (pkg / "License.rtf").read_text()
        self.assertIn("Boring Remote", lic)
        self.assertIn("GNU Affero General Public License", lic)
        self.assertNotIn("personal data", lic)                           # not upstream's privacy policy

    def test_rustdesk_text_back_in_the_installer_fails_check(self):
        self.rebrand()
        wxl = self.root / "res/msi/Package/Language/Package.en-us.wxl"
        wxl.write_text(wxl.read_text(encoding="utf-8-sig").replace(
            'Value="Uninstall Boring Remote"', 'Value="Uninstall RustDesk"'), encoding="utf-8")
        r = run(CHECK, self.root)
        self.assertNotEqual(r.returncode, 0)
        self.assertRegex(r.stdout, r"FAIL no RustDesk in installer text: .*Uninstall RustDesk")

    def test_blank_installer_art_fails_check(self):
        self.rebrand()
        bmp = self.root / "res/msi/Package/Resources/WixUIDialogBmp.bmp"
        data = bmp.read_bytes()
        bmp.write_bytes(data[:54] + bytes(len(data) - 54))  # same size, all black
        r = run(CHECK, self.root)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("FAIL MSI dialog art", r.stdout)

    def test_stale_app_version_pin_fails_check(self):
        cargo = self.root / "Cargo.toml"
        cargo.write_text(re.sub(r'(?m)^version = "[^"]*"', 'version = "9.9.9"', cargo.read_text(), 1))
        self.rebrand()
        r = run(CHECK, self.root)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("FAIL workflow VERSION matches Cargo.toml version", r.stdout)
        self.assertIn("9.9.9", r.stdout)

    def edit(self, rel, old, new):
        path = self.root / rel
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text, rel)
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def assert_check_fails(self, fact):
        r = run(CHECK, self.root)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(f"FAIL {fact}", r.stdout)

    UPDATE_FACT = "the only update endpoints are VERSION_URL, its .sig, fulfillment /update and the Windows downloads (ADR 0004/0007)"

    def test_planted_rustdesk_update_url_fails_check(self):
        self.rebrand()
        self.edit("src/update_notice.rs", "pub const VERSION_URL",
                  'pub const OLD_URL: &str = "https://api.rustdesk.com/version/latest";\npub const VERSION_URL')
        self.assert_check_fails(self.UPDATE_FACT)

    def test_planted_github_releases_url_fails_check(self):
        self.rebrand()
        self.edit("src/update_notice_run.rs", "use crate::update_notice",
                  'const X: &str = "https://github.com/rustdesk/rustdesk/releases/latest";\nuse crate::update_notice')
        self.assert_check_fails(self.UPDATE_FACT)

    def test_version_url_passes_check(self):
        self.rebrand()
        r = run(CHECK, self.root)
        self.assertIn(f"PASS {self.UPDATE_FACT}", r.stdout)

    WHITELIST_CALL = ("        if !self.check_whitelist(&addr).await {\n"
                      "            return false;\n"
                      "        }\n")

    def test_whitelist_check_moved_later_in_on_open_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", self.WHITELIST_CALL, "")
        self.edit("src/server/connection.rs", "        self.ip = addr.ip().to_string();\n",
                  "        self.ip = addr.ip().to_string();\n" + self.WHITELIST_CALL)
        self.assert_check_fails("whitelist is enforced on incoming connections")

    def test_dropping_v4_mapped_normalisation_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "        let addr = hbb_common::try_into_v4(addr);\n", "")
        self.assert_check_fails("whitelist is enforced on incoming connections")

    # --- ADR 0003: private LAN allowed, LAN Discovery on ---------------------
    WHITELIST_FACT = "whitelist locked to Tailscale + private LAN, nothing public (ADR 0003)"
    LAN_LISTENER = "LAN discovery listener answers pings (ADR 0003)"
    LAN_UNLOCKED = "LAN discovery not locked off (ADR 0003)"

    def test_lan_facts_pass_after_rebrand(self):
        self.rebrand()
        r = run(CHECK, self.root)
        for fact in (self.WHITELIST_FACT, self.LAN_LISTENER, self.LAN_UNLOCKED):
            self.assertIn(f"PASS {fact}", r.stdout)

    def test_public_range_in_whitelist_fails_check(self):
        self.rebrand()
        self.edit(rebrand.HBB, "192.168.0.0/16", "192.168.0.0/16,8.8.8.0/24")
        self.assert_check_fails(self.WHITELIST_FACT)

    def test_lan_listener_stripped_again_fails_check(self):
        self.rebrand()
        sig = "pub(super) fn start_listening() -> ResultType<()> {\n"
        self.edit("src/lan.rs", sig, f"{sig}    {rebrand.GUARD_OK}\n")
        self.assert_check_fails(self.LAN_LISTENER)

    def test_lan_discovery_locked_off_fails_check(self):
        self.rebrand()
        self.edit(rebrand.HBB, '("direct-server", "Y")',
                  '("direct-server", "Y"), ("enable-lan-discovery", "N")')
        self.assert_check_fails(self.LAN_UNLOCKED)

    def test_changed_protocol_file_fails_check(self):
        self.rebrand()
        proto = self.root / "libs/hbb_common/protos/rendezvous.proto"
        proto.write_text(proto.read_text() + "\nmessage Sneaky { string id = 1; }\n")
        self.assert_check_fails("protocol files are upstream's")

    def test_crlf_checkout_of_protocol_files_passes_check(self):  # Windows, text=auto
        for rel in ("libs/hbb_common/protos/rendezvous.proto", "libs/base/protos/message.proto"):
            path = self.root / rel
            path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
        self.rebrand()
        self.assertIn("PASS protocol files are upstream's", run(CHECK, self.root).stdout)

    def test_new_protocol_file_fails_check(self):
        self.rebrand()
        (self.root / "src/extra.proto").write_text('syntax = "proto3";\n')
        self.assert_check_fails("protocol files are upstream's")

    LICENSE_SKIP = "    if True:  # boring-remote: License.rtf comes from boring/msi and keeps its upstream credit\n"

    def test_preprocess_rewriting_the_license_fails_check(self):
        self.rebrand()
        self.edit("res/msi/preprocess.py", self.LICENSE_SKIP, '    if app_name == "RustDesk":\n')
        self.assert_check_fails("installer license is the Boring Remote AGPL notice")

    def test_license_check_is_behaviour_not_the_comment(self):
        self.rebrand()
        self.edit("res/msi/preprocess.py", self.LICENSE_SKIP, "    if app_name:  # reworded, same effect\n")
        r = run(CHECK, self.root)
        self.assertIn("PASS installer license is the Boring Remote AGPL notice", r.stdout)

    # --- branding ------------------------------------------------
    def test_upstream_logo_copied_anywhere_fails_check(self):
        upstream_icon = subprocess.run(["git", "-C", str(REPO), "show", "HEAD:res/icon.png"],
                                       check=True, capture_output=True).stdout
        self.rebrand()
        (self.root / "flutter/assets/logo.png").write_bytes(upstream_icon)
        r = run(CHECK, self.root)
        self.assertNotEqual(r.returncode, 0)
        self.assertRegex(r.stdout, r"FAIL no upstream RustDesk logo or icon ships.*flutter/assets/logo.png")

    def test_rustdesk_link_on_the_about_page_fails_check(self):
        self.rebrand()
        page = "flutter/lib/desktop/pages/desktop_setting_page.dart"
        self.edit(page, rebrand.ABOUT_NEW, rebrand.ABOUT_OLD)  # upstream's links and copyright block back
        r = run(CHECK, self.root)
        self.assertRegex(r.stdout, r"FAIL no RustDesk name or link in the Mac and Windows app's strings: "
                                   r".*desktop_setting_page.dart: .*rustdesk.com/privacy")

    def test_second_legal_line_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/desktop/widgets/tabbar_widget.dart", "'Boring Remote'",
                  "'" + rebrand.LEGAL_LINE + "'")
        self.assert_check_fails("About page has the one plain AGPL legal line")

    def test_rustdesk_back_in_a_translation_fails_check(self):
        self.rebrand()
        de = self.root / "src/lang/de.rs"
        de.write_text(de.read_text().replace('("Close", "', '("Close", "RustDesk ', 1))
        r = run(CHECK, self.root)
        self.assertRegex(r.stdout, r"FAIL no RustDesk name or link in any translation: 1 values: de.rs: Close")

    def test_coloured_menu_bar_icon_fails_check(self):
        self.rebrand()
        tray = self.root / "res/mac-tray-dark-x2.png"
        tray.write_bytes((HERE / "art/icon-32.png").read_bytes())  # the colour icon, not a template
        self.assert_check_fails("Mac menu-bar icon res/mac-tray-dark-x2.png is a template glyph")

    def test_contrast_matches_wcag(self):
        self.assertAlmostEqual(check.contrast("FFFFFF", "000000"), 21.0, places=2)  # WCAG's own extremes
        self.assertAlmostEqual(check.contrast("767676", "FFFFFF"), 4.54, places=2)  # the known 4.5:1 grey
        self.assertLess(check.contrast("FFFFFF", "FF5949"), 4.5)  # why coral can't carry text

    def test_coral_filled_button_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/common.dart", "backgroundColor: MyTheme.ink,\n        foregroundColor: Colors.white,\n"
                  "        shape:", "backgroundColor: MyTheme.accent,\n        shape:")
        r = run(CHECK, self.root)
        self.assertRegex(r.stdout, r"FAIL coral is never text or a fill under text: .*flutter/lib/common.dart:\d+")
        self.assertIn("FAIL every text colour pair clears 4.5:1", r.stdout)

    def test_coral_text_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/desktop/pages/desktop_setting_page.dart", "color: MyTheme.accentText,",
                  "color: MyTheme.accent,")
        r = run(CHECK, self.root)
        self.assertRegex(r.stdout, r"FAIL coral is never text or a fill under text: .*desktop_setting_page.dart:\d+")

    # --- v1.7 t09: extras in the kit, one simple Settings page ------
    def test_upstream_colour_back_in_an_extras_screen_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/desktop/pages/port_forward_page.dart", "color: Kit.line", "color: Colors.red")
        r = run(CHECK, self.root)
        self.assertRegex(r.stdout, r"FAIL port forward, terminal and camera use kit tokens only: "
                                   r".*port_forward_page.dart: Colors.red")

    def test_simple_settings_unwired_fails_check(self):
        self.rebrand()
        self.edit(rebrand.SETTINGS, "SimpleSettings(", "Placeholder(")
        r = run(CHECK, self.root)
        self.assertIn("FAIL Mac Settings is one simple page with Advanced behind it", r.stdout)

    # --- v1.7 t06: three-screen Setup ----------------------------------------------
    def test_setup_unwired_fails_check(self):
        self.rebrand()
        self.edit(rebrand.HOME, "if ((isMacOS || isWindows) && _boringSetup) {", "if (false) {")
        r = run(CHECK, self.root)
        self.assertIn("FAIL Setup wired: first launch, Settings, this Mac's name, System Settings panes (v1.7 t06)",
                      r.stdout)

    # --- v1.7 t12: Windows gets the v1.7 UI ------------------------------------------
    def test_windows_facts_pass_after_rebrand(self):
        self.rebrand()
        r = run(CHECK, self.root)
        for fact in (WIN_UI, WIN_SETUP, WIN_RULE, WIN_UPDATE):
            self.assertIn(f"PASS {fact}", r.stdout)

    def test_a_v17_screen_back_to_mac_only_fails_check(self):
        self.rebrand()
        self.edit(rebrand.T07_TOOLBAR, "    if (isMacOS || isWindows) {\n", "    if (isMacOS) {\n")
        r = run(CHECK, self.root)
        self.assertIn(f"FAIL {WIN_UI}", r.stdout)

    def test_windows_setup_without_the_reach_step_fails_check(self):
        self.rebrand()
        self.edit(rebrand.HOME, "isWindows ? SetupPlatform.windows : SetupPlatform.mac", "SetupPlatform.mac")
        r = run(CHECK, self.root)
        self.assertIn(f"FAIL {WIN_SETUP}", r.stdout)

    def test_installer_rule_limited_to_one_port_fails_check(self):
        self.rebrand()
        self.edit("res/msi/CustomActions/FirewallRules.cpp", "//hr = pNetFwRule->put_Protocol(6);", "hr = pNetFwRule->put_Protocol(6);")
        r = run(CHECK, self.root)
        self.assertIn(f"FAIL {WIN_RULE}", r.stdout)

    def test_windows_update_check_unwired_fails_check(self):
        self.rebrand()
        self.edit("src/update_install_run.rs", "crate::platform::update_to(p)", "Ok::<(), String>(())")
        r = run(CHECK, self.root)
        self.assertIn(f"FAIL {WIN_UPDATE}", r.stdout)

    # --- v1.7 t05: High Efficiency on a Local link between two Boring Remotes ----
    def test_high_efficiency_unwired_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs",
                  "platform_additions.insert(base::high_efficiency::MARKER.into(), json!(crate::VERSION));",
                  "")
        self.assert_check_fails(HE_WIRED)

    def test_high_efficiency_badge_without_the_targets_answer_fails_check(self):
        self.rebrand()
        self.edit("src/client/io_loop.rs", rebrand.T05_BADGE, "")
        self.assert_check_fails(HE_WIRED)

    # --- v1.7 t03: Direct Link, Tailscale fallback, encrypted off Tailscale ----
    def test_ip_branch_back_before_the_direct_link_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", rebrand.DIRECT_LINK_CALL,
                  "        if hbb_common::is_domain_port_str(peer) {\n            bail!(\"x\");\n        }\n"
                  + rebrand.DIRECT_LINK_CALL)
        self.assert_check_fails(CONNECT_DIRECT)

    def test_rendezvous_lookup_before_the_direct_link_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", "        // boring-remote (v1.7 t03): every peer is a name or IP",
                  "        let _ = crate::get_rendezvous_server(1_000).await;\n"
                  "        // boring-remote (v1.7 t03): every peer is a name or IP")
        self.assert_check_fails(CONNECT_DIRECT)

    def test_public_answer_accepted_fails_check(self):
        self.rebrand()
        self.edit("libs/base/src/direct_link.rs", "!addrs.iter().all(|a| crate::lan::is_allowed(a.ip()))",
                  "!addrs.iter().any(|a| crate::lan::is_allowed(a.ip()))")
        self.assert_check_fails(CONNECT_TAILNET)

    def test_widened_tailnet_range_fails_check(self):
        self.rebrand()
        self.edit("libs/base/src/direct_link.rs", "(v4.octets()[1] & 0xc0) == 64", "(v4.octets()[1] & 0x80) == 0")
        self.assert_check_fails(CONNECT_TAILNET)

    def test_reworded_error_fails_check(self):
        self.rebrand()
        self.edit("libs/base/src/direct_link.rs", rebrand.NOT_ON_NETWORK, "failed to connect")
        self.assert_check_fails(CONNECT_TAILNET)

    def test_fallback_past_a_refusal_fails_check(self):
        self.rebrand()
        self.edit("libs/base/src/direct_link.rs", "Err(Failure::Refused(e)) => return Err(e),",
                  "Err(Failure::Refused(_)) => {}")
        self.assert_check_fails(CONNECT_TAILNET)

    def test_no_answer_budget_covering_the_handshake_fails_check(self):
        self.rebrand()
        self.edit("libs/base/src/direct_link.rs", "match handshake(s, addr).await {",
                  "match hbb_common::timeout(ms, handshake(s, addr)).await.unwrap_or(Err(Failure::Unreachable)) {")
        self.assert_check_fails(CONNECT_TAILNET)

    def test_identity_pinned_on_the_id_alone_fails_check(self):
        self.rebrand()
        self.edit("libs/base/src/direct_link.rs", "t.lan != lan || (known_id == id && t.pk == pk)", "true")
        self.assert_check_fails(CONNECT_PIN)

    def test_plaintext_direct_link_on_the_lan_fails_check(self):
        self.rebrand()
        self.edit("libs/base/src/direct_link.rs", "    !is_tailscale(ip)\n", "    false\n")
        self.assert_check_fails(CONNECT_ENCRYPTED)

    def test_target_accepting_an_unkeyed_direct_link_fails_check(self):
        self.rebrand()
        self.edit("src/server.rs", "        base::direct_link::require_encrypted(addr.ip(), &stream)?;\n", "")
        self.assert_check_fails(CONNECT_ENCRYPTED)

    def test_direct_listener_back_to_plaintext_fails_check(self):
        self.rebrand()
        self.edit("src/rendezvous_mediator.rs", "direct_link: encrypt,", "direct_link: false,")
        self.assert_check_fails(CONNECT_ENCRYPTED)

    def test_not_found_key_missing_from_a_language_fails_check(self):
        self.rebrand()
        self.edit("src/lang/fr.rs", f'        ("{rebrand.NOT_ON_NETWORK}", ""),\n', "")
        r = run(CHECK, self.root)
        self.assertRegex(r.stdout, rf"FAIL {NOT_FOUND_TRANSLATED}: .*fr.rs")

    # --- v1.7 t04: LAN trust, no default password ----------------------------------
    def test_preset_password_in_hard_settings_fails_check(self):
        self.rebrand()
        self.edit("libs/hbb_common/src/config.rs",
                  "pub static ref HARD_SETTINGS: RwLock<HashMap<String, String>> = Default::default();",
                  'pub static ref HARD_SETTINGS: RwLock<HashMap<String, String>> = RwLock::new('
                  '[("password", "letmein1A")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect());')
        self.assert_check_fails(NO_DEFAULT_PASSWORD)

    def test_hardcoded_unattended_password_fails_check(self):
        self.rebrand()
        self.edit("src/server.rs", "pub fn new() -> ServerPtr {\n",
                  'pub fn new() -> ServerPtr {\n    Config::set_permanent_password("Boring2026");\n')
        self.assert_check_fails(NO_DEFAULT_PASSWORD)

    def test_trusted_skip_moved_out_of_the_login_decision_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "if self.boring_trust.is_trusted() {", "if self.authorized {")
        self.assert_check_fails(TRUST_WIRED)

    def test_one_time_code_granting_lasting_trust_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", rebrand.T04_GRANT,
                  "        self.boring_trust.approve(base::trust::SignIn::Allowed, &self.lr.my_name);\n")
        self.assert_check_fails(ONE_TIME_CODE)

    def test_lan_macs_that_left_deleted_from_the_stored_list_fails_check(self):
        self.rebrand()
        self.edit("src/lan.rs", rebrand.T02_END_CYCLE, "    peers.retain(|p| p.online);\n")
        self.assert_check_fails(RUST_HOOKS)

    def test_trust_option_renamed_on_one_side_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/desktop/kit/trust.dart", "'boring-trust-tokens'", "'boring-tokens'")
        self.assert_check_fails(TRUST_TOKENS)

    def test_tabs_back_as_the_default_fails_check(self):  # v1.7 t11
        self.rebrand()
        self.edit("libs/hbb_common/src/config.rs",
                  '("enable-open-new-connections-in-tabs", "N")',
                  '("enable-open-new-connections-in-tabs", "Y")')
        self.assert_check_fails("new sessions open in windows (tabs option off by default)")

    def test_mac_full_screen_restore_skipping_the_monitor_fails_check(self):  # v1.7 t11
        self.rebrand()
        self.edit("flutter/lib/common.dart",
                  "        // boring-remote: Mac too, so full screen lands on the Target's monitor.\n"
                  "        await restoreFrame();\n",
                  "        if (!isMacOS) {\n          await restoreFrame();\n        }\n")
        self.assert_check_fails("restore moves the window to its monitor before full screen on Mac")

    def test_moved_patch_target_stops_the_script_and_writes_nothing(self):
        cfg = self.root / "libs/hbb_common/src/config.rs"
        cfg.write_text(cfg.read_text().replace('&["rs-ny.rustdesk.com"]', '&["rs-sg.rustdesk.com"]'))
        before = tree_hashes(self.root)
        r = run(REBRAND, self.root)
        self.assertEqual(r.returncode, 2)
        self.assertIn("patch target moved", r.stderr)
        self.assertIn("libs/hbb_common/src/config.rs", r.stderr)
        self.assertIn("rebrand: nothing written", r.stdout)
        self.assertEqual(before, tree_hashes(self.root))  # no patch, copy or workflow removal

    def test_line_endings_are_kept(self):
        crlf = ["flutter/macos/Runner/Configs/AppInfo.xcconfig", "res/msi/Package/Package.wxs",
                "libs/hbb_common/src/config.rs"]
        for rel in crlf:
            path = self.root / rel
            path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
        self.rebrand()
        for rel in crlf:
            data = (self.root / rel).read_bytes()
            self.assertEqual(data.count(b"\n"), data.count(b"\r\n"), f"{rel} lost CRLF")
        self.assertIn(b"PRODUCT_NAME = BoringRemote\r\n", (self.root / crlf[0]).read_bytes())
        for rel in ("src/common.rs", "flutter/windows/runner/Runner.rc"):  # LF stays LF
            self.assertNotIn(b"\r", (self.root / rel).read_bytes(), rel)
        self.assertIn("rebrand: 0 changed, 0 moved", self.rebrand().stdout)


if __name__ == "__main__":
    unittest.main()
