#!/usr/bin/env python3
"""Seam 2: the rebrand script against a clean copy of this checkout.

Run:  python3 -m unittest boring/test_rebrand.py -v
Needs git and an initialised libs/hbb_common submodule. Each test exports a
fresh tree (committed HEAD of the repo and of the submodule) into a temp dir,
so your working tree is never touched.
"""
import base64
import contextlib
import io
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
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
CONNECT_DIRECT = check.CONNECT_DIRECT
CONNECT_TAILNET = "connect box dials only Tailscale or private-LAN addresses, else the plain error"
CONNECT_ENCRYPTED = check.CONNECT_ENCRYPTED
NOT_FOUND_TRANSLATED = "every connect error is in every translation file"
CONNECT_PIN = "Direct Link pins the Target on the address dialled and on its ID (identity changed otherwise)"
ONE_TIME_CODE = "a one-time code lets a Controller in for that session only (ADR 0005)"
REMOVED_ASKS = "a removed Trusted Controller is asked again; its password does not undo Remove (A2 step 5)"
HE_WIRED = "High Efficiency wired: Target marks itself and answers the ask, badge waits for the answer"
RUST_HOOKS = "v1.7 Rust hooks landed: base modules, Direct Link meta, LAN end of cycle, Controller name"
NO_DEFAULT_PASSWORD = "no default or blank password ships (ADR 0002)"
TRUST_WIRED = "LAN trust wired: token exchange both ends, approval prompt, Trusted Controllers (v1.7 t04)"
TRUST_TOKENS = "trust tokens: 256-bit, constant-time, option names agree in Rust and Dart"
MAC_BUNDLE = "Mac bundle is Boring Remote.app; its exe stays BoringRemote (t17)"
MAC_PLISTS = "launchd plists run Boring Remote.app directly, no sh -c (t17)"
MAC_MOVE = "a 1.6.x BoringRemote.app is moved once; both paths count as installed until then (t17)"
ACCESS = "Access: Settings and Home check what serves sessions; remote access is its own switch (t17)"
AGENT_RESTART = "the agent restart checks --server came up; a job stuck at spawn failed is booted out and in again (t17)"
SETTINGS_GEAR = "Settings opens from a gear, not the three-line menu (t17)"
SUPPORT = "support file and crash files wired: a panic hook at every startup, Settings Help, Home's notice (t20)"
SUPPORT_REDACT = "the support file removes every secret by name and hashes IDs (t20)"
WIN_NAMES = "Windows service, firewall rule and Apps list say Boring Remote; exe and install dir unchanged (t17)"
ASK_INFO = check.ASK_INFO
ROOT_BUNDLE = check.ROOT_BUNDLE
SETTINGS_ALLOW = "Settings: Allow next to removed and waiting Controllers, over the service like Remove (t04)"
ALWAYS_ASK = check.ALWAYS_ASK
ALWAYS_ASK_FORGET = check.ALWAYS_ASK_FORGET
ALWAYS_ASK_SALT = check.ALWAYS_ASK_SALT
TRUST_WRITES = check.TRUST_WRITES
NEW_ALWAYS_ASK = check.NEW_ALWAYS_ASK
AUTHORIZED_ONCE = check.AUTHORIZED_ONCE
REBRAND = HERE / "rebrand.py"
CHECK = HERE / "check.py"
WHITELIST_FIRST = "a whitelist the buyer sets is still checked first on incoming connections"
REMOTE_CONFIG = "allow-remote-config-modification locked off (a UI hint; the session guard holds the settings)"
HBB = rebrand.HBB
PROTOCOL = "protocol files are upstream's plus our two LoginRequest fields (boring/protocol.sha256)"


def export_clean_tree(dest):
    for sub, out in (("", dest), ("libs/hbb_common", dest / "libs/hbb_common")):
        out.mkdir(parents=True, exist_ok=True)
        archive = subprocess.run(["git", "-C", str(REPO / sub), "archive", "HEAD"],
                                 check=True, capture_output=True).stdout
        subprocess.run(["tar", "-x", "-C", str(out)], input=archive, check=True)
    # An unpatched upstream tree still has its own workflows; put one back so the
    # tree under test looks like a fresh upstream checkout.
    wf = dest / ".github/workflows"
    wf.mkdir(parents=True, exist_ok=True)
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
        for fact in ("the only rendezvous server is rs.theboringremote.com", "whitelist", "app name", "hwcodec",
                     "MSI product name", "MSI banner art"):
            self.assertIn(fact, r.stdout)
        for fact in ("no RustDesk name or link in the Mac and Windows app's strings",
                     check.ABOUT_LEGAL, check.LICENCE_BUNDLED, check.SOURCE_LINK,
                     "no RustDesk name or link in any translation",
                     "no RustDesk in app metadata", "window titles and tray tooltip say Boring Remote",
                     "no upstream RustDesk logo or icon ships", "every logo slot holds Boring Remote art",
                     "Mac menu-bar icon res/mac-tray-dark-x2.png is a template glyph",
                     CONNECT_DIRECT, NOT_FOUND_TRANSLATED, CONNECT_ENCRYPTED, TRUST_WIRED, ONE_TIME_CODE,
                     HE_WIRED, RUST_HOOKS, SUPPORT, ASK_INFO, ROOT_BUNDLE, ALWAYS_ASK, ALWAYS_ASK_FORGET,
                     TRUST_WRITES, NEW_ALWAYS_ASK):
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
        self.assert_check_fails(WHITELIST_FIRST)

    def test_dropping_v4_mapped_normalisation_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "        let addr = hbb_common::try_into_v4(addr);\n", "")
        self.assert_check_fails(WHITELIST_FIRST)

    # --- ADR 0003: private LAN allowed, LAN Discovery on ---------------------
    # 1.8 (ADR 0005): no global whitelist (Hosted connections arrive relayed); the Direct Link
    # listener keeps the Tailscale + private-LAN rule as its own hook.
    WHITELIST_FACT = "the Direct Link (21118) answers Tailscale and private-LAN addresses only, with no global whitelist"
    LAN_LISTENER = "LAN discovery listener answers pings (ADR 0003)"
    LAN_UNLOCKED = "LAN discovery not locked off (ADR 0003)"

    def test_lan_facts_pass_after_rebrand(self):
        self.rebrand()
        r = run(CHECK, self.root)
        for fact in (self.WHITELIST_FACT, self.LAN_LISTENER, self.LAN_UNLOCKED):
            self.assertIn(f"PASS {fact}", r.stdout)

    def test_public_range_in_whitelist_fails_check(self):
        self.rebrand()
        self.edit("src/rendezvous_mediator.rs", "                if !base::lan::is_allowed(addr.ip()) {\n",
                  "                if false && !base::lan::is_allowed(addr.ip()) {\n")
        self.assert_check_fails(self.WHITELIST_FACT)

    def test_lan_listener_stripped_again_fails_check(self):
        self.rebrand()
        sig = "pub(super) fn start_listening() -> ResultType<()> {\n"
        self.edit("src/lan.rs", sig, f"{sig}    {rebrand.GUARD_OK}\n")
        self.assert_check_fails(self.LAN_LISTENER)

    LAN_BOTH_WAYS = "LAN Discovery both ways: asks known computers directly, skips loopback and Tailscale (t21)"

    def test_lan_both_ways_passes_after_rebrand(self):
        self.rebrand()
        self.assertIn(f"PASS {self.LAN_BOTH_WAYS}", run(CHECK, self.root).stdout)

    def test_lan_broadcast_only_again_fails_check(self):
        self.rebrand()
        self.edit("src/lan.rs", rebrand.T21_SEND, rebrand.T21_SEND_OLD)
        self.assert_check_fails(self.LAN_BOTH_WAYS)

    def test_lan_listener_not_noting_pings_fails_check(self):
        self.rebrand()
        self.edit("src/lan.rs", rebrand.T21_HEARD, "")
        self.assert_check_fails(self.LAN_BOTH_WAYS)

    # --- v1.7 t26: Home says computer about the Target, and lists each machine once -
    TARGET_WORDS = "the Target is a computer on both builds: Home, connect errors, other-end lines (t26)"
    USED_BEFORE = "Used before lists each machine once, newest address, nothing deleted from disk (t26)"

    def test_t26_passes_after_rebrand(self):
        self.rebrand()
        out = run(CHECK, self.root).stdout
        self.assertIn(f"PASS {self.TARGET_WORDS}", out)
        self.assertIn(f"PASS {self.USED_BEFORE}", out)

    def test_home_title_saying_mac_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/desktop/kit/mac_home.dart", "'Connect to a computer'", "'Connect to a ${KitWords.one}'")
        self.assert_check_fails(self.TARGET_WORDS)

    def test_other_end_line_following_this_machines_word_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/desktop/kit/kit_look.dart", "Password for that computer", "Password for that ${KitWords.one}")
        self.assert_check_fails(self.TARGET_WORDS)

    def test_connect_error_saying_mac_fails_check(self):
        self.rebrand()
        self.edit("libs/base/src/direct_link.rs", "Couldn't reach that computer.", "Couldn't reach that Mac.")
        self.assert_check_fails(self.TARGET_WORDS)

    def test_unnamed_recent_saying_mac_fails_check(self):
        self.rebrand()
        self.edit(rebrand.HOME, "KitWords.unnamed", "'Unnamed Mac'")
        self.assert_check_fails(self.TARGET_WORDS)

    def test_this_machine_losing_its_word_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/desktop/kit/mac_home.dart", "To reach this $one", "To reach this computer")
        self.assert_check_fails(self.TARGET_WORDS)

    # --- v1.7 t29: Transfer files from Home, with no screen capture on the Target -
    def test_t29_passes_after_rebrand(self):
        self.rebrand()
        out = run(CHECK, self.root).stdout
        for fact in (check.TRANSFER_HOME, check.TRANSFER_ASK, check.TRANSFER_NO_CAPTURE, CONNECT_DIRECT):
            self.assertIn(f"PASS {fact}", out)

    def test_home_transfer_opening_a_session_fails_check(self):
        self.rebrand()
        self.edit(rebrand.HOME, "connect(context, t, isFileTransfer: true)", "connect(context, t)")
        self.assert_check_fails(check.TRANSFER_HOME)

    def test_a_list_without_the_button_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/desktop/kit/mac_home.dart", "trailing: _transferButton(() => m.ip),\n", "")
        self.assert_check_fails(check.TRANSFER_HOME)

    def test_address_box_without_the_button_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/desktop/kit/mac_home.dart", "_transferButton(() => _typedTarget(_address.text)", "_transferButton(() => ''")
        self.assert_check_fails(check.TRANSFER_HOME)

    def test_a_transfer_skipping_the_trust_gate_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "if self.boring_trust.must_ask() {",
                  "if self.file_transfer.is_none() && self.boring_trust.must_ask() {")
        self.assert_check_fails(check.TRANSFER_ASK)

    def test_ask_saying_control_for_a_transfer_fails_check(self):
        self.rebrand()
        self.edit(rebrand.SERVER_MODEL, "files: client.type_() == ClientType.file,", "files: false,")
        self.assert_check_fails(check.TRANSFER_ASK)

    def test_a_transfer_subscribing_the_screen_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs",
                  "if self.file_transfer.is_some() || self.terminal {\n            res.set_peer_info(pi);",
                  "if self.terminal {\n            res.set_peer_info(pi);")
        self.assert_check_fails(check.TRANSFER_NO_CAPTURE)

    def test_is_remote_counting_a_transfer_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "self.file_transfer.is_none()\n            && !self.is_port_forward()",
                  "!self.is_port_forward()")
        self.assert_check_fails(check.TRANSFER_NO_CAPTURE)

    def test_a_new_way_to_the_monitor_service_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "    fn try_sub_camera_displays(&mut self) {\n",
                  "    fn sneak(&mut self, s: &mut Server) { s.try_add_monitor_service(0); }\n"
                  "    fn try_sub_camera_displays(&mut self) {\n")
        self.assert_check_fails(check.TRANSFER_NO_CAPTURE)

    def test_a_transfer_allowed_to_pick_a_display_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "Some(message::Union::FileAction(_)) | Some(message::Union::FileResponse(_)) => true,",
                  "Some(message::Union::FileAction(_)) | Some(message::Union::FileResponse(_)) | Some(message::Union::VideoReceived(_)) => true,")
        self.assert_check_fails(check.TRANSFER_NO_CAPTURE)

    def test_home_listing_every_address_fails_check(self):
        self.rebrand()
        self.edit(rebrand.HOME, "oneEntryPerMachine(", "List.of(")
        self.assert_check_fails(self.USED_BEFORE)

    def test_home_without_the_pinned_keys_fails_check(self):
        self.rebrand()
        self.edit(rebrand.HOME, "identitiesFromKnown(bind.mainGetLocalOption(key: kDirectLinkKnownOption))",
                  "const <String, String>{}")
        self.assert_check_fails(self.USED_BEFORE)

    def test_home_deleting_a_collapsed_entry_fails_check(self):
        self.rebrand()
        self.edit(rebrand.HOME, "    List<MacEntry> usedBefore() {\n",
                  "    List<MacEntry> usedBefore() {\n      bind.mainRemovePeer(id: '');\n")
        self.assert_check_fails(self.USED_BEFORE)

    def test_setup_without_ready_line_fails_check(self):
        self.rebrand()
        self.edit(rebrand.HOME, "        readyChecks: boringAccessChecks(),\n", "")
        self.assert_check_fails("Setup wired: first launch, Settings, this Mac's name, System Settings panes (v1.7 t06)")

    def test_clear_switches_without_our_bundle_id_fails_check(self):
        # tccutil with no bundle id resets every app on the Mac.
        self.rebrand()
        self.edit("flutter/lib/desktop/kit/access.dart", "['reset', service, kBundleId]", "['reset', service]")
        self.assert_check_fails(check.CLEAR_SWITCHES)

    def test_clear_switches_on_another_bundle_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/desktop/kit/access.dart", "const kBundleId = 'io.boringlabs.remote.agent';",
                  "const kBundleId = 'com.example.other';")
        self.assert_check_fails(check.CLEAR_SWITCHES)

    def test_clear_switches_resetting_everything_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/desktop/kit/access.dart", "const kSwitchServices = ['Accessibility', 'ScreenCapture', 'ListenEvent'];",
                  "const kSwitchServices = ['All'];")
        self.assert_check_fails(check.CLEAR_SWITCHES)

    def test_tccutil_anywhere_else_fails_check(self):
        self.rebrand()
        self.edit(rebrand.HOME, "  final ok = await clearSwitches(Process.run);\n",
                  "  final ok = await clearSwitches(Process.run);\n  await Process.run('tccutil', ['reset', 'All']);\n")
        self.assert_check_fails(check.CLEAR_SWITCHES)

    def test_access_without_the_way_out_fails_check(self):
        self.rebrand()
        self.edit(rebrand.SETTINGS, ", clearSwitches: isMacOS ? boringClearSwitches : null), // v1.7 t17, t31", "), // v1.7 t17, t31")
        self.assert_check_fails(check.CLEAR_SWITCHES)

    def test_ready_reading_the_window_again_fails_check(self):
        self.rebrand()
        self.edit(rebrand.HOME, "read: () => boringServeWatch.serves((a) => a.control),", "read: () async => bind.mainIsProcessTrusted(prompt: false),")
        self.assert_check_fails(check.SERVER_ANSWERS)

    def test_server_not_answering_for_itself_fails_check(self):
        self.rebrand()
        self.edit("src/ipc.rs", 'name == "boring-serve-access"', 'name == "boring-serve-acces"')
        self.assert_check_fails(check.SERVER_ANSWERS)

    def test_no_new_process_read_fails_check(self):
        self.rebrand()
        self.edit("src/core_main.rs", 'args[0] == "--boring-access"', 'args[0] == "--boring-acces"')
        self.assert_check_fails(check.SERVER_ANSWERS)

    def test_auto_restart_during_a_session_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/desktop/kit/access.dart", "if (s.sessions > 0 || !mayRestart() || _restarts >= maxRestarts) return;",
                  "if (!mayRestart() || _restarts >= maxRestarts) return;")
        self.assert_check_fails(check.SERVER_ANSWERS)

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

    def test_second_rustdesk_credit_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/desktop/widgets/tabbar_widget.dart", "'Boring Remote'",
                  "'" + rebrand.LEGAL_CREDIT + "'")
        self.assert_check_fails(check.ABOUT_LEGAL)

    def test_legal_passes_on_a_rebranded_tree(self):
        self.rebrand()
        r = run(CHECK, self.root)
        for fact in (check.ABOUT_LEGAL, check.LEGAL_NOTICES, check.LICENCE_BUNDLED, check.SOURCE_LINK,
                     check.SOURCE_NOTICE, check.NO_OWNER):
            self.assertIn(f"PASS {fact}", r.stdout)
        self.assertEqual(rebrand.FORK_URL, "https://boringlabs.online/remote/source/")
        about = (self.root / rebrand.SETTINGS).read_text()
        self.assertNotIn("Purslane", about)
        self.assertNotIn("AGPL", about)
        self.assertNotIn("Purslane", (self.root / "flutter/lib/common.dart").read_text())
        self.assertIn("The source code for each version is at https://boringlabs.online/remote/source/",
                      (self.root / "res/msi/Package/License.rtf").read_text())
        self.assertEqual((self.root / rebrand.LICENCE_ASSET).read_bytes(), (self.root / "LICENCE").read_bytes())

    def test_legal_item_gone_from_about_fails_check(self):
        self.rebrand()
        self.edit(rebrand.SETTINGS, rebrand.ABOUT_NEW, "")
        self.assert_check_fails(check.ABOUT_LEGAL)

    def test_a_missing_notice_in_legal_fails_check(self):
        self.rebrand()
        for line in ("Text(LegalWords.noWarranty),", "Text(LegalWords.credit),", "Text(LegalWords.license),",
                     "child: const Text(LegalWords.readLicense)),", "Text(LegalWords.sourceUrl),"):
            self.edit(rebrand.LEGAL_DART, line, "")
            self.assert_check_fails(check.LEGAL_NOTICES)
            self.rebrand_reset_legal()

    def rebrand_reset_legal(self):
        shutil.copy(REPO / rebrand.LEGAL_DART, self.root / rebrand.LEGAL_DART)

    def test_source_button_gone_from_legal_fails_check(self):
        self.rebrand()
        self.edit(rebrand.LEGAL_DART, "openUrl(LegalWords.sourceUrl)", "null")
        self.assert_check_fails(check.LEGAL_NOTICES)

    def test_source_link_moved_or_gone_fails_check(self):
        self.rebrand()
        self.edit(rebrand.LEGAL_DART, rebrand.FORK_URL, "https://example.com/")
        self.assert_check_fails(check.SOURCE_LINK)
        self.rebrand_reset_legal()
        self.edit("res/msi/Package/License.rtf", rebrand.FORK_URL, "")
        self.assert_check_fails(check.SOURCE_LINK)

    def test_license_missing_from_the_app_fails_check(self):
        self.rebrand()
        (self.root / rebrand.LICENCE_ASSET).unlink()
        self.assert_check_fails(check.LICENCE_BUNDLED)

    def test_notice_gone_fails_check(self):
        self.rebrand()
        (self.root / "NOTICE").unlink()
        self.assert_check_fails(check.SOURCE_NOTICE)

    def test_owner_name_in_shipped_text_fails_check(self):
        self.rebrand()
        for rel, old, new in (("flutter/lib/desktop/kit/kit.dart", "// The app uses", f"// {check.OWNER_WORDS[0]} uses"),
                              ("res/msi/Package/License.rtf", "Boring Labs", check.OWNER_WORDS[1].title())):
            self.edit(rel, old, new)
            self.assert_check_fails(check.NO_OWNER)
            self.edit(rel, new, old)

    def test_source_tarball(self):
        """What goes on the source page: both repos, NOTICE dated, no history, no owner on the files."""
        out = self.tmp / "out"
        r = subprocess.run(["bash", str(HERE / "release/source-tarball.sh"), "HEAD", str(out)],
                           capture_output=True, text=True, cwd=REPO)
        self.assertEqual(r.returncode, 0, r.stderr)
        head = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        name = f"BoringRemote-{head[:9]}-source"
        path = out / f"{name}.tar.gz"
        self.assertEqual(r.stdout.split()[0], str(path))
        with tarfile.open(path) as tar:
            members = tar.getmembers()
            names = {m.name for m in members}
            for rel in ("NOTICE", "LICENCE", "boring/rebrand.py", "libs/hbb_common/Cargo.toml", "Cargo.toml"):
                self.assertIn(f"{name}/{rel}", names)
            self.assertFalse([n for n in names if n.endswith("/.git") or "/.git/" in n])
            self.assertEqual({(m.uid, m.gid, m.uname, m.gname) for m in members}, {(0, 0, "", "")})
            self.assertRegex(tar.extractfile(f"{name}/NOTICE").read().decode(),
                             rf"This copy is commit {head}, dated \d{{4}}-\d{{2}}-\d{{2}}\.\n$")

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

    def test_retina_rule_without_high_efficiency_fails_check(self):  # ADR 0006 amendment
        self.rebrand()
        self.edit("src/server.rs", rebrand.T05_RETINA, rebrand.T05_RETINA_OLD)
        self.assert_check_fails(HE_WIRED)

    def test_av1_uncapped_fails_check(self):  # ADR 0006 amendment, device check A3
        self.rebrand()
        self.edit("libs/base/src/high_efficiency.rs", " && av1_keeps_up", "")
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
        self.edit("src/client.rs", "        // boring-remote (v1.7 t03): a name or IP is a Direct Link",
                  "        let _ = crate::get_rendezvous_server(1_000).await;\n"
                  "        // boring-remote (v1.7 t03): a name or IP is a Direct Link")
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

    # v1.7 t25: every LAN address, fastest first
    def test_fastest_lan_passes_on_a_clean_rebrand(self):
        self.rebrand()
        self.assertIn(f"PASS {check.FASTEST_LAN}", run(CHECK, self.root).stdout)

    def test_pong_without_the_address_list_fails_check(self):
        self.rebrand()
        self.edit("src/lan.rs", rebrand.T25_PONG, rebrand.T25_PONG_OLD)
        self.assert_check_fails(check.FASTEST_LAN)

    def test_pong_addresses_not_kept_fails_check(self):
        self.rebrand()
        self.edit("src/lan.rs", rebrand.T25_STORE, rebrand.T25_STORE_OLD)
        self.assert_check_fails(check.FASTEST_LAN)

    def test_public_address_from_a_pong_fails_check(self):  # ADR 0003
        self.rebrand()
        self.edit("libs/base/src/lan.rs", "        .filter(|a| is_lan(a.ip))\n", "")
        self.assert_check_fails(check.FASTEST_LAN)

    def test_public_address_as_a_candidate_fails_check(self):  # ADR 0003
        self.rebrand()
        self.edit("libs/base/src/direct_link.rs", "if crate::lan::is_lan(ip) && !mine && !dial.contains(&addr) {",
                  "if !mine && !dial.contains(&addr) {")
        self.assert_check_fails(check.FASTEST_LAN)

    def test_is_lan_widened_to_public_fails_check(self):  # ADR 0003
        self.rebrand()
        self.edit("libs/base/src/lan.rs", "is_allowed(ip) && !crate::direct_link::is_tailscale(ip)", "true")
        self.assert_check_fails(check.FASTEST_LAN)

    def test_dial_skipping_the_handshake_fails_check(self):
        self.rebrand()
        self.edit("libs/base/src/direct_link.rs", "judge(strict, addr, handshake(stream, addr, known, HANDSHAKE_TIMEOUT_MS).await)",
                  "judge(strict, addr, Ok((stream, None)))")
        self.assert_check_fails(check.FASTEST_LAN)

    def test_race_stopping_at_the_first_address_fails_check(self):
        self.rebrand()
        self.edit("libs/base/src/direct_link.rs", "std::iter::once(plan.direct).chain(plan.others).chain(tailscale)",
                  "std::iter::once(plan.direct).chain(tailscale)")
        self.assert_check_fails(check.FASTEST_LAN)

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
        self.edit("libs/base/src/direct_link.rs", "(t.lan != at && t.tailscale != at) || (known_id == id && t.pk == pk)", "true")
        self.assert_check_fails(CONNECT_PIN)

    def test_plaintext_tailscale_dial_fails_check(self):  # audit H2
        self.rebrand()
        self.edit("libs/base/src/direct_link.rs", "    let who = secure(&mut stream, known, addr, ms).await?;\n",
                  "    if is_tailscale(addr.ip()) {\n        return Ok((stream, None));\n    }\n"
                  "    let who = secure(&mut stream, known, addr, ms).await?;\n")
        self.assert_check_fails(CONNECT_ENCRYPTED)

    def test_must_encrypt_exemption_back_fails_check(self):  # audit H2
        self.rebrand()
        self.edit("libs/base/src/direct_link.rs", "pub fn is_tailscale(ip: IpAddr) -> bool {",
                  "pub fn must_encrypt(ip: IpAddr) -> bool {\n    !is_tailscale(ip)\n}\n\npub fn is_tailscale(ip: IpAddr) -> bool {")
        self.assert_check_fails(CONNECT_ENCRYPTED)

    def test_target_letting_tailscale_in_unkeyed_fails_check(self):  # audit H2
        self.rebrand()
        self.edit("libs/base/src/direct_link.rs", "    if !stream.is_secured() {\n        bail!(\"plaintext",
                  "    if !is_tailscale(peer) && !stream.is_secured() {\n        bail!(\"plaintext")
        self.assert_check_fails(CONNECT_ENCRYPTED)

    def test_target_accepting_an_unkeyed_direct_link_fails_check(self):
        self.rebrand()
        self.edit("src/server.rs", "        base::direct_link::require_encrypted(addr.ip(), &stream)?;\n", "")
        self.assert_check_fails(CONNECT_ENCRYPTED)

    def test_direct_listener_back_to_plaintext_fails_check(self):
        self.rebrand()
        self.edit("src/rendezvous_mediator.rs", "direct_link: true,", "direct_link: false,")
        self.assert_check_fails(CONNECT_ENCRYPTED)

    # --- audit H1: who the ask is, and Allow by key -----------------------------------
    def test_settings_allow_matching_by_name_fails_check(self):
        self.rebrand()
        self.edit(rebrand.SETTINGS, "for (final id in waitingFrom(c, ApprovalDesk.waitingNow.value)) {",
                  "for (final id in [for (final w in ApprovalDesk.waitingNow.value) if (w.name == c.name) w.id]) {")
        self.assert_check_fails(SETTINGS_ALLOW)

    def test_waiting_from_matching_any_key_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/desktop/kit/approval.dart", "if (w.trust == 'removed' && ", "if (")
        self.assert_check_fails(SETTINGS_ALLOW)

    def test_prompt_back_to_the_name_alone_fails_check(self):
        self.rebrand()
        self.edit(rebrand.CM_PAGE, "            trust: client.boringTrust,\n            ip: client.boringIp,\n", "")
        self.assert_check_fails(ASK_INFO)

    def test_ask_info_not_sent_to_the_connection_window_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", rebrand.H1_LOGIN_SEND, "")
        self.assert_check_fails(ASK_INFO)

    # --- audit H3: root runs only a root-owned bundle ----------------------------------
    def test_daemon_install_without_locking_the_bundle_fails_check(self):
        self.rebrand()
        self.edit("src/platform/privileges_scripts/install.scpt", "set sh to sh0 & sh1", "set sh to sh1")
        self.assert_check_fails(ROOT_BUNDLE)

    def test_verifier_run_before_the_lock_fails_check(self):
        self.rebrand()
        self.edit("src/platform/privileges_scripts/install-update.sh",
                  'newer "$VERSION" "$FROM" || fail "$VERSION is not newer than $FROM"\nlock_bundle "$APP"\n',
                  'newer "$VERSION" "$FROM" || fail "$VERSION is not newer than $FROM"\n')
        self.assert_check_fails(ROOT_BUNDLE)

    def test_bundle_handed_back_to_the_user_fails_check(self):
        self.rebrand()
        self.edit("src/platform/privileges_scripts/update.scpt", rebrand.H3_ROOT_SCPT, rebrand.H3_STAFF_SCPT)
        self.assert_check_fails(ROOT_BUNDLE)

    def test_verify_package_without_the_root_refusal_fails_check(self):
        self.rebrand()
        self.edit("src/update_install.rs", "base::bundle_move::refuse_as_root(&e)", "None::<String>")
        self.assert_check_fails(ROOT_BUNDLE)

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
        self.edit("src/server/connection.rs", "if self.boring_trust.must_ask() {", "if self.authorized {")
        self.assert_check_fails(TRUST_WIRED)

    def test_one_time_code_granting_lasting_trust_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", rebrand.T04_GRANT,
                  "        self.boring_trust.approve(base::trust::SignIn::Allowed, &self.lr.my_name);\n")
        self.assert_check_fails(ONE_TIME_CODE)

    def test_removed_controller_let_in_by_password_fails_check(self):  # device check A2 step 5
        self.rebrand()
        self.edit("src/server/connection.rs", "if self.boring_trust.must_ask() {", "if false {")
        self.assert_check_fails(REMOVED_ASKS)

    def test_remove_dropping_the_entry_fails_check(self):
        self.rebrand()
        self.edit("libs/base/src/trust.rs", "            t.removed = true;\n        }\n        true\n", "        }\n        true\n")
        self.assert_check_fails(REMOVED_ASKS)

    # --- Always ask for password (per Trusted Controller) ------------------------------
    def test_always_ask_let_in_by_its_token_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "            if self.boring_trust.always_ask() {\n                if !(",
                  "            if false {\n                if !(")
        self.assert_check_fails(ALWAYS_ASK)

    def test_always_ask_let_in_by_a_one_time_code_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs",
                  "\n                    && self.conn_audit_primary_auth == ConnAuditPrimaryAuth::PermanentPassword", "")
        self.assert_check_fails(ALWAYS_ASK)

    def test_always_ask_without_the_wrong_password_limits_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", rebrand.T04_ALWAYS_ASK,
                  rebrand.T04_ALWAYS_ASK.replace("self.update_failure_with_scope(failure, false, 0, FailureScope::Default);", ""))
        self.assert_check_fails(ALWAYS_ASK)

    def test_always_ask_gate_dropped_fails_check(self):  # a click or switch sides would let it in
        self.rebrand()
        self.edit("src/server/connection.rs", rebrand.T04_ALWAYS_ASK_GATE, "")
        self.assert_check_fails(ALWAYS_ASK)

    def test_always_ask_entry_changed_by_a_sign_in_fails_check(self):
        self.rebrand()
        self.edit("libs/base/src/trust.rs", "        if self.always_ask() {\n            return false;\n        }\n", "")
        self.assert_check_fails(ALWAYS_ASK)

    def test_always_ask_switched_without_the_typed_password_fails_check(self):
        self.rebrand()
        self.edit(rebrand.SETTINGS, "trustEdit('always_ask', k, on: on, password: pw)",
                  "trustEdit('always_ask', k, on: on, password: '')")
        self.assert_check_fails(ALWAYS_ASK)

    def test_a_session_kept_after_switch_on_fails_check(self):  # review L1
        self.rebrand()
        self.edit("src/server/connection.rs", rebrand.T04_ALWAYS_ASK_KICK, "")
        self.assert_check_fails(ALWAYS_ASK)

    def test_a_tunnel_kept_after_switch_on_fails_check(self):  # review L1 re-check
        self.rebrand()
        self.edit("src/server/connection.rs", rebrand.T04_ALWAYS_ASK_TUNNEL, "")
        self.assert_check_fails(ALWAYS_ASK)

    def test_salt_turned_over_in_two_writes_fails_check(self):  # review Low: a crash between = no password
        self.rebrand()
        self.edit("libs/base/src/trust.rs",
                  "    match Config::set_permanent_password_storage_for_sync(&new_storage, &fresh) {",
                  "    let _ = Config::set_permanent_password_storage_for_sync(\"\", &fresh);\n"
                  "    match Config::set_permanent_password_storage_for_sync(&new_storage, &fresh) {")
        self.assert_check_fails(ALWAYS_ASK_SALT)

    def test_always_ask_on_without_turning_the_salt_over_fails_check(self):  # review H1
        self.rebrand()
        self.edit("libs/base/src/trust.rs", "                    rotate_salt(password)?;\n", "")
        self.assert_check_fails(ALWAYS_ASK_SALT)

    def test_settings_writing_the_list_option_itself_fails_check(self):  # review L2
        self.rebrand()
        self.edit(rebrand.SETTINGS, "                      onForget: (id) async {\n",
                  "                      onForget: (id) async {\n"
                  "                        await bind.mainSetOption(key: kTrustedControllersOption, value: '[]');\n")
        self.assert_check_fails(TRUST_WRITES)

    def test_a_settings_windows_stale_list_stored_fails_check(self):  # review L2
        self.rebrand()
        self.edit("src/ipc.rs", rebrand.T04_KEEP_LIST, rebrand.T04_KEEP_LIST_OLD)
        self.assert_check_fails(TRUST_WRITES)

    def test_an_unreadable_list_written_over_fails_check(self):  # review L2
        self.rebrand()
        self.edit("libs/base/src/trust.rs", "Trusted::parse_strict(&raw).ok_or(UNREADABLE)?", "Trusted::parse(&raw)")
        self.assert_check_fails(TRUST_WRITES)

    def test_new_computers_switch_ignored_fails_check(self):  # review M1
        self.rebrand()
        self.edit("libs/base/src/trust.rs", "self.new_always_ask ||", "false ||")
        self.assert_check_fails(NEW_ALWAYS_ASK)

    def test_a_second_place_that_lets_a_session_in_fails_check(self):  # review L5
        self.rebrand()
        self.edit("src/server/connection.rs", "        self.authorized = true;\n",
                  "        self.authorized = true;\n        self.authorized = true;\n")
        self.assert_check_fails(AUTHORIZED_ONCE)

    def test_a_trust_anchor_found_twice_is_a_moved_target(self):  # review L5
        before = tree_hashes(self.root)
        self.edit("src/client.rs", rebrand.T04_ALWAYS_ASK_FORGET_AT,
                  rebrand.T04_ALWAYS_ASK_FORGET_AT + "            }\n        }\n" + rebrand.T04_ALWAYS_ASK_FORGET_AT)
        edited = tree_hashes(self.root)
        r = run(REBRAND, self.root)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("patch anchor not unique, 2 copies (always ask: the Controller keeps no password", r.stderr)
        self.assertEqual(tree_hashes(self.root), edited, "nothing written")
        self.assertNotEqual(before, edited)

    def test_controller_keeping_the_password_of_a_target_that_always_asks_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", rebrand.T04_ALWAYS_ASK_FORGET, "")
        self.assert_check_fails(ALWAYS_ASK_FORGET)

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

    # --- ticket 05: permanent password only ---------------------------------------
    PERMANENT_ONLY = "one-time password off: only the permanent password is accepted"
    NO_PASSWORD = "no Unattended Password: no unattended access, only Allow on the Target, for that session only"
    THROTTLED = "wrong passwords are still throttled before and after every password check"
    IPC_GUARDED = "a remote session can't change the password, PIN or security options"
    GENERATOR = "generated password: OS RNG, 16+ characters, no look-alike characters, wired to Set Password"
    SYNC_GUARDED = "a remote session can't replace the whole config (Data::SyncConfig refused)"
    TYPED_16 = "a typed password needs 16+ characters; Generate (Reset once set) is the main action"
    SHOWN_ONCE = "the new password closes only on I've saved it, and Reset asks before replacing"
    CLIPBOARD = "a copied password leaves the clipboard after a minute"
    ONE_TIME_LABEL = "one-time password label hidden when it is off (desktop and mobile)"
    UI_KEYS = "new UI strings (tickets 05, 06, 07, 09) have a key in every translation file"

    def test_password_lock_facts_pass_after_rebrand(self):
        self.rebrand()
        r = run(CHECK, self.root)
        for fact in (self.PERMANENT_ONLY, self.NO_PASSWORD, self.THROTTLED, self.IPC_GUARDED, self.GENERATOR,
                     REMOTE_CONFIG, self.SYNC_GUARDED, self.TYPED_16, self.SHOWN_ONCE, self.CLIPBOARD,
                     self.ONE_TIME_LABEL, self.UI_KEYS):
            self.assertIn(f"PASS {fact}", r.stdout)

    def test_password_lock_facts_fail_on_clean_upstream_tree(self):
        r = run(CHECK, self.root)
        for fact in (self.PERMANENT_ONLY, self.NO_PASSWORD, self.IPC_GUARDED, self.GENERATOR, self.SYNC_GUARDED,
                     self.TYPED_16, self.SHOWN_ONCE, self.ONE_TIME_LABEL, self.UI_KEYS):
            self.assertIn(f"FAIL {fact}", r.stdout)

    def test_both_passwords_allowed_fails_check(self):
        self.rebrand()
        self.edit(HBB, '("verification-method", "use-permanent-password")',
                  '("verification-method", "use-both-passwords")')
        self.assert_check_fails(self.PERMANENT_ONLY)

    def test_remote_config_modification_allowed_fails_check(self):
        self.rebrand()
        self.edit(HBB, '("allow-remote-config-modification", "N")', '("allow-remote-config-modification", "Y")')
        self.assert_check_fails(REMOTE_CONFIG)

    def test_no_password_gate_removed_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", rebrand.NO_PASSWORD_ASK, "")
        self.assert_check_fails(self.NO_PASSWORD)

    def test_no_password_gate_after_click_to_accept_fails_check(self):
        self.rebrand()
        conn = "src/server/connection.rs"
        self.edit(conn, rebrand.NO_PASSWORD_ASK, "")
        self.edit(conn, "            } else if self.is_recent_session(false) {\n",
                  "            }\n" + rebrand.NO_PASSWORD_ASK + "            if self.is_recent_session(false) {\n")
        self.assert_check_fails(self.NO_PASSWORD)

    def test_refuse_login_ignoring_the_lock_fails_check(self):
        self.rebrand()
        self.edit("src/password_lock.rs", "    verification_method != PERMANENT_ONLY\n", "    false\n")
        self.assert_check_fails(self.NO_PASSWORD)

    def test_no_password_login_waiting_to_be_stored_fails_check(self):
        # No password here: Allow lets it in for that session only. Waiting as if the password were
        # right would let Allow store it (base::trust::take_wait).
        self.rebrand()
        self.edit("src/server/connection.rs", "                self.boring_trust.wait_for_allow(false);\n                #[cfg",
                  "                self.boring_trust.wait_for_allow(true);\n                #[cfg")
        self.assert_check_fails(self.NO_PASSWORD)

    def test_no_password_login_falling_through_fails_check(self):
        self.rebrand()
        conn = "src/server/connection.rs"
        gate = rebrand.NO_PASSWORD_ASK
        self.edit(conn, gate, gate.replace("                return true;\n            }\n", "            }\n"))
        self.assert_check_fails(self.NO_PASSWORD)

    def test_throttle_dropped_from_the_password_check_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs",
                  "                let (failure, res) = self.check_failure(0).await;\n"
                  "                if !res {\n                    return true;\n                }\n"
                  "                if !self.validate_password(",
                  "                let failure = ((0, 0, 0), 0);\n                if !self.validate_password(")
        self.assert_check_fails(self.THROTTLED)

    def test_failed_password_not_counted_fails_check(self):
        self.rebrand()
        wrong = ("                if !self.validate_password(allow_logon_screen_password) {\n"
                 "                    self.update_failure_with_scope(failure, false, 0, FailureScope::Default);\n")
        self.edit("src/server/connection.rs", wrong, wrong.splitlines(True)[0])
        self.assert_check_fails(self.THROTTLED)

    def test_lockout_message_removed_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", 'self.send_login_error("Too many wrong attempts").await;', "")
        self.assert_check_fails(self.THROTTLED)

    def test_ipc_password_guard_removed_fails_check(self):
        self.rebrand()
        self.edit("src/ipc.rs", f"if {rebrand.IPC_GUARD} {{", "if false {")
        self.assert_check_fails(self.IPC_GUARDED)

    def test_ipc_options_guard_removed_fails_check(self):
        self.rebrand()
        self.edit("src/ipc.rs", "&Config::get_options(),", "&value.clone(),")
        self.assert_check_fails(self.IPC_GUARDED)

    def test_short_generated_password_fails_check(self):
        self.rebrand()
        self.edit("src/password_lock.rs", "pub const LEN: usize = 20;", "pub const LEN: usize = 12;")
        self.assert_check_fails(self.GENERATOR)

    def test_ambiguous_alphabet_fails_check(self):
        self.rebrand()
        self.edit("src/password_lock.rs", 'b"ABCDEFGHJK', 'b"0OABCDEFGHJK')
        self.assert_check_fails(self.GENERATOR)

    def test_non_os_rng_fails_check(self):
        self.rebrand()
        self.edit("src/password_lock.rs", "generate_with(&mut OsRng)",
                  "generate_with(&mut hbb_common::rand::thread_rng())")
        self.assert_check_fails(self.GENERATOR)

    def test_generator_drawing_from_part_of_the_alphabet_fails_check(self):
        self.rebrand()
        self.edit("src/password_lock.rs", "rng.gen_range(0..ALPHABET.len())", "rng.gen_range(0..10)")
        self.assert_check_fails(self.GENERATOR)

    def test_refuse_login_on_a_constant_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs",
                  "refuse_login(&Config::get_option(keys::OPTION_VERIFICATION_METHOD))",
                  "refuse_login(crate::password_lock::PERMANENT_ONLY)")
        self.assert_check_fails(self.NO_PASSWORD)

    def test_widened_throttle_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "let res = if failure.2 > 30 {", "let res = if failure.2 > 3000 {")
        self.assert_check_fails(self.THROTTLED)

    def test_session_count_always_zero_fails_check(self):
        self.rebrand()
        self.edit("src/password_lock.rs", "    crate::server::AUTHED_CONNS.lock().unwrap().len()\n", "    0\n")
        self.assert_check_fails(self.IPC_GUARDED)

    def test_option_dropped_from_the_security_list_fails_check(self):
        self.rebrand()
        self.edit("src/password_lock.rs", "    keys::OPTION_APPROVE_MODE,\n", "")
        self.assert_check_fails(self.IPC_GUARDED)

    def test_ipc_guard_moved_off_its_arm_fails_check(self):
        # Still three guards in the file, but the salt write is no longer behind one.
        self.rebrand()
        self.edit("src/ipc.rs", f'name == "salt" {{\n                    if {rebrand.IPC_GUARD} {{',
                  f'name == "salt" {{\n                    // {rebrand.IPC_GUARD}\n                    if false {{')
        self.assert_check_fails(self.IPC_GUARDED)

    def test_config_sync_during_a_session_fails_check(self):
        self.rebrand()
        self.edit("src/ipc.rs", rebrand.SYNC_GUARD, "")
        self.assert_check_fails(self.SYNC_GUARDED)

    def test_short_typed_password_fails_check(self):
        self.rebrand()
        self.edit(rebrand.HOME, "MinCharactersValidationRule(16)", "MinCharactersValidationRule(8)")
        self.assert_check_fails(self.TYPED_16)

    def test_new_password_closing_on_escape_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/desktop/widgets/generated_password.dart",
                  "dialogButton(\"I've saved it\", onPressed: close),\n        ],\n",
                  "dialogButton(\"I've saved it\", onPressed: close),\n        ],\n        onCancel: close,\n")
        self.assert_check_fails(self.SHOWN_ONCE)

    def test_reset_without_asking_fails_check(self):
        self.rebrand()
        self.edit(rebrand.HOME, "              final go = await confirmReplacePassword();\n              if (go == null) return;\n",
                  "              final go = true;\n")
        self.assert_check_fails(self.SHOWN_ONCE)

    def test_password_left_on_the_clipboard_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/desktop/widgets/generated_password.dart",
                  "await Clipboard.setData(const ClipboardData(text: ''));", "")
        self.assert_check_fails(self.CLIPBOARD)

    def test_mobile_one_time_label_fails_check(self):
        self.rebrand()
        self.edit(rebrand.MOBILE_SERVER, "translate(showOneTime ? 'One-time Password' : 'Password'),",
                  "translate('One-time Password'),")
        self.assert_check_fails(self.ONE_TIME_LABEL)

    def test_ui_string_missing_from_a_language_fails_check(self):
        self.rebrand()
        self.edit("src/lang/de.rs", '        ("Generate", ""),\n', "")
        self.assert_check_fails(self.UI_KEYS)

    # --- ticket 06 on 1.7's one Trusted list (option B: the Controller proves its key) ----------
    APPROVE_LOCKED = "new Controllers need the password and Allow on the Target (approve mode locked, ask can't hide)"
    TRUST_GATE = "a right password waits for Allow on the Target unless a Trusted Controller shows its token or key"
    ACCEPT_GATED = ("Allow only counts for a login waiting on it, and stores a Controller only after its password, "
                    "with no other session open")
    SWAP = "a new login on a connection waiting on Allow ends it (the click can't land on another login)"
    NO_DEAD_ACCEPT = "no Allow prompt for a login without the right password (empty or wrong)"
    LOGON_SITES = "exactly six ways into a session, each gated or explained"
    REMOVE = "Remove ends that Controller's sessions; while anyone is connected Settings only tightens the list"
    PROOF = ("a Trusted login by key needs that key's signature over this login, for this Target; a known ID alone "
             "never skips Allow")
    SIGNED = "Controllers sign each login with their own key (this challenge, the Target's Machine ID, their ID)"
    KEY_STORED = ("the Controller's key rides 1.7's list: optional, never written empty, its own entries never "
                  "match a token")
    TRUST_RS = "libs/base/src/trust.rs"
    CONN = "src/server/connection.rs"

    def test_trust_facts_pass_after_rebrand(self):
        self.rebrand()
        r = run(CHECK, self.root)
        for fact in (self.APPROVE_LOCKED, self.TRUST_GATE, self.ACCEPT_GATED, self.SWAP, self.NO_DEAD_ACCEPT,
                     self.LOGON_SITES, self.REMOVE, self.PROOF, self.SIGNED, self.KEY_STORED, PROTOCOL):
            self.assertIn(f"PASS {fact}", r.stdout)

    def test_trust_facts_fail_on_clean_upstream_tree(self):
        r = run(CHECK, self.root)
        for fact in (self.APPROVE_LOCKED, self.TRUST_GATE, self.ACCEPT_GATED, self.SWAP, self.NO_DEAD_ACCEPT,
                     self.LOGON_SITES, self.REMOVE, self.PROOF, self.SIGNED, PROTOCOL):
            self.assertIn(f"FAIL {fact}", r.stdout)

    def test_password_only_approve_mode_fails_check(self):
        self.rebrand()
        self.edit(HBB, '("approve-mode", "")', '("approve-mode", "password")')
        self.assert_check_fails(self.APPROVE_LOCKED)

    def test_hideable_prompt_fails_check(self):
        self.rebrand()
        self.edit(HBB, '("allow-hide-cm", "N")', '("allow-hide-cm", "Y")')
        self.assert_check_fails(self.APPROVE_LOCKED)

    def test_trust_gate_removed_fails_check(self):
        self.rebrand()
        self.edit(self.CONN, rebrand.TRUST_GATE, "")
        self.assert_check_fails(self.TRUST_GATE)

    def test_trust_gate_that_lets_the_ask_through_fails_check(self):
        self.rebrand()
        self.edit(self.CONN, "                    if !self.boring_trust.skips_click() {\n",
                  "                    if false && !self.boring_trust.skips_click() {\n")
        self.assert_check_fails(self.TRUST_GATE)

    def test_any_key_skipping_allow_fails_check(self):
        self.rebrand()
        self.edit(self.TRUST_RS, "        self.trusted.is_some() || matches!(self.by_key, Some(ByKey::Trusted(..)))\n",
                  "        self.trusted.is_some() || self.by_key.is_some()\n")
        self.assert_check_fails(self.TRUST_GATE)

    def test_a_key_overriding_the_tokens_verdict_fails_check(self):
        self.rebrand()
        self.edit(self.TRUST_RS, "        if self.trusted.is_some() || self.always_ask.is_some() || self.removed.is_some() {\n"
                                 "            return;\n        }\n        let Some(c) = self.pk",
                  "        let Some(c) = self.pk")
        self.assert_check_fails(self.TRUST_GATE)

    def test_ask_not_counted_fails_check(self):
        self.rebrand()
        self.edit(self.CONN, "                        self.update_failure_with_scope(failure, false, 0, FailureScope::Default);\n"
                             "                        self.boring_trust.wait_for_allow(true);\n",
                  "                        self.boring_trust.wait_for_allow(true);\n")
        self.assert_check_fails(self.TRUST_GATE)

    def test_ungated_allow_fails_check(self):
        self.rebrand()
        self.edit(self.CONN, rebrand.ACCEPT_GATE, "")
        self.assert_check_fails(self.ACCEPT_GATED)

    def test_allow_remembered_during_another_session_fails_check(self):
        self.rebrand()
        self.edit(self.TRUST_RS, "self.may_remember = password_right && others == 0;", "self.may_remember = password_right;")
        self.assert_check_fails(self.ACCEPT_GATED)

    def test_password_alone_storing_a_new_controller_fails_check(self):
        self.rebrand()
        self.edit(self.TRUST_RS, "        if how != SignIn::Allowed {\n            self.pending = None;",
                  "        if how == SignIn::ThisSessionOnly {\n            self.pending = None;")
        self.assert_check_fails(self.ACCEPT_GATED)

    def test_allow_storing_without_the_password_fails_check(self):
        self.rebrand()
        self.edit(self.TRUST_RS, "        let how = self.effective(how);\n", "")
        self.assert_check_fails(self.ACCEPT_GATED)

    def test_new_login_on_a_waiting_connection_kept_fails_check(self):
        self.rebrand()
        self.edit(self.CONN, rebrand.FORGET_ON_LOGIN, "")
        self.assert_check_fails(self.SWAP)

    def test_allow_prompt_without_a_password_fails_check(self):
        self.rebrand()
        self.edit(self.CONN, rebrand.EMPTY_PASSWORD_NO_CM, rebrand.EMPTY_PASSWORD_CM)
        self.assert_check_fails(self.NO_DEAD_ACCEPT)

    def test_seventh_way_into_a_session_fails_check(self):
        self.rebrand()
        self.edit(self.CONN, "            if !self.check_login_scope(&lr).await {\n",
                  "            if !self.send_logon_response_and_keep_alive().await {\n                return false;\n"
                  "            }\n            if !self.check_login_scope(&lr).await {\n")
        self.assert_check_fails(self.LOGON_SITES)

    def test_removed_controller_keeping_its_session_fails_check(self):
        self.rebrand()
        self.edit(self.TRUST_RS, "(c.removed || !self.password_right && !self.stays && c.always_ask)",
                  "(!self.password_right && !self.stays && c.always_ask)")
        self.assert_check_fails(self.REMOVE)

    def test_settings_letting_more_in_during_a_session_fails_check(self):
        self.rebrand()
        self.edit(self.TRUST_RS, "        Edit::Allow { .. } if sessions > 0 => return Err(IN_SESSION),\n", "")
        self.assert_check_fails(self.REMOVE)

    def test_service_edit_blind_to_sessions_fails_check(self):
        self.rebrand()
        self.edit("src/ipc.rs", "base::trust::edit_in_session(&value, crate::password_lock::authed_sessions())",
                  "base::trust::edit_in_session(&value, 0)")
        self.assert_check_fails(self.REMOVE)

    def test_unverified_signature_fails_check(self):
        self.rebrand()
        self.edit(self.TRUST_RS, "    let signed = sign::verify(sig, &sign::PublicKey(key)).ok()?;\n    (signed == want).then_some(key)",
                  "    let _ = (sig, want);\n    Some(key)")
        self.assert_check_fails(self.PROOF)

    def test_key_proven_on_an_unkeyed_connection_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "    if !secured || !crate::client::boring_is_machine_id(own_id) {",
                  "    if !crate::client::boring_is_machine_id(own_id) {")
        self.assert_check_fails(self.PROOF)

    def test_key_never_checked_fails_check(self):
        self.rebrand()
        self.edit(self.CONN, rebrand.T04_PROVE, "")
        self.assert_check_fails(self.PROOF)

    def test_login_message_without_its_domain_fails_check(self):
        self.rebrand()
        self.edit(self.TRUST_RS, 'const LOGIN_DOMAIN: &[u8] = b"\\0boring-remote', 'const LOGIN_DOMAIN: &[u8] = b"boring-remote')
        self.assert_check_fails(self.PROOF)

    def test_controller_signing_any_challenge_fails_check(self):
        # A Target picks the challenge; unchecked, it could make the Controller's key sign a SignedId.
        self.rebrand()
        self.edit(self.TRUST_RS, " && challenge.bytes().all(|b| b.is_ascii_alphanumeric());", ";")
        self.assert_check_fails(self.PROOF)

    def test_controller_not_signing_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", rebrand.SIGN_LOGIN, "")
        self.assert_check_fails(self.SIGNED)

    def test_login_signed_before_the_challenge_is_known_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", rebrand.HASH_FIRST_NEW, rebrand.HASH_FIRST_OLD)
        self.assert_check_fails(self.SIGNED)

    def test_controller_ui_making_its_own_key_pair_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "    let pair = Config::get_existing_key_pair();",
                  "    let pair = Some(Config::get_key_pair());")
        self.assert_check_fails(self.SIGNED)

    def test_trust_policy_left_out_of_ios_controllers_fails_check(self):
        self.rebrand()
        self.edit("src/lib.rs", "mod trust_policy;", rebrand.NON_IOS + "mod trust_policy;")
        self.assert_check_fails(self.SIGNED)

    def test_key_written_empty_fails_check(self):
        self.rebrand()
        self.edit(self.TRUST_RS, '    #[serde(default, skip_serializing_if = "String::is_empty")]\n    pub pk: String,',
                  "    #[serde(default)]\n    pub pk: String,")
        self.assert_check_fails(self.KEY_STORED)

    def test_renumbered_login_fields_fail_the_pin(self):
        # review S3: the pin is check.py's own, so moving our fields in rebrand.py alone fails.
        self.rebrand()
        moved = rebrand.PROTO_FIELDS.replace("= 1001;", "= 18;")
        self.edit("libs/base/protos/message.proto", rebrand.PROTO_FIELDS, moved)
        saved = rebrand.PROTO_PATCH
        rel, old, new, why = saved
        rebrand.PROTO_PATCH = (rel, old, new.replace(rebrand.PROTO_FIELDS, moved), why)
        try:
            ok, msg = check.protocol_matches(self.root)
        finally:
            rebrand.PROTO_PATCH = saved
        self.assertFalse(ok)
        self.assertIn("pinned", msg)

    def test_login_fields_dropped_from_the_protocol_fails_check(self):
        self.rebrand()
        self.edit("libs/base/protos/message.proto", rebrand.PROTO_FIELDS, "")
        self.assert_check_fails(PROTOCOL)

    def test_other_edit_next_to_the_login_fields_fails_check(self):
        self.rebrand()
        self.edit("libs/base/protos/message.proto", rebrand.PROTO_FIELDS,
                  rebrand.PROTO_FIELDS + "  bytes sneaky = 1002;\n")
        self.assert_check_fails(PROTOCOL)

    # --- ticket 07: the Hosted path (ADR 0005) ----------------------------------------
    # Independent of rebrand.py and check.py: the servers' public key as Jason published it
    # (boring-remote-servers keys/id_ed25519.pub) and the domain from the spec.
    SERVERS_PUB = "2hUye2snQY5Roz1FXgypyJQwCjUuNcIX08ukFeo6TYk="
    HOST = "rs.theboringremote.com"
    ONLY_HOST = "the only rendezvous server is rs.theboringremote.com (ADR 0005)"
    FORCED = "rendezvous server and list are always ours (exe name, Settings, config file, serial path skipped)"
    LOCKED_SERVERS = "server settings locked to rs.theboringremote.com (relay follows; no API server)"
    BAKED = "baked server key is server-key.pub (built-in key and locked key option)"
    NO_WHITELIST = "no global whitelist left (ADR 0005: Hosted connections arrive from anywhere)"
    PUBLIC = "no shipped code names a RustDesk public server or its key"
    MACHINE_ID = "the Target shows its Machine ID and keeps it across restarts (made once, then read from its config)"
    HOSTED_SIGNED = ("Controllers sign a Machine-ID login only on a stream that verified the Target (pinned Direct Link or "
                     "the baked server key)")

    def locked(self):
        return check.rust_map((self.root / HBB).read_text(), "OVERWRITE_SETTINGS")

    def test_hosted_facts_pass_after_rebrand(self):
        self.rebrand()
        r = run(CHECK, self.root)
        for fact in (self.ONLY_HOST, self.FORCED, self.LOCKED_SERVERS, self.BAKED, self.NO_WHITELIST,
                     self.PUBLIC, self.MACHINE_ID, self.HOSTED_SIGNED, CONNECT_DIRECT, self.PROOF, self.SIGNED):
            self.assertIn(f"PASS {fact}", r.stdout)

    def test_hosted_facts_fail_on_clean_upstream_tree(self):
        r = run(CHECK, self.root)
        for fact in (self.ONLY_HOST, self.FORCED, self.LOCKED_SERVERS, self.BAKED, self.MACHINE_ID,
                     self.HOSTED_SIGNED):
            self.assertIn(f"FAIL {fact}", r.stdout)

    def test_rendezvous_host_is_exactly_ours(self):
        self.rebrand()
        cfg = (self.root / HBB).read_text()
        self.assertIn(f'pub const RENDEZVOUS_SERVERS: &[&str] = &["{self.HOST}"];', cfg)
        self.assertNotIn("rs-ny.rustdesk.com", cfg)

    def test_baked_key_equals_the_checked_in_public_key(self):
        self.rebrand()
        self.assertEqual((HERE / "server-key.pub").read_text().strip(), self.SERVERS_PUB)
        cfg = (self.root / HBB).read_text()
        self.assertIn(f'pub const RS_PUB_KEY: &str = "{self.SERVERS_PUB}";', cfg)
        self.assertEqual(self.locked().get("key"), self.SERVERS_PUB)
        self.assertNotIn("OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw=", cfg)

    def test_whitelist_is_gone(self):
        self.rebrand()
        self.assertNotIn("whitelist", self.locked())
        self.assertNotIn("100.64.0.0/10", (self.root / HBB).read_text())

    def test_overrides_force_our_values(self):
        self.rebrand()
        locked = self.locked()
        for key in ("custom-rendezvous-server", "relay-server", "rendezvous-servers"):
            self.assertEqual(locked.get(key), self.HOST, key)
        self.assertEqual(locked.get("api-server"), "")
        cfg = (self.root / HBB).read_text()
        self.assertEqual(check.first_statement(cfg, "pub fn get_rendezvous_server() -> String {"),
                         'if true { return format!("{}:{RENDEZVOUS_PORT}", RENDEZVOUS_SERVERS[0]); }'
                         " // boring-remote: the Hosted servers only")
        self.assertTrue(check.first_statement(cfg, "pub fn get_rendezvous_servers() -> Vec<String> {")
                        .startswith("if true { return RENDEZVOUS_SERVERS.iter()"))
        common = (self.root / "src/common.rs").read_text()
        for sig in ("pub fn read_custom_client(config: &str) {", "fn get_api_server_(api: String, custom: String) -> String {"):
            self.assertTrue(check.first_statement(common, sig).startswith("if true { return"), sig)
        self.assertTrue(check.first_statement((self.root / "src/platform/windows.rs").read_text(),
                        "pub fn get_license_from_exe_name() -> ResultType<CustomServer> {").startswith("if true { bail!"))

    def rebrand_with_key(self, text):
        """rebrand.py run from a copy of boring/ whose server-key.pub holds `text` (None: missing)."""
        copy = self.tmp / "boring"
        shutil.copytree(HERE, copy, ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copy(HERE.parent / "LICENCE", self.tmp / "LICENCE")  # COPIES takes ../LICENCE (ticket 32)
        key = copy / "server-key.pub"
        key.unlink()
        if text is not None:
            key.write_text(text)
        return run(copy / "rebrand.py", self.root)

    def test_missing_or_malformed_server_key_stops_the_rebrand_and_writes_nothing(self):
        before = tree_hashes(self.root)
        for text in (None, "", "not a key", "AAAA", self.SERVERS_PUB[:-4] + "!!!=",
                     "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw="):
            r = self.rebrand_with_key(text)
            self.assertEqual(r.returncode, 2, f"{text!r}: {r.stdout}{r.stderr}")
            self.assertIn("server-key.pub: server key", r.stderr)
            self.assertEqual(before, tree_hashes(self.root), repr(text))
            shutil.rmtree(self.tmp / "boring")
        r = self.rebrand_with_key(self.SERVERS_PUB + "\n")  # a trailing newline is fine
        self.assertEqual(r.returncode, 0, r.stderr)

    def check_with_key_file(self, text):
        saved = check.SERVER_KEY
        check.SERVER_KEY = self.tmp / "server-key.pub"
        check.SERVER_KEY.write_text(text)
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                check.run_checks(self.root)
        finally:
            check.SERVER_KEY = saved
        return out.getvalue()

    def test_baked_key_differing_from_the_checked_in_file_fails_check(self):
        self.rebrand()
        other = base64.b64encode(bytes(range(32))).decode()
        self.assertIn(f"FAIL {self.BAKED}", self.check_with_key_file(other))
        self.assertIn(f"FAIL {self.BAKED}", self.check_with_key_file("garbage"))
        self.assertIn(f"PASS {self.BAKED}", self.check_with_key_file(self.SERVERS_PUB))

    def test_mismatched_built_in_key_fails_check(self):
        self.rebrand()
        other = base64.b64encode(bytes(range(32))).decode()
        self.edit(HBB, f'pub const RS_PUB_KEY: &str = "{self.SERVERS_PUB}";', f'pub const RS_PUB_KEY: &str = "{other}";')
        self.assert_check_fails(self.BAKED)

    def test_mismatched_locked_key_fails_check(self):
        self.rebrand()
        self.edit(HBB, f'("key", "{self.SERVERS_PUB}")', '("key", "")')
        self.assert_check_fails(self.BAKED)

    def test_tailscale_whitelist_fails_check(self):
        self.rebrand()
        self.edit(HBB, '("direct-server", "Y")', f'("whitelist", "{rebrand.TAILNET}"), ("direct-server", "Y")')
        self.assert_check_fails(self.NO_WHITELIST)

    def test_default_whitelist_fails_check(self):
        self.rebrand()
        self.edit(HBB, '("allow-only-conn-window-open", "N")',
                  '("allow-only-conn-window-open", "N"), ("whitelist", "100.64.0.0/10")')
        self.assert_check_fails(self.NO_WHITELIST)

    def test_public_rustdesk_host_fails_check(self):
        self.rebrand()
        for planted in ('const SNEAKY: &str = "rs-ny.rustdesk.com";\n',
                        'const SNEAKY: &str = "rs-sg.rustdesk.com:21116";\n',
                        'const SNEAKY: &str = "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw=";\n'):
            path = self.root / "src/trust_policy.rs"
            saved = path.read_text()
            path.write_text(saved + planted)
            self.assert_check_fails(self.PUBLIC)
            path.write_text(saved)

    def test_second_rendezvous_server_fails_check(self):
        self.rebrand()
        self.edit(HBB, f'&["{self.HOST}"]', f'&["{self.HOST}", "rs.example.com"]')
        self.assert_check_fails(self.ONLY_HOST)

    def test_config_file_server_override_back_fails_check(self):
        self.rebrand()
        self.edit(HBB, "        if true { return format!(", "        if false { return format!(")
        self.assert_check_fails(self.FORCED)

    def test_serial_path_server_list_back_fails_check(self):
        self.rebrand()
        self.edit(HBB, "        if true { return RENDEZVOUS_SERVERS.iter()", "        if false { return RENDEZVOUS_SERVERS.iter()")
        self.assert_check_fails(self.FORCED)

    def test_blank_relay_server_fails_check(self):
        self.rebrand()
        self.edit(HBB, f'("relay-server", "{self.HOST}")', '("relay-server", "")')
        self.assert_check_fails(self.LOCKED_SERVERS)

    def test_api_server_derived_again_fails_check(self):
        self.rebrand()
        self.edit("src/common.rs", '    if true { return "".to_owned(); } // boring-remote: no API server (spec slice 2)\n', "")
        self.assert_check_fails("API server lookup (none derived from the rendezvous server: no audit posts) "
                                "returns before doing anything")

    def test_id_at_server_taking_the_rendezvous_path_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", "peer.bytes().all(|b| b.is_ascii_digit())",
                  "peer.bytes().all(|b| b.is_ascii_digit() || b == b'@' || b == b'.')")
        self.assert_check_fails(CONNECT_DIRECT)

    def test_target_hiding_its_machine_id_fails_check(self):
        self.rebrand()
        self.edit(rebrand.HOME, "      if (!isOutgoingOnly) buildIDBoard(context),\n", "")
        self.assert_check_fails(self.MACHINE_ID)

    def test_machine_id_regenerated_each_start_fails_check(self):
        self.rebrand()
        self.edit(HBB, "        let mut id = CONFIG.read().unwrap().id.clone();\n        if id.is_empty() {\n",
                  "        let mut id = CONFIG.read().unwrap().id.clone();\n        if true {\n")
        self.assert_check_fails(self.MACHINE_ID)

    def test_machine_id_label_missing_from_a_language_fails_check(self):
        self.rebrand()
        self.edit("src/lang/de.rs", '        ("Machine ID", ""),\n', "")
        self.assert_check_fails(self.UI_KEYS)

    # Controller side: sign a Machine ID only over a stream verified against the baked key,
    # decided from that stream at send time (review M1), and refuse unverified ones (S1).
    def test_signing_a_machine_id_on_an_unkeyed_stream_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "    if !secured {\n        return None;\n    }\n", "")
        self.assert_check_fails(self.HOSTED_SIGNED)

    def test_signing_under_another_servers_key_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "    key.is_empty() || key == hbb_common::config::RS_PUB_KEY\n",
                  "    !key.is_empty()\n")
        self.assert_check_fails(self.HOSTED_SIGNED)

    def test_machine_id_running_with_another_key_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", rebrand.KEY_GUARD, "")
        self.assert_check_fails(self.HOSTED_SIGNED)

    def test_verified_flag_kept_per_session_fails_check(self):
        # review M1: a session's connections share its LoginConfigHandler.
        self.rebrand()
        self.edit("src/client.rs", "    pub other_server: Option<(String, String, String)>,\n",
                  "    pub other_server: Option<(String, String, String)>,\n    pub boring_verified_target: Option<String>,\n")
        self.assert_check_fails(self.HOSTED_SIGNED)

    def test_login_signed_without_asking_its_stream_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", "sign_login(lr, &challenge, peer.is_secured(), link);",
                  "sign_login(lr, &challenge, true, link);")
        self.assert_check_fails(self.SIGNED)

    def test_login_signed_where_it_is_built_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", "        match self.conn_type {\n            ConnType::FILE_TRANSFER",
                  "        crate::trust_policy::sign_login(&mut lr, &self.hash.challenge, true);\n"
                  "        match self.conn_type {\n            ConnType::FILE_TRANSFER")
        self.assert_check_fails(self.SIGNED)

    def test_unverified_machine_id_session_continued_fails_check(self):
        # review S1: no Continue past the insecure prompt for a Machine ID.
        self.rebrand()
        self.edit("src/client/io_loop.rs", rebrand.REFUSE_UNVERIFIED, "")
        self.assert_check_fails(self.HOSTED_SIGNED)

    def test_unverified_machine_id_port_forward_continued_fails_check(self):
        self.rebrand()
        self.edit("src/port_forward.rs", rebrand.REFUSE_UNVERIFIED_PF, "")
        self.assert_check_fails(self.HOSTED_SIGNED)

    def test_stream_keyed_outside_the_verified_branch_fails_check(self):
        # is_secured() would no longer mean the Target's signed identity checked out.
        self.rebrand()
        self.edit("src/client.rs", "                // non-secure path with is_secured() false",
                  "                conn.set_key(secretbox::gen_key());\n                // non-secure path with is_secured() false")
        self.assert_check_fails(self.HOSTED_SIGNED)

    def test_target_key_taken_without_the_servers_signature_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", "                    if id == peer_id {\n                        sign_pk = Some(sign::PublicKey(pk));",
                  "                    if true {\n                        sign_pk = Some(sign::PublicKey(pk));")
        self.assert_check_fails(self.HOSTED_SIGNED)

    # Review S2-S6: what the Hosted path newly exposes.
    RELAY = "the Controller's relay is always the locked relay-server, never a host the peer names"
    NO_STUN = "no WebRTC, IPv6 or UDP punch, and no third-party STUN or TURN host ships"
    DIRECT_TAILNET = "the Direct Link (21118) answers Tailscale and private-LAN addresses only, with no global whitelist"
    NO_CHANGE_ID = "Change ID is off: hidden on desktop and mobile, refused if called (the Machine ID never changes)"

    def test_exposure_facts_pass_after_rebrand_and_fail_upstream(self):
        upstream = run(CHECK, self.root).stdout
        self.rebrand()
        rebranded = run(CHECK, self.root).stdout
        for fact in (self.RELAY, self.NO_STUN, self.DIRECT_TAILNET, self.NO_CHANGE_ID):
            self.assertIn(f"FAIL {fact}", upstream)
            self.assertIn(f"PASS {fact}", rebranded)

    def test_relay_named_by_the_peer_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", rebrand.RELAY_OURS, "")
        self.assert_check_fails(self.RELAY)

    def test_relay_helper_returning_the_advertised_host_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", "    Ok(ours)\n}\n", "    Ok(advertised.to_owned())\n}\n")
        self.assert_check_fails(self.RELAY)

    def test_webrtc_or_punch_unlocked_fails_check(self):
        for key in ("enable-webrtc", "enable-ipv6-punch", "enable-udp-punch"):
            with self.subTest(key=key):
                self.rebrand()
                self.edit(HBB, f'("{key}", "N")', f'("{key}", "Y")')
                self.assert_check_fails(self.NO_STUN)
                self.edit(HBB, f'("{key}", "Y")', f'("{key}", "N")')

    def test_target_answering_webrtc_fails_check(self):
        self.rebrand()
        self.edit("src/rendezvous_mediator.rs", "        let webrtc_viable = false\n            && ",
                  "        let webrtc_viable = ")
        self.assert_check_fails(self.NO_STUN)

    def test_target_ipv6_punch_fails_check(self):
        self.rebrand()
        self.edit("src/rendezvous_mediator.rs",
                  "    if true { return Default::default(); } // boring-remote: no IPv6 punch (ticket 07)\n", "")
        self.assert_check_fails(self.NO_STUN)

    def test_third_party_stun_host_fails_check(self):
        self.rebrand()
        self.edit("libs/hbb_common/src/webrtc.rs", f'["stun:{self.HOST}:3478"]', '["stun:stun.l.google.com:19302"]')
        self.assert_check_fails(self.NO_STUN)

    def test_direct_ip_from_any_address_fails_check(self):
        self.rebrand()
        self.edit("src/rendezvous_mediator.rs", rebrand.DIRECT_LAN_ONLY, "")
        self.assert_check_fails(self.DIRECT_TAILNET)

    def test_change_id_back_fails_check(self):
        self.rebrand()
        self.edit(HBB, '("disable-change-id", "Y")', '("disable-change-id", "N")')
        self.assert_check_fails(self.NO_CHANGE_ID)

    def test_change_id_callable_fails_check(self):
        self.rebrand()
        self.edit("src/ui_interface.rs",
                  "    if true { return INVALID_FORMAT; } // boring-remote: the Machine ID never changes (ticket 07)\n", "")
        self.assert_check_fails(self.NO_CHANGE_ID)

    def test_whitelist_in_builtin_or_hard_settings_fails_check(self):
        self.rebrand()
        self.edit(HBB, "pub static ref HARD_SETTINGS: RwLock<HashMap<String, String>> = Default::default();",
                  'pub static ref HARD_SETTINGS: RwLock<HashMap<String, String>> = '
                  'RwLock::new([("whitelist", "100.64.0.0/10")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect());')
        self.assert_check_fails(self.NO_WHITELIST)

    def test_swapped_key_baked_by_the_rebrand_fails_check(self):
        # review S5: swap server-key.pub, rebrand with it, check: the pin catches it.
        other = base64.b64encode(bytes(range(1, 33))).decode()
        r = self.rebrand_with_key(other)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f'pub const RS_PUB_KEY: &str = "{other}";', (self.root / HBB).read_text())
        self.assertIn(f"FAIL {self.BAKED}", self.check_with_key_file(other))

    def test_key_differing_from_the_servers_repo_fails_check(self):
        self.rebrand()
        saved = check.SERVERS_REPO_KEY
        check.SERVERS_REPO_KEY = self.tmp / "servers-id_ed25519.pub"
        check.SERVERS_REPO_KEY.write_text(base64.b64encode(bytes(range(32))).decode())
        try:
            out = self.check_with_key_file(self.SERVERS_PUB)
        finally:
            check.SERVERS_REPO_KEY = saved
        self.assertIn(f"FAIL {self.BAKED}", out)

    def test_machine_id_label_listed_in_english_fails_check(self):
        # review N5: English shows the key as it is, so en.rs doesn't list it.
        self.rebrand()
        self.assertNotIn('("Machine ID", ', (self.root / "src/lang/en.rs").read_text())
        path = self.root / "src/lang/en.rs"
        text = path.read_text()
        path.write_text(rebrand.LANG_END.sub(lambda m: '),\n        ("Machine ID", ""),\n' + m.group(1), text, count=1))
        self.assert_check_fails(self.UI_KEYS)

    # Target side: its Machine ID is a signed name only on a keyed connection.
    def test_machine_id_name_on_an_unkeyed_connection_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "    if !secured || !crate::client::boring_is_machine_id(own_id) {",
                  "    if !crate::client::boring_is_machine_id(own_id) {")
        self.assert_check_fails(self.PROOF)

    def test_gate_claiming_every_connection_is_keyed_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "                    self.stream.is_secured(),\n                ),\n                &base::trust::Trusted::load(),",
                  "                    true,\n                ),\n                &base::trust::Trusted::load(),")
        self.assert_check_fails(self.PROOF)

    def test_gate_naming_the_claimed_machine_id_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "                    &self.hash.challenge,\n                    &Config::get_id(),\n",
                  "                    &self.hash.challenge,\n                    &lr.username,\n")
        self.assert_check_fails(self.PROOF)


    # --- review-v18: the port review's findings ---------------------------------------------------
    def test_review_v18_facts_pass_after_rebrand_and_fail_on_upstream(self):
        facts = (check.REVIEW_M1, check.REVIEW_S1, check.REVIEW_S2, check.REVIEW_S3, check.REVIEW_S4,
                 check.REVIEW_S6, check.REVIEW_S7)
        r = run(CHECK, self.root)
        # S1, S3 and S7 live in our own files (base::trust, direct_link, connect_plan), there on a raw
        # checkout too; the rest need rebrand's hooks.
        for fact in (check.REVIEW_M1, check.REVIEW_S2, check.REVIEW_S4, check.REVIEW_S6):
            self.assertIn(f"FAIL {fact}", r.stdout)
        self.rebrand()
        r = run(CHECK, self.root)
        for fact in facts:
            self.assertIn(f"PASS {fact}", r.stdout)

    def test_token_back_ahead_of_the_password_fails_check(self):  # M1
        self.rebrand()
        self.edit("src/server/connection.rs", rebrand.LOCK_GATE,
                  "            if self.boring_trust.is_trusted() {\n                if !self.send_logon_response_and_keep_alive().await {\n"
                  "                    return false;\n                }\n                return true;\n            }\n" + rebrand.LOCK_GATE)
        self.assert_check_fails(check.REVIEW_M1)

    def test_lock_checked_after_the_trusted_checks_fails_check(self):  # M1
        self.rebrand()
        conn = "src/server/connection.rs"
        self.edit(conn, rebrand.LOCK_GATE, "")
        self.edit(conn, rebrand.T04_MUST_ASK, rebrand.T04_MUST_ASK + rebrand.LOCK_GATE)
        self.assert_check_fails(check.REVIEW_M1)

    def test_token_not_skipping_the_click_fails_check(self):  # M1: then a token would need Allow every time
        self.rebrand()
        self.edit("libs/base/src/trust.rs", "        self.trusted.is_some() || matches!(self.by_key, Some(ByKey::Trusted(..)))\n",
                  "        matches!(self.by_key, Some(ByKey::Trusted(..)))\n")
        self.assert_check_fails(check.REVIEW_M1)

    def test_token_alone_binding_a_key_fails_check(self):  # S1
        self.rebrand()
        self.edit("libs/base/src/trust.rs", "self.trusted.is_some() && self.password_right,", "self.trusted.is_some(),")
        self.assert_check_fails(check.REVIEW_S1)

    def test_failed_key_store_kept_quiet_fails_check(self):  # S1, standards
        self.rebrand()
        self.edit("libs/base/src/trust.rs", "                Err(e) => hbb_common::log::warn!(\"Trusted Controller {:?}: its key not stored: {}\", name, e),\n",
                  "                Err(_) => {}\n")
        self.assert_check_fails(check.REVIEW_S1)

    def test_typed_name_login_unsigned_again_fails_check(self):  # S2
        self.rebrand()
        self.edit("src/client.rs", "crate::trust_policy::sign_login(lr, &challenge, peer.is_secured(), link);",
                  "crate::trust_policy::sign_login(lr, &challenge, peer.is_secured(), None);")
        self.assert_check_fails(check.REVIEW_S2)

    def test_key_only_row_left_beside_its_token_row_fails_check(self):  # S2
        self.rebrand()
        self.edit("libs/base/src/trust.rs", "        self.list.retain(|c| !folds(c));\n", "")
        self.assert_check_fails(check.REVIEW_S2)

    def test_remove_leaving_a_row_with_the_same_key_fails_check(self):  # S2
        self.rebrand()
        self.edit("libs/base/src/trust.rs", "t.key == key || !pk.is_empty() && t.pk == pk", "t.key == key")
        self.assert_check_fails(check.REVIEW_S2)

    def test_unpinned_machine_id_dialled_from_an_advert_fails_check(self):  # S3
        self.rebrand()
        self.edit("libs/base/src/direct_link.rs", "    if !known.pinned(id) {\n        return None;\n    }\n", "")
        self.assert_check_fails(check.REVIEW_S3)

    def test_name_fallback_for_a_1_7_target_dropped_fails_check(self):  # compat
        self.rebrand()
        self.edit("libs/base/src/direct_link.rs", "        plan.tailscale = tailscale_answer(name, ms).await", "        plan.tailscale = None::<SocketAddr>")
        self.assert_check_fails(check.REVIEW_S3)

    def test_uuid_mismatch_changing_the_machine_id_fails_check(self):  # S4
        self.rebrand()
        self.edit("src/rendezvous_mediator.rs", rebrand.KEEP_ID, "")
        self.assert_check_fails(check.REVIEW_S4)

    def test_machine_id_conflict_hidden_from_home_fails_check(self):  # S4
        self.rebrand()
        self.edit(rebrand.HOME, "if (bind.mainGetOptionSync(key: kBoringIdConflict) == 'Y') const MachineIdConflictNotice(),", "")
        self.assert_check_fails(check.REVIEW_S4)

    def test_direct_link_logging_before_its_lan_check_fails_check(self):  # S5
        self.rebrand()
        med = "src/rendezvous_mediator.rs"
        self.edit(med, rebrand.DIRECT_LAN_ONLY + '                log::info!("direct access from {}", addr);\n',
                  '                log::info!("direct access from {}", addr);\n' + rebrand.DIRECT_LAN_ONLY)
        self.assert_check_fails("the Direct Link (21118) answers Tailscale and private-LAN addresses only, with no global whitelist")

    def test_removed_token_ask_not_counted_fails_check(self):  # S6
        self.rebrand()
        self.edit("src/server/connection.rs", rebrand.T04_MUST_ASK,
                  rebrand.T04_MUST_ASK.replace(
                      "                self.update_failure_with_scope(failure, false, 0, FailureScope::Default);\n", "", 1))
        self.assert_check_fails(check.REVIEW_S6)

    def test_unlocked_known_write_fails_check(self):  # S7
        self.rebrand()
        self.edit("src/connect_plan.rs", "base::direct_link::Known::edit(|known| known.pin_id(id, pk))",
                  "{ let mut known = base::direct_link::Known::load(); let ok = known.pin_id(id, pk); known.save(); ok }")
        self.assert_check_fails(check.REVIEW_S7)

    # --- ticket 08 on 1.7's Direct Link: a Machine ID's Direct Link first, Hosted after -----------
    FIRST = "a pinned Machine ID tries a Direct Link where it was met (~3 s on Tailscale), then the Hosted servers (ticket 08)"
    PINNED = ("the Hosted path holds the same pin as a Direct Link, and a tailnet address is kept only from a pinned "
              "Target (tickets 08, 16)")
    DOWN = "Hosted servers unreachable: a plain error naming rs.theboringremote.com (ticket 08)"
    PLAN = "src/connect_plan.rs"
    LINK = "libs/base/src/direct_link.rs"

    def test_direct_first_facts_pass_after_rebrand_and_fail_on_upstream(self):
        r = run(CHECK, self.root)
        for fact in (self.FIRST, self.PINNED, self.DOWN):
            self.assertIn(f"FAIL {fact}", r.stdout)
        self.rebrand()
        r = run(CHECK, self.root)
        for fact in (self.FIRST, self.PINNED, self.DOWN):
            self.assertIn(f"PASS {fact}", r.stdout)

    def test_no_direct_link_before_the_hosted_servers_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", "crate::connect_plan::direct_first(peer, interface.is_force_relay()).await",
                  "None::<(hbb_common::Stream, base::direct_link::Route, Option<Vec<u8>>)>")
        self.assert_check_fails(self.FIRST)

    def test_another_computer_at_a_machine_ids_address_let_through_fails_check(self):
        self.rebrand()
        self.edit(self.LINK, "    plan.dialled = None;\n    Some(plan)", "    plan.dialled = Some(plan.direct);\n    Some(plan)")
        self.assert_check_fails(self.FIRST)

    def test_a_refused_direct_link_not_handed_to_hosted_fails_check(self):
        self.rebrand()
        self.edit(self.LINK, "        Err(Failure::Refused(e)) => Err(Failure::Stale(e)),", "        Err(Failure::Refused(e)) => Err(Failure::Refused(e)),")
        self.assert_check_fails(self.FIRST)

    def test_slow_tailscale_attempt_fails_check(self):
        self.rebrand()
        self.edit(self.PLAN, "pub const DIRECT_FIRST_MS: u64 = 3_000;", "pub const DIRECT_FIRST_MS: u64 = 18_000;")
        self.assert_check_fails(self.FIRST)

    def test_typed_name_falling_back_to_the_hosted_servers_fails_check(self):
        self.rebrand()
        self.edit(self.PLAN, "        return vec![Attempt::DirectLink];", "        return vec![Attempt::DirectLink, Attempt::Hosted];")
        self.assert_check_fails(self.FIRST)

    def test_hosted_path_accepting_a_changed_key_fails_check(self):
        self.rebrand()
        self.edit(self.LINK, "            Some(t) => t.pk == pk,\n", "            Some(_) => true,\n")
        self.assert_check_fails(self.PINNED)

    def test_unverified_session_recording_a_tailnet_address_fails_check(self):
        self.rebrand()
        self.edit(self.PLAN, "    if !(secured && crate::client::boring_is_machine_id(id)) {\n        return;\n    }\n    let reported",
                  "    let reported")
        self.assert_check_fails(self.PINNED)

    def test_lan_address_kept_as_tailscale_fails_check(self):
        self.rebrand()
        self.edit(self.LINK, "        if !is_tailscale(ip) {\n            return false;\n        }\n        let Some(t) = self.0.get_mut(id)",
                  "        let Some(t) = self.0.get_mut(id)")
        self.assert_check_fails(self.PINNED)

    def test_target_not_reporting_its_tailnet_address_fails_check(self):
        self.rebrand()
        self.edit(self.CONN_RS, rebrand.REPORT_TAILNET, "")
        self.assert_check_fails(self.PINNED)

    def test_rendezvous_error_passed_through_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", rebrand.HOSTED_DOWN_ERR, "")
        self.assert_check_fails(self.DOWN)

    def test_relay_failure_passed_through_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", rebrand.HOSTED_RELAY_ERR, "")
        self.assert_check_fails(self.DOWN)

    def test_hosted_down_key_missing_from_a_language_fails_check(self):
        self.rebrand()
        self.edit("src/lang/fr.rs", f'        ("{rebrand.HOSTED_DOWN}", ""),\n', "")
        self.assert_check_fails(self.DOWN)

    CONN_RS = "src/server/connection.rs"

    # --- ticket 09: 1.8.0 first launch sets a Permanent password ---------------------
    HOSTED_GATE = ("no app-generated Permanent password, no Hosted servers: the Target registers its Machine ID "
                   "only once the generator's marker is set; Direct IP keeps listening (ticket 09)")
    MARKER = ("only an app-generated password sets the Hosted marker: the daemon writes it with the password, "
              "any other password write clears it, and no Options write or remote session sets it (ticket 09)")
    TICK = "a live Hosted registration ends within a tick once the generated password is gone, whatever removed it (ticket 09)"
    LOCK = "src/password_lock.rs"

    def test_hosted_gate_facts_pass_after_rebrand(self):
        self.rebrand()
        r = run(CHECK, self.root)
        for fact in (self.HOSTED_GATE, self.MARKER, self.TICK):
            self.assertIn(f"PASS {fact}", r.stdout)

    def test_hosted_gate_facts_fail_on_clean_upstream_tree(self):
        r = run(CHECK, self.root)
        for fact in (self.HOSTED_GATE, self.MARKER, self.TICK):
            self.assertIn(f"FAIL {fact}", r.stdout)

    def test_registering_without_a_password_fails_check(self):
        self.rebrand()
        self.edit("src/rendezvous_mediator.rs", rebrand.HOSTED_GATE, "                let servers = Config::get_rendezvous_servers();\n")
        self.assert_check_fails(self.HOSTED_GATE)

    def test_gate_on_any_password_fails_check(self):
        # A 1.7.x typed password must not turn Hosted on (review M1).
        self.rebrand()
        self.edit("src/rendezvous_mediator.rs", "crate::password_lock::hosted_on(),", "Config::has_permanent_password(),")
        self.assert_check_fails(self.HOSTED_GATE)

    def test_gate_ignoring_the_marker_fails_check(self):
        self.rebrand()
        self.edit(self.LOCK, '    marker == "Y" && has_password\n', "    has_password\n")
        self.assert_check_fails(self.HOSTED_GATE)

    def test_gate_helper_ignoring_the_password_fails_check(self):
        self.rebrand()
        self.edit(self.LOCK, "    if password_set {\n", "    if true {\n")
        self.assert_check_fails(self.HOSTED_GATE)

    def test_direct_ip_behind_the_password_gate_fails_check(self):
        # The tailnet path keeps working while setup is pending: Direct IP is never gated.
        self.rebrand()
        med = "src/rendezvous_mediator.rs"
        spawn = "        tokio::spawn(async move {\n            direct_server(server_cloned).await;\n        });\n"
        self.edit(med, spawn, "        if Config::has_permanent_password() {\n" + spawn + "        }\n")
        self.assert_check_fails(self.HOSTED_GATE)

    def test_registration_kept_after_the_password_goes_fails_check(self):
        self.rebrand()
        self.edit("src/rendezvous_mediator.rs", rebrand.TICK_EXIT, "")
        self.assert_check_fails(self.TICK)

    def test_typed_password_keeping_the_marker_fails_check(self):
        self.rebrand()
        self.edit("src/ipc.rs", rebrand.CLEAR_MARKER, "")
        self.assert_check_fails(self.MARKER)

    def test_marker_writable_during_a_session_fails_check(self):
        self.rebrand()
        self.edit(self.LOCK, '&["permanent-password", GENERATED_CONFIG, ', '&["permanent-password", ')
        self.assert_check_fails(self.MARKER)

    def test_marker_settable_through_options_fails_check(self):
        self.rebrand()
        self.edit(self.LOCK, "    pin_option(&mut incoming, current, GENERATED_OPTION);\n", "")
        self.assert_check_fails(self.MARKER)

    def test_generator_using_the_typed_password_path_fails_check(self):
        self.rebrand()
        self.edit(self.LOCK, "send_generated(pw.clone())", "crate::ui_interface::set_permanent_password_with_result(pw.clone())")
        self.assert_check_fails(self.MARKER)

    def test_daemon_marking_any_password_fails_check(self):
        self.rebrand()
        self.edit(self.LOCK, "    if !generated_write_allowed(\n", "    if false && !generated_write_allowed(\n")
        self.assert_check_fails(self.MARKER)

    SETUP_SCREEN = ("1.8.0 first launch: a computer with no password made here gets Setup's password step alone, "
                    "which runs the generator (asking first if a password is set) and shows it once (ticket 09)")
    PANEL = "flutter/lib/desktop/kit/password.dart"

    def test_setup_screen_fact_passes_after_rebrand(self):
        self.rebrand()
        self.assertIn(f"PASS {self.SETUP_SCREEN}", run(CHECK, self.root).stdout)

    def test_setup_screen_fact_fails_on_clean_upstream_tree(self):
        self.assertIn(f"FAIL {self.SETUP_SCREEN}", run(CHECK, self.root).stdout)

    def test_setup_screen_not_wired_into_the_home_page_fails_check(self):
        self.rebrand()
        self.edit(rebrand.HOME, rebrand.PASSWORD_SETUP_BRANCH, "")
        self.assert_check_fails(self.SETUP_SCREEN)

    def test_setup_without_the_generator_fails_check(self):
        self.rebrand()
        self.edit(rebrand.HOME, "        generatePassword: () => bind.mainGeneratePermanentPassword(),\n",
                  "        generatePassword: () async => '',\n")
        self.assert_check_fails(self.SETUP_SCREEN)

    def test_replacing_a_password_without_asking_fails_check(self):
        self.rebrand()
        self.edit(self.PANEL, "                        setState(() => _step = _Step.confirm);\n", "                        _make();\n")
        self.edit(self.PANEL, "      case _Step.confirm:\n", "      case _Step.saved when false:\n")
        self.assert_check_fails(self.SETUP_SCREEN)

    def test_a_refusal_shown_as_a_password_fails_check(self):
        self.rebrand()
        self.edit(self.PANEL, "    if (pass.isEmpty) {\n", "    if (pass == '\u0000') {\n")
        self.assert_check_fails(self.SETUP_SCREEN)

    KEPT = ("the 1.8.0 Update keeps 1.7.x's config: same config dir and License key option, the update script "
            "never touches it, and nothing we add clears saved machines or settings (ticket 09)")

    def test_config_kept_fact_passes_after_rebrand(self):
        self.rebrand()
        self.assertIn(f"PASS {self.KEPT}", run(CHECK, self.root).stdout)

    def test_config_kept_fact_fails_on_clean_upstream_tree(self):
        self.assertIn(f"FAIL {self.KEPT}", run(CHECK, self.root).stdout)

    def test_moved_config_dir_fails_check(self):
        # A new org or app name is a new, empty config dir: every saved machine gone.
        self.rebrand()
        self.edit(HBB, '"io.boringlabs".to_owned()', '"io.boringlabs.remote".to_owned()')
        self.assert_check_fails(self.KEPT)

    def test_renamed_license_key_option_fails_check(self):
        self.rebrand()
        self.edit("src/license_key.rs", '"boring-license-key"', '"boring-license"')
        self.assert_check_fails(self.KEPT)

    def test_migration_clearing_saved_machines_fails_check(self):
        self.rebrand()
        self.edit("src/password_lock.rs", "pub fn generate() -> String {\n",
                  "pub fn migrate() {\n    for (id, _, _) in PeerConfig::peers(None) {\n"
                  "        PeerConfig::remove(&id);\n    }\n}\n\npub fn generate() -> String {\n")
        self.assert_check_fails(self.KEPT)

    def test_update_script_touching_the_config_fails_check(self):
        self.rebrand()
        self.edit("src/platform/privileges_scripts/install-update.sh", 'rm -rf "$PREV"\n',
                  'rm -rf "$PREV"\nrm -rf "$ROOT/Library/Preferences/io.boringlabs.BoringRemote"\n')
        self.assert_check_fails(self.KEPT)

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
        self.assertIn(b"PRODUCT_NAME = Boring Remote\r\nEXECUTABLE_NAME = BoringRemote\r\n", (self.root / crlf[0]).read_bytes())
        for rel in ("src/common.rs", "flutter/windows/runner/Runner.rc"):  # LF stays LF
            self.assertNotIn(b"\r", (self.root / rel).read_bytes(), rel)
        self.assertIn("rebrand: 0 changed, 0 moved", self.rebrand().stdout)

    # --- v1.7 review: Home, Settings, copy -------------------------------------------
    HOME_OUTSIDE = "Home's outside-the-building sheet gives this computer's Machine ID, then its Tailscale address (ADR 0005)"

    def test_machine_id_from_a_ui_copy_in_the_outside_sheet_fails_check(self):
        self.rebrand()
        self.edit(rebrand.HOME, "machineId: () => bind.mainGetMyId(),",
                  "machineId: () async => gFFI.serverModel.serverId.text,")
        self.assert_check_fails(self.HOME_OUTSIDE)

    def test_tailscale_range_drifting_from_the_tailnet_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/desktop/kit/tailscale.dart", "(b[1] & 0xc0) == 64", "(b[1] & 0x80) == 0")
        self.assert_check_fails(self.HOME_OUTSIDE)

    def test_quality_pick_keeping_high_efficiency_fails_check(self):  # v1.7 t05 follow-up
        self.rebrand()
        self.edit(rebrand.T07_TOOLBAR,
                  "            linkType.setStreamType(streamTypeAfterQualityPick(linkType.stream_type.value));\n", "")
        self.assert_check_fails("a hand-picked quality ends High Efficiency: badge back to Local (v1.7 t05 follow-up)")

    def test_settings_without_the_download_link_fails_check(self):  # ticket 15, app side
        self.rebrand()
        self.edit(rebrand.SETTINGS, "          openUrl: (u) => launchUrlString(u), // Download Boring Remote (ticket 15)\n", "")
        self.assert_check_fails("Settings: Download Boring Remote and set up another computer (ticket 15)")

    def test_transfer_list_dropping_deletes_again_fails_check(self):  # v1.7 t08 follow-up
        self.rebrand()
        self.edit(rebrand.FILE_MGR, "            if (j.type != JobType.none)\n", "            if (j.type == JobType.transfer)\n")
        self.assert_check_fails("File Transfer lists delete jobs too (v1.7 t08 follow-up)")

    # --- v1.7 t27: file transfer at full speed ----------------------------------------
    def test_full_speed_hooks_land_and_the_tick_ceiling_is_gone(self):
        self.rebrand()
        conn = (self.root / rebrand.CONN).read_text()
        self.assertIn("base::file_speed::pump_read_jobs(&mut conn.read_jobs", conn)
        self.assertNotIn("match fs::handle_read_jobs(", conn)
        io_loop = (self.root / rebrand.IO_LOOP).read_text()
        self.assertIn("base::file_speed::pump_read_jobs(&mut self.read_jobs, &mut peer)", io_loop)
        # An old Target still gets upstream's pace.
        self.assertIn("fs::handle_read_jobs(&mut self.read_jobs, &mut peer)", io_loop)
        self.assertIn("boring_full_speed: false,", io_loop)
        self.assertIn("pub mod file_speed;", (self.root / rebrand.BASE_LIB).read_text())
        self.assertIn("&& self.boring_compress.should_try(file_num, name)", (self.root / rebrand.FS_RS).read_text())

    def test_full_speed_leaves_the_protocol_alone(self):
        self.rebrand()
        r = run(CHECK, self.root)
        self.assertIn(f"PASS {check.TRANSFER_HOOKS}", r.stdout)
        self.assertIn("PASS protocol files are upstream's", r.stdout)

    def test_a_second_rebrand_changes_nothing_after_t27(self):
        self.rebrand()
        files = (rebrand.CONN, rebrand.IO_LOOP, rebrand.UI_CM, rebrand.IPC, rebrand.FS_RS, rebrand.FILE_MGR)
        first = {rel: (self.root / rel).read_bytes() for rel in files}
        self.rebrand()
        for rel in files:
            self.assertEqual(first[rel], (self.root / rel).read_bytes(), rel)

    def test_one_block_per_tick_on_the_target_fails_check(self):
        self.rebrand()
        self.edit(rebrand.CONN, "match base::file_speed::pump_read_jobs(&mut conn.read_jobs, &mut conn.stream).await {",
                  "match fs::handle_read_jobs(&mut conn.read_jobs, &mut conn.stream).await {")
        self.assert_check_fails(check.TRANSFER_HOOKS)

    def test_target_reading_past_its_cm_fails_check(self):
        self.rebrand()
        self.edit(rebrand.CONN, "res = conn.stream.next(), if conn.boring_cm_window.has_room() => {", "res = conn.stream.next() => {")
        self.assert_check_fails(check.TRANSFER_HOOKS)

    def test_cm_that_never_acks_fails_check(self):
        self.rebrand()
        self.edit(rebrand.UI_CM, "allow_err!(self.tx.send(Data::FileWriteAck(n)));", "let _ = n;")
        self.assert_check_fails(check.TRANSFER_HOOKS)

    def test_transfer_list_without_speed_fails_check(self):
        self.rebrand()
        self.edit(rebrand.FILE_MGR, "                  speed: j.speed, // boring-remote (v1.7 t27)\n", "")
        self.assert_check_fails(check.TRANSFER_HOOKS)

    def test_panes_without_the_drive_list_fails_check(self):
        self.rebrand()
        self.edit(rebrand.FILE_MGR, "          TransferDrives(load: _boringLoadDrives, onOpen: controller.openDirectory), // boring-remote (v1.7 t27)\n", "")
        self.assert_check_fails(check.TRANSFER_HOOKS)

    # --- v1.7 t30: every file proved ---------------------------------------------------
    def test_verify_hooks_land_and_the_protocol_stays(self):
        self.rebrand()
        r = run(CHECK, self.root)
        self.assertIn(f"PASS {check.VERIFY_HOOKS}", r.stdout)
        self.assertIn(f"PASS {check.VERIFY_WORDS}", r.stdout)
        self.assertIn(f"PASS {check.VERIFY_EVERYTHING}", r.stdout)
        self.assertIn("PASS protocol files are upstream's", r.stdout)
        fs = (self.root / rebrand.FS_RS).read_text()
        self.assertIn("pub boring: crate::file_verify::JobVerify,", fs)
        self.assertIn("async fn boring_write(&mut self, block: FileTransferBlock)", fs)
        self.assertIn('blake3 = "=1.8.2"', (self.root / rebrand.BASE_TOML).read_text())

    def test_a_second_rebrand_changes_nothing_after_t30(self):
        self.rebrand()
        files = (rebrand.CARGO_LOCK, rebrand.BASE_TOML, rebrand.FS_RS, rebrand.CONN, rebrand.IO_LOOP, rebrand.UI_CM,
                 rebrand.IPC, rebrand.UI_SESSION, rebrand.FLUTTER_RS, rebrand.FFI_MODEL, rebrand.FILE_MODEL)
        first = {rel: (self.root / rel).read_bytes() for rel in files}
        self.rebrand()
        for rel in files:
            self.assertEqual(first[rel], (self.root / rel).read_bytes(), rel)

    def test_the_lock_names_both_constant_time_eqs(self):
        self.rebrand()
        lock = (self.root / rebrand.CARGO_LOCK).read_text()
        self.assertIn(' "constant_time_eq 0.2.6",\n', lock)
        self.assertIn(' "constant_time_eq 0.3.1",\n', lock)
        self.assertNotIn(' "constant_time_eq",\n', lock)

    def test_real_name_before_the_read_back_fails_check(self):
        self.rebrand()
        self.edit(rebrand.FS_RS, "if self.r#type == JobType::Printer || self.boring.receiving() {",
                  "if self.r#type == JobType::Printer {")
        self.assert_check_fails(check.VERIFY_HOOKS)

    def test_done_before_the_last_verdict_fails_check(self):
        self.rebrand()
        self.edit(rebrand.FS_RS, "if !job.boring_holds_done() && job.job_completed() {\n                    job_log",
                  "if job.job_completed() {\n                    job_log")
        self.assert_check_fails(check.VERIFY_HOOKS)

    def test_target_that_never_says_it_can_fails_check(self):
        self.rebrand()
        self.edit(rebrand.CONN, "platform_additions.insert(base::file_verify::MARKER.into(), json!(true));\n", "\n")
        self.assert_check_fails(check.VERIFY_HOOKS)

    def test_proof_out_of_scope_on_the_target_fails_check(self):
        self.rebrand()
        self.edit(rebrand.CONN, rebrand.T30_CONN_SCOPE, "")
        self.assert_check_fails(check.VERIFY_HOOKS)

    def test_pane_setting_dropping_hidden_files_fails_check(self):
        self.rebrand()
        self.edit(rebrand.IO_LOOP, "Data::SendFiles((id, r#type, path, to, file_num, _, is_remote)) => {",
                  "Data::SendFiles((id, r#type, path, to, file_num, include_hidden, is_remote)) => {")
        self.assert_check_fails(check.VERIFY_EVERYTHING)

    def test_a_softer_verified_fails_check(self):
        self.rebrand()
        rel = "libs/base/src/file_verify.rs"
        self.edit(rel, "self.failed.is_empty()\n            && self.skipped.is_empty()\n",
                  "self.failed.is_empty()\n")
        self.assert_check_fails(check.VERIFY_WORDS)

    def test_verified_with_something_left_behind_fails_check(self):
        self.rebrand()
        self.edit("libs/base/src/file_verify.rs", "            && self.not_copied.is_empty()\n", "")
        self.assert_check_fails(check.VERIFY_WORDS)

    def test_verified_with_nothing_proved_fails_check(self):
        self.rebrand()
        self.edit("libs/base/src/file_verify.rs", "            && self.files + self.folders > 0\n", "")
        self.assert_check_fails(check.VERIFY_WORDS)

    def test_writing_through_a_link_fails_check(self):
        self.rebrand()
        self.edit(rebrand.FS_RS, "crate::file_verify::create_work_file(&path).await?", "File::create(&path).await?")
        self.assert_check_fails(check.VERIFY_HOOKS)

    def test_a_forged_report_on_a_download_fails_check(self):
        self.rebrand()
        self.edit(rebrand.IO_LOOP, "if verify::report_is_wanted(self.boring_verify_os.is_some(), receiving_here) {", "if true {")
        self.assert_check_fails(check.VERIFY_HOOKS)

    def test_a_download_taking_the_peers_report_fails_check(self):
        self.rebrand()
        self.edit(rebrand.IO_LOOP, "let report = if boring_received { boring_report } else { self.boring_reports.remove(&d.id) };",
                  "let report = boring_report.or_else(|| self.boring_reports.remove(&d.id));")
        self.assert_check_fails(check.VERIFY_HOOKS)

    def test_a_file_changed_under_the_read_going_unnoticed_fails_check(self):
        self.rebrand()
        self.edit(rebrand.FS_RS, "self.boring_after_read(file_num, boring_changed);", "self.boring_after_read(file_num, None);")
        self.assert_check_fails(check.VERIFY_HOOKS)

    def test_linux_announcing_it_proves_files_fails_check(self):
        self.rebrand()
        self.edit(rebrand.CONN, '#[cfg(any(target_os = "windows", target_os = "macos"))]\n        platform_additions.insert(base::file_verify::MARKER',
                  '#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]\n        platform_additions.insert(base::file_verify::MARKER')
        self.assert_check_fails(check.VERIFY_HOOKS)

    def test_changing_the_old_peer_words_fails_check(self):
        self.rebrand()
        rel = "libs/base/src/file_verify.rs"
        self.edit(rel, "Not verified: the other computer needs the latest Boring Remote", "Sent")
        self.assert_check_fails(check.VERIFY_WORDS)
    def test_transfer_theme_without_extensions_fails_check(self):  # v1.7 t28
        self.rebrand()
        self.edit(rebrand.FILE_MGR, "            data: boringKitTheme,\n", "            data: Kit.theme(),\n")
        self.assert_check_fails("File Transfer theme carries the extensions upstream's location bar reads (v1.7 t28)")

    def test_ui_errors_not_logged_fails_check(self):  # v1.7 t28
        self.rebrand()
        self.edit("flutter/lib/main.dart", "  logUiErrors((text) => bind.mainLogUiError(text: text));\n", "")
        self.assert_check_fails("UI errors reach the app log (v1.7 t28)")

    def test_windows_setup_falling_back_to_scutil_fails_check(self):  # v1.7 t12 follow-up
        self.rebrand()
        self.edit(rebrand.HOME, "            : isWindows // v1.7 review: Windows' own computer name; scutil is Mac only\n"
                                "                ? Future.value(windowsComputerName(Platform.environment, Platform.localHostname))\n", "")
        self.assert_check_fails("Windows Setup starts from the Windows computer name, never scutil (v1.7 t12 follow-up)")

    def test_reach_check_by_rule_name_only_fails_check(self):  # v1.7 t12 follow-up
        self.rebrand()
        self.edit(rebrand.HOME, " && windowsRuleAllowsExe('${r.stdout}', Platform.resolvedExecutable)", "")
        self.assert_check_fails("Windows reach check counts the installer's rule only for this exe (v1.7 t12 follow-up)")

    # --- v1.7 review: nothing left in the RustDesk look ------------------------------
    def test_more_menus_back_in_rustdesk_colours_fails_check(self):
        self.rebrand()
        self.edit(rebrand.T07_TOOLBAR, "static const Color blueColor = Kit.glass;",
                  "static const Color blueColor = MyTheme.button;")
        self.assert_check_fails("session toolbar and its More menus in the kit on Mac and Windows")

    def test_rustdesk_cards_back_in_all_settings_fails_check(self):
        self.rebrand()
        self.edit(rebrand.SETTINGS, "    return KitSection(title: translate(title), trailing: title_suffix ?? const [],"
                  " children: children);\n", "")
        self.assert_check_fails("All settings in the kit on Mac and Windows: sections, tab list, buttons, checkboxes")

    def test_connection_window_minimised_on_allow_fails_check(self):
        self.rebrand()
        self.edit(rebrand.CM_PAGE, "onAllow: () => handleAccept(context),",
                  "onAllow: () {\n              handleAccept(context);\n              windowManager.minimize();\n"
                  "            },")
        self.assert_check_fails("connection window in the kit: who is in, plain switches, kit buttons; Allow keeps it open")

    def test_rustdesk_message_icon_back_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/common.dart", "    final plain = kitMessageWords(type, title, text);\n",
                  "    msgboxIcon(type);\n    final plain = kitMessageWords(type, title, text);\n")
        r = run(CHECK, self.root)
        self.assertIn("FAIL dialogs in the kit on Mac and Windows: password prompt, connecting and errors in plain words: "
                      "msgboxContent shows RustDesk's icon before the kit message", r.stdout)

    def test_rustdesk_install_page_back_fails_check(self):
        self.rebrand()
        self.edit(rebrand.LOOK_INSTALL, "    if (isMacOS || isWindows) return boringInstallScreen();\n", "")
        self.assert_check_fails("Windows install screen in the kit, plain words")

    def test_coral_text_in_the_look_kit_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/desktop/kit/kit_look.dart", "TextStyle(color: Kit.paper, fontSize: 18",
                  "TextStyle(color: Kit.coral, fontSize: 18")
        r = run(CHECK, self.root)
        self.assertRegex(r.stdout, r"FAIL look kit wired: .*kit_look.dart: coral text")


    # --- v1.7 t17: the app file is "Boring Remote.app" ---------------------------------
    def test_bundle_name_facts_pass_after_rebrand(self):
        self.rebrand()
        r = run(CHECK, self.root)
        for fact in (MAC_BUNDLE, MAC_PLISTS, MAC_MOVE, WIN_NAMES, SETTINGS_GEAR, ACCESS, AGENT_RESTART):
            self.assertIn(f"PASS {fact}", r.stdout)
        xc = (self.root / "flutter/macos/Runner/Configs/AppInfo.xcconfig").read_text()
        self.assertIn("PRODUCT_NAME = Boring Remote\n", xc)
        self.assertIn("EXECUTABLE_NAME = BoringRemote\n", xc)
        pbx = (self.root / "flutter/macos/Runner.xcodeproj/project.pbxproj").read_text()
        self.assertIn('path = "Boring Remote.app";', pbx)  # unquoted, the space breaks the project file

    def test_bundle_name_back_to_the_internal_name_fails_check(self):
        self.rebrand()
        self.edit("flutter/macos/Runner/Configs/AppInfo.xcconfig", "PRODUCT_NAME = Boring Remote\n",
                  "PRODUCT_NAME = BoringRemote\n")
        self.assert_check_fails(MAC_BUNDLE)

    def test_daemon_back_through_an_unquoted_sh_c_fails_check(self):
        self.rebrand()
        self.edit("src/platform/privileges_scripts/daemon.plist",
                  "<string>/Applications/Boring Remote.app/Contents/MacOS/service</string>",
                  "<string>/bin/sh</string>\n        <string>-c</string>\n"
                  "        <string>/Applications/Boring Remote.app/Contents/MacOS/service</string>")
        self.assert_check_fails(MAC_PLISTS)

    def test_agent_that_stays_down_after_a_clean_exit_fails_check(self):
        self.rebrand()
        self.edit("src/platform/privileges_scripts/agent.plist", "<key>KeepAlive</key>\n        <true/>",
                  "<key>KeepAlive</key>\n        <dict>\n            <key>SuccessfulExit</key>\n            <false />\n"
                  "        </dict>")
        self.assert_check_fails(MAC_PLISTS)

    def test_old_path_no_longer_trusted_by_ipc_fails_check(self):
        self.rebrand()
        self.edit("src/ipc/auth.rs", '["Boring Remote.app", "BoringRemote.app"]', '["Boring Remote.app"]')
        self.assert_check_fails(MAC_MOVE)

    def test_login_switch_stopping_remote_access_again_fails_check(self):
        self.rebrand()
        self.edit(rebrand.SETTINGS, "          onOpenAtLogin: (on) {\n",
                  "          onOpenAtLogin: (on) {\n            mainSetBoolOption(kOptionStopService, !on);\n")
        self.assert_check_fails(ACCESS)

    def test_access_fix_back_to_kickstart_only_fails_check(self):
        self.rebrand()
        self.edit(rebrand.HOME, "    if (!await restartAgent(Process.run, await uid())) debugPrint('Access: --server still down');\n",
                  "    await Process.run('launchctl', ['kickstart', '-k', 'gui/${await uid()}/$kAgentLabel']);\n")
        self.assert_check_fails(AGENT_RESTART)

    def test_kit_restart_without_bootout_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/desktop/kit/access.dart", "  await run('launchctl', ['bootout', job]);\n", "")
        self.assert_check_fails(AGENT_RESTART)

    def test_bundle_move_back_to_kickstart_only_fails_check(self):
        self.rebrand()
        self.edit("libs/base/src/bundle_move.rs", "restart_agent(&mut launchctl, &mut sleep, uid)", "launchctl(&[\"kickstart\", &target])")
        self.assert_check_fails(AGENT_RESTART)

    def test_update_restart_leaving_the_agent_to_keepalive_fails_check(self):
        self.rebrand()
        self.edit(check.INSTALL_SCRIPT, "  user_session && agent_restart\n", "")
        self.assert_check_fails(AGENT_RESTART)

    def test_lan_address_with_no_fallback_back_to_the_short_budget_fails_check(self):
        self.rebrand()
        self.edit("libs/base/src/direct_link.rs", "is_tailscale(addr.ip()) || addr == last {", "is_tailscale(addr.ip()) {")
        self.assert_check_fails(CONNECT_TAILNET)

    def test_three_line_settings_icon_back_fails_check(self):
        self.rebrand()
        self.edit(rebrand.LOOK_TAB_PAGE, "icon: Icons.settings_outlined,", "icon: IconFont.menu,")
        self.assert_check_fails(SETTINGS_GEAR)

    def test_firewall_rule_named_after_the_exe_fails_check(self):
        self.rebrand()
        self.edit("res/msi/CustomActions/FirewallRules.cpp", 'L"Boring Remote Service"', 'L"%ls Service", exeName')
        self.assert_check_fails(WIN_NAMES)

    # --- v1.7 t20: Save a support file, crash files ---------------------------------
    def test_support_facts_pass_after_rebrand(self):
        self.rebrand()
        r = run(CHECK, self.root)
        for fact in (SUPPORT, SUPPORT_REDACT):
            self.assertIn(f"PASS {fact}", r.stdout)

    def test_panic_hook_missing_from_the_server_startup_fails_check(self):
        self.rebrand()
        self.edit("src/core_main.rs", rebrand.T20_HOOK_CORE, "")
        self.assert_check_fails(SUPPORT)

    def test_settings_without_the_support_button_fails_check(self):
        self.rebrand()
        self.edit(rebrand.SETTINGS, rebrand.T20_HELP, "")
        self.assert_check_fails(SUPPORT)

    def test_home_without_the_crash_notice_fails_check(self):
        self.rebrand()
        self.edit(rebrand.HOME, rebrand.T20_NOTICE, "")
        self.assert_check_fails(SUPPORT)

    def test_a_secret_back_in_the_support_file_fails_check(self):
        self.rebrand()
        self.edit("libs/base/src/support.rs", '    "boring-trust-tokens",\n', "")
        self.assert_check_fails(SUPPORT_REDACT)

    def test_config_copied_raw_into_the_support_file_fails_check(self):
        self.rebrand()
        self.edit("libs/base/src/support.rs", "redact_toml(&text).as_bytes()", "text.as_bytes()")
        self.assert_check_fails(SUPPORT_REDACT)


if __name__ == "__main__":
    unittest.main()
