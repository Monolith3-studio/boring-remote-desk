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
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check  # noqa: E402  (shares the installer-string reader with check.py)
import rebrand  # noqa: E402

REPO = HERE.parent
CONNECT_DIRECT = "connect box: only a Machine ID reaches the rendezvous path; names connect Direct IP"
CONNECT_TAILNET = "names connect Direct IP only to Tailscale addresses, else the plain error"
NOT_FOUND_TRANSLATED = "plain not-found error is in every translation file"
REBRAND = HERE / "rebrand.py"
CHECK = HERE / "check.py"
WHITELIST_FIRST = "a whitelist the buyer sets is still checked first on incoming connections"
REMOTE_CONFIG = "allow-remote-config-modification locked off (a UI hint; the session guard holds the settings)"
HBB = rebrand.HBB
PROTOCOL = "protocol files are upstream's plus our two LoginRequest fields (boring/protocol.sha256)"
TRUSTED_IF = "    if password == Password::Right && key.map_or(false, |k| trusted.contains(controller, k)) {"


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
                     "About page has the one plain AGPL legal line",
                     "no RustDesk name or link in any translation",
                     "no RustDesk in app metadata", "window titles and tray tooltip say Boring Remote",
                     "no upstream RustDesk logo or icon ships", "every logo slot holds Boring Remote art",
                     "Mac menu-bar icon res/mac-tray-dark-x2.png is a template glyph",
                     CONNECT_DIRECT, CONNECT_TAILNET, NOT_FOUND_TRANSLATED):
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

    UPDATE_FACT = "the only update endpoints are VERSION_URL, its .sig and fulfillment /update (ADR 0004)"

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

    # --- connect by tailnet name ----------------------------------
    def test_domain_port_branch_back_in_connect_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", "        if !boring_is_machine_id(peer) {\n            return Ok((\n                (\n"
                  "                    connect_tcp_local(boring_tailnet_addr(peer).await?",
                  "        if hbb_common::is_domain_port_str(peer) {\n            return Ok((\n                (\n"
                  "                    connect_tcp_local(boring_tailnet_addr(peer).await?")
        self.assert_check_fails(CONNECT_DIRECT)

    def test_rendezvous_lookup_before_the_tailnet_guard_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", "        // boring-remote: a Machine ID goes through the Hosted servers",
                  "        let _ = crate::get_rendezvous_server(1_000).await;\n"
                  "        // boring-remote: a Machine ID goes through the Hosted servers")
        self.assert_check_fails(CONNECT_DIRECT)

    def test_non_tailnet_answer_accepted_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", "!addrs.iter().all(|a| boring_is_tailnet(*a))",
                  "!addrs.iter().any(|a| boring_is_tailnet(*a))")
        self.assert_check_fails(CONNECT_TAILNET)

    def test_widened_tailnet_range_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", "(ip.octets()[1] & 0xc0) == 64", "(ip.octets()[1] & 0x80) == 0")
        self.assert_check_fails(CONNECT_TAILNET)

    def test_reworded_error_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", rebrand.NOT_FOUND, "failed to lookup address information")
        self.assert_check_fails(CONNECT_TAILNET)

    def test_not_found_key_missing_from_a_language_fails_check(self):
        self.rebrand()
        self.edit("src/lang/fr.rs", f'        ("{rebrand.NOT_FOUND}", ""),\n', "")
        r = run(CHECK, self.root)
        self.assertRegex(r.stdout, rf"FAIL {NOT_FOUND_TRANSLATED}: .*fr.rs")

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
    NO_PASSWORD = "no permanent password: no unattended access, only a click on the Target (not remembered)"
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
                     self.ONE_TIME_LABEL, self.UI_KEYS, "one-time password length pinned"):
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
        self.edit("src/server/connection.rs", rebrand.NO_PASSWORD_GATE, "")
        self.assert_check_fails(self.NO_PASSWORD)

    def test_no_password_gate_after_click_to_accept_fails_check(self):
        self.rebrand()
        conn = "src/server/connection.rs"
        self.edit(conn, rebrand.NO_PASSWORD_GATE, "")
        self.edit(conn, "            } else if self.is_recent_session(false) {\n",
                  "            }\n" + rebrand.NO_PASSWORD_GATE + "            if self.is_recent_session(false) {\n")
        self.assert_check_fails(self.NO_PASSWORD)

    def test_refuse_login_ignoring_the_lock_fails_check(self):
        self.rebrand()
        self.edit("src/password_lock.rs", "    verification_method != PERMANENT_ONLY\n", "    false\n")
        self.assert_check_fails(self.NO_PASSWORD)

    def test_no_password_login_counted_as_right_password_fails_check(self):
        # ticket 06: Right would let a trusted Controller in unattended and remember new ones.
        self.rebrand()
        self.edit("src/server/connection.rs", "crate::trust_policy::Password::NotSet", "crate::trust_policy::Password::Right")
        self.assert_check_fails(self.NO_PASSWORD)

    def test_no_password_login_falling_through_fails_check(self):
        self.rebrand()
        conn = "src/server/connection.rs"
        gate = rebrand.NO_PASSWORD_GATE
        self.edit(conn, gate, gate.replace("                return true;\n            }\n", "            }\n"))
        self.assert_check_fails(self.NO_PASSWORD)

    def test_no_password_approval_remembered_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "if password == Password::Right && remember && !trusted.has_id(controller) {",
                  "if remember && !trusted.has_id(controller) {")
        self.assert_check_fails(self.NO_PASSWORD)

    def test_no_password_trusted_controller_skipping_the_click_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", TRUSTED_IF, TRUSTED_IF.replace("password == Password::Right && ", ""))
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
        self.edit("src/server/connection.rs",
                  "                    self.update_failure_with_scope(failure, false, 0, FailureScope::Default);\n", "")
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
        self.edit("src/lang/de.rs", '        ("Trusted Controllers", ""),\n', "")
        self.assert_check_fails(self.UI_KEYS)

    # --- ticket 06: trusted Controllers --------------------------------------------
    APPROVE_LOCKED = "unknown Controllers need the password and a click on the Target (approve mode locked, prompt can't hide)"
    TRUST_GATE = "a right password waits for a click on the Target unless the Controller proves a trusted key"
    PROOF = "a trusted login needs the stored key's signature over this login; a known ID alone never skips the click"
    SIGNED = "Controllers sign each login with their own key (this challenge, the Target they dialed, their ID)"
    ACCEPT_GATED = "the Target's Accept only counts for a login waiting on it; a stray one ends the connection"
    TRUST_LIST = "trusted Controllers live in the daemon's config; only an Accept with no other session open adds one"
    BUDGET = "every Accept prompt counts against the IP's failure budget; an approval clears it"
    SWAP = "a new login on a connection waiting on Accept ends it (the click can't land on another login)"
    NO_DEAD_ACCEPT = "no Accept prompt for a login without the right password (empty or wrong)"
    LOGON_SITES = "exactly five ways into a session, each gated or explained"
    REMOVE = "removing a trusted Controller works during a session and ends its sessions"
    ID_LOG = "a Controller-supplied ID is logged throttled and only if storable"
    TRUST_SETTINGS = "Settings lists trusted Controllers with Remove, behind the security unlock"

    def test_trust_facts_pass_after_rebrand(self):
        self.rebrand()
        r = run(CHECK, self.root)
        for fact in (self.APPROVE_LOCKED, self.TRUST_GATE, self.ACCEPT_GATED, self.TRUST_LIST,
                     self.TRUST_SETTINGS, self.BUDGET, self.SWAP, self.NO_DEAD_ACCEPT, self.LOGON_SITES,
                     self.REMOVE, self.ID_LOG, self.PROOF, self.SIGNED, PROTOCOL):
            self.assertIn(f"PASS {fact}", r.stdout)

    def test_trust_facts_fail_on_clean_upstream_tree(self):
        r = run(CHECK, self.root)
        for fact in (self.APPROVE_LOCKED, self.TRUST_GATE, self.ACCEPT_GATED, self.TRUST_LIST,
                     self.TRUST_SETTINGS, self.BUDGET, self.SWAP, self.NO_DEAD_ACCEPT, self.LOGON_SITES,
                     self.REMOVE, self.PROOF, self.SIGNED, PROTOCOL):
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
        self.edit("src/server/connection.rs", rebrand.TRUST_GATE, "")
        self.assert_check_fails(self.TRUST_GATE)

    def test_trust_gate_after_logon_fails_check(self):
        self.rebrand()
        conn = "src/server/connection.rs"
        self.edit(conn, rebrand.TRUST_GATE, "")
        self.edit(conn, "                    self.try_start_cm(lr.my_id, lr.my_name, self.authorized);\n                }\n            }\n",
                  rebrand.TRUST_GATE + "                    self.try_start_cm(lr.my_id, lr.my_name, self.authorized);\n"
                  "                }\n            }\n")
        self.assert_check_fails(self.TRUST_GATE)

    def test_trust_gate_that_lets_ask_through_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "                        return true;\n                    }\n"
                  "                    self.update_failure_with_scope(failure, true,",
                  "                    }\n                    self.update_failure_with_scope(failure, true,")
        self.assert_check_fails(self.TRUST_GATE)

    def test_policy_letting_an_unasked_controller_in_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "AtTarget::NotAsked => Decision::Ask,", "AtTarget::NotAsked => Decision::Allow,")
        self.assert_check_fails(self.TRUST_GATE)

    def test_trusted_check_without_the_password_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", TRUSTED_IF, TRUSTED_IF.replace("password == Password::Right && ", ""))
        self.assert_check_fails(self.TRUST_GATE)

    def test_ungated_accept_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", rebrand.ACCEPT_GATE, "")
        self.assert_check_fails(self.ACCEPT_GATED)

    def test_new_login_on_a_waiting_connection_kept_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", rebrand.FORGET_ON_LOGIN,
                  "            crate::trust_policy::forget(self.inner.id());\n")
        self.assert_check_fails(self.SWAP)

    def test_accept_that_ignores_pending_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "        return false;\n    };\n    let trusted = load();",
                  "        return true;\n    };\n    let trusted = load();")
        self.assert_check_fails(self.ACCEPT_GATED)

    def test_stray_accept_left_hanging_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "                                conn.send_close_reason_no_retry(\"\").await;\n"
                  "                                conn.on_close(\"connection manager\", true).await;\n"
                  "                                break;\n                            }\n                            clear_failures",
                  "                                continue;\n                            }\n                            clear_failures")
        self.assert_check_fails(self.ACCEPT_GATED)

    def test_wait_kept_after_close_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs",
                  "        crate::trust_policy::forget(self.inner.id()); // boring-remote (ticket 06)\n", "")
        self.assert_check_fails(self.ACCEPT_GATED)

    def test_prompt_not_counted_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "                    {\n                        "
                  "self.update_failure_with_scope(failure, false, 0, FailureScope::Default);\n",
                  "                    {\n")
        self.assert_check_fails(self.BUDGET)

    def test_no_password_prompt_not_throttled_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "                let (failure, res) = self.check_failure(0).await;\n"
                  "                if !res {\n                    return true;\n                }\n"
                  "                self.update_failure_with_scope(failure, false, 0, FailureScope::Default);\n"
                  "                crate::trust_policy::on_login(", "                crate::trust_policy::on_login(")
        self.assert_check_fails(self.BUDGET)

    def test_accept_prompt_after_a_wrong_password_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "LOGIN_MSG_PASSWORD_WRONG)\n                        .await;\n",
                  "LOGIN_MSG_PASSWORD_WRONG)\n                        .await;\n"
                  "                    self.try_start_cm(lr.my_id, lr.my_name, false);\n")
        self.assert_check_fails(self.NO_DEAD_ACCEPT)

    def test_accept_prompt_without_a_password_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", rebrand.EMPTY_PASSWORD_NO_CM, rebrand.EMPTY_PASSWORD_CM)
        self.assert_check_fails(self.NO_DEAD_ACCEPT)

    def test_sixth_way_into_a_session_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "            if !self.check_login_scope(&lr).await {\n",
                  "            if !self.send_logon_response_and_keep_alive().await {\n                return false;\n"
                  "            }\n            if !self.check_login_scope(&lr).await {\n")
        self.assert_check_fails(self.LOGON_SITES)

    def test_recent_session_with_one_time_passwords_on_fails_check(self):
        self.rebrand()
        self.edit(HBB, '("verification-method", "use-permanent-password")', '("verification-method", "use-both-passwords")')
        self.assert_check_fails(self.LOGON_SITES)

    def test_unanswered_prompt_no_longer_times_out_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "                _ = login_deadline(conn.authorized, started) => {\n"
                  "                    conn.on_close(\"Timeout\", true).await;\n                    break;\n                }\n", "")
        self.assert_check_fails(self.ACCEPT_GATED)

    def test_trusted_list_left_out_of_the_session_guard_fails_check(self):
        self.rebrand()
        self.edit("src/password_lock.rs", "    crate::trust_policy::TRUSTED_OPTION,\n", "")
        self.assert_check_fails(self.TRUST_LIST)

    def test_trusted_list_key_mismatch_fails_check(self):
        # The session guard names the constant itself; the Settings list must follow a rename.
        self.rebrand()
        self.edit("src/trust_policy.rs", 'pub const TRUSTED_OPTION: &str = "boring-trusted-controllers";',
                  'pub const TRUSTED_OPTION: &str = "boring-trusted";')
        self.assert_check_fails(self.TRUST_SETTINGS)

    def test_remove_key_mismatch_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", 'pub const REMOVE_OPTION: &str = "boring-trusted-controllers-remove";',
                  'pub const REMOVE_OPTION: &str = "boring-untrust";')
        self.assert_check_fails(self.REMOVE)

    def test_trusted_list_in_local_options_fails_check(self):
        # Local options live in the UI process's config, not the daemon's, and skip the guard.
        self.rebrand()
        self.edit("src/trust_policy.rs", "Config::set_option(TRUSTED_OPTION", "LocalConfig::set_option(TRUSTED_OPTION")
        self.assert_check_fails(self.TRUST_LIST)

    def test_approval_remembered_during_another_session_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "let remember = crate::password_lock::authed_sessions() == 0;", "let remember = true;")
        self.assert_check_fails(self.TRUST_LIST)

    def test_ui_copy_of_the_trusted_list_taken_fails_check(self):
        self.rebrand()
        self.edit("src/ipc.rs", "                let removed = crate::trust_policy::take_options(&mut value, &Config::get_options());\n",
                  "                let removed: Vec<String> = Vec::new();\n")
        self.assert_check_fails(self.TRUST_LIST)

    def test_removed_controller_keeps_its_session_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", rebrand.CLOSE_ARM, "")
        self.assert_check_fails(self.REMOVE)

    def test_controller_id_logged_on_every_login_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "        hbb_common::throttled_log!(\n            std::time::Duration::from_secs(60),\n            info,\n",
                  "        log::info!(\n")
        self.assert_check_fails(self.ID_LOG)

    def test_settings_without_trusted_list_fails_check(self):
        self.rebrand()
        self.edit(rebrand.SETTINGS, rebrand.TRUST_CARD, "")
        self.assert_check_fails(self.TRUST_SETTINGS)

    def test_settings_list_outside_the_unlock_fails_check(self):
        self.rebrand()
        self.edit(rebrand.SETTINGS, rebrand.TRUST_CARD, "")
        self.edit(rebrand.SETTINGS, "            _lock(locked, 'Unlock Security Settings', () {\n",
                  rebrand.TRUST_CARD + "            _lock(locked, 'Unlock Security Settings', () {\n")
        self.assert_check_fails(self.TRUST_SETTINGS)

    def test_settings_widget_on_another_key_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/desktop/widgets/trusted_controllers.dart",
                  "const kBoringTrustedControllers = 'boring-trusted-controllers';",
                  "const kBoringTrustedControllers = 'trusted';")
        self.assert_check_fails(self.TRUST_SETTINGS)

    # --- trust binding (option B): the Controller proves its key ----------------------
    def test_trust_keyed_on_the_id_alone_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "|(t, k)| t == id && k == key", "|(t, _)| t == id")
        self.assert_check_fails(self.PROOF)

    def test_unverified_signature_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "    (signed == want).then_some(key)\n", "    let _ = (signed, want);\n    Some(key)\n")
        self.assert_check_fails(self.PROOF)

    def test_gate_trusting_the_presented_key_unsigned_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", rebrand.LOGIN_KEY, "lr.boring_controller_pk.as_ref().try_into().ok()")
        self.assert_check_fails(self.PROOF)

    def test_signature_naming_the_claimed_target_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "    target_names(arrived_on, from, own_id, secured)\n        .iter()",
                  "    [lr.username.clone()]\n        .iter()")
        self.assert_check_fails(self.PROOF)

    def test_target_named_by_a_relay_or_lan_arrival_address_fails_check(self):
        # review M1: a relayed or punched login arrives on the Target's LAN or relay-side address.
        self.rebrand()
        self.edit("src/trust_policy.rs", "    if !(is_tailnet(arrived_on) && is_tailnet(from)) {\n",
                  "    if !is_tailnet(arrived_on) {\n")
        self.assert_check_fails(self.PROOF)

    def test_gate_key_not_proven_against_this_connection_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "self.stream.local_addr().ip(),\n                            &self.ip,",
                  'self.stream.local_addr().ip(),\n                            "100.64.0.1",')
        self.assert_check_fails(self.PROOF)

    def test_controller_signing_a_lan_address_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "    is_tailnet(ip).then(|| ip.to_string())\n", "    Some(ip.to_string())\n")
        self.assert_check_fails(self.SIGNED)

    def test_controller_signing_a_machine_id_fails_check(self):
        # No signed ID logins until the session's Target identity is verified (Hosted, 07/08).
        self.rebrand()
        self.edit("src/trust_policy.rs", "        None => DIALED.lock().unwrap().iter().find(|(p, _)| p == peer)?.1,\n",
                  "        None => return Some(peer.to_owned()),\n")
        self.assert_check_fails(self.SIGNED)

    def test_controller_ui_making_its_own_key_pair_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "    let pair = Config::get_existing_key_pair();\n",
                  "    let pair = Some(Config::get_key_pair());\n")
        self.assert_check_fails(self.SIGNED)

    def test_sign_login_signing_another_id_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "signature(challenge, &target, &lr.my_id, &sk)",
                  "signature(challenge, &target, &lr.username, &sk)")
        self.assert_check_fails(self.SIGNED)

    def test_approval_replacing_a_trusted_key_fails_check(self):
        # review S1: a prompt for an already trusted ID with another key must not swap the key.
        self.rebrand()
        self.edit("src/trust_policy.rs", " && remember && !trusted.has_id(controller) {", " && remember {")
        self.assert_check_fails(self.TRUST_LIST)

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

    def test_keyless_entry_kept_by_parse_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "    Some((id, unhex(key)?))\n", "    Some((id, unhex(key).unwrap_or([0; 32])))\n")
        self.assert_check_fails(self.PROOF)

    def test_controller_not_signing_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", rebrand.SIGN_LOGIN, "")
        self.assert_check_fails(self.SIGNED)

    def test_login_signed_before_the_challenge_is_known_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", rebrand.HASH_FIRST_NEW, rebrand.HASH_FIRST_OLD)
        self.assert_check_fails(self.SIGNED)

    def test_controller_signing_any_challenge_fails_check(self):
        # A Target picks the challenge; unchecked, it could make the Controller's key sign a SignedId.
        self.rebrand()
        self.edit("src/trust_policy.rs", "\n        && challenge.bytes().all(|b| b.is_ascii_alphanumeric());", ";")
        self.assert_check_fails(self.SIGNED)

    def test_login_message_without_its_domain_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", 'const LOGIN_DOMAIN: &[u8] = b"\\0boring-remote', 'const LOGIN_DOMAIN: &[u8] = b"boring-remote')
        self.assert_check_fails(self.SIGNED)

    def test_tailnet_name_not_bound_to_its_address_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", rebrand.NOTE_DIALED, "")
        self.assert_check_fails(self.SIGNED)

    def test_trust_policy_left_out_of_ios_controllers_fails_check(self):
        self.rebrand()
        self.edit("src/lib.rs", "mod trust_policy;", rebrand.NON_IOS + "mod trust_policy;")
        self.assert_check_fails(self.SIGNED)

    def test_login_fields_dropped_from_the_protocol_fails_check(self):
        self.rebrand()
        self.edit("libs/base/protos/message.proto", rebrand.PROTO_FIELDS, "")
        self.assert_check_fails(PROTOCOL)

    def test_other_edit_next_to_the_login_fields_fails_check(self):
        self.rebrand()
        self.edit("libs/base/protos/message.proto", rebrand.PROTO_FIELDS,
                  rebrand.PROTO_FIELDS + "  bytes sneaky = 1002;\n")
        self.assert_check_fails(PROTOCOL)

    def test_migration_writing_more_than_it_drops_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "    trusted\n}\n", "    save(&trusted);\n    trusted\n}\n")
        self.assert_check_fails(self.TRUST_LIST)

    # --- ticket 07: the Hosted path (ADR 0005) ----------------------------------------
    # Independent of rebrand.py and check.py: the servers' public key as Jason published it
    # (boring-remote-servers keys/id_ed25519.pub) and the domain from the spec.
    SERVERS_PUB = "2hUye2snQY5Roz1FXgypyJQwCjUuNcIX08ukFeo6TYk="
    HOST = "rs.theboringremote.com"
    ONLY_HOST = "the only rendezvous server is rs.theboringremote.com (ADR 0005)"
    FORCED = "rendezvous server and list are always ours (exe name, Settings, config file, serial path skipped)"
    LOCKED_SERVERS = "server settings locked to rs.theboringremote.com (relay follows; no API server)"
    BAKED = "baked server key is server-key.pub (built-in key and locked key option)"
    NO_WHITELIST = "no Tailscale whitelist left (ADR 0005)"
    PUBLIC = "no shipped code names a RustDesk public server or its key"
    MACHINE_ID = "the Target shows its Machine ID and keeps it across restarts (made once, then read from its config)"
    HOSTED_SIGNED = ("Controllers sign a Machine-ID login only on a session that verified the Target "
                     "against the baked server key")

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
        self.edit("src/trust_policy.rs", "(secured && crate::client::boring_is_machine_id(peer))",
                  "crate::client::boring_is_machine_id(peer)")
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
        self.edit("src/client.rs", "sign_login(lr, &challenge, peer.is_secured(), reached);",
                  "sign_login(lr, &challenge, true, reached);")
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
    DIRECT_TAILNET = "Direct IP (21118) answers tailnet addresses only"
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
        self.edit("src/rendezvous_mediator.rs", rebrand.DIRECT_TAILNET_ONLY, "")
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
        self.edit("src/trust_policy.rs", "    if secured && crate::client::boring_is_machine_id(own_id) {",
                  "    if crate::client::boring_is_machine_id(own_id) {")
        self.assert_check_fails(self.PROOF)

    def test_gate_claiming_every_connection_is_keyed_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "                            self.stream.is_secured(),\n",
                  "                            true,\n")
        self.assert_check_fails(self.PROOF)

    def test_gate_naming_the_claimed_machine_id_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "                            &Config::get_id(),\n",
                  "                            &lr.username,\n")
        self.assert_check_fails(self.PROOF)

    # --- ticket 08: tailnet first, the Hosted servers as fallback -----------------------
    FIRST = "a saved Machine ID tries its tailnet address first (~3 s), then the Hosted servers (ticket 08)"
    TAILNET_SIGNED = "a tailnet-first login signs only the address its own stream reached, at send time (ticket 08)"
    LEARNED = "a saved Machine ID records a tailnet address only from its verified Target (ticket 08)"
    DOWN = "Hosted servers unreachable: a plain error naming rs.theboringremote.com (ticket 08)"
    PATH = "the session shows tailnet direct, direct or relayed (ticket 08)"

    def test_tailnet_first_facts_pass_after_rebrand_and_fail_on_upstream(self):
        r = run(CHECK, self.root)
        for fact in (self.FIRST, self.TAILNET_SIGNED, self.LEARNED, self.DOWN, self.PATH):
            self.assertIn(f"FAIL {fact}", r.stdout)
        self.rebrand()
        r = run(CHECK, self.root)
        for fact in (self.FIRST, self.TAILNET_SIGNED, self.LEARNED, self.DOWN, self.PATH, self.HOSTED_SIGNED):
            self.assertIn(f"PASS {fact}", r.stdout)

    def test_no_tailnet_attempt_before_the_hosted_servers_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", "        if let Some(stream) = boring_tailnet_first(peer, conn_type, interface.is_force_relay()).await {",
                  "        if let Some(stream) = None::<Stream> {")
        self.assert_check_fails(self.FIRST)

    def test_slow_tailnet_attempt_fails_check(self):
        self.rebrand()
        self.edit("src/connect_plan.rs", "pub const TAILNET_TIMEOUT_MS: u64 = 3_000;",
                  "pub const TAILNET_TIMEOUT_MS: u64 = 30_000;")
        self.assert_check_fails(self.FIRST)

    def test_saved_lan_address_dialed_fails_check(self):
        self.rebrand()
        self.edit("src/connect_plan.rs", "a.parse::<IpAddr>().ok()).filter(|ip| is_tailnet(*ip));",
                  "a.parse::<IpAddr>().ok());")
        self.assert_check_fails(self.FIRST)

    def test_typed_name_falling_back_to_the_hosted_servers_fails_check(self):
        self.rebrand()
        self.edit("src/connect_plan.rs", "        return vec![Attempt::DirectIp(peer.id.to_owned())];\n",
                  "        let _ = Attempt::DirectIp(peer.id.to_owned());\n")
        self.assert_check_fails(self.FIRST)

    def test_reached_address_kept_after_the_login_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "    Some(streams.remove(i).1)\n", "    Some(streams[i].1)\n")
        self.assert_check_fails(self.TAILNET_SIGNED)

    def test_tailnet_stream_read_elsewhere_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", "        let reached = crate::trust_policy::take_tailnet_stream(",
                  "        let _ = crate::trust_policy::is_tailnet_stream(peer.local_addr());\n"
                  "        let reached = crate::trust_policy::take_tailnet_stream(")
        self.assert_check_fails(self.TAILNET_SIGNED)

    def test_controller_signing_a_saved_lan_address_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", ".filter(|ip| is_tailnet(*ip) && crate::client::boring_is_machine_id(peer))",
                  ".filter(|_| crate::client::boring_is_machine_id(peer))")
        self.assert_check_fails(self.TAILNET_SIGNED)

    def test_every_unverified_machine_id_let_through_fails_check(self):
        self.rebrand()
        self.edit("src/client/io_loop.rs", "is_secured || crate::trust_policy::is_tailnet_stream(peer.local_addr());",
                  "true;")
        self.assert_check_fails(self.TAILNET_SIGNED)

    def test_unverified_session_recording_a_tailnet_address_fails_check(self):
        self.rebrand()
        self.edit("src/connect_plan.rs", "    if !verified || !crate::client::boring_is_machine_id(id) {",
                  "    if !crate::client::boring_is_machine_id(id) {")
        self.assert_check_fails(self.LEARNED)

    def test_target_not_reporting_its_tailnet_address_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "        crate::connect_plan::add_own_tailnet(&mut platform_additions);\n", "")
        self.assert_check_fails(self.LEARNED)

    def test_rendezvous_error_passed_through_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", "            anyhow!(crate::connect_plan::HOSTED_DOWN)\n", "            err\n")
        self.assert_check_fails(self.DOWN)

    def test_hosted_down_error_not_naming_our_servers_fails_check(self):
        self.rebrand()
        self.edit("src/connect_plan.rs", " (rs.theboringremote.com)", "")
        self.assert_check_fails(self.DOWN)

    def test_hosted_down_key_missing_from_a_language_fails_check(self):
        self.rebrand()
        self.edit("src/lang/de.rs", f'        ("{rebrand.HOSTED_DOWN}", ""),\n', "")
        self.assert_check_fails(self.DOWN)

    def test_session_without_the_tailnet_label_fails_check(self):
        self.rebrand()
        self.edit("flutter/lib/common.dart", "  if (streamType == 'Tailnet') {\n", "  if (false) {\n")
        self.assert_check_fails(self.PATH)
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

    SETUP_SCREEN = ("1.8.0 first launch: a Target without an app-generated Permanent password gets the setup screen, "
                    "which runs the generator (asking first if a password is set) and shows it once; never again "
                    "once one is generated (ticket 09)")
    SETUP = "flutter/lib/desktop/widgets/password_setup.dart"

    def test_setup_screen_fact_passes_after_rebrand(self):
        self.rebrand()
        self.assertIn(f"PASS {self.SETUP_SCREEN}", run(CHECK, self.root).stdout)

    def test_setup_screen_fact_fails_on_clean_upstream_tree(self):
        self.assertIn(f"FAIL {self.SETUP_SCREEN}", run(CHECK, self.root).stdout)

    def test_setup_screen_not_wired_into_the_home_page_fails_check(self):
        self.rebrand()
        self.edit(rebrand.HOME, rebrand.SETUP_HOOK, "")
        self.assert_check_fails(self.SETUP_SCREEN)

    def test_setup_screen_shown_with_a_generated_password_fails_check(self):
        self.rebrand()
        self.edit(self.SETUP, "  if (await generatedPasswordSet()) return;\n", "")
        self.assert_check_fails(self.SETUP_SCREEN)

    def test_setup_screen_skipped_for_a_typed_password_fails_check(self):
        # A 1.7.x typed password still gets the screen (review M1).
        self.rebrand()
        self.edit(self.SETUP, "  return bind.mainGetOption(key: kBoringPasswordGenerated) == 'Y';\n",
                  "  return (await bind.mainGetCommon(key: \"permanent-password-set\")) == \"true\";\n")
        self.assert_check_fails(self.SETUP_SCREEN)

    def test_setup_screen_replacing_a_password_without_asking_fails_check(self):
        self.rebrand()
        self.edit(self.SETUP, "        final go = await confirmReplacePassword();\n        if (go == null) return;\n", "")
        self.assert_check_fails(self.SETUP_SCREEN)

    def test_setup_screen_not_showing_the_password_once_fails_check(self):
        self.rebrand()
        self.edit(self.SETUP, "showGeneratedPasswordOnce(pass);", "showToast(pass);")
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
        self.assertIn(b"PRODUCT_NAME = BoringRemote\r\n", (self.root / crlf[0]).read_bytes())
        for rel in ("src/common.rs", "flutter/windows/runner/Runner.rc"):  # LF stays LF
            self.assertNotIn(b"\r", (self.root / rel).read_bytes(), rel)
        self.assertIn("rebrand: 0 changed, 0 moved", self.rebrand().stdout)


if __name__ == "__main__":
    unittest.main()
