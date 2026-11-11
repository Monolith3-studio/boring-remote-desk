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
CONNECT_DIRECT = "connect box never reaches the ID/rendezvous path"
CONNECT_TAILNET = "names connect Direct IP only to Tailscale addresses, else the plain error"
NOT_FOUND_TRANSLATED = "plain not-found error is in every translation file"
REBRAND = HERE / "rebrand.py"
CHECK = HERE / "check.py"
HBB = rebrand.HBB


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
        for fact in ("rendezvous servers empty", "whitelist", "app name", "hwcodec",
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
        self.assert_check_fails("whitelist is enforced on incoming connections")

    def test_dropping_v4_mapped_normalisation_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "        let addr = hbb_common::try_into_v4(addr);\n", "")
        self.assert_check_fails("whitelist is enforced on incoming connections")

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
        self.edit("src/client.rs", "        if true {\n            return Ok((\n                (\n"
                  "                    connect_tcp_local(boring_tailnet_addr(peer).await?",
                  "        if hbb_common::is_domain_port_str(peer) {\n            return Ok((\n                (\n"
                  "                    connect_tcp_local(boring_tailnet_addr(peer).await?")
        self.assert_check_fails(CONNECT_DIRECT)

    def test_rendezvous_lookup_before_the_tailnet_guard_fails_check(self):
        self.rebrand()
        self.edit("src/client.rs", "        // boring-remote: anything that is not an IP is a tailnet name",
                  "        let _ = crate::get_rendezvous_server(1_000).await;\n"
                  "        // boring-remote: anything that is not an IP is a tailnet name")
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

    def test_password_lock_facts_pass_after_rebrand(self):
        self.rebrand()
        r = run(CHECK, self.root)
        for fact in (self.PERMANENT_ONLY, self.NO_PASSWORD, self.THROTTLED, self.IPC_GUARDED, self.GENERATOR,
                     "a Controller can't change the Target's settings (allow-remote-config-modification locked off)",
                     "one-time password length pinned", "one-time password label hidden when it is off"):
            self.assertIn(f"PASS {fact}", r.stdout)

    def test_password_lock_facts_fail_on_clean_upstream_tree(self):
        r = run(CHECK, self.root)
        for fact in (self.PERMANENT_ONLY, self.NO_PASSWORD, self.IPC_GUARDED, self.GENERATOR):
            self.assertIn(f"FAIL {fact}", r.stdout)

    def test_both_passwords_allowed_fails_check(self):
        self.rebrand()
        self.edit(HBB, '("verification-method", "use-permanent-password")',
                  '("verification-method", "use-both-passwords")')
        self.assert_check_fails(self.PERMANENT_ONLY)

    def test_remote_config_modification_allowed_fails_check(self):
        self.rebrand()
        self.edit(HBB, '("allow-remote-config-modification", "N")', '("allow-remote-config-modification", "Y")')
        self.assert_check_fails("a Controller can't change the Target's settings")

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
        self.edit("src/trust_policy.rs", "if decision == Decision::Allow && password == Password::Right {",
                  "if decision == Decision::Allow {")
        self.assert_check_fails(self.NO_PASSWORD)

    def test_no_password_trusted_controller_skipping_the_click_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "    if password == Password::Right && trusted.contains(controller) {",
                  "    if trusted.contains(controller) {")
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

    # --- ticket 06: trusted Controllers --------------------------------------------
    APPROVE_LOCKED = "unknown Controllers need the password and a click on the Target (approve mode locked, prompt can't hide)"
    TRUST_GATE = "a right password from an unknown Controller waits for a click on the Target before logging in"
    ACCEPT_GATED = "the Target's Accept only counts for a login waiting on it (password checked, or none set)"
    TRUST_LIST = "trusted Controllers saved in the daemon's config, a remote session can't change them"
    TRUST_SETTINGS = "Settings lists trusted Controllers with Remove, behind the security unlock"

    def test_trust_facts_pass_after_rebrand(self):
        self.rebrand()
        r = run(CHECK, self.root)
        for fact in (self.APPROVE_LOCKED, self.TRUST_GATE, self.ACCEPT_GATED, self.TRUST_LIST,
                     self.TRUST_SETTINGS):
            self.assertIn(f"PASS {fact}", r.stdout)

    def test_trust_facts_fail_on_clean_upstream_tree(self):
        r = run(CHECK, self.root)
        for fact in (self.APPROVE_LOCKED, self.TRUST_GATE, self.ACCEPT_GATED, self.TRUST_LIST,
                     self.TRUST_SETTINGS):
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
                  "                    if !self.send_logon_response_and_keep_alive().await {",
                  "                    }\n                    if !self.send_logon_response_and_keep_alive().await {")
        self.assert_check_fails(self.TRUST_GATE)

    def test_policy_not_refusing_wrong_password_first_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "    if password == Password::Wrong {\n        return Decision::Refuse;\n    }\n", "")
        self.assert_check_fails(self.TRUST_GATE)

    def test_policy_allowing_unanswered_prompt_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "AtTarget::NoAnswer => Decision::Refuse,", "AtTarget::NoAnswer => Decision::Allow,")
        self.assert_check_fails(self.TRUST_GATE)

    def test_ungated_accept_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", rebrand.ACCEPT_GATE, "")
        self.assert_check_fails(self.ACCEPT_GATED)

    def test_wait_not_voided_by_a_new_login_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", rebrand.FORGET_ON_LOGIN, "")
        self.assert_check_fails(self.ACCEPT_GATED)

    def test_accept_that_ignores_pending_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", "            return false;\n        };\n        let (_, controller, password)",
                  "            return true;\n        };\n        let (_, controller, password)")
        self.assert_check_fails(self.ACCEPT_GATED)

    def test_unanswered_prompt_no_longer_times_out_fails_check(self):
        self.rebrand()
        self.edit("src/server/connection.rs", "                _ = login_deadline(conn.authorized, started) => {\n"
                  "                    conn.on_close(\"Timeout\", true).await;\n                    break;\n                }\n", "")
        self.assert_check_fails(self.ACCEPT_GATED)

    def test_trusted_list_left_out_of_the_session_guard_fails_check(self):
        self.rebrand()
        self.edit("src/password_lock.rs", '    "boring-trusted-controllers",\n', "")
        self.assert_check_fails(self.TRUST_LIST)

    def test_trusted_list_key_mismatch_fails_check(self):
        self.rebrand()
        self.edit("src/trust_policy.rs", 'pub const TRUSTED_OPTION: &str = "boring-trusted-controllers";',
                  'pub const TRUSTED_OPTION: &str = "boring-trusted";')
        self.assert_check_fails(self.TRUST_LIST)

    def test_trusted_list_in_local_options_fails_check(self):
        # Local options live in the UI process's config, not the daemon's, and skip the guard.
        self.rebrand()
        self.edit("src/trust_policy.rs", "Config::set_option(TRUSTED_OPTION", "LocalConfig::set_option(TRUSTED_OPTION")
        self.assert_check_fails(self.TRUST_LIST)

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
