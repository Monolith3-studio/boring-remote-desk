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
