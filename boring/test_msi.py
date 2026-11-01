"""Windows installer (v1.7 ticket 12): branded in the app's own kit, and CI proves its app rule.

Seams: the committed art in boring/msi (what rebrand.py copies into res/msi), make_art.py's
palette as the generator states it, the app kit's tokens in flutter/lib/desktop/kit/kit.dart,
and the workflow text. Stdlib only.

Run: python3 -m unittest boring/test_msi.py -v
"""
import pathlib
import re
import struct
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
MSI = ROOT / "boring" / "msi"
KIT = ROOT / "flutter" / "lib" / "desktop" / "kit" / "kit.dart"
WORKFLOW = ROOT / ".github" / "workflows" / "boring-build.yml"


def kit_tokens():
    """{name: (r, g, b)} from `static const Color name = Color(0xFFRRGGBB);` in kit.dart."""
    return {n: tuple(bytes.fromhex(h)) for n, h in
            re.findall(r"static const Color (\w+) = Color\(0xFF([0-9A-Fa-f]{6})\);", KIT.read_text())}


def art_palette():
    """{NAME: (r, g, b)} from make_art.py's `NAME = (0x.., 0x.., 0x..)` lines."""
    return {n: tuple(int(x, 16) for x in v) for n, *v in
            re.findall(r"^([A-Z]+) = \(0x([0-9A-F]{2}), 0x([0-9A-F]{2}), 0x([0-9A-F]{2})\)", (MSI / "make_art.py").read_text(), re.M)}


def bmp_pixels(path):
    """Every (r, g, b) in a bottom-up 24-bit BMP."""
    data = path.read_bytes()
    off, = struct.unpack_from("<I", data, 10)
    w, h = struct.unpack_from("<ii", data, 18)
    bpp, = struct.unpack_from("<H", data, 28)
    assert bpp == 24, f"{path.name} is {bpp}-bit"
    stride = (w * 3 + 3) & ~3
    px = set()
    for y in range(abs(h)):
        row = data[off + y * stride: off + y * stride + w * 3]
        px.update((row[i + 2], row[i + 1], row[i]) for i in range(0, len(row), 3))
    return px


class KitArt(unittest.TestCase):
    def test_installer_palette_is_the_app_kit(self):
        kit, art = kit_tokens(), art_palette()
        for name in ("ink", "glass", "paper", "muted", "coral"):
            self.assertEqual(art[name.upper()], kit[name], name)

    def test_dialog_and_banner_are_drawn_in_kit_ink_and_coral(self):
        kit = kit_tokens()
        for name in ("WixUIDialogBmp.bmp", "WixUIBannerBmp.bmp"):
            px = bmp_pixels(MSI / name)
            self.assertIn(kit["ink"], px, name)
            self.assertIn(kit["coral"], px, name)


class FirewallRuleInCI(unittest.TestCase):
    """The MSI smoke test proves the app rule that lets other computers reach Direct Link."""

    def smoke(self):
        text = WORKFLOW.read_text()
        m = re.search(r"- name: Smoke test MSI \(silent install and uninstall\)\n(.*?)(?=\n      - )", text, re.S)
        self.assertIsNotNone(m)
        return m.group(1)

    def test_install_leaves_an_inbound_any_port_rule_for_the_exe(self):
        st = self.smoke()
        self.assertIn("Get-NetFirewallRule -DisplayName 'BoringRemote Service'", st)
        for needle in ("'Inbound'", "'Allow'", "Profile)\" -ne 'Any'", "LocalPort)\" -ne 'Any'",
                       "Protocol)\" -ne 'Any'", "$af.Program -ne $exe"):
            self.assertIn(needle, st)
        self.assertLess(st.index("Get-NetFirewallRule"), st.index("/x `\"$msi`\""))

    def test_uninstall_removes_the_rule(self):
        st = self.smoke()
        self.assertIn('throw "firewall rule left after uninstall"', st)
        self.assertGreater(st.index("firewall rule left after uninstall"), st.index("/x `\"$msi`\""))


if __name__ == "__main__":
    unittest.main()
