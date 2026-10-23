#!/usr/bin/env python3
"""Make the Boring Remote app art that replaces every RustDesk logo slot (ticket 17).

Usage:  python3 boring/art/make_app_art.py [--icns PATH]

One icon family on every surface: ink body, paper screen, coral pointer, the
same glyph as the Mac kit (the-boring-remote/design/icon/AppIcon.icns, make-icon.swift)
and the Windows MSI icon (boring/msi/make_art.py). Flat colours only.

--icns is the Mac kit's AppIcon.icns, copied as-is (default:
~/code/the-boring-remote/design/icon/AppIcon.icns). Its largest image is the master
for the PNG sizes upstream ships. The Windows tray icon and icon.svg are drawn
from the same grid as boring/msi/make_art.py. The menu-bar icon is a template
glyph: pure black plus alpha, so macOS tints it for light and dark menu bars.

Writes, next to this file (all committed; boring/rebrand.py copies them in):
  AppIcon.icns            Mac app and Dock icon
  icon-1024.png           res/icon.png, res/mac-icon.png
  icon-32/64/128/256.png  res/32x32.png, 64x64.png, 128x128.png, 128x128@2x.png
  tray.ico                Windows tray (16..64)
  menubar-60.png / -48    Mac menu-bar template (upstream's two sizes)
  icon.svg                in-app icon (tab bar, connection window), res/logo.svg
  preview/*.png           what to look at
Needs Pillow. Deterministic: same input, same bytes.
"""
import argparse
import pathlib
import shutil
import sys

from PIL import Image, ImageDraw

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "msi"))
import make_art  # noqa: E402  (the shared glyph and palette)

INK, GLASS, PAPER, CORAL = make_art.INK, make_art.GLASS, make_art.PAPER, make_art.CORAL
SS = 8
ARROW = [(432, 334), (432, 564), (488, 512), (528, 596), (564, 580), (524, 494), (598, 490)]


def hexc(c):
    return "#%02x%02x%02x" % c


def icon_svg():
    """The Windows-cropped app icon as plain SVG shapes (flutter_svg draws rect, polygon)."""
    pts = " ".join(f"{x},{y}" for x, y in ARROW)
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="84 84 856 856">\n'
        f'  <rect x="100" y="100" width="824" height="824" rx="185" fill="{hexc(INK)}"/>\n'
        f'  <rect x="212" y="252" width="600" height="400" rx="28" fill="{hexc(PAPER)}"/>\n'
        f'  <rect x="242" y="282" width="540" height="340" rx="8" fill="{hexc(GLASS)}"/>\n'
        f'  <rect x="472" y="652" width="80" height="92" fill="{hexc(PAPER)}"/>\n'
        f'  <rect x="372" y="732" width="280" height="44" rx="12" fill="{hexc(PAPER)}"/>\n'
        f'  <polygon points="{pts}" fill="{hexc(CORAL)}"/>\n'
        "</svg>\n")


def menubar(size):
    """Template glyph: the screen as an outline with the pointer inside, black on clear."""
    S = size * SS
    m = Image.new("L", (S, S), 0)
    d = ImageDraw.Draw(m)
    # glyph box on the 1024 grid: screen 212..812 x 252..776 (incl. stand), centred with padding
    pad = 0.06
    k = S * (1 - 2 * pad) / 600
    ox, oy = S * pad - 212 * k, (S - 524 * k) / 2 - 252 * k
    X = lambda v: ox + v * k
    Y = lambda v: oy + v * k
    stroke = 56  # on the 1024 grid; ~2.9px at 60px, 1px at 18px
    d.rounded_rectangle([X(212), Y(252), X(812), Y(652)], 40 * k, fill=255)
    d.rounded_rectangle([X(212 + stroke), Y(252 + stroke), X(812 - stroke), Y(652 - stroke)], 14 * k, fill=0)
    d.rectangle([X(472), Y(652), X(552), Y(744)], fill=255)
    d.rounded_rectangle([X(372), Y(732), X(652), Y(776)], 12 * k, fill=255)
    d.polygon([(X(a), Y(b)) for a, b in ARROW], fill=255)
    alpha = m.resize((size, size), Image.LANCZOS)
    im = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    im.putalpha(alpha)
    return im


def on(bg, glyph, tint, scale):
    """Preview: the template as macOS draws it, tinted, on a menu-bar colour."""
    w = glyph.width * scale
    g = glyph.resize((w, w), Image.LANCZOS)
    out = Image.new("RGB", (w + 2 * scale * 8, w + 2 * scale * 4), bg)
    solid = Image.new("RGB", g.size, tint)
    out.paste(solid, (scale * 8, scale * 4), g.getchannel("A"))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--icns", type=pathlib.Path,
                    default=pathlib.Path("~/code/the-boring-remote/design/icon/AppIcon.icns").expanduser())
    args = ap.parse_args()
    if not args.icns.is_file():
        sys.exit(f"missing {args.icns}: pass --icns (the Mac kit's AppIcon.icns)")
    shutil.copyfile(args.icns, HERE / "AppIcon.icns")
    src = Image.open(HERE / "AppIcon.icns")
    # Pillow opens an icns at its largest image
    master = src.convert("RGBA").resize((1024, 1024), Image.LANCZOS)

    def png(im, name):
        im.save(HERE / name, optimize=False)
        print("wrote", HERE / name)

    png(master, "icon-1024.png")
    for s in (32, 64, 128, 256):
        png(master.resize((s, s), Image.LANCZOS), f"icon-{s}.png")
    win = make_art.icon_master()  # Windows crop of the same glyph, reads at 16px
    win.save(HERE / "tray.ico", sizes=[(16, 16), (20, 20), (24, 24), (32, 32), (48, 48), (64, 64)],
             bitmap_format="bmp")  # BMP entries, like upstream's tray icon: any ICO reader takes them
    print("wrote", HERE / "tray.ico")
    for s in (60, 48):
        png(menubar(s), f"menubar-{s}.png")
    (HERE / "icon.svg").write_text(icon_svg())
    print("wrote", HERE / "icon.svg")

    pv = HERE / "preview"
    pv.mkdir(exist_ok=True)
    bar = menubar(60)
    light, dark = on((0xEC, 0xEC, 0xEC), bar, (0, 0, 0), 2), on((0x2B, 0x2A, 0x2F), bar, (0xFF, 0xFF, 0xFF), 2)
    sheet = Image.new("RGB", (light.width * 2 + 24, light.height), (0xFF, 0xFF, 0xFF))
    sheet.paste(light, (0, 0))
    sheet.paste(dark, (light.width + 24, 0))
    sheet.save(pv / "menubar-light-dark.png")
    g = bar.resize((18, 18), Image.LANCZOS)  # 1x: an 18pt glyph in a 24pt menu bar
    real = Image.new("RGB", (60, 24), (0xEC, 0xEC, 0xEC))
    real.paste((0x2B, 0x2A, 0x2F), (30, 0, 60, 24))
    real.paste((0, 0, 0), (6, 3, 24, 21), g.getchannel("A"))
    real.paste((0xFF, 0xFF, 0xFF), (36, 3, 54, 21), g.getchannel("A"))
    real.resize((real.width * 6, real.height * 6), Image.NEAREST).save(pv / "menubar-1x-zoom.png")
    strip = Image.new("RGB", (16 + 24 + 32 + 48 + 64 + 6 * 12, 64 + 24), PAPER)
    x = 12
    for s in (16, 24, 32, 48, 64):
        ico = win.resize((s, s), Image.LANCZOS)
        strip.paste(ico, (x, 12 + 64 - s), ico)
        x += s + 12
    strip.resize((strip.width * 2, strip.height * 2), Image.NEAREST).save(pv / "tray-sizes@2x.png")
    m256 = master.resize((256, 256), Image.LANCZOS)
    m256.save(pv / "app-icon-256.png")
    # one sheet: Mac icon, Windows icon (MSI/exe), tray sizes, menu bar light and dark
    msi = Image.open(HERE.parent / "msi/icon.ico").convert("RGBA").resize((256, 256), Image.LANCZOS)
    tray_im, bars = Image.open(pv / "tray-sizes@2x.png"), Image.open(pv / "menubar-light-dark.png")
    sheet = Image.new("RGB", (max(256 * 2 + 48 * 3, tray_im.width + 96),
                              256 + tray_im.height + bars.height + 48 * 4), PAPER)
    sheet.paste(m256, (48, 48), m256)
    sheet.paste(msi, (48 * 2 + 256, 48), msi)
    sheet.paste(tray_im, (48, 48 * 2 + 256))
    sheet.paste(bars, (48, 48 * 3 + 256 + tray_im.height))
    sheet.save(pv / "sheet.png")
    print("previews in", pv)


if __name__ == "__main__":
    main()
