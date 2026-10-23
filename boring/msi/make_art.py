#!/usr/bin/env python3
"""Draw the Windows installer art in the Boring Labs kit (Boring Type, Labs palette).

Usage:  python3 boring/msi/make_art.py [--fonts DIR]

Writes, next to this file (all committed; boring/rebrand.py copies them into res/):
  WixUIBannerBmp.bmp   493x58   top banner on every inner MSI dialog
  WixUIDialogBmp.bmp   493x312  Welcome / Finish dialog background
  icon.ico             16..256  product icon (MSI, shortcuts, Apps list, exe)
  preview/*.png        2x previews, plus mocks with WiX's own text drawn on top

The fonts are Boring Type and are NOT in this repo (they are not ours to publish).
Point --fonts (or BORING_TYPE_DIR) at a folder holding neue-corp-ultrabold.otf and
neue-corp-medium.otf. The script stops if a face is missing rather than fall back.
Needs Pillow. The icon is the Boring Remote app icon (ink body, paper screen, coral
pointer) redrawn from the Mac kit's make-icon.swift, cropped tighter for Windows.
"""
import argparse
import os
import pathlib
import sys

from PIL import Image, ImageDraw, ImageFont

HERE = pathlib.Path(__file__).resolve().parent

INK = (0x0C, 0x0B, 0x11)
GLASS = (0x21, 0x1D, 0x22)
PAPER = (0xF0, 0xEF, 0xEB)
MUTED = (0x9B, 0x99, 0x9D)
CORAL = (0xFF, 0x59, 0x49)
SS = 4  # supersample, then downscale: clean edges at 1x

# WixUI layout in pixels (dialog units x 4/3): text the installer draws over our art.
DIALOG_PANEL = 164   # Welcome/Finish text starts at x=180 (135 du)
BANNER_TEXT_END = 406  # banner description ends at x=406 (25+280 du)


def face(fonts, file, size):
    p = fonts / file
    if not p.is_file():
        sys.exit(f"missing Boring Type face {p} (pass --fonts or set BORING_TYPE_DIR)")
    return ImageFont.truetype(str(p), size * SS)


def screen_glyph(d, x, y, w):
    """The app icon's screen with someone else's coral pointer, w px wide at (x, y)."""
    s = w * SS / 600  # icon grid: screen is 600 x 400 at (212, 252) in a 1024 grid
    X = lambda v: x * SS + (v - 212) * s
    Y = lambda v: y * SS + (v - 252) * s
    d.rounded_rectangle([X(212), Y(252), X(812), Y(652)], 28 * s, fill=PAPER)
    d.rounded_rectangle([X(242), Y(282), X(782), Y(622)], 8 * s, fill=GLASS)
    d.rectangle([X(472), Y(652), X(552), Y(744)], fill=PAPER)
    d.rounded_rectangle([X(372), Y(732), X(652), Y(776)], 12 * s, fill=PAPER)
    arrow = [(432, 334), (432, 564), (488, 512), (528, 596), (564, 580), (524, 494), (598, 490)]
    d.polygon([(X(a), Y(b)) for a, b in arrow], fill=CORAL)


def flask(d, x, y, size):
    """Labs mark: solid evenodd Erlenmeyer flask (24 grid), drawn as body minus window."""
    k = size * SS / 24
    P = lambda pts: [(x * SS + a * k, y * SS + b * k) for a, b in pts]
    d.polygon(P([(6.7, 2.1), (17.3, 2.1), (17.3, 3.9), (15.9, 3.9), (15.9, 8.0), (19.9, 18.7),
                 (19.6, 20.6), (17.7, 21.9), (6.3, 21.9), (4.4, 20.6), (4.1, 18.7), (8.1, 8.0),
                 (8.1, 3.9), (6.7, 3.9)]), fill=CORAL)
    return P([(10, 4.5), (14, 4.5), (14, 8.5), (16.6, 14), (7.4, 14), (10, 8.5)])


def text(d, xy, s, font, fill, kern=0.0):
    x, y = xy[0] * SS, xy[1] * SS
    for ch in s:
        d.text((x, y), ch, font=font, fill=fill)
        x += font.getlength(ch) + kern * SS
    return x / SS


def canvas(w, h, bg):
    im = Image.new("RGB", (w * SS, h * SS), bg)
    return im, ImageDraw.Draw(im)


def finish(im, w, h):
    return im.resize((w, h), Image.LANCZOS)


def eyebrow(d, x, y, fonts, bg):
    window = flask(d, x, y, 12)
    d.polygon(window, fill=bg)
    return text(d, (x + 17, y - 1), "BORING LABS", face(fonts, "neue-corp-medium.otf", 12), MUTED, kern=1.2)


def dialog(fonts):
    W, H = 493, 312
    im, d = canvas(W, H, PAPER)
    d.rectangle([0, 0, DIALOG_PANEL * SS, H * SS], fill=INK)
    d.rectangle([(DIALOG_PANEL - 3) * SS, 0, DIALOG_PANEL * SS, H * SS], fill=CORAL)
    eyebrow(d, 20, 24, fonts, INK)
    screen_glyph(d, 22, 92, 116)
    big = face(fonts, "neue-corp-ultrabold.otf", 34)
    text(d, (20, 216), "Boring", big, PAPER)
    text(d, (20, 250), "Remote", big, PAPER)
    return finish(im, W, H)


def banner(fonts):
    W, H = 493, 58
    im, d = canvas(W, H, PAPER)
    x0 = BANNER_TEXT_END + 8
    d.rectangle([x0 * SS, 0, W * SS, H * SS], fill=INK)
    d.rectangle([x0 * SS, 0, (x0 + 3) * SS, H * SS], fill=CORAL)
    screen_glyph(d, x0 + 3 + (W - x0 - 3 - 52) / 2, (H - 52 * 524 / 600) / 2, 52)
    return finish(im, W, H)


def icon_master():
    """App icon on a 1024 grid, cropped to the body so it reads at 16px on Windows."""
    im = Image.new("RGBA", (1024 * SS, 1024 * SS), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    d.rounded_rectangle([100 * SS, 100 * SS, 924 * SS, 924 * SS], 185 * SS, fill=INK)
    screen_glyph(d, 212, 252, 600)  # at its own place on the 1024 grid
    im = im.crop((84 * SS, 84 * SS, 940 * SS, 940 * SS))
    return im.resize((256, 256), Image.LANCZOS)


def mock(art, lines, out):
    """Preview only: WiX's own text (Windows draws it in Tahoma) over our art."""
    im = art.convert("RGB").resize((art.width * 2, art.height * 2), Image.LANCZOS)
    d = ImageDraw.Draw(im)
    for (x, y), s, size, bold in lines:
        f = None
        for name in (("Tahoma Bold.ttf", "Arial Bold.ttf") if bold else ("Tahoma.ttf", "Arial.ttf")):
            for base in ("/System/Library/Fonts/Supplemental", "/Library/Fonts", "C:/Windows/Fonts"):
                if os.path.isfile(f"{base}/{name}"):
                    f = ImageFont.truetype(f"{base}/{name}", size * 2)
                    break
            if f:
                break
        d.text((x * 2, y * 2), s, font=f or ImageFont.load_default(), fill=(0, 0, 0))
    im.save(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--fonts", type=pathlib.Path, default=os.environ.get("BORING_TYPE_DIR"),
                    help="folder with the Boring Type .otf files (or set BORING_TYPE_DIR)")
    args = ap.parse_args()
    if not args.fonts:
        ap.error("pass --fonts DIR or set BORING_TYPE_DIR")
    fonts = pathlib.Path(args.fonts).expanduser()

    dlg, ban, ico = dialog(fonts), banner(fonts), icon_master()
    dlg.save(HERE / "WixUIDialogBmp.bmp")   # RGB -> 24-bit BMP, what Windows Installer wants
    ban.save(HERE / "WixUIBannerBmp.bmp")
    ico.save(HERE / "icon.ico", sizes=[(16, 16), (20, 20), (24, 24), (32, 32), (40, 40),
                                      (48, 48), (64, 64), (128, 128), (256, 256)])

    pv = HERE / "preview"
    pv.mkdir(exist_ok=True)
    dlg.resize((986, 624), Image.LANCZOS).save(pv / "dialog@2x.png")
    ban.resize((986, 116), Image.LANCZOS).save(pv / "banner@2x.png")
    ico.save(pv / "icon-256.png")
    mock(dlg, [((180, 27), "Welcome to the Boring Remote", 16, True),
               ((180, 47), "Setup Wizard", 16, True),
               ((180, 107), "The Setup Wizard will install Boring Remote on", 11, False),
               ((180, 122), "your computer. Click Next to continue or Cancel", 11, False),
               ((180, 137), "to exit the Setup Wizard.", 11, False)], pv / "mock-welcome.png")
    mock(ban, [((20, 8), "Destination Folder", 11, True),
               ((33, 31), "Click Next to install to the default folder or click Change", 11, False)],
         pv / "mock-banner.png")
    for p in ("WixUIDialogBmp.bmp", "WixUIBannerBmp.bmp", "icon.ico"):
        print("wrote", HERE / p)


if __name__ == "__main__":
    main()
