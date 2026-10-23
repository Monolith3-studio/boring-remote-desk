#!/usr/bin/env python3
"""Draw the Mac DMG window art in the Boring Remote kit (Boring Type, Labs palette).

Usage:  python3 boring/dmg/make_art.py [--fonts DIR]

Writes, next to this file (all committed; boring/dmg/settings.py points dmgbuild here):
  background.png      640x440   Finder window content at 1x
  background@2x.png   1280x880  the same at 2x (dmgbuild joins both into one HiDPI TIFF)

The Finder window is 640x440 of content (settings.py adds the title bar). Icons sit at
(160, 178) and (480, 178), top-left origin, the same numbers as settings.py ICONS.
Everything that matters ends by y = 380, so it still fits when a Mac shows Finder's
path bar and status bar on every window.

The fonts are Boring Type and are NOT in this repo (they are not ours to publish).
Point --fonts (or BORING_TYPE_DIR) at a folder holding neue-corp-ultrabold.otf and
neue-corp-medium.otf. The script stops if a face is missing rather than fall back.
Needs Pillow. Output is deterministic: same fonts, same bytes.
"""
import argparse
import importlib.util
import os
import pathlib

from PIL import Image

HERE = pathlib.Path(__file__).resolve().parent
# One kit: the drawing helpers and palette come from the Windows installer art.
_spec = importlib.util.spec_from_file_location("msi_art", HERE.parent / "msi" / "make_art.py")
_msi = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_msi)
CORAL, INK, MUTED, PAPER, SS = _msi.CORAL, _msi.INK, _msi.MUTED, _msi.PAPER, _msi.SS
canvas, eyebrow, face, text = _msi.canvas, _msi.eyebrow, _msi.face, _msi.text

W, H = 640, 440
APP_XY, APPS_XY = (160, 178), (480, 178)  # icon centres, must match settings.py
PANEL = (0x19, 0x17, 0x1A)
PLATE = (0x7D, 0x7D, 0x82)  # mid grey: Finder draws icon names black in Light Mode, white in Dark

STEPS = [
    "Drag Boring Remote onto Applications.",
    "First open: right-click the app, then Open.",
    "Allow Screen Recording and Accessibility when it asks.",
]


def centred(d, y, s, font, fill, kern=0.0):
    w = sum(font.getlength(ch) for ch in s) / SS + kern * (len(s) - 1)
    text(d, ((W - w) / 2, y), s, font, fill, kern)


def background(fonts, scale):
    im, d = canvas(W, H, INK)
    R = lambda x0, y0, x1, y1: [x0 * SS, y0 * SS, x1 * SS, y1 * SS]

    label = face(fonts, "neue-corp-medium.otf", 12)
    ew = 17 + sum(label.getlength(ch) for ch in "BORING LABS") / SS + 1.2 * 10
    eyebrow(d, (W - ew) / 2, 22, fonts, INK)
    centred(d, 40, "Boring Remote", face(fonts, "neue-corp-ultrabold.otf", 36), PAPER)
    centred(d, 88, "Drive your other computers over your tailnet.", face(fonts, "neue-corp-medium.otf", 16), MUTED)

    # Drag arrow between the icons.
    y = APP_XY[1]
    d.rectangle(R(246, y - 2, 376, y + 2), fill=CORAL)
    d.polygon([(398 * SS, y * SS), (374 * SS, (y - 13) * SS), (374 * SS, (y + 13) * SS)], fill=CORAL)

    for x in (APP_XY[0], APPS_XY[0]):
        d.rounded_rectangle(R(x - 78, 232, x + 78, 256), 2 * SS, fill=PLATE)

    # Steps panel.
    x0, y0, x1, y1 = 60, 276, 580, 372
    d.rounded_rectangle(R(x0, y0, x1, y1), 2 * SS, fill=PANEL)
    d.rectangle(R(x0, y0, x0 + 3, y1), fill=CORAL)
    num = face(fonts, "neue-corp-ultrabold.otf", 16)
    body = face(fonts, "neue-corp-medium.otf", 16)
    for i, s in enumerate(STEPS):
        ry = y0 + 14 + i * 25
        text(d, (x0 + 24, ry), str(i + 1), num, CORAL)
        text(d, (x0 + 48, ry), s, body, PAPER)

    return im.resize((W * scale, H * scale), Image.LANCZOS)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--fonts", type=pathlib.Path, default=os.environ.get("BORING_TYPE_DIR"),
                    help="folder with the Boring Type .otf files (or set BORING_TYPE_DIR)")
    args = ap.parse_args()
    if not args.fonts:
        ap.error("pass --fonts DIR or set BORING_TYPE_DIR")
    fonts = pathlib.Path(args.fonts).expanduser()
    for scale, name in ((1, "background.png"), (2, "background@2x.png")):
        # 144 dpi on the 2x file so tiffutil -cathidpicheck accepts the pair
        background(fonts, scale).save(HERE / name, dpi=(72 * scale, 72 * scale), optimize=True)
        print("wrote", HERE / name)


if __name__ == "__main__":
    main()
