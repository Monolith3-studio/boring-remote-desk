#!/usr/bin/env python3
"""Bundle Boring Type into the Flutter app at build time (ADR 0006).

The font binaries are not ours to publish (this repo is public, AGPL), so they are never
committed. CI fetches a zip from a private store when the BORING_TYPE_URL secret is set,
copies the fonts into flutter/assets/fonts/boring-type/ and declares them in
flutter/pubspec.yaml under the family names the kit asks for (kit.dart fontUi / fontText).
Without the secret it logs one line and the app uses the system font, as it does locally.

The zip holds the font files plus boring-type.json:
    {"Neue Corp": [{"file": "NeueCorp-Regular.otf", "weight": 400}, ...],
     "Söhne": [{"file": "Soehne-Buch.otf", "weight": 400, "style": "italic"}, ...]}

Run from the repo root, after rebrand.py, before the Flutter build:
    python3 boring/fonts.py            # exit 0 with or without the secret, 1 on a bad archive
"""
import io
import json
import os
import pathlib
import re
import sys
import urllib.request
import zipfile

SECRET = "BORING_TYPE_URL"
MANIFEST = "boring-type.json"
DEST = "flutter/assets/fonts/boring-type"
PUBSPEC = "flutter/pubspec.yaml"
KIT = "flutter/lib/desktop/kit/kit.dart"
FONT_FILE = re.compile(r"^[\w .-]+\.(otf|ttf)$")


def kit_families(root):
    kit = (root / KIT).read_text(encoding="utf-8")
    return [m.group(1) for m in re.finditer(r"static const String font\w+ = '([^']+)';", kit)]


def pubspec_block(manifest):
    lines = []
    for family, faces in manifest.items():
        lines += [f"    - family: {family}", "      fonts:"]
        for f in faces:
            lines.append(f"        - asset: assets/fonts/boring-type/{f['file']}")
            if "weight" in f:
                lines.append(f"          weight: {int(f['weight'])}")
            if f.get("style") == "italic":
                lines.append("          style: italic")
    return "\n".join(lines) + "\n"


def bundle(root, data):
    """Unpack the zip bytes into DEST and declare its families in the pubspec. Returns a summary."""
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = {pathlib.PurePosixPath(n).name: n for n in z.namelist() if not n.endswith("/")}
        if MANIFEST not in names:
            raise ValueError(f"no {MANIFEST} in the archive")
        manifest = json.loads(z.read(names[MANIFEST]))
        wanted = kit_families(root)
        missing = [f for f in wanted if f not in manifest]
        if missing:
            raise ValueError(f"the archive has no {', '.join(missing)} (kit.dart asks for {', '.join(wanted)})")
        dest = root / DEST
        dest.mkdir(parents=True, exist_ok=True)
        count = 0
        for family, faces in manifest.items():
            for f in faces:
                name = f.get("file", "")
                if not FONT_FILE.match(name) or name not in names:
                    raise ValueError(f"{family}: {name!r} is not a font file in the archive")
                (dest / name).write_bytes(z.read(names[name]))
                count += 1
    pubspec = root / PUBSPEC
    text = pubspec.read_text(encoding="utf-8")
    if "assets/fonts/boring-type/" not in text:
        if text.count("\n  fonts:\n") != 1:
            raise ValueError(f"{PUBSPEC}: no single top-level fonts: list to add to")
        text = text.replace("\n  fonts:\n", "\n  fonts:\n" + pubspec_block(manifest), 1)
        pubspec.write_text(text, encoding="utf-8")
    return f"{count} files, families {', '.join(manifest)}"


def main(root):
    url = os.environ.get(SECRET, "").strip()
    if not url:
        print(f"Boring Type: {SECRET} is not set; this build uses the system font.")
        return 0
    try:
        # r2.dev answers 403 to urllib's default User-Agent
        req = urllib.request.Request(url, headers={"User-Agent": "boring-remote-ci"})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read()
    except Exception as e:  # its message can carry the URL, which is the secret: name the error only
        print(f"Boring Type: could not download the fonts ({type(e).__name__})", file=sys.stderr)
        return 1
    try:
        print(f"Boring Type: bundled {bundle(root, data)}")
    except (ValueError, zipfile.BadZipFile, KeyError, TypeError) as e:
        print(f"Boring Type: the font archive is not usable: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parent.parent))
