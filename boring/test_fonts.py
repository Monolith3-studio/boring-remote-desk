"""boring/fonts.py: Boring Type is bundled only when the secret is set, never committed."""
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
FONTS = HERE / "fonts.py"


def font_zip(manifest, files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("boring-type/boring-type.json", json.dumps(manifest))
        for name in files:
            z.writestr(f"boring-type/{name}", b"OTTO not a real font")
    return buf.getvalue()


class Fonts(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="fonts-"))
        for rel in ("flutter/pubspec.yaml", "flutter/lib/desktop/kit/kit.dart"):
            (self.tmp / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / rel, self.tmp / rel)
        self.pubspec = (self.tmp / "flutter/pubspec.yaml").read_text(encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_fonts(self, url):
        env = {k: v for k, v in os.environ.items() if k != "BORING_TYPE_URL"}
        if url is not None:
            env["BORING_TYPE_URL"] = url
        return subprocess.run([sys.executable, str(FONTS), str(self.tmp)], env=env, capture_output=True, text=True)

    def test_no_secret_logs_one_line_and_changes_nothing(self):
        r = self.run_fonts(None)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("BORING_TYPE_URL is not set; this build uses the system font", r.stdout)
        self.assertEqual((self.tmp / "flutter/pubspec.yaml").read_text(encoding="utf-8"), self.pubspec)
        self.assertFalse((self.tmp / "flutter/assets/fonts").exists())

    def test_with_the_secret_the_kits_families_are_bundled_and_declared(self):
        manifest = {"Neue Corp": [{"file": "NeueCorp-Regular.otf", "weight": 400}],
                    "Söhne": [{"file": "Soehne-Buch.otf", "weight": 400}, {"file": "Soehne-Kursiv.otf", "style": "italic"}]}
        archive = self.tmp / "bt.zip"
        archive.write_bytes(font_zip(manifest, ["NeueCorp-Regular.otf", "Soehne-Buch.otf", "Soehne-Kursiv.otf"]))
        r = self.run_fonts(archive.as_uri())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((self.tmp / "flutter/assets/fonts/boring-type/Soehne-Kursiv.otf").is_file())
        pubspec = (self.tmp / "flutter/pubspec.yaml").read_text(encoding="utf-8")
        self.assertIn("    - family: Neue Corp\n      fonts:\n        - asset: assets/fonts/boring-type/NeueCorp-Regular.otf\n"
                      "          weight: 400\n", pubspec)
        self.assertIn("        - asset: assets/fonts/boring-type/Soehne-Kursiv.otf\n          style: italic\n", pubspec)
        self.assertEqual(self.run_fonts(archive.as_uri()).returncode, 0)  # a second run adds nothing twice
        self.assertEqual((self.tmp / "flutter/pubspec.yaml").read_text(encoding="utf-8"), pubspec)

    def test_an_archive_without_a_kit_family_fails_the_build_without_naming_the_url(self):
        archive = self.tmp / "secret-path.zip"
        archive.write_bytes(font_zip({"Neue Corp": [{"file": "NeueCorp-Regular.otf"}]}, ["NeueCorp-Regular.otf"]))
        r = self.run_fonts(archive.as_uri())
        self.assertEqual(r.returncode, 1)
        self.assertIn("no Söhne", r.stderr)
        r = self.run_fonts("https://nowhere.invalid/secret-path.zip")
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("secret-path", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
