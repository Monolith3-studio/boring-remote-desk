#!/usr/bin/env python3
"""sign-release round trip with a throwaway key made here. Never the real key.

Run:  python3 -m unittest boring/release/test_sign_release.py -v
"""
import base64
import hashlib
import importlib.machinery
import importlib.util
import json
import pathlib
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

HERE = pathlib.Path(__file__).resolve().parent
_loader = importlib.machinery.SourceFileLoader("sign_release", str(HERE / "sign-release"))
_spec = importlib.util.spec_from_loader("sign_release", _loader)
sr = importlib.util.module_from_spec(_spec)
_loader.exec_module(sr)

RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def b64(b):
    return base64.b64encode(b).decode()


class SignRelease(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.key = Ed25519PrivateKey.generate()
        self.seed = self.key.private_bytes(serialization.Encoding.Raw,
                                           serialization.PrivateFormat.Raw,
                                           serialization.NoEncryption())
        self.pkg = self.tmp / "BoringRemote-1.6.0-macos-arm64.app.tar.xz"
        self.pkg.write_bytes(b"package bytes \x00\x01")
        self.vf = self.tmp / "the-boring-remote-version.json"
        self.vf.write_text(json.dumps({
            "version": "1.6.0", "sha256": "aa", "url": "u",
            "package_sha256": hashlib.sha256(self.pkg.read_bytes()).hexdigest(),
            "package_sig": "", "min_version": "1.5.0"}))
        self.keys = self.tmp / "keys.json"

    def write_keys(self, current, backup):
        self.keys.write_text(json.dumps({"current": current, "backup": backup}))

    def test_round_trip_signs_package_and_version_file(self):
        other = Ed25519PrivateKey.generate().public_key().public_bytes(**RAW)
        self.write_keys(b64(other), b64(self.key.public_key().public_bytes(**RAW)))
        sr.sign_release(self.tmp, lambda: b64(self.seed), self.keys)

        pub = self.key.public_key()
        data = json.loads(self.vf.read_text())
        pub.verify(base64.b64decode(data["package_sig"]), self.pkg.read_bytes())
        sig = (self.tmp / "the-boring-remote-version.json.sig").read_text().strip()
        pub.verify(base64.b64decode(sig), self.vf.read_bytes())
        self.assertEqual(data["version"], "1.6.0")
        self.assertEqual(data["min_version"], "1.5.0")

    def test_key_not_embedded_fails_and_writes_no_sig(self):
        stranger = b64(Ed25519PrivateKey.generate().public_key().public_bytes(**RAW))
        self.write_keys(stranger, stranger)
        with self.assertRaises(sr.SignError):
            sr.sign_release(self.tmp, lambda: b64(self.seed), self.keys)
        self.assertFalse((self.tmp / "the-boring-remote-version.json.sig").exists())

    def test_package_hash_mismatch_fails(self):
        self.write_keys(b64(self.key.public_key().public_bytes(**RAW)), "")
        self.pkg.write_bytes(b"tampered")
        with self.assertRaises(sr.SignError):
            sr.sign_release(self.tmp, lambda: b64(self.seed), self.keys)


if __name__ == "__main__":
    unittest.main()
