"""check.py updater guard (spec slice 8, ADR 0004) against small fixture trees.

One passing tree, then one tree per forbidden pattern.

    python3 -m unittest boring/test_check_updater.py -v
"""
import contextlib
import io
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import check  # noqa: E402

OSA = ('const OSA: &str = r#"on run argv\n  do shell script (quoted form of item 1 of argv)'
       ' with administrator privileges\nend run"#;\n'
       'fn run() { let s = exe.join("Resources/boring-install-update.sh"); }\n')
GOOD = {
    "src/update_notice.rs":
        'pub const VERSION_URL: &str = "https://boringlabs.online/downloads/the-boring-remote-version.json";\n'
        'pub fn sig_url() -> String { format!("{VERSION_URL}.sig") }\n',
    "src/license_key.rs":
        'pub const UPDATE_ENDPOINT: &str = "https://boring-store-fulfillment.restless-term-7ead.workers.dev/update";\n',
    "src/update_install_run.rs": OSA,
    "src/platform/privileges_scripts/install-update.sh": "#!/bin/sh\n# run with administrator privileges\n",
    "src/platform/privileges_scripts/install.scpt": 'do shell script sh with administrator privileges\n',
    "src/platform/macos.rs": 'pub fn elevate() { let s = "with administrator privileges"; }\n',
    "flutter/lib/x.dart": "final link = 'https://boringlabs.online/remote/update';\n",
    "boring/update-pubkeys.json":
        '{"current": "sJyFBUc4U5I42j4FvNuafMRd4s2rdqQNiQPTfUU8q3o=",'
        ' "backup": "fUGKPveLBQfyeExmew6ttY+xlFygkFC02liG1adqZnk="}\n',
}


def run(**changes):
    tmp = pathlib.Path(tempfile.mkdtemp())
    for rel, text in {**GOOD, **changes}.items():
        if text is None:
            continue
        (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp / rel).write_text(text)
    c = check.Check(tmp)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        check.updater_checks(c)
    return c, out.getvalue()


class UpdaterGuard(unittest.TestCase):
    def assert_fails(self, needle, **changes):
        c, out = run(**changes)
        self.assertGreater(c.failed, 0, out)
        self.assertIn(needle, out)

    def test_passing_tree(self):
        c, out = run()
        self.assertEqual(c.failed, 0, out)
        self.assertIn("ADR 0004", out)

    def test_new_update_url_fails(self):
        self.assert_fails("FAIL", **{"src/sneaky.rs": 'const U: &str = "https://evil.example/update/latest";\n'})

    def test_upstream_update_url_fails(self):
        self.assert_fails("FAIL", **{"flutter/lib/y.dart":
                                     "final u = 'https://api.github.com/repos/rustdesk/rustdesk/releases/latest';\n"})

    def test_moved_version_url_fails(self):
        self.assert_fails("FAIL", **{"src/update_notice.rs":
                                     'pub const VERSION_URL: &str = "https://evil.example/v.json";\n'})

    def test_moved_update_endpoint_fails(self):
        self.assert_fails("FAIL", **{"src/license_key.rs":
                                     'pub const UPDATE_ENDPOINT: &str = "https://evil.example/update";\n'})

    def test_other_admin_caller_fails(self):
        self.assert_fails("src/foo.rs", **{"src/foo.rs":
                                           'fn sneak() { let s = "do shell script x with administrator privileges"; }\n'})

    def test_admin_runner_not_running_install_script_fails(self):
        self.assert_fails("FAIL", **{"src/update_install_run.rs": OSA.replace("boring-install-update.sh", "x.sh")})

    def test_missing_install_script_fails(self):
        self.assert_fails("FAIL", **{"src/platform/privileges_scripts/install-update.sh": None})

    def test_same_keys_fail(self):
        k = "sJyFBUc4U5I42j4FvNuafMRd4s2rdqQNiQPTfUU8q3o="
        self.assert_fails("FAIL", **{"boring/update-pubkeys.json": f'{{"current": "{k}", "backup": "{k}"}}'})

    def test_missing_key_fails(self):
        self.assert_fails("FAIL", **{"boring/update-pubkeys.json":
                                     '{"current": "sJyFBUc4U5I42j4FvNuafMRd4s2rdqQNiQPTfUU8q3o="}'})


if __name__ == "__main__":
    unittest.main()
