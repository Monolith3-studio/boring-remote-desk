"""check.py activate-link guard (ticket 14) against small fixture trees.

    python3 -m unittest boring/test_check_activate_link.py -v
"""
import contextlib
import io
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import check  # noqa: E402

PLIST = ("<key>CFBundleURLSchemes</key>\n\t\t\t<array>\n\t\t\t\t<string>boringremote</string>\n"
         "\t\t\t</array>\n")
BRANCH = ('  } else if (uri.authority == "activate") {\n    final url = uri.toString();\n'
          "    Timer(Duration(seconds: 1), () async {\n"
          "      showActivateLinkResult(await bind.mainActivateLink(url: url));\n    });\n    return null;\n"
          '  } else if (uri.authority == "config") {\n')
GOOD = {
    "flutter/macos/Runner/Info.plist": PLIST,
    "src/activate_link.rs": 'const SCHEME: &str = "boringremote://";\n',
    "flutter/lib/common.dart": BRANCH,
    "flutter/lib/main.dart": "void main() {}\n",
    "src/platform/delegate.rs": "fn f() {}\n",
    "src/license_key_run.rs":
        "pub fn activate_link(url: &str) -> String {\n    match crate::activate_link::parse(url) {\n"
        "        Some(key) => set_and_check(&key),\n        None => \"rejected\".to_owned(),\n    }\n}\n",
}


def run(**changes):
    tmp = pathlib.Path(tempfile.mkdtemp())
    for rel, text in {**GOOD, **changes}.items():
        (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp / rel).write_text(text)
    c = check.Check(tmp)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        check.activate_link_checks(c)
    return c, out.getvalue()


class ActivateLinkGuard(unittest.TestCase):
    def assert_fails(self, needle, **changes):
        c, out = run(**changes)
        self.assertGreater(c.failed, 0, out)
        self.assertIn(needle, out)

    def test_passing_tree(self):
        c, out = run()
        self.assertEqual(c.failed, 0, out)

    def test_upstream_scheme_left_fails(self):
        self.assert_fails("URL scheme", **{"flutter/macos/Runner/Info.plist": PLIST.replace("boringremote", "rustdesk")})

    def test_second_scheme_fails(self):
        self.assert_fails("URL scheme", **{"flutter/macos/Runner/Info.plist":
                                           PLIST.replace("</array>", "<string>extra</string></array>")})

    def test_second_activate_branch_fails(self):
        self.assert_fails("activate branch", **{"flutter/lib/common.dart": BRANCH + BRANCH})

    def test_activate_branch_running_a_command_fails(self):
        self.assert_fails("activate branch", **{"flutter/lib/common.dart": BRANCH.replace(
            "    return null;\n", "    command = '--connect';\n    return null;\n")})

    def test_key_stored_without_parser_fails(self):
        self.assert_fails("only via the parser", **{"src/license_key_run.rs":
                                                    "pub fn activate_link(url: &str) -> String {\n"
                                                    "    set_and_check(url)\n}\n"})

    def test_logged_link_fails(self):
        self.assert_fails("never logged", **{"flutter/lib/main.dart": '  debugPrint("launch args: $args");\n'})


if __name__ == "__main__":
    unittest.main()
