"""check.py workflow guard (spec slice 2 + 7): no GitHub Actions workflow in the fork.

Releases build on the Studio (boring/release/build-mac); GitHub never builds.
Any file under .github/workflows/ fails, on disk or tracked in git (rebrand.py
deletes upstream's workflows from the build copy, but GitHub runs what is committed).
.github/patches/ stays: the release script applies the Flutter patch from there.

    python3 -m unittest boring/test_check_workflows.py -v
"""
import contextlib
import io
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import check  # noqa: E402

PATCH = ".github/patches/flutter_3.24.4_dropdown_menu_enableFilter.diff"


def tree(files, git=False):
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="wf-guard-"))
    for rel, text in files.items():
        (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp / rel).write_text(text)
    if git:
        subprocess.run(["git", "-C", str(tmp), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(tmp), "add", "-A"], check=True)
    return tmp


def guard(root):
    c = check.Check(root)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        check.workflow_guard(c)
    return c, out.getvalue()


class WorkflowGuard(unittest.TestCase):
    def test_patches_alone_pass(self):
        c, out = guard(tree({PATCH: "diff\n", "Cargo.toml": "x\n"}))
        self.assertEqual(c.failed, 0, out)
        self.assertIn("PASS no GitHub Actions workflow", out)

    def test_any_file_under_workflows_fails(self):
        for rel in (".github/workflows/boring-build.yml", ".github/workflows/flutter-build.yml",
                    ".github/workflows/notes.txt", ".github/workflows/sub/x.yaml"):
            c, out = guard(tree({PATCH: "diff\n", rel: "on: push\n"}))
            self.assertGreater(c.failed, 0, rel)
            self.assertIn(rel, out)

    def test_workflow_tracked_in_git_but_deleted_on_disk_fails(self):
        root = tree({".github/workflows/flutter-build.yml": "on: push\n"}, git=True)
        (root / ".github/workflows/flutter-build.yml").unlink()
        c, out = guard(root)
        self.assertGreater(c.failed, 0, out)
        self.assertIn(".github/workflows/flutter-build.yml", out)

    def test_this_repo_has_no_workflow(self):
        c, out = guard(check.pathlib.Path(__file__).resolve().parent.parent)
        self.assertEqual(c.failed, 0, out)


if __name__ == "__main__":
    unittest.main()
