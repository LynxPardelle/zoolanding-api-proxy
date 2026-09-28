"""Exercise the actual promotion shell with disposable local Git repositories."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]


class TestPromotionGuardTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.repo = root / "checkout"
        self.repo.mkdir()
        self.origin = root / "origin.git"
        self.bash = shutil.which("bash")
        if os.name == "nt":
            git_bash = Path("C:/Program Files/Git/bin/bash.exe")
            if git_bash.is_file():
                self.bash = str(git_bash)
        self.assertIsNotNone(self.bash, "Bash is required for promotion regressions")
        self.env = {
            key: os.environ[key]
            for key in ("PATH", "SystemRoot", "TEMP", "TMP")
            if key in os.environ
        }
        self.env.update({
            "HOME": str(root),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "file",
            "GIT_AUTHOR_NAME": "Offline fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.test",
            "GIT_COMMITTER_NAME": "Offline fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.test",
        })
        self.git("init", "--quiet", "--initial-branch=test")
        self.git("init", "--quiet", "--bare", str(self.origin))
        self.git("remote", "add", "origin", self.origin.as_posix())
        self.empty_tree = self.git("mktree", input_text="")
        self.before = self.commit(self.empty_tree)
        self.main = self.commit(self.empty_tree, self.before, label="main")
        blob = self.git("hash-object", "-w", "--stdin", input_text="reviewed dev")
        self.dev_tree = self.git("mktree", input_text=f"100644 blob {blob}\tnote.txt\n")
        self.dev = self.commit(self.dev_tree, self.before, label="dev")
        self.git("update-ref", "refs/heads/main", self.main)
        self.git("update-ref", "refs/heads/dev", self.dev)
        self.git("push", "--quiet", "origin", "refs/heads/main", "refs/heads/dev")
        workflow = (ROOT / ".github/workflows/deploy-test.yml").read_text(encoding="utf-8")
        step = workflow.split("      - name: Verify exact TEST promotion context\n", 1)[1]
        step = step.split("      - name:", 1)[0]
        self.script = textwrap.dedent(step.split("        run: |\n", 1)[1])

    def git(self, *args, input_text=None):
        result = subprocess.run(
            ["git", *args], cwd=self.repo, env=self.env, input=input_text,
            capture_output=True, text=True, timeout=10, check=True,
        )
        return result.stdout.strip()

    def commit(self, tree, *parents, label="fixture"):
        args = ["commit-tree", tree]
        for parent in parents:
            args.extend(["-p", parent])
        return self.git(*args, input_text=label)

    def check_guard(self, parents=None, tree=None, **environment):
        release = self.commit(
            tree or self.dev_tree, *(parents or [self.before, self.dev]), label="release",
        )
        self.git("update-ref", "HEAD", release)
        env = {
            **self.env, "RELEASE_SHA": release, "BEFORE_SHA": self.before,
            "GITHUB_REF": "refs/heads/test", "PUSH_FORCED": "false", **environment,
        }
        return subprocess.run(
            [self.bash, "--noprofile", "--norc", "-c", self.script],
            cwd=self.repo, env=env, capture_output=True, text=True, timeout=10,
        )

    def test_accepts_exact_dev_to_test_merge(self):
        result = self.check_guard()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_main_to_test_merge(self):
        result = self.check_guard(parents=[self.before, self.main], tree=self.empty_tree)
        self.assertNotEqual(result.returncode, 0)

    def test_rejects_unreviewed_parent_even_with_identical_tree(self):
        substitute = self.commit(self.dev_tree, self.before, label="unreviewed")
        result = self.check_guard(parents=[self.before, substitute])
        self.assertNotEqual(result.returncode, 0)

    def test_rejects_changed_release_tree(self):
        self.assertNotEqual(self.check_guard(tree=self.empty_tree).returncode, 0)

    def test_rejects_stale_dev_parent(self):
        advanced = self.commit(self.dev_tree, self.dev, label="new dev")
        self.git("update-ref", "refs/heads/dev", advanced)
        self.git("push", "--quiet", "origin", "refs/heads/dev")
        self.assertNotEqual(self.check_guard().returncode, 0)

    def test_rejects_reversed_merge_parents(self):
        self.assertNotEqual(
            self.check_guard(parents=[self.dev, self.before]).returncode, 0,
        )

    def test_rejects_single_parent_and_octopus_merges(self):
        for parents in ([self.dev], [self.before, self.dev, self.main]):
            with self.subTest(parents=len(parents)):
                self.assertNotEqual(self.check_guard(parents=parents).returncode, 0)

    def test_rejects_wrong_push_context(self):
        for environment in (
            {"BEFORE_SHA": self.main},
            {"PUSH_FORCED": "true"},
            {"GITHUB_REF": "refs/heads/main"},
            {"GITHUB_REF": "refs/heads/dev"},
            {"RELEASE_SHA": "not-a-full-sha"},
        ):
            with self.subTest(field=next(iter(environment))):
                self.assertNotEqual(self.check_guard(**environment).returncode, 0)


if __name__ == "__main__":
    unittest.main()
