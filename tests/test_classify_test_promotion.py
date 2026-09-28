"""Exercise exact TEST source-only selection without AWS or release artifacts."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SHA, TREE, BASE = (letter * 40 for letter in "abc")


class PromotionSelectionTests(unittest.TestCase):
    def module(self):
        path = ROOT / "tools/classify_test_promotion.py"
        self.assertTrue(path.is_file(), "source-only selection is not implemented")
        spec = importlib.util.spec_from_file_location("promotion", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def selection(self, **changes):
        return json.dumps(dict(schemaVersion=1, mode="thn-source-only", devSha=SHA,
                               devTree=TREE, testBaseSha=BASE) | changes)

    def test_absent_selection_preserves_ordinary_delivery(self):
        for raw in (None, ""):
            self.assertEqual(self.module().classify_selection(raw, SHA, TREE, BASE), "legacy")

    def test_exact_selection_chooses_source_only(self):
        self.assertEqual(self.module().classify_selection(self.selection(), SHA, TREE, BASE), "thn-source-only")

    def test_invalid_and_ambiguous_selection_fails_closed(self):
        module = self.module()
        invalid = [" ", "{", "null", "[]", "true", self.selection(schemaVersion=True),
                   self.selection(mode="legacy"), self.selection(extra=1), self.selection(devSha=42),
                   self.selection(devTree="B" * 40), self.selection(testBaseSha="0" * 40),
                   self.selection().replace('"schemaVersion": 1', '"schemaVersion": NaN'),
                   self.selection().replace('"schemaVersion": 1', '"schemaVersion": 1, "schemaVersion": 1'),
                   " " * 4097, self.selection().replace(', "testBaseSha": "' + BASE + '"', "")]
        for raw in invalid:
            with self.subTest(raw=raw[:50]), self.assertRaises(module.PromotionSelectionError):
                module.classify_selection(raw, SHA, TREE, BASE)

    def test_stale_source_tree_or_test_base_is_rejected(self):
        module = self.module()
        for key in ("devSha", "devTree", "testBaseSha"):
            with self.subTest(key=key), self.assertRaisesRegex(module.PromotionSelectionError, "stale"):
                module.classify_selection(self.selection(**{key: "d" * 40}), SHA, TREE, BASE)

    def test_invalid_observed_context_never_selects_legacy(self):
        module = self.module()
        for args in ((None, TREE, BASE), (SHA, "0" * 40, BASE), (SHA, TREE, "")):
            with self.assertRaisesRegex(module.PromotionSelectionError, "context"):
                module.classify_selection(None, *args)

    def test_cli_sanitizes_errors_and_rejects_overrides(self):
        self.module()
        env = dict(os.environ, API_TEST_PROMOTION_SELECTION_JSON=self.selection(),
                   PROMOTED_DEV_SHA=SHA, PROMOTED_DEV_TREE=TREE, PROMOTED_TEST_BASE_SHA=BASE)
        command = [sys.executable, str(ROOT / "tools/classify_test_promotion.py")]
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "thn-source-only\n", ""))
        for raw, args in (("private-marker-do-not-echo", []), (self.selection(), ["legacy"])):
            result = subprocess.run(command + args, env=env | {"API_TEST_PROMOTION_SELECTION_JSON": raw}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertNotIn("private-marker", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_selected_workflow_cannot_transport_or_deploy_ordinary_release(self):
        import yaml
        workflow = yaml.safe_load((ROOT / ".github/workflows/deploy-test.yml").read_text(encoding="utf-8"))
        jobs = workflow["jobs"]
        self.assertEqual(jobs["deploy"].get("if"), "needs.validate.outputs.promotion_mode == 'legacy'")
        steps = jobs["validate"]["steps"]
        classifier = next(s for s in steps if s.get("id") == "promotion")
        self.assertIn("vars.API_TEST_PROMOTION_SELECTION_JSON", str(classifier["env"]))
        self.assertIn("HEAD^1", classifier["run"])
        for step in steps:
            if step.get("name") in ("Assemble immutable release artifact", "Compute release identity", "Define artifact name", "Upload exact validated artifact"):
                self.assertEqual(step.get("if"), "steps.promotion.outputs.mode == 'legacy'")
        self.assertNotIn("id-token", jobs["validate"]["permissions"])
        self.assertNotIn("configure-aws-credentials", str(steps))


if __name__ == "__main__":
    unittest.main()
