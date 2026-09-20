"""Manual-only TEST workflow and pre-credential identity gates."""

from pathlib import Path
import unittest

from tools import thn_dedicated_runtime_test as release


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/thn-dedicated-runtime-test.yml"


class DedicatedRuntimeWorkflowTests(unittest.TestCase):
    def test_workflow_has_no_automatic_deployment_trigger(self):
        self.assertTrue(WORKFLOW.is_file(), "dedicated manual workflow is missing")
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", source)
        self.assertNotIn("\n  push:", source)
        self.assertNotIn("\n  pull_request:", source)
        self.assertIn("environment: test", source)
        self.assertIn("options: [verify, create]", source)
        self.assertIn("default: verify", source)
        self.assertIn("python tools/thn_dedicated_runtime_test.py", source)
        self.assertNotIn("sam deploy", source)

    def test_context_requires_exact_test_branch_and_dedicated_role(self):
        self.assertTrue(hasattr(release, "validate_context"), "workflow context gate missing")
        values = {
            "GITHUB_REPOSITORY": "LynxPardelle/zoolanding-api-proxy",
            "GITHUB_REF": "refs/heads/test",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_SHA": "a" * 40,
            "SOURCE_SHA": "a" * 40,
            "AWS_CLOUDFORMATION_ROLE_ARN":
                "arn:aws:iam::123456789012:role/zoolanding-deployer-thn-auth-runtime-test-cfn-exec",
        }
        self.assertEqual(release.validate_context(values, "123456789012"),
                         values["AWS_CLOUDFORMATION_ROLE_ARN"])
        for key, value in (("GITHUB_REF", "refs/heads/dev"),
                           ("GITHUB_REPOSITORY", "other/repo"),
                           ("GITHUB_EVENT_NAME", "push"),
                           ("SOURCE_SHA", "b" * 40),
                           ("AWS_CLOUDFORMATION_ROLE_ARN",
                            "arn:aws:iam::123456789012:role/zoolanding-deployer-api-proxy-test-cfn-exec")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                release.validate_context({**values, key: value}, "123456789012")


if __name__ == "__main__":
    unittest.main()
