"""Manual-only TEST workflow and pre-credential identity gates."""

from pathlib import Path
import io
import os
import unittest
from unittest.mock import patch

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
        self.assertIn("secrets.THN_FIRST_PLAN_REFERENCE_JSON", source)
        self.assertNotIn("secrets.THN_DEDICATED_RUNTIME_PLAN_JSON", source)
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
        with patch.dict(os.environ, values):
            self.assertEqual(release.validate_context(os.environ, "123456789012"),
                             values["AWS_CLOUDFORMATION_ROLE_ARN"])
        for key, value in (("GITHUB_REF", "refs/heads/dev"),
                           ("GITHUB_REPOSITORY", "other/repo"),
                           ("GITHUB_EVENT_NAME", "push"),
                           ("SOURCE_SHA", "b" * 40),
                           ("AWS_CLOUDFORMATION_ROLE_ARN",
                            "arn:aws:iam::123456789012:role/zoolanding-deployer-api-proxy-test-cfn-exec")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                release.validate_context({**values, key: value}, "123456789012")

    def test_check_context_cli_accepts_real_os_environ_mapping(self):
        values = {
            "GITHUB_REPOSITORY": "LynxPardelle/zoolanding-api-proxy",
            "GITHUB_REF": "refs/heads/test",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_SHA": "a" * 40,
            "SOURCE_SHA": "a" * 40,
            "AWS_CLOUDFORMATION_ROLE_ARN":
                "arn:aws:iam::765932874577:role/zoolanding-deployer-thn-auth-runtime-test-cfn-exec",
        }
        output = io.StringIO()
        with patch.dict(os.environ, values), patch("sys.argv", ["release", "--check-context"]), \
                patch("sys.stdout", output):
            self.assertEqual(release.main(), 0)
        self.assertEqual(output.getvalue().strip(), "dedicated_runtime_context_verified")


if __name__ == "__main__":
    unittest.main()
