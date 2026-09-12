"""Keep workflow discovery separate from privileged manual TEST operations."""
from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
BRANCH = "codex/thn-first-provisioning-20260912"
FILES = ("recover-aws-test.yml", "thn-first-provision-test.yml", "thn-retained-routes-test.yml")


class ManualWorkflowRegistrationTests(unittest.TestCase):
    def workflows(self):
        for name in FILES:
            yield name, yaml.load((ROOT / ".github/workflows" / name).read_text(encoding="utf-8"), Loader=yaml.BaseLoader)

    def test_registration_push_is_limited_to_existing_delivery_branch(self):
        for name, workflow in self.workflows():
            with self.subTest(workflow=name):
                self.assertEqual(set(workflow["on"]), {"push", "workflow_dispatch"})
                self.assertEqual(workflow["on"]["push"], {"branches": [BRANCH]})

    def test_registration_has_no_credentials_checkout_environment_or_artifact(self):
        for name, workflow in self.workflows():
            with self.subTest(workflow=name):
                self.assertIn("register", workflow["jobs"])
                self.assertEqual(workflow["jobs"]["register"], {
                    "if": "github.event_name == 'push'",
                    "runs-on": "ubuntu-24.04",
                    "permissions": {"contents": "read"},
                    "steps": [{"run": "echo 'TEST manual workflow registered. No checkout, environment, artifact or AWS credentials.'"}],
                })

    def test_every_operational_job_remains_manual_only(self):
        for name, workflow in self.workflows():
            for job_name, job in workflow["jobs"].items():
                if job_name == "register":
                    continue
                with self.subTest(workflow=name, job=job_name):
                    self.assertEqual(job.get("if"), "github.event_name == 'workflow_dispatch'")


if __name__ == "__main__":
    unittest.main()
