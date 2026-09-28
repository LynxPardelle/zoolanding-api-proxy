"""Execute the real shell guard using fake AWS/SAM programs, never the cloud."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "Linux deployment shell")
class DeploymentIdentityGuardTests(unittest.TestCase):
    def run_guard(self, **overrides):
        script = Path(__file__).resolve().parents[1] / "tools/run_test_change_set.sh"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, body in {
                "aws": "#!/bin/sh\necho 123456789012\n",
                "sam": "#!/bin/sh\necho reached-sam\nexit 77\n",
            }.items():
                program = root / name
                program.write_text(body)
                program.chmod(0o700)
            (root / ".aws-sam/build/release-tools").mkdir(parents=True)
            for name in ["parameters.json", "expected.json", "required.json",
                         ".aws-sam/build/template.yaml",
                         ".aws-sam/build/release-tools/review_test_change_set.py"]:
                (root / name).touch()
            env = {"PATH": str(root) + os.pathsep + os.defpath,
                   "HOME": str(root), "RUNNER_TEMP": str(root),
                   "STACK_NAME": "zoolanding-api-proxy-test",
                   "CHANGE_SET_NAME": "offline-check", "RELEASE_SHA": "a" * 40,
                   "ARTIFACTS_BUCKET": "offline-fixture",
                   "PARAMETER_FILE": "parameters.json",
                   "EXPECTED_PARAMETER_FILE": "expected.json",
                   "REQUIRED_PARAMETER_FILE": "required.json",
                   "AWS_REGION": "us-east-1", "GITHUB_RUN_ID": "1",
                   "GITHUB_RUN_ATTEMPT": "1",
                   "AWS_CLOUDFORMATION_ROLE_ARN":
                       "arn:aws:iam::123456789012:role/zoolanding-deployer-api-proxy-test-cfn-exec"}
            env.update(overrides)
            return subprocess.run(["bash", str(script)], cwd=root, env=env,
                                  capture_output=True, text=True, timeout=10)

    def test_wrong_identity_or_target_never_reaches_packaging(self):
        cases = [
            {"AWS_CLOUDFORMATION_ROLE_ARN": ""},
            {"AWS_CLOUDFORMATION_ROLE_ARN": "arn:aws:iam::123456789012:role/Administrator"},
            {"AWS_CLOUDFORMATION_ROLE_ARN":
             "arn:aws:iam::999999999999:role/zoolanding-deployer-api-proxy-test-cfn-exec"},
            {"AWS_REGION": "us-west-2"},
            {"STACK_NAME": "zoolanding-api-proxy-production"},
        ]
        for overrides in cases:
            with self.subTest(overrides=overrides):
                result = self.run_guard(**overrides)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("reached-sam", result.stdout)

    def test_matching_test_identity_reaches_fake_packaging(self):
        result = self.run_guard()
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertIn("reached-sam", result.stdout)

