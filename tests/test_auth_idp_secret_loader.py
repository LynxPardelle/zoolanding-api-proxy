import json
import os
import unittest
from unittest.mock import patch

from tools import auth_idp_secret_loader as loader


class Completed:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TestAuthIdpSecretLoader(unittest.TestCase):
    def test_builds_zoosite_secret_names(self):
        self.assertEqual(
            loader.secret_name(tenant_id="zoosite", auth_profile_id="staff", provider_id="google"),
            "/zoolanding/auth/zoosite/staff/google",
        )

    def test_rejects_missing_or_placeholder_values(self):
        for payload in (
            {"clientId": "", "clientSecret": "valid-secret"},
            {"clientId": "valid-client", "clientSecret": "placeholder"},
            {"clientId": "fake-client", "clientSecret": "valid-secret"},
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(loader.LoaderError):
                    loader.validate_secret_payload(payload)

    def test_check_secret_reports_shape_without_returning_values(self):
        with patch.object(
            loader,
            "run_aws",
            return_value=Completed(
                stdout=json.dumps({"clientId": "google-client-id", "clientSecret": "google-client-secret"})
            ),
        ):
            status = loader.check_secret("/zoolanding/auth/zoosite/staff/google", region="us-east-1")

        self.assertEqual(status, {"exists": True, "validShape": True, "placeholder": False})
        self.assertNotIn("google-client-secret", json.dumps(status))

    def test_upsert_uses_secret_file_instead_of_secret_string_argument(self):
        calls = []

        def fake_run_aws(args, *, input_text=None):
            calls.append(args)
            if args[:2] == ["secretsmanager", "describe-secret"]:
                return Completed(returncode=255, stderr="ResourceNotFoundException")
            if args[:2] == ["secretsmanager", "create-secret"]:
                secret_string_arg = args[args.index("--secret-string") + 1]
                self.assertTrue(secret_string_arg.startswith("file://"))
                self.assertNotIn("google-client-secret", " ".join(args))
                return Completed()
            raise AssertionError(args)

        with patch.object(loader, "run_aws", side_effect=fake_run_aws):
            action = loader.write_secret(
                "/zoolanding/auth/zoosite/staff/google",
                {"clientId": "google-client-id", "clientSecret": "google-client-secret"},
                provider_id="google",
                tenant_id="zoosite",
                auth_profile_id="staff",
                region="us-east-1",
                dry_run=False,
            )

        self.assertEqual(action, "created")
        self.assertTrue(any(call[:2] == ["secretsmanager", "create-secret"] for call in calls))

    def test_build_payload_reads_environment_without_echoing(self):
        env = {
            "GOOGLE_CLIENT_ID": "google-client-id",
            "GOOGLE_CLIENT_SECRET": "google-client-secret",
        }
        with patch.dict(os.environ, env):
            payload = loader.build_secret_payload("google", no_prompt=True)

        self.assertEqual(payload["clientId"], "google-client-id")
        self.assertEqual(payload["clientSecret"], "google-client-secret")


if __name__ == "__main__":
    unittest.main()
