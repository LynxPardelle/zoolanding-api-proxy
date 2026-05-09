import json
import os
import sys
import unittest

CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from tools.ensure_secret_placeholders import build_create_secret_command, build_placeholder_secret


class TestSecretPlaceholders(unittest.TestCase):
    def test_builds_placeholder_json_without_real_secret_values(self):
        secret = build_placeholder_secret(["clientId", "clientSecret"])

        self.assertEqual(secret, {
            "clientId": "__SET_IN_AWS_CONSOLE__",
            "clientSecret": "__SET_IN_AWS_CONSOLE__",
        })

    def test_builds_aws_cli_create_command_from_manifest_entry(self):
        entry = {
            "name": "zoolanding/api/music/tidal",
            "description": "TIDAL OAuth credentials for music.lynxpardelle.com.",
            "fields": ["clientId", "clientSecret"],
            "tags": {
                "DraftDomain": "music.lynxpardelle.com",
                "Provider": "TIDAL",
            },
        }

        command = build_create_secret_command(entry, region="us-east-1")

        self.assertEqual(command[:6], [
            "aws",
            "secretsmanager",
            "create-secret",
            "--region",
            "us-east-1",
            "--name",
        ])
        self.assertIn("zoolanding/api/music/tidal", command)
        self.assertIn("Key=ManagedBy,Value=zoolanding-api-proxy", command)
        self.assertIn("Key=Provider,Value=TIDAL", command)
        secret_string = command[command.index("--secret-string") + 1]
        self.assertEqual(json.loads(secret_string), {
            "clientId": "__SET_IN_AWS_CONSOLE__",
            "clientSecret": "__SET_IN_AWS_CONSOLE__",
        })
        self.assertNotIn("tidal-client-secret", secret_string)


if __name__ == "__main__":
    unittest.main()
