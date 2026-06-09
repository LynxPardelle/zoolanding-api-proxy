import os
import sys
import unittest
from unittest.mock import patch

os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("CONFIG_TABLE_NAME", "zoolanding-config-registry")
os.environ.setdefault("CONFIG_PAYLOADS_BUCKET_NAME", "zoolanding-config-payloads")
os.environ.setdefault("LOG_LEVEL", "ERROR")

CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import lambda_function as lf
import zoolanding_lambda_common as common


class TestPolicyLoading(unittest.TestCase):
    def test_loads_server_policy_from_published_domain_prefix(self):
        metadata = {
            "domain": "music.lynxpardelle.com",
            "published": {
                "versionId": "20260507T010203Z-test",
                "prefix": "sites/music.lynxpardelle.com/versions/20260507T010203Z-test",
            },
        }
        policy = {"version": 1, "sources": [], "actions": []}

        with patch.object(lf, "load_item", return_value=metadata) as load_item, \
                patch.object(lf, "load_json_from_s3", return_value=policy) as load_json:
            result = lf._load_policy_for_domain("Music.LynxPardelle.com")

        self.assertEqual(result, policy)
        load_item.assert_called_once_with("zoolanding-config-registry", "SITE#music.lynxpardelle.com")
        load_json.assert_called_once_with(
            "zoolanding-config-payloads",
            "sites/music.lynxpardelle.com/versions/20260507T010203Z-test/music.lynxpardelle.com/server/integrations.json",
        )

    def test_missing_published_policy_is_not_found(self):
        metadata = {
            "domain": "music.lynxpardelle.com",
            "published": {"prefix": "sites/music.lynxpardelle.com/versions/current"},
        }

        with patch.object(lf, "load_item", return_value=metadata), \
                patch.object(lf, "load_json_from_s3", return_value=None):
            with self.assertRaises(lf.NotFoundError):
                lf._load_policy_for_domain("music.lynxpardelle.com")

    def test_missing_s3_payload_access_denied_is_treated_as_not_found(self):
        class FakeAccessDenied(Exception):
            response = {"Error": {"Code": "AccessDenied"}}

        class FakeS3Client:
            def get_object(self, **_kwargs):
                raise FakeAccessDenied()

        with patch.object(common, "ClientError", FakeAccessDenied), \
                patch.object(common, "get_s3_client", return_value=FakeS3Client()):
            result = common.load_json_from_s3("zoolanding-config-payloads", "missing/server/policy.json")

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
