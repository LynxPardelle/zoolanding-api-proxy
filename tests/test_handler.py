import json
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


class Ctx:
    aws_request_id = "proxy-tests-request"


def api_event(path, body):
    return {
        "path": path,
        "rawPath": path,
        "requestContext": {"http": {"path": path}},
        "isBase64Encoded": False,
        "body": json.dumps(body),
    }


def response_payload(response):
    return json.loads(response["body"])


class TestApiProxyHandler(unittest.TestCase):
    def setUp(self):
        self.fetch_calls = []
        self.policy = {
            "version": 1,
            "sources": [
                {
                    "id": "pokemon-list",
                    "method": "GET",
                    "url": "https://pokeapi.co/api/v2/pokemon",
                    "allowedInputFields": ["limit", "offset"],
                    "response": {"allowedFields": ["results", "count"]},
                },
                {
                    "id": "music-releases",
                    "method": "GET",
                    "url": "https://music.example.test/releases",
                    "allowedInputFields": ["artist"],
                    "response": {"allowedFields": ["items.title", "items.href"]},
                },
            ],
            "actions": [
                {
                    "id": "newsletter-subscribe",
                    "method": "POST",
                    "url": "https://mailing.example.test/subscribe",
                    "credentialRef": "zoolanding/api/music/newsletter",
                    "auth": {"type": "bearer", "secretField": "accessToken"},
                    "allowedInputFields": ["email", "language"],
                    "response": {"allowedFields": ["status", "subscriberId"]},
                },
                {
                    "id": "song-rating",
                    "method": "PUT",
                    "url": "https://music.example.test/rating",
                    "allowedInputFields": ["songId", "rating"],
                    "response": {"allowedFields": ["status"]},
                },
                {
                    "id": "bad-method",
                    "method": "CONNECT",
                    "url": "https://music.example.test/tunnel",
                    "allowedInputFields": [],
                },
            ],
        }

    def fake_fetch(self, **kwargs):
        self.fetch_calls.append(kwargs)
        if kwargs["url"] == "https://pokeapi.co/api/v2/pokemon":
            return {
                "count": 2,
                "results": [{"name": "bulbasaur"}, {"name": "ivysaur"}],
                "internalToken": "must-not-return",
            }
        if kwargs["url"] == "https://mailing.example.test/subscribe":
            return {
                "status": "subscribed",
                "subscriberId": "sub_123",
                "accessToken": "must-not-return",
            }
        if kwargs["url"] == "https://music.example.test/rating":
            return {"status": "updated", "debug": "hidden"}
        if kwargs["url"] == "https://music.example.test/releases":
            return {
                "items": [
                    {"title": "Looking Bass", "href": "https://example.test/1", "internalId": "secret"},
                    {"title": "Melancholy", "href": "https://example.test/2", "internalId": "secret"},
                ],
                "debug": "hidden",
            }
        raise lf.UpstreamError("unexpected upstream target")

    def test_read_source_allows_multiple_sources_and_filters_response_fields(self):
        event = api_event("/api-proxy/read", {
            "domain": "music.lynxpardelle.com",
            "pageId": "default",
            "sourceId": "pokemon-list",
            "input": {"limit": 2, "offset": 0},
        })

        with patch.object(lf, "_load_policy_for_domain", return_value=self.policy), \
                patch.object(lf, "_fetch_upstream", side_effect=self.fake_fetch):
            response = lf.lambda_handler(event, Ctx())

        payload = response_payload(response)
        self.assertEqual(response["statusCode"], 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["data"], {
            "count": 2,
            "results": [{"name": "bulbasaur"}, {"name": "ivysaur"}],
        })
        self.assertEqual(len(self.fetch_calls), 1)
        self.assertEqual(self.fetch_calls[0]["method"], "GET")
        self.assertEqual(self.fetch_calls[0]["query"], {"limit": 2, "offset": 0})

    def test_read_source_reflects_managed_site_origin(self):
        event = api_event("/api-proxy/read", {
            "domain": "music.lynxpardelle.com",
            "pageId": "default",
            "sourceId": "pokemon-list",
            "input": {"limit": 2},
        })
        event["headers"] = {"Origin": "https://music.lynxpardelle.com"}

        with patch.object(lf, "_load_policy_for_domain", return_value=self.policy), \
                patch.object(lf, "_fetch_upstream", side_effect=self.fake_fetch), \
                patch.object(common, "load_item", return_value={"published": {"versionId": "v1"}}), \
                patch.dict(os.environ, {"ALLOWED_CORS_ORIGINS": "https://zoolandingpage.com.mx,https://test.zoolandingpage.com.mx"}):
            response = lf.lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(response["headers"]["Access-Control-Allow-Origin"], "https://music.lynxpardelle.com")

    def test_public_origin_cannot_request_another_domain(self):
        event = api_event("/api-proxy/read", {
            "domain": "zoolandingpage.com.mx",
            "sourceId": "pokemon-list",
            "input": {"limit": 2},
        })
        event["headers"] = {"Origin": "https://music.lynxpardelle.com"}

        response = lf.lambda_handler(event, Ctx())

        payload = response_payload(response)
        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(payload["error"], "Origin is not allowed for requested domain")
        self.assertEqual(self.fetch_calls, [])

    def test_unknown_source_rejected_without_upstream_call(self):
        event = api_event("/api-proxy/read", {
            "domain": "music.lynxpardelle.com",
            "sourceId": "missing",
        })

        with patch.object(lf, "_load_policy_for_domain", return_value=self.policy), \
                patch.object(lf, "_fetch_upstream", side_effect=self.fake_fetch):
            response = lf.lambda_handler(event, Ctx())

        payload = response_payload(response)
        self.assertEqual(response["statusCode"], 404)
        self.assertFalse(payload["ok"])
        self.assertEqual(self.fetch_calls, [])

    def test_filters_nested_array_fields(self):
        event = api_event("/api-proxy/read", {
            "domain": "music.lynxpardelle.com",
            "sourceId": "music-releases",
            "input": {"artist": "Lynx Pardelle"},
        })

        with patch.object(lf, "_load_policy_for_domain", return_value=self.policy), \
                patch.object(lf, "_fetch_upstream", side_effect=self.fake_fetch):
            response = lf.lambda_handler(event, Ctx())

        payload = response_payload(response)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(payload["data"], {
            "items": [
                {"title": "Looking Bass", "href": "https://example.test/1"},
                {"title": "Melancholy", "href": "https://example.test/2"},
            ],
        })
        self.assertNotIn("internalId", response["body"])
        self.assertNotIn("debug", response["body"])

    def test_rejects_input_fields_not_declared_by_policy(self):
        event = api_event("/api-proxy/action", {
            "domain": "music.lynxpardelle.com",
            "actionId": "newsletter-subscribe",
            "input": {
                "email": "listener@example.test",
                "language": "en",
                "admin": True,
            },
        })

        with patch.object(lf, "_load_policy_for_domain", return_value=self.policy), \
                patch.object(lf, "_fetch_upstream", side_effect=self.fake_fetch):
            response = lf.lambda_handler(event, Ctx())

        payload = response_payload(response)
        self.assertEqual(response["statusCode"], 400)
        self.assertFalse(payload["ok"])
        self.assertIn("not allowed", payload["error"])
        self.assertEqual(self.fetch_calls, [])

    def test_rejects_http_method_not_allowed_by_proxy(self):
        event = api_event("/api-proxy/action", {
            "domain": "music.lynxpardelle.com",
            "actionId": "bad-method",
        })

        with patch.object(lf, "_load_policy_for_domain", return_value=self.policy), \
                patch.object(lf, "_fetch_upstream", side_effect=self.fake_fetch):
            response = lf.lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(self.fetch_calls, [])

    def test_action_resolves_secret_and_filters_secret_from_response(self):
        event = api_event("/api-proxy/action", {
            "domain": "music.lynxpardelle.com",
            "pageId": "default",
            "actionId": "newsletter-subscribe",
            "input": {
                "email": "listener@example.test",
                "language": "en",
            },
        })

        with patch.object(lf, "_load_policy_for_domain", return_value=self.policy), \
                patch.object(lf, "_get_secret", return_value={"accessToken": "super-secret-token"}), \
                patch.object(lf, "_fetch_upstream", side_effect=self.fake_fetch):
            response = lf.lambda_handler(event, Ctx())

        payload = response_payload(response)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(payload["data"], {
            "status": "subscribed",
            "subscriberId": "sub_123",
        })
        self.assertEqual(self.fetch_calls[0]["headers"]["Authorization"], "Bearer super-secret-token")
        self.assertNotIn("super-secret-token", response["body"])
        self.assertNotIn("accessToken", response["body"])

    def test_put_action_uses_json_body_and_filters_response(self):
        event = api_event("/api-proxy/action", {
            "domain": "music.lynxpardelle.com",
            "actionId": "song-rating",
            "input": {"songId": "lynx-track-1", "rating": 5},
        })

        with patch.object(lf, "_load_policy_for_domain", return_value=self.policy), \
                patch.object(lf, "_fetch_upstream", side_effect=self.fake_fetch):
            response = lf.lambda_handler(event, Ctx())

        payload = response_payload(response)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(payload["data"], {"status": "updated"})
        self.assertEqual(self.fetch_calls[0]["method"], "PUT")
        self.assertEqual(self.fetch_calls[0]["body"], {"songId": "lynx-track-1", "rating": 5})

    def test_upstream_failure_returns_safe_error_body(self):
        event = api_event("/api-proxy/action", {
            "domain": "music.lynxpardelle.com",
            "actionId": "song-rating",
            "input": {"songId": "lynx-track-1", "rating": 5},
        })

        def fail_fetch(**_kwargs):
            raise lf.UpstreamError("upstream leaked super-secret-token")

        with patch.object(lf, "_load_policy_for_domain", return_value=self.policy), \
                patch.object(lf, "_fetch_upstream", side_effect=fail_fetch):
            response = lf.lambda_handler(event, Ctx())

        payload = response_payload(response)
        self.assertEqual(response["statusCode"], 502)
        self.assertEqual(payload["error"], "Upstream request failed")
        self.assertNotIn("super-secret-token", response["body"])

    def test_preflight_reflects_allowed_testing_origin(self):
        event = api_event("/api-proxy/read", {})
        event["httpMethod"] = "OPTIONS"
        event["headers"] = {"origin": "https://test.zoolandingpage.com.mx"}

        with patch.dict(os.environ, {"ALLOWED_CORS_ORIGINS": "https://zoolandingpage.com.mx,https://test.zoolandingpage.com.mx"}):
            response = lf.lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(response["headers"]["Access-Control-Allow-Origin"], "https://test.zoolandingpage.com.mx")
        self.assertEqual(response["headers"]["Vary"], "Origin")

    def test_preflight_reflects_managed_site_origin(self):
        event = api_event("/api-proxy/read", {})
        event["httpMethod"] = "OPTIONS"
        event["headers"] = {"Origin": "https://music.lynxpardelle.com"}

        with patch.object(common, "load_item", return_value={"published": {"versionId": "v1"}}), \
                patch.dict(os.environ, {"ALLOWED_CORS_ORIGINS": "https://zoolandingpage.com.mx,https://test.zoolandingpage.com.mx"}):
            response = lf.lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(response["headers"]["Access-Control-Allow-Origin"], "https://music.lynxpardelle.com")

    def test_preflight_does_not_reflect_unlisted_public_origin(self):
        event = api_event("/api-proxy/action", {})
        event["httpMethod"] = "OPTIONS"
        event["headers"] = {"Origin": "https://attacker.example"}

        with patch.dict(os.environ, {"ALLOWED_CORS_ORIGINS": "https://zoolandingpage.com.mx,https://test.zoolandingpage.com.mx"}):
            response = lf.lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(response["headers"]["Access-Control-Allow-Origin"], "https://zoolandingpage.com.mx")

    def test_preflight_allows_localhost_for_qa(self):
        event = api_event("/api-proxy/read", {})
        event["httpMethod"] = "OPTIONS"
        event["headers"] = {"Origin": "http://127.0.0.1:4202"}

        with patch.dict(os.environ, {"ALLOWED_CORS_ORIGINS": "https://zoolandingpage.com.mx,https://test.zoolandingpage.com.mx"}):
            response = lf.lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(response["headers"]["Access-Control-Allow-Origin"], "http://127.0.0.1:4202")


if __name__ == "__main__":
    unittest.main()
