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
                    "id": "pokemon-detail",
                    "method": "GET",
                    "url": "https://pokeapi.co/api/v2/pokemon/pikachu",
                    "allowedInputFields": [],
                    "response": {
                        "singleItem": True,
                        "allowedFields": [
                            "id",
                            "name",
                            "sprites.other.official-artwork.front_default",
                            "types.type.name",
                        ],
                    },
                },
                {
                    "id": "pokemon-detail-template",
                    "method": "GET",
                    "urlTemplate": "https://pokeapi.co/api/v2/pokemon/{pokemonName}",
                    "allowedInputFields": ["pokemonName", "locale"],
                    "response": {
                        "singleItem": True,
                        "allowedFields": [
                            "id",
                            "name",
                            "sprites.other.official-artwork.front_default",
                            "types.type.name",
                        ],
                    },
                },
                {
                    "id": "bad-template",
                    "method": "GET",
                    "urlTemplate": "https://pokeapi.co/api/v2/pokemon/{secretName}",
                    "allowedInputFields": ["pokemonName"],
                    "response": {"allowedFields": ["name"]},
                },
                {
                    "id": "music-releases",
                    "method": "GET",
                    "url": "https://music.example.test/releases",
                    "allowedInputFields": ["artist"],
                    "response": {"allowedFields": ["items.title", "items.href"]},
                },
                {
                    "id": "tidal-albums",
                    "method": "GET",
                    "url": "https://openapi.tidal.com/v2/artists/10212180/relationships/albums",
                    "credentialRef": "zoolanding/api/music/tidal",
                    "auth": {
                        "type": "oauth2-client-credentials",
                        "tokenUrl": "https://auth.tidal.com/v1/oauth2/token",
                        "clientIdField": "clientId",
                        "clientSecretField": "clientSecret",
                    },
                    "headers": {
                        "Accept": "application/vnd.tidal.v1+json",
                    },
                    "allowedInputFields": ["countryCode", "include"],
                    "response": {
                        "allowedFields": [
                            "included.id",
                            "included.type",
                            "included.attributes.title",
                            "included.attributes.releaseDate",
                        ],
                    },
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
        if kwargs["url"] == "https://pokeapi.co/api/v2/pokemon/pikachu":
            return {
                "id": 25,
                "name": "pikachu",
                "sprites": {
                    "other": {
                        "official-artwork": {
                            "front_default": "https://raw.githubusercontent.com/PokeAPI/sprites/master/sprites/pokemon/other/official-artwork/25.png",
                        },
                    },
                },
                "types": [
                    {"slot": 1, "type": {"name": "electric", "url": "https://pokeapi.co/api/v2/type/13/"}},
                ],
                "internalToken": "must-not-return",
            }
        if kwargs["url"] == "https://pokeapi.co/api/v2/pokemon/charizard":
            return {
                "id": 6,
                "name": "charizard",
                "sprites": {
                    "other": {
                        "official-artwork": {
                            "front_default": "https://raw.githubusercontent.com/PokeAPI/sprites/master/sprites/pokemon/other/official-artwork/6.png",
                        },
                    },
                },
                "types": [
                    {"slot": 1, "type": {"name": "fire", "url": "https://pokeapi.co/api/v2/type/10/"}},
                    {"slot": 2, "type": {"name": "flying", "url": "https://pokeapi.co/api/v2/type/3/"}},
                ],
                "internalToken": "must-not-return",
            }
        if kwargs["url"] == "https://pokeapi.co/api/v2/pokemon/mr%2Fmime":
            return {
                "id": 122,
                "name": "mr-mime",
                "sprites": {
                    "other": {
                        "official-artwork": {
                            "front_default": "https://raw.githubusercontent.com/PokeAPI/sprites/master/sprites/pokemon/other/official-artwork/122.png",
                        },
                    },
                },
                "types": [
                    {"slot": 1, "type": {"name": "psychic", "url": "https://pokeapi.co/api/v2/type/14/"}},
                ],
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
        if kwargs["url"] == "https://openapi.tidal.com/v2/artists/10212180/relationships/albums":
            return {
                "data": [{"id": "500", "type": "albums"}],
                "included": [
                    {
                        "id": "500",
                        "type": "albums",
                        "attributes": {
                            "title": "Void Techno",
                            "releaseDate": "2018-09-07",
                            "privateDebug": "hidden",
                        },
                    }
                ],
                "accessToken": "must-not-return",
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
        self.assertEqual(self.fetch_calls[0]["headers"]["User-Agent"], lf.DEFAULT_USER_AGENT)
        self.assertEqual(self.fetch_calls[0]["query"], {"limit": 2, "offset": 0})

    def test_read_source_can_wrap_filtered_object_as_single_item(self):
        event = api_event("/api-proxy/read", {
            "domain": "music.lynxpardelle.com",
            "sourceId": "pokemon-detail",
        })

        with patch.object(lf, "_load_policy_for_domain", return_value=self.policy), \
                patch.object(lf, "_fetch_upstream", side_effect=self.fake_fetch):
            response = lf.lambda_handler(event, Ctx())

        payload = response_payload(response)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(payload["data"], {
            "items": [
                {
                    "id": 25,
                    "name": "pikachu",
                    "sprites": {
                        "other": {
                            "official-artwork": {
                                "front_default": "https://raw.githubusercontent.com/PokeAPI/sprites/master/sprites/pokemon/other/official-artwork/25.png",
                            },
                        },
                    },
                    "types": [
                        {"type": {"name": "electric"}},
                    ],
                },
            ],
        })
        self.assertNotIn("internalToken", response["body"])

    def test_read_source_resolves_url_template_and_forwards_remaining_query_input(self):
        event = api_event("/api-proxy/read", {
            "domain": "music.lynxpardelle.com",
            "sourceId": "pokemon-detail-template",
            "input": {"pokemonName": "charizard", "locale": "es"},
        })

        with patch.object(lf, "_load_policy_for_domain", return_value=self.policy), \
                patch.object(lf, "_fetch_upstream", side_effect=self.fake_fetch):
            response = lf.lambda_handler(event, Ctx())

        payload = response_payload(response)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(payload["data"]["items"][0]["name"], "charizard")
        self.assertEqual(self.fetch_calls[0]["url"], "https://pokeapi.co/api/v2/pokemon/charizard")
        self.assertEqual(self.fetch_calls[0]["query"], {"locale": "es"})
        self.assertNotIn("pokemonName", self.fetch_calls[0]["query"])

    def test_read_source_percent_encodes_url_template_values(self):
        event = api_event("/api-proxy/read", {
            "domain": "music.lynxpardelle.com",
            "sourceId": "pokemon-detail-template",
            "input": {"pokemonName": "mr/mime"},
        })

        with patch.object(lf, "_load_policy_for_domain", return_value=self.policy), \
                patch.object(lf, "_fetch_upstream", side_effect=self.fake_fetch):
            response = lf.lambda_handler(event, Ctx())

        payload = response_payload(response)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(payload["data"]["items"][0]["name"], "mr-mime")
        self.assertEqual(self.fetch_calls[0]["url"], "https://pokeapi.co/api/v2/pokemon/mr%2Fmime")
        self.assertEqual(self.fetch_calls[0]["query"], {})

    def test_rejects_url_template_placeholders_not_declared_by_policy(self):
        event = api_event("/api-proxy/read", {
            "domain": "music.lynxpardelle.com",
            "sourceId": "bad-template",
            "input": {"pokemonName": "pikachu"},
        })

        with patch.object(lf, "_load_policy_for_domain", return_value=self.policy), \
                patch.object(lf, "_fetch_upstream", side_effect=self.fake_fetch):
            response = lf.lambda_handler(event, Ctx())

        payload = response_payload(response)
        self.assertEqual(response["statusCode"], 400)
        self.assertIn("not allowed", payload["error"])
        self.assertEqual(self.fetch_calls, [])

    def test_rejects_invalid_url_template_input_values(self):
        event = api_event("/api-proxy/read", {
            "domain": "music.lynxpardelle.com",
            "sourceId": "pokemon-detail-template",
            "input": {"pokemonName": {"name": "pikachu"}},
        })

        with patch.object(lf, "_load_policy_for_domain", return_value=self.policy), \
                patch.object(lf, "_fetch_upstream", side_effect=self.fake_fetch):
            response = lf.lambda_handler(event, Ctx())

        payload = response_payload(response)
        self.assertEqual(response["statusCode"], 400)
        self.assertIn("must be a scalar", payload["error"])
        self.assertEqual(self.fetch_calls, [])

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

    def test_read_source_resolves_oauth_client_credentials_and_filters_tidal_response(self):
        event = api_event("/api-proxy/read", {
            "domain": "music.lynxpardelle.com",
            "sourceId": "tidal-albums",
            "input": {"countryCode": "MX", "include": "albums"},
        })

        with patch.object(lf, "_load_policy_for_domain", return_value=self.policy), \
                patch.object(lf, "_get_secret", return_value={
                    "clientId": "tidal-client-id",
                    "clientSecret": "tidal-client-secret",
                }), \
                patch.object(lf, "_fetch_oauth_client_credentials_token", return_value="tidal-access-token"), \
                patch.object(lf, "_fetch_upstream", side_effect=self.fake_fetch):
            response = lf.lambda_handler(event, Ctx())

        payload = response_payload(response)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(payload["data"], {
            "included": [
                {
                    "id": "500",
                    "type": "albums",
                    "attributes": {
                        "title": "Void Techno",
                        "releaseDate": "2018-09-07",
                    },
                },
            ],
        })
        self.assertEqual(self.fetch_calls[0]["headers"]["Authorization"], "Bearer tidal-access-token")
        self.assertEqual(self.fetch_calls[0]["headers"]["Accept"], "application/vnd.tidal.v1+json")
        self.assertEqual(self.fetch_calls[0]["query"], {"countryCode": "MX", "include": "albums"})
        self.assertNotIn("tidal-client-secret", response["body"])
        self.assertNotIn("tidal-access-token", response["body"])
        self.assertNotIn("privateDebug", response["body"])

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
