import json
import os
from pathlib import Path
import re
import sys
from tempfile import TemporaryDirectory
import unittest
import time
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("CONFIG_TABLE_NAME", "zoolanding-config-registry")
os.environ.setdefault("CONFIG_PAYLOADS_BUCKET_NAME", "zoolanding-config-payloads")
os.environ.setdefault("LOG_LEVEL", "ERROR")

CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import auth_service as auth
import lambda_function as lf
import zoolanding_lambda_common as common


class Ctx:
    aws_request_id = "auth-service-tests-request"


def api_event(path, body=None, *, method="POST", headers=None, query=None, request_context=None):
    return {
        "path": path,
        "rawPath": path,
        "httpMethod": method,
        "headers": headers or {},
        "queryStringParameters": query or {},
        "requestContext": request_context or {"http": {"path": path, "method": method}},
        "isBase64Encoded": False,
        "body": json.dumps(body) if body is not None else None,
    }


def payload(response):
    return json.loads(response["body"])


def active_registry():
    return {
        "version": 1,
        "profiles": [
            {
                "authProfileId": "staff",
                "status": "active",
                "tenantId": "tenant-a",
                "issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
                "hostedUiDomain": "https://auth.example.test",
                "clientId": "public-client-id",
                "audiences": ["public-client-id"],
                "loginPath": "/login",
                "logoutPath": "/logout",
                "callbackUrls": ["https://example.test/auth/callback"],
                "logoutUrls": ["https://example.test/logout"],
                "scopes": ["openid", "email", "profile"],
                "allowedGroups": ["Editors"],
                "tenantClaim": "custom:tenant_id",
                "groupClaim": "cognito:groups",
                "socialIdpSecretRefs": {
                    "google": "/zoolanding/auth/tenant-a/staff/google",
                    "facebook": "/zoolanding/auth/tenant-a/staff/facebook",
                },
            },
            {
                "authProfileId": "planned",
                "status": "planned",
                "tenantId": "tenant-a",
                "issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_planned",
                "hostedUiDomain": "https://planned-auth.example.test",
                "clientId": "planned-public-client-id",
                "audiences": ["planned-public-client-id"],
                "loginPath": "/login",
                "logoutPath": "/logout",
                "callbackUrls": ["https://example.test/auth/callback"],
                "logoutUrls": ["https://example.test/logout"],
                "allowedGroups": ["Viewers"],
            },
        ],
    }


class TestAuthServiceRuntimeConfig(unittest.TestCase):
    def test_runtime_config_returns_public_active_profile_without_secret_refs(self):
        event = api_event("/auth/runtime-config", {
            "domain": "Example.Test",
            "authProfileId": "staff",
        })

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()):
            response = auth.auth_lambda_handler(event, Ctx())

        body = payload(response)
        self.assertEqual(response["statusCode"], 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["auth"]["enabled"], True)
        self.assertEqual(body["auth"]["authProfileId"], "staff")
        self.assertEqual(body["auth"]["provider"], "cognito")
        self.assertEqual(body["auth"]["clientId"], "public-client-id")
        self.assertEqual(body["auth"]["loginPath"], "/login")
        self.assertEqual(body["auth"]["redirectPath"], "/auth/callback")
        self.assertEqual(body["auth"]["logoutPath"], "/logout")
        self.assertEqual(body["auth"]["groupsClaim"], "cognito:groups")
        self.assertEqual(body["auth"]["allowedGroups"], ["Editors"])
        self.assertNotIn("profileId", body["auth"])
        self.assertNotIn("callbackUrls", body["auth"])
        self.assertNotIn("jwksUrl", body["auth"])
        self.assertNotIn("socialIdpSecretRefs", json.dumps(body))
        self.assertNotIn("clientSecret", json.dumps(body))
        self.assertNotIn("facebook", json.dumps(body))

    def test_runtime_config_disables_profiles_that_are_not_active(self):
        event = api_event("/auth/runtime-config", {
            "domain": "example.test",
            "authProfileId": "planned",
        })

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()):
            response = auth.auth_lambda_handler(event, Ctx())

        body = payload(response)
        self.assertEqual(response["statusCode"], 200)
        self.assertFalse(body["auth"]["enabled"])
        self.assertEqual(body["auth"]["authProfileId"], "planned")
        self.assertEqual(body["auth"]["provider"], "cognito")
        self.assertEqual(body["auth"]["clientId"], "planned-public-client-id")
        self.assertEqual(body["auth"]["redirectPath"], "/auth/callback")
        self.assertEqual(body["auth"]["logoutPath"], "/logout")
        self.assertNotIn("status", body["auth"])
        self.assertNotIn("socialIdpSecretRefs", json.dumps(body))
        self.assertNotIn("clientSecret", json.dumps(body))

    def test_runtime_config_rejects_browser_supplied_secret_or_policy_fields(self):
        event = api_event("/auth/runtime-config", {
            "domain": "example.test",
            "authProfileId": "staff",
            "clientSecret": "x",
        })

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()):
            response = auth.auth_lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(payload(response)["error"], "Unsupported auth runtime option")
        self.assertNotIn("clientSecret", json.dumps(payload(response)))

    def test_lambda_function_dispatches_auth_runtime_config_route(self):
        event = api_event("/auth/runtime-config", {
            "domain": "example.test",
            "authProfileId": "staff",
        })

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()):
            response = lf.lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 200)
        self.assertTrue(payload(response)["auth"]["enabled"])

    def test_lambda_function_dispatches_stage_prefixed_auth_runtime_config_route(self):
        event = api_event("/Prod/auth/runtime-config", {
            "domain": "example.test",
            "authProfileId": "staff",
        })

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()):
            response = lf.lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 200)
        self.assertTrue(payload(response)["auth"]["enabled"])

    def test_public_origin_cannot_request_runtime_config_for_another_domain(self):
        event = api_event(
            "/auth/runtime-config",
            {"domain": "example.test", "authProfileId": "staff"},
            headers={"Origin": "https://music.example.test"},
        )

        with patch.object(auth, "load_item", return_value=None), \
                patch.object(auth, "load_auth_registry_for_domain") as load_registry:
            response = auth.auth_lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(payload(response)["error"], "Origin is not allowed for requested domain")
        load_registry.assert_not_called()

    def test_managed_alias_origin_can_request_canonical_runtime_config(self):
        event = api_event(
            "/auth/runtime-config",
            {"domain": "example.test", "authProfileId": "staff"},
            headers={"Origin": "https://alias.example.test"},
        )
        metadata = {
            "published": {
                "versionId": "v1",
                "prefix": "sites/example.test/versions/v1",
            },
            "environmentAliases": {
                "production": ["alias.example.test"],
            },
        }

        def auth_load_item(_table_name, pk, sk="METADATA"):
            if pk == "SITE#example.test" and sk == "METADATA":
                return metadata
            return None

        def cors_load_item(_table_name, pk, sk="METADATA"):
            if pk == "ALIAS#alias.example.test" and sk == "SITE":
                return {"domain": "example.test"}
            return None

        with patch.object(auth, "load_item", side_effect=auth_load_item), \
                patch.object(auth, "load_json_from_s3", return_value=active_registry()), \
                patch.object(common, "load_item", side_effect=cors_load_item), \
                patch.dict(os.environ, {"ALLOWED_CORS_ORIGINS": "https://zoolandingpage.com.mx,https://test.zoolandingpage.com.mx"}):
            response = auth.auth_lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(response["headers"]["Access-Control-Allow-Origin"], "https://alias.example.test")
        self.assertTrue(payload(response)["auth"]["enabled"])

    def test_alias_lookup_origin_can_request_canonical_runtime_config(self):
        event = api_event(
            "/auth/runtime-config",
            {"domain": "example.test", "authProfileId": "staff"},
            headers={"Origin": "https://lookup-alias.example.test"},
        )
        metadata = {
            "published": {
                "versionId": "v1",
                "prefix": "sites/example.test/versions/v1",
            },
        }

        def auth_load_item(_table_name, pk, sk="METADATA"):
            if pk == "SITE#example.test" and sk == "METADATA":
                return metadata
            if pk == "ALIAS#lookup-alias.example.test" and sk == "SITE":
                return {"domain": "example.test"}
            return None

        def cors_load_item(_table_name, pk, sk="METADATA"):
            if pk == "ALIAS#lookup-alias.example.test" and sk == "SITE":
                return {"domain": "example.test"}
            return None

        with patch.object(auth, "load_item", side_effect=auth_load_item), \
                patch.object(auth, "load_json_from_s3", return_value=active_registry()), \
                patch.object(common, "load_item", side_effect=cors_load_item), \
                patch.dict(os.environ, {"ALLOWED_CORS_ORIGINS": "https://zoolandingpage.com.mx,https://test.zoolandingpage.com.mx"}):
            response = auth.auth_lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(response["headers"]["Access-Control-Allow-Origin"], "https://lookup-alias.example.test")
        self.assertTrue(payload(response)["auth"]["enabled"])

    def test_test_origin_can_preview_runtime_config_for_other_domains(self):
        event = api_event(
            "/auth/runtime-config",
            {"domain": "example.test", "authProfileId": "staff"},
            headers={"Origin": "https://test.zoolandingpage.com.mx"},
        )

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()), \
                patch.dict(os.environ, {"ALLOWED_CORS_ORIGINS": "https://zoolandingpage.com.mx,https://test.zoolandingpage.com.mx"}):
            response = auth.auth_lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(response["headers"]["Access-Control-Allow-Origin"], "https://test.zoolandingpage.com.mx")
        self.assertTrue(payload(response)["auth"]["enabled"])


class TestAuthServiceTemplateContract(unittest.TestCase):
    def test_provisioning_plan_post_route_requires_aws_iam_authorizer(self):
        with open(os.path.join(PROJECT_ROOT, "template.yaml"), encoding="utf-8") as template_file:
            template = template_file.read()

        self.assertRegex(
            template,
            re.compile(
                r"AuthProvisioningPlanPost:.*?Method:\s*POST.*?Auth:\s*Authorizer:\s*AWS_IAM",
                re.S,
            ),
        )


class TestAuthServiceProvisioningPlan(unittest.TestCase):
    def test_provisioning_plan_is_denied_by_default(self):
        event = api_event("/auth/provisioning-plan", {
            "domain": "example.test",
            "authProfileId": "staff",
        })

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()):
            response = auth.auth_lambda_handler(event, Ctx())

        body = payload(response)
        self.assertEqual(response["statusCode"], 403)
        self.assertEqual(body["error"], "Provisioning plan access denied")
        self.assertNotIn("google", json.dumps(body))

    def test_trusted_server_caller_can_read_plan_with_secret_refs_but_no_raw_credentials(self):
        event = api_event(
            "/auth/provisioning-plan",
            {"domain": "example.test", "authProfileId": "staff"},
            request_context={
                "identity": {
                    "userArn": "arn:aws:sts::123456789012:assumed-role/zoolanding-auth-planner/session"
                }
            },
        )

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()), \
                patch.dict(os.environ, {"AUTH_PROVISIONING_ALLOWED_ROLE_NAMES": "zoolanding-auth-planner"}):
            response = auth.auth_lambda_handler(event, Ctx())

        body = payload(response)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(body["plan"]["mode"], "plan-only")
        self.assertEqual(body["plan"]["provider"], "cognito")
        self.assertEqual(body["plan"]["tenantId"], "tenant-a")
        self.assertEqual(body["plan"]["socialIdpSecretRefs"]["google"], "/zoolanding/auth/tenant-a/staff/google")
        self.assertNotIn("clientSecretValue", json.dumps(body))
        self.assertNotIn("refreshToken", json.dumps(body))


class TestAuthServiceAuthorizer(unittest.TestCase):
    def test_verify_jwt_validates_rs256_signature_and_accepts_cognito_client_id(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = jwt.encode(
            {
                "sub": "user-123",
                "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
                "client_id": "public-client-id",
                "exp": int(time.time()) + 300,
            },
            private_key,
            algorithm="RS256",
            headers={"kid": "local-test-key"},
        )

        class FakeSigningKey:
            key = private_key.public_key()

        class FakeJwkClient:
            def __init__(self, jwks_url):
                self.jwks_url = jwks_url

            def get_signing_key_from_jwt(self, received_token):
                self.received_token = received_token
                return FakeSigningKey()

        with patch.object(auth, "PyJWKClient", FakeJwkClient):
            claims = auth.verify_jwt(
                token,
                issuer="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
                audiences=["public-client-id"],
                jwks_url="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool/.well-known/jwks.json",
            )

        self.assertEqual(claims["sub"], "user-123")
        self.assertEqual(claims["client_id"], "public-client-id")

    def test_jwt_authorizer_allows_matching_tenant_audience_and_group_without_echoing_token(self):
        event = {
            "type": "TOKEN",
            "authorizationToken": "Bearer header.payload.signature",
            "methodArn": "arn:aws:execute-api:us-east-1:123456789012:api/Prod/GET/blogs",
            "headers": {"x-zoolanding-domain": "example.test", "x-zoolanding-auth-profile-id": "staff"},
        }
        verified_claims = {
            "sub": "user-123",
            "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
            "client_id": "public-client-id",
            "custom:tenant_id": "tenant-a",
            "cognito:groups": ["Editors"],
        }

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()), \
                patch.object(auth, "verify_jwt", return_value=verified_claims) as verify_jwt:
            response = auth.jwt_authorizer_handler(event, Ctx())

        self.assertEqual(response["principalId"], "user-123")
        self.assertEqual(response["policyDocument"]["Statement"][0]["Effect"], "Allow")
        self.assertEqual(response["context"]["domain"], "example.test")
        self.assertEqual(response["context"]["authProfileId"], "staff")
        self.assertEqual(response["context"]["tenantId"], "tenant-a")
        self.assertNotIn("header.payload.signature", json.dumps(response))
        verify_jwt.assert_called_once()

    def test_jwt_authorizer_denies_claims_without_required_group(self):
        event = {
            "type": "TOKEN",
            "authorizationToken": "Bearer header.payload.signature",
            "methodArn": "arn:aws:execute-api:us-east-1:123456789012:api/Prod/GET/blogs",
            "headers": {"x-zoolanding-domain": "example.test", "x-zoolanding-auth-profile-id": "staff"},
        }
        verified_claims = {
            "sub": "user-123",
            "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
            "client_id": "public-client-id",
            "custom:tenant_id": "tenant-a",
            "cognito:groups": ["Viewers"],
        }

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()), \
                patch.object(auth, "verify_jwt", return_value=verified_claims):
            response = auth.jwt_authorizer_handler(event, Ctx())

        self.assertEqual(response["policyDocument"]["Statement"][0]["Effect"], "Deny")
        self.assertNotIn("header.payload.signature", json.dumps(response))


class TestAuthRegistryAdapter(unittest.TestCase):
    def test_dry_run_local_registry_directory_resolves_stage_prefixed_runtime_config_without_secrets(self):
        with TemporaryDirectory() as temp_dir:
            registry_dir = Path(temp_dir) / "zoositioweb.com.mx" / "server"
            registry_dir.mkdir(parents=True)
            (registry_dir / "auth-profile-registry.json").write_text(
                json.dumps(active_registry()),
                encoding="utf-8",
            )

            event = api_event(
                "/Prod/auth/runtime-config",
                {"domain": "zoositioweb.com.mx", "authProfileId": "staff"},
                headers={"Origin": "http://127.0.0.1:4202"},
            )

            with patch.dict(os.environ, {
                "DRY_RUN": "1",
                "LOCAL_AUTH_REGISTRY_DIR": temp_dir,
            }), patch.object(auth, "load_item") as load_item:
                response = lf.lambda_handler(event, Ctx())

        body = payload(response)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(response["headers"]["Access-Control-Allow-Origin"], "http://127.0.0.1:4202")
        self.assertTrue(body["ok"])
        self.assertEqual(body["domain"], "zoositioweb.com.mx")
        self.assertTrue(body["auth"]["enabled"])
        self.assertEqual(body["auth"]["authProfileId"], "staff")
        self.assertEqual(body["auth"]["provider"], "cognito")
        self.assertEqual(body["auth"]["clientId"], "public-client-id")
        self.assertNotIn("socialIdpSecretRefs", json.dumps(body))
        self.assertNotIn("clientSecret", json.dumps(body))
        self.assertNotIn("refreshToken", json.dumps(body))
        load_item.assert_not_called()

    def test_registry_adapter_loads_server_only_registry_from_published_s3_prefix(self):
        metadata = {
            "published": {
                "versionId": "v1",
                "prefix": "sites/example.test/versions/v1",
            },
        }

        with patch.object(auth, "load_item", return_value=metadata) as load_item, \
                patch.object(auth, "load_json_from_s3", return_value=active_registry()) as load_json:
            result = auth.load_auth_registry_for_domain("Example.Test")

        self.assertEqual(result["version"], 1)
        load_item.assert_called_once_with("zoolanding-config-registry", "SITE#example.test")
        load_json.assert_called_once_with(
            "zoolanding-config-payloads",
            "sites/example.test/versions/v1/example.test/server/auth-profile-registry.json",
        )

    def test_registry_validation_rejects_raw_secret_material(self):
        registry = active_registry()
        registry["profiles"][0]["clientSecret"] = "raw-secret-value"

        with self.assertRaises(auth.AuthRegistryError):
            auth.validate_auth_registry(registry)

    def test_registry_validation_rejects_secret_ref_values_that_do_not_look_like_refs(self):
        registry = active_registry()
        registry["profiles"][0]["socialIdpSecretRefs"]["google"] = "raw-google-secret-value"

        with self.assertRaises(auth.AuthRegistryError):
            auth.validate_auth_registry(registry)

    def test_registry_validation_requires_tenant_id_for_active_profiles(self):
        registry = active_registry()
        del registry["profiles"][0]["tenantId"]

        with self.assertRaises(auth.AuthRegistryError):
            auth.validate_auth_registry(registry)


if __name__ == "__main__":
    unittest.main()
