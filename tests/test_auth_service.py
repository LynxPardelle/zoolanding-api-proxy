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


def template_resource_block(template, resource_name):
    match = re.search(
        rf"^  {re.escape(resource_name)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9]+:\n|\Z)",
        template,
        re.M | re.S,
    )
    if not match:
        raise AssertionError(f"Template resource not found: {resource_name}")
    return match.group("body")


def build_profile(auth_profile_id, status, **overrides):
    profile = {
        "authProfileId": auth_profile_id,
        "status": status,
        "tenantId": "tenant-a",
        "issuer": f"https://cognito-idp.us-east-1.amazonaws.com/us-east-1_{auth_profile_id}",
        "hostedUiDomain": f"https://{auth_profile_id}-auth.example.test",
        "clientId": f"{auth_profile_id}-public-client-id",
        "audiences": [f"{auth_profile_id}-public-client-id"],
        "loginPath": "/login",
        "logoutPath": "/logout",
        "callbackUrls": [f"https://example.test/{auth_profile_id}/auth/callback"],
        "logoutUrls": [f"https://example.test/{auth_profile_id}/logout"],
        "scopes": ["openid", "email", "profile"],
        "allowedGroups": ["Editors"],
        "tenantClaim": "custom:tenant_id",
        "groupClaim": "cognito:groups",
    }
    profile.update(overrides)
    return profile


def active_registry():
    return {
        "version": 1,
        "defaultAuthProfileId": "staff",
        "profiles": [
            build_profile(
                "staff",
                "active",
                issuer="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
                hostedUiDomain="https://auth.example.test",
                clientId="public-client-id",
                audiences=["public-client-id"],
                callbackUrls=["https://example.test/auth/callback"],
                logoutUrls=["https://example.test/logout"],
                socialIdpSecretRefs={
                    "google": "/zoolanding/auth/tenant-a/staff/google",
                    "facebook": "/zoolanding/auth/tenant-a/staff/facebook",
                },
            ),
            build_profile(
                "planned",
                "planned",
                allowedGroups=["Viewers"],
                callbackUrls=["https://example.test/auth/callback"],
                logoutUrls=["https://example.test/logout"],
                socialIdentityProviders=[
                    {
                        "providerId": "facebook",
                        "providerType": "facebook",
                        "clientIdRef": "/zoolanding/auth/tenant-a/planned/facebook/client-id",
                        "clientSecretRef": "/zoolanding/auth/tenant-a/planned/facebook/client-secret",
                    },
                    {
                        "providerId": "google",
                        "providerType": "google",
                        "clientIdRef": "/zoolanding/auth/tenant-a/planned/google/client-id",
                        "clientSecretRef": "/zoolanding/auth/tenant-a/planned/google/client-secret",
                        "scopes": ["openid", "email", "profile"],
                    },
                    {
                        "providerId": "partner-oidc",
                        "providerType": "oidc",
                        "clientIdRef": "/zoolanding/auth/tenant-a/planned/oidc/client-id",
                        "clientSecretRef": "/zoolanding/auth/tenant-a/planned/oidc/client-secret",
                        "issuer": "https://idp.example.test",
                        "discoveryUrl": "https://idp.example.test/.well-known/openid-configuration",
                        "authorizeUrl": "https://idp.example.test/oauth2/authorize",
                        "tokenUrl": "https://idp.example.test/oauth2/token",
                        "userInfoUrl": "https://idp.example.test/userinfo",
                        "jwksUrl": "https://idp.example.test/jwks.json",
                        "scopes": ["openid", "email", "profile"],
                    },
                ],
            ),
            build_profile(
                "provisioning",
                "provisioning",
                allowedGroups=["Operators"],
            ),
            build_profile(
                "suspended",
                "suspended",
                allowedGroups=["Auditors"],
            ),
            build_profile(
                "failed",
                "failed",
                allowedGroups=["Auditors"],
            ),
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

    def test_runtime_config_uses_effective_active_state_for_completed_apply(self):
        reset_auth_clients()
        registry = active_registry()
        plan = auth._cognito_plan("example.test", registry["profiles"][1])
        dynamodb = FakeDynamoClient()
        key = auth._auth_state_key(plan)
        dynamodb.items[(key["pk"], key["sk"])] = {
            "pk": {"S": key["pk"]},
            "sk": {"S": key["sk"]},
            "status": {"S": "active"},
            "configHash": {"S": plan["configHash"]},
            "runtimeAuthJson": {"S": json.dumps({
                "issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_CREATED",
                "hostedUiDomain": "https://planned-auth.auth.us-east-1.amazoncognito.com",
                "clientId": "public-client-created",
                "userPoolId": "us-east-1_CREATED",
            })},
        }
        fake_boto3 = FakeBoto3(
            cognito=FakeCognitoClient(),
            dynamodb=dynamodb,
            ssm=FakeSsmClient(fake_social_secret_values()),
            secrets=FakeSecretsClient(),
        )
        event = api_event("/auth/runtime-config", {
            "domain": "Example.Test",
            "authProfileId": "planned",
        })

        with patch.object(auth, "load_auth_registry_for_domain", return_value=registry), \
                patch.object(auth, "boto3", fake_boto3), \
                patch.dict(os.environ, {"AUTH_PROVISIONING_STATE_TABLE_NAME": "test-auth-state"}):
            response = auth.auth_lambda_handler(event, Ctx())

        body = payload(response)
        self.assertEqual(response["statusCode"], 200)
        self.assertTrue(body["auth"]["enabled"])
        self.assertEqual(body["auth"]["clientId"], "public-client-created")
        self.assertEqual(body["auth"]["issuer"], "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_CREATED")
        self.assertEqual(body["auth"]["hostedUiDomain"], "https://planned-auth.auth.us-east-1.amazoncognito.com")

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


class TestAuthServiceCustomAuthForms(unittest.TestCase):
    def custom_auth_registry(self):
        registry = active_registry()
        registry["profiles"][0]["customAuth"] = {
            "signin": {
                "enabled": True,
            },
            "signup": {
                "enabled": True,
                "setTenantClaim": True,
                "defaultGroups": ["Editors"],
            },
            "passwordRecovery": {
                "enabled": True,
            },
        }
        return registry

    def test_registry_validation_accepts_custom_password_recovery_policy_key(self):
        registry = self.custom_auth_registry()

        auth.validate_auth_registry(registry)

    def fake_aws(self):
        reset_auth_clients()
        cognito = FakeCognitoClient()
        dynamodb = FakeDynamoClient()
        ssm = FakeSsmClient({})
        secrets = FakeSecretsClient()
        return cognito, FakeBoto3(cognito=cognito, dynamodb=dynamodb, ssm=ssm, secrets=secrets)

    def test_custom_signup_derives_tenant_and_group_policy_server_side(self):
        cognito, fake_boto3 = self.fake_aws()
        event = api_event("/auth/signup", {
            "domain": "Example.Test",
            "authProfileId": "staff",
            "email": "New.User@Example.Test",
            "password": "StrongPassphrase123!",
            "language": "es",
            "tenantId": "evil-tenant",
            "groups": ["Admins"],
        }, headers={"Origin": "https://example.test"})

        with patch.object(auth, "load_auth_registry_for_domain", return_value=self.custom_auth_registry()), \
                patch.object(auth, "boto3", fake_boto3):
            response = auth.auth_lambda_handler(event, Ctx())

        body = payload(response)
        serialized = json.dumps(body, sort_keys=True)
        self.assertEqual(response["statusCode"], 400)
        self.assertFalse(body["ok"])
        self.assertIn("Unsupported signup option", body["error"])
        self.assertEqual(cognito.calls, [])
        self.assertNotIn("StrongPassphrase123", serialized)

        clean_event = api_event("/auth/signup", {
            "domain": "Example.Test",
            "authProfileId": "staff",
            "email": "New.User@Example.Test",
            "password": "StrongPassphrase123!",
            "language": "es",
        }, headers={"Origin": "https://example.test"})

        with patch.object(auth, "load_auth_registry_for_domain", return_value=self.custom_auth_registry()), \
                patch.object(auth, "boto3", fake_boto3):
            response = auth.auth_lambda_handler(clean_event, Ctx())

        body = payload(response)
        serialized = json.dumps(body, sort_keys=True)
        self.assertEqual(response["statusCode"], 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["authProfileId"], "staff")
        self.assertEqual(body["status"], "confirmation-required")
        self.assertNotIn("password", serialized.lower())
        self.assertNotIn("StrongPassphrase123", serialized)
        self.assertEqual([call[0] for call in cognito.calls], ["sign_up", "admin_add_user_to_group"])
        sign_up = cognito.calls[0][1]
        self.assertEqual(sign_up["ClientId"], "public-client-id")
        self.assertEqual(sign_up["Username"], "new.user@example.test")
        self.assertEqual(sign_up["UserAttributes"], [
            {"Name": "email", "Value": "new.user@example.test"},
            {"Name": "custom:tenant_id", "Value": "tenant-a"},
        ])
        self.assertEqual(sign_up["ClientMetadata"], {
            "domain": "example.test",
            "authProfileId": "staff",
            "language": "es",
        })
        group_call = cognito.calls[1][1]
        self.assertEqual(group_call["UserPoolId"], "us-east-1_pool")
        self.assertEqual(group_call["Username"], "new.user@example.test")
        self.assertEqual(group_call["GroupName"], "Editors")

    def test_custom_signin_returns_public_session_without_token_material(self):
        cognito, fake_boto3 = self.fake_aws()
        event = api_event("/auth/signin", {
            "domain": "example.test",
            "authProfileId": "staff",
            "email": "Client@Example.Test",
            "password": "StrongPassphrase123!",
            "language": "es",
            "tenantId": "evil",
        }, headers={"Origin": "https://example.test"})

        with patch.object(auth, "load_auth_registry_for_domain", return_value=self.custom_auth_registry()), \
                patch.object(auth, "boto3", fake_boto3):
            response = auth.auth_lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(cognito.calls, [])

        clean_event = api_event("/auth/signin", {
            "domain": "example.test",
            "authProfileId": "staff",
            "email": "Client@Example.Test",
            "password": "StrongPassphrase123!",
            "language": "es",
        }, headers={"Origin": "https://example.test"})

        verified_claims = {
            "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool",
            "aud": "public-client-id",
            "sub": "user-123",
            "email": "client@example.test",
            "name": "Client Example",
            "custom:tenant_id": "tenant-a",
            "cognito:groups": ["Editors"],
            "exp": 1999999999,
        }
        with patch.object(auth, "load_auth_registry_for_domain", return_value=self.custom_auth_registry()), \
                patch.object(auth, "boto3", fake_boto3), \
                patch.object(auth, "verify_jwt", return_value=verified_claims) as verify_jwt:
            response = auth.auth_lambda_handler(clean_event, Ctx())

        body = payload(response)
        serialized = json.dumps(body, sort_keys=True)
        self.assertEqual(response["statusCode"], 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["status"], "signed-in")
        self.assertEqual(body["session"]["profile"]["subject"], "user-123")
        self.assertEqual(body["session"]["profile"]["email"], "client@example.test")
        self.assertEqual(body["session"]["profile"]["roles"], ["Editors"])
        self.assertEqual(body["session"]["provider"], "cognito")
        self.assertEqual(body["session"]["expiresAtEpochMs"], 1999999999000)
        self.assertNotIn("id-token-value", serialized)
        self.assertNotIn("StrongPassphrase123", serialized)
        self.assertNotIn("password", serialized.lower())
        self.assertEqual([call[0] for call in cognito.calls], ["initiate_auth"])
        self.assertEqual(cognito.calls[0][1]["AuthFlow"], "USER_PASSWORD_AUTH")
        self.assertEqual(cognito.calls[0][1]["ClientId"], "public-client-id")
        self.assertEqual(cognito.calls[0][1]["AuthParameters"], {
            "USERNAME": "client@example.test",
            "PASSWORD": "StrongPassphrase123!",
        })
        verify_jwt.assert_called_once()

    def test_password_recovery_uses_profile_client_and_never_accepts_tenant_policy(self):
        cognito, fake_boto3 = self.fake_aws()
        event = api_event("/auth/forgot-password", {
            "domain": "example.test",
            "authProfileId": "staff",
            "email": "new.user@example.test",
            "custom:tenant_id": "evil",
        }, headers={"Origin": "https://example.test"})

        with patch.object(auth, "load_auth_registry_for_domain", return_value=self.custom_auth_registry()), \
                patch.object(auth, "boto3", fake_boto3):
            response = auth.auth_lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(cognito.calls, [])

        clean_event = api_event("/auth/forgot-password", {
            "domain": "example.test",
            "authProfileId": "staff",
            "email": "new.user@example.test",
            "language": "es",
        }, headers={"Origin": "https://example.test"})

        with patch.object(auth, "load_auth_registry_for_domain", return_value=self.custom_auth_registry()), \
                patch.object(auth, "boto3", fake_boto3):
            response = auth.auth_lambda_handler(clean_event, Ctx())

        body = payload(response)
        serialized = json.dumps(body, sort_keys=True)
        self.assertEqual(response["statusCode"], 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["status"], "code-sent")
        self.assertNotIn("tenant-a", serialized)
        self.assertEqual([call[0] for call in cognito.calls], ["forgot_password"])
        self.assertEqual(cognito.calls[0][1]["ClientId"], "public-client-id")
        self.assertEqual(cognito.calls[0][1]["Username"], "new.user@example.test")
        self.assertEqual(cognito.calls[0][1]["ClientMetadata"], {
            "domain": "example.test",
            "authProfileId": "staff",
            "language": "es",
        })

    def test_confirmation_and_password_reset_complete_the_custom_auth_lifecycle(self):
        cognito, fake_boto3 = self.fake_aws()
        requests = [
            ("/auth/confirm-signup", {
                "domain": "example.test",
                "authProfileId": "staff",
                "email": "new.user@example.test",
                "code": "123456",
                "language": "es",
            }, "confirm_sign_up", "confirmed"),
            ("/auth/resend-confirmation", {
                "domain": "example.test",
                "authProfileId": "staff",
                "email": "new.user@example.test",
                "language": "es",
            }, "resend_confirmation_code", "code-sent"),
            ("/auth/confirm-forgot-password", {
                "domain": "example.test",
                "authProfileId": "staff",
                "email": "new.user@example.test",
                "code": "654321",
                "password": "NewStrongPassphrase123!",
                "language": "es",
            }, "confirm_forgot_password", "password-reset"),
        ]

        for path, body, expected_call, expected_status in requests:
            with patch.object(auth, "load_auth_registry_for_domain", return_value=self.custom_auth_registry()), \
                    patch.object(auth, "boto3", fake_boto3):
                response = auth.auth_lambda_handler(api_event(path, body, headers={"Origin": "https://example.test"}), Ctx())

            parsed = payload(response)
            self.assertEqual(response["statusCode"], 200)
            self.assertTrue(parsed["ok"])
            self.assertEqual(parsed["status"], expected_status)

        self.assertEqual(
            [call[0] for call in cognito.calls],
            ["confirm_sign_up", "resend_confirmation_code", "confirm_forgot_password"],
        )
        self.assertEqual(cognito.calls[0][1]["ConfirmationCode"], "123456")
        self.assertEqual(cognito.calls[1][1]["Username"], "new.user@example.test")
        self.assertEqual(cognito.calls[2][1]["ConfirmationCode"], "654321")
        self.assertEqual(cognito.calls[2][1]["Password"], "NewStrongPassphrase123!")


class TestAuthServiceTemplateContract(unittest.TestCase):
    def test_custom_auth_form_routes_are_public_post_routes(self):
        with open(os.path.join(PROJECT_ROOT, "template.yaml"), encoding="utf-8") as template_file:
            template = template_file.read()

        for logical_id, path in (
            ("AuthSigninPost", "/auth/signin"),
            ("AuthSignupPost", "/auth/signup"),
            ("AuthConfirmSignupPost", "/auth/confirm-signup"),
            ("AuthResendConfirmationPost", "/auth/resend-confirmation"),
            ("AuthForgotPasswordPost", "/auth/forgot-password"),
            ("AuthConfirmForgotPasswordPost", "/auth/confirm-forgot-password"),
        ):
            self.assertRegex(
                template,
                re.compile(
                    rf"{logical_id}:.*?Path:\s*{re.escape(path)}.*?Method:\s*POST",
                    re.S,
                ),
            )

    def test_api_proxy_has_cognito_self_service_permissions_only_for_auth_forms(self):
        with open(os.path.join(PROJECT_ROOT, "template.yaml"), encoding="utf-8") as template_file:
            template = template_file.read()

        api_proxy = template_resource_block(template, "ApiProxyFunction")
        self.assertIn("cognito-idp:InitiateAuth", api_proxy)
        self.assertIn("cognito-idp:SignUp", api_proxy)
        self.assertIn("cognito-idp:ConfirmSignUp", api_proxy)
        self.assertIn("cognito-idp:ResendConfirmationCode", api_proxy)
        self.assertIn("cognito-idp:ForgotPassword", api_proxy)
        self.assertIn("cognito-idp:ConfirmForgotPassword", api_proxy)
        self.assertIn("cognito-idp:AdminAddUserToGroup", api_proxy)
        self.assertRegex(api_proxy, re.compile(r"arn:aws:cognito-idp:\$\{AWS::Region\}:\$\{AWS::AccountId\}:userpool/\*"))

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

    def test_provisioning_executor_post_route_requires_aws_iam_authorizer(self):
        with open(os.path.join(PROJECT_ROOT, "template.yaml"), encoding="utf-8") as template_file:
            template = template_file.read()

        self.assertRegex(
            template,
            re.compile(
                r"AuthProvisioningExecutorPost:.*?Method:\s*POST.*?Auth:\s*Authorizer:\s*AWS_IAM",
                re.S,
            ),
        )

    def test_provisioning_executor_uses_separate_lambda_and_state_table_without_api_proxy_cognito_writes(self):
        with open(os.path.join(PROJECT_ROOT, "template.yaml"), encoding="utf-8") as template_file:
            template = template_file.read()

        api_proxy = template_resource_block(template, "ApiProxyFunction")
        executor = template_resource_block(template, "AuthProvisioningExecutorFunction")

        self.assertIn("AuthProvisioningStateTable:", template)
        self.assertRegex(
            executor,
            re.compile(
                r"Handler:\s*auth_service\.auth_lambda_handler"
                r".*?AUTH_PROVISIONING_STATE_TABLE_NAME:"
                r".*?AuthProvisioningExecutorPost:.*?Authorizer:\s*AWS_IAM",
                re.S,
            ),
        )
        self.assertNotIn("cognito-idp:CreateUserPool", api_proxy)
        self.assertNotIn("cognito-idp:CreateUserPoolClient", api_proxy)
        self.assertNotIn("cognito-idp:CreateIdentityProvider", api_proxy)
        self.assertNotIn("cognito-idp:UpdateUserPoolClient", api_proxy)

    def test_provisioning_executor_template_grants_minimal_apply_permissions_only_to_executor(self):
        with open(os.path.join(PROJECT_ROOT, "template.yaml"), encoding="utf-8") as template_file:
            template = template_file.read()

        api_proxy = template_resource_block(template, "ApiProxyFunction")
        executor = template_resource_block(template, "AuthProvisioningExecutorFunction")
        required_executor_actions = {
            "cognito-idp:CreateUserPool",
            "cognito-idp:CreateUserPoolClient",
            "cognito-idp:CreateUserPoolDomain",
            "cognito-idp:DescribeIdentityProvider",
            "cognito-idp:DescribeUserPool",
            "cognito-idp:DescribeUserPoolClient",
            "cognito-idp:DescribeUserPoolDomain",
            "cognito-idp:ListGroups",
            "cognito-idp:ListTagsForResource",
            "cognito-idp:ListUserPoolClients",
            "cognito-idp:ListUserPools",
            "cognito-idp:UpdateIdentityProvider",
            "cognito-idp:UpdateUserPoolClient",
            "ssm:GetParameter",
            "secretsmanager:GetSecretValue",
            "dynamodb:GetItem",
            "dynamodb:PutItem",
        }
        forbidden_cognito_actions = {
            "cognito-idp:*",
            "cognito-idp:AdminCreateUser",
            "cognito-idp:AdminSetUserPassword",
            "cognito-idp:AdminDeleteUser",
            "cognito-idp:DeleteUserPool",
            "cognito-idp:DeleteUserPoolClient",
            "cognito-idp:DeleteIdentityProvider",
        }

        for action in required_executor_actions:
            self.assertIn(action, executor)
        for action in forbidden_cognito_actions:
            self.assertNotIn(action, executor)
        self.assertIn("AuthProvisioningStateTable", executor)
        self.assertIn("AuthProvisioningSecretParameterPrefix", executor)
        wildcard_statement = re.search(
            r"- Effect: Allow\s+Action:\s+(?P<actions>(?:\s+- cognito-idp:[^\n]+\n)+)\s+Resource:\s+'\*'",
            executor,
            re.S,
        )
        self.assertIsNotNone(wildcard_statement)
        wildcard_actions = set(re.findall(r"cognito-idp:[A-Za-z]+", wildcard_statement.group("actions")))
        self.assertEqual(
            {
                "cognito-idp:CreateUserPool",
                "cognito-idp:DescribeUserPoolDomain",
                "cognito-idp:ListUserPools",
            },
            wildcard_actions,
        )
        scoped_statement = re.search(
            r"- Effect: Allow\s+Action:\s+(?P<actions>(?:\s+- cognito-idp:[^\n]+\n)+)\s+Resource:\s+Fn::Sub:\s+arn:aws:cognito-idp:\$\{AWS::Region\}:\$\{AWS::AccountId\}:userpool/\*",
            executor,
            re.S,
        )
        self.assertIsNotNone(scoped_statement)
        scoped_actions = set(re.findall(r"cognito-idp:[A-Za-z]+", scoped_statement.group("actions")))
        self.assertIn("cognito-idp:ListTagsForResource", scoped_actions)
        self.assertIn("cognito-idp:ListUserPoolClients", scoped_actions)
        self.assertNotIn("cognito-idp:ListTagsForResource", wildcard_actions)
        self.assertNotIn("cognito-idp:ListUserPoolClients", wildcard_actions)
        self.assertNotIn("cognito-idp:CreateUserPool", api_proxy)
        self.assertNotIn("cognito-idp:CreateUserPoolClient", api_proxy)
        self.assertNotIn("cognito-idp:CreateIdentityProvider", api_proxy)
        self.assertNotIn("cognito-idp:UpdateUserPoolClient", api_proxy)


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

    def test_provisioning_plan_rejects_unsupported_request_fields(self):
        event = api_event(
            "/auth/provisioning-plan",
            {
                "domain": "example.test",
                "authProfileId": "planned",
                "clientSecret": "must-not-pass",
            },
            request_context={
                "identity": {
                    "userArn": "arn:aws:sts::123456789012:assumed-role/zoolanding-auth-planner/session"
                }
            },
        )

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()), \
                patch.dict(os.environ, {"AUTH_PROVISIONING_ALLOWED_ROLE_NAMES": "zoolanding-auth-planner"}):
            response = auth.auth_lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(payload(response)["error"], "Unsupported auth provisioning option")
        self.assertNotIn("must-not-pass", response["body"])

    def test_trusted_server_caller_can_read_planned_plan_with_deterministic_operations_and_secret_refs(self):
        event = api_event(
            "/auth/provisioning-plan",
            {"domain": "example.test", "authProfileId": "planned"},
            request_context={
                "identity": {
                    "userArn": "arn:aws:sts::123456789012:assumed-role/zoolanding-auth-planner/session"
                }
            },
        )

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()), \
                patch.dict(os.environ, {"AUTH_PROVISIONING_ALLOWED_ROLE_NAMES": "zoolanding-auth-planner"}):
            response = auth.auth_lambda_handler(event, Ctx())
            repeated_response = auth.auth_lambda_handler(event, Ctx())

        body = payload(response)
        repeated_body = payload(repeated_response)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(body["plan"]["mode"], "plan-only")
        self.assertEqual(body["plan"]["planVersion"], "2026-06-10.v1")
        self.assertEqual(body["plan"]["provider"], "cognito")
        self.assertEqual(body["plan"]["tenantId"], "tenant-a")
        self.assertEqual(body["plan"]["authProfileId"], "planned")
        self.assertRegex(body["plan"]["configHash"], r"^[0-9a-f]{64}$")
        self.assertFalse(body["plan"]["runtimeAuth"]["currentEnabled"])
        self.assertEqual(body["plan"]["lifecycle"]["executorAction"], "prepare-provisioning")
        self.assertEqual(body["plan"]["lifecycle"]["expectedFinalStatus"], "active")
        self.assertEqual(body["plan"]["runtimeAuth"]["publicClient"]["clientId"], "planned-public-client-id")
        self.assertEqual(
            body["plan"]["operations"][0]["operationKey"],
            "cognito:example.test:planned:ensure-user-pool",
        )
        self.assertEqual(body["plan"]["planKey"], repeated_body["plan"]["planKey"])
        self.assertEqual(body["plan"]["configHash"], repeated_body["plan"]["configHash"])
        self.assertEqual(
            body["plan"]["operations"][0]["idempotencyKey"],
            repeated_body["plan"]["operations"][0]["idempotencyKey"],
        )
        providers = {item["providerId"]: item for item in body["plan"]["socialIdentityProviders"]}
        self.assertEqual(
            providers["google"]["secretRefs"]["clientSecret"],
            "/zoolanding/auth/tenant-a/planned/google/client-secret",
        )
        self.assertEqual(providers["partner-oidc"]["providerType"], "oidc")
        self.assertEqual(providers["partner-oidc"]["tokenUrl"], "https://idp.example.test/oauth2/token")
        self.assertNotIn("clientSecretValue", json.dumps(body))
        self.assertNotIn("refreshToken", json.dumps(body))
        self.assertNotIn("must-not-pass", json.dumps(body))

    def test_plan_key_and_operation_idempotency_change_with_sanitized_config(self):
        registry = active_registry()
        changed_registry = active_registry()
        changed_registry["profiles"][1]["callbackUrls"] = ["https://example.test/changed/auth/callback"]
        event = api_event(
            "/auth/provisioning-plan",
            {"domain": "example.test", "authProfileId": "planned"},
            request_context={
                "identity": {
                    "userArn": "arn:aws:sts::123456789012:assumed-role/zoolanding-auth-planner/session"
                }
            },
        )

        with patch.object(auth, "load_auth_registry_for_domain", return_value=registry), \
                patch.dict(os.environ, {"AUTH_PROVISIONING_ALLOWED_ROLE_NAMES": "zoolanding-auth-planner"}):
            response = auth.auth_lambda_handler(event, Ctx())
        with patch.object(auth, "load_auth_registry_for_domain", return_value=changed_registry), \
                patch.dict(os.environ, {"AUTH_PROVISIONING_ALLOWED_ROLE_NAMES": "zoolanding-auth-planner"}):
            changed_response = auth.auth_lambda_handler(event, Ctx())

        body = payload(response)["plan"]
        changed_body = payload(changed_response)["plan"]
        self.assertNotEqual(body["configHash"], changed_body["configHash"])
        self.assertNotEqual(body["planKey"], changed_body["planKey"])
        self.assertNotEqual(body["operations"][0]["idempotencyKey"], changed_body["operations"][0]["idempotencyKey"])

    def test_planned_profile_can_be_planned_before_real_cognito_client_id_exists(self):
        registry = active_registry()
        planned = registry["profiles"][1]
        planned.pop("clientId", None)
        planned.pop("audiences", None)
        planned["desiredClientAlias"] = "staff-web"
        event = api_event(
            "/auth/provisioning-plan",
            {"domain": "example.test", "authProfileId": "planned"},
            request_context={
                "identity": {
                    "userArn": "arn:aws:sts::123456789012:assumed-role/zoolanding-auth-planner/session"
                }
            },
        )

        with patch.object(auth, "load_auth_registry_for_domain", return_value=registry), \
                patch.dict(os.environ, {"AUTH_PROVISIONING_ALLOWED_ROLE_NAMES": "zoolanding-auth-planner"}):
            response = auth.auth_lambda_handler(event, Ctx())

        body = payload(response)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(body["plan"]["runtimeAuth"]["publicClient"]["clientId"], "staff-web")
        self.assertEqual(body["plan"]["runtimeAuth"]["publicClient"]["audiences"], [])

    def test_active_profile_still_requires_real_audience_or_client_id(self):
        registry = active_registry()
        active = registry["profiles"][0]
        active.pop("clientId", None)
        active.pop("audiences", None)
        event = api_event(
            "/auth/provisioning-plan",
            {"domain": "example.test", "authProfileId": "staff"},
            request_context={
                "identity": {
                    "userArn": "arn:aws:sts::123456789012:assumed-role/zoolanding-auth-planner/session"
                }
            },
        )

        with patch.object(auth, "load_auth_registry_for_domain", return_value=registry), \
                patch.dict(os.environ, {"AUTH_PROVISIONING_ALLOWED_ROLE_NAMES": "zoolanding-auth-planner"}):
            response = auth.auth_lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 500)
        self.assertEqual(payload(response)["error"], "Provisioning plan requires an audience/clientId")

    def test_provisioning_status_returns_resumable_plan(self):
        event = api_event(
            "/auth/provisioning-plan",
            {"domain": "example.test", "authProfileId": "provisioning"},
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
        self.assertEqual(body["plan"]["status"], "provisioning")
        self.assertEqual(body["plan"]["lifecycle"]["executorAction"], "resume-provisioning")
        self.assertEqual(body["plan"]["lifecycle"]["expectedFinalStatus"], "active")
        self.assertGreater(len(body["plan"]["operations"]), 0)

    def test_active_status_returns_noop_plan(self):
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
        self.assertEqual(body["plan"]["status"], "active")
        self.assertTrue(body["plan"]["runtimeAuth"]["currentEnabled"])
        self.assertEqual(body["plan"]["lifecycle"]["executorAction"], "noop-already-active")
        self.assertEqual(body["plan"]["operations"], [])

    def test_suspended_and_failed_statuses_return_manual_review_plan(self):
        for auth_profile_id in ("suspended", "failed"):
            event = api_event(
                "/auth/provisioning-plan",
                {"domain": "example.test", "authProfileId": auth_profile_id},
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
            self.assertEqual(body["plan"]["status"], auth_profile_id)
            self.assertFalse(body["plan"]["runtimeAuth"]["currentEnabled"])
        self.assertEqual(body["plan"]["lifecycle"]["executorAction"], "manual-review")
        self.assertEqual(body["plan"]["operations"], [])


class FakeCognitoClient:
    def __init__(self, *, user_pools=None, user_pool_clients=None):
        self.calls = []
        self.groups = set()
        self.user_pools = {}
        self.user_pool_clients = {}
        for user_pool in user_pools or []:
            pool_id = user_pool["Id"]
            arn = user_pool.get("Arn") or f"arn:aws:cognito-idp:us-east-1:123456789012:userpool/{pool_id}"
            self.user_pools[pool_id] = {
                "Id": pool_id,
                "Name": user_pool["Name"],
                "Arn": arn,
                "Tags": dict(user_pool.get("Tags") or {}),
            }
        for user_pool_id, clients in (user_pool_clients or {}).items():
            self.user_pool_clients[user_pool_id] = {}
            for client in clients:
                client_id = client["ClientId"]
                self.user_pool_clients[user_pool_id][client_id] = {
                    "ClientId": client_id,
                    "ClientName": client["ClientName"],
                    **({"ClientSecret": client["ClientSecret"]} if client.get("ClientSecret") else {}),
                }

    def _record(self, name, **kwargs):
        self.calls.append((name, kwargs))

    def create_user_pool(self, **kwargs):
        self._record("create_user_pool", **kwargs)
        pool_id = "us-east-1_TESTPOOL" if "us-east-1_TESTPOOL" not in self.user_pools else f"us-east-1_TESTPOOL{len(self.user_pools) + 1}"
        arn = f"arn:aws:cognito-idp:us-east-1:123456789012:userpool/{pool_id}"
        self.user_pools[pool_id] = {
            "Id": pool_id,
            "Name": kwargs["PoolName"],
            "Arn": arn,
            "Tags": dict(kwargs.get("UserPoolTags") or {}),
        }
        return {"UserPool": {"Id": pool_id, "Name": kwargs["PoolName"], "Arn": arn}}

    def describe_user_pool(self, **kwargs):
        self._record("describe_user_pool", **kwargs)
        user_pool = self.user_pools.get(kwargs["UserPoolId"]) or {
            "Id": kwargs["UserPoolId"],
            "Name": "unknown",
            "Arn": f"arn:aws:cognito-idp:us-east-1:123456789012:userpool/{kwargs['UserPoolId']}",
            "Tags": {},
        }
        return {"UserPool": {key: value for key, value in user_pool.items() if key != "Tags"}}

    def list_user_pools(self, **kwargs):
        self._record("list_user_pools", **kwargs)
        return {
            "UserPools": [
                {"Id": user_pool["Id"], "Name": user_pool["Name"]}
                for user_pool in self.user_pools.values()
            ]
        }

    def list_tags_for_resource(self, **kwargs):
        self._record("list_tags_for_resource", **kwargs)
        for user_pool in self.user_pools.values():
            if user_pool["Arn"] == kwargs["ResourceArn"]:
                return {"Tags": dict(user_pool.get("Tags") or {})}
        return {"Tags": {}}

    def describe_user_pool_domain(self, **kwargs):
        self._record("describe_user_pool_domain", **kwargs)
        return {}

    def create_user_pool_domain(self, **kwargs):
        self._record("create_user_pool_domain", **kwargs)
        return {}

    def create_user_pool_client(self, **kwargs):
        self._record("create_user_pool_client", **kwargs)
        user_pool_id = kwargs["UserPoolId"]
        clients = self.user_pool_clients.setdefault(user_pool_id, {})
        client_id = "public-client-created" if "public-client-created" not in clients else f"public-client-created-{len(clients) + 1}"
        clients[client_id] = {
            "ClientId": client_id,
            "ClientName": kwargs["ClientName"],
        }
        return {"UserPoolClient": {"ClientId": client_id, "ClientName": kwargs["ClientName"]}}

    def describe_user_pool_client(self, **kwargs):
        self._record("describe_user_pool_client", **kwargs)
        client = self.user_pool_clients.get(kwargs["UserPoolId"], {}).get(kwargs["ClientId"]) or {
            "ClientId": kwargs["ClientId"],
            "ClientName": "unknown",
        }
        return {"UserPoolClient": dict(client)}

    def list_user_pool_clients(self, **kwargs):
        self._record("list_user_pool_clients", **kwargs)
        return {
            "UserPoolClients": [
                {"ClientId": client["ClientId"], "ClientName": client["ClientName"]}
                for client in self.user_pool_clients.get(kwargs["UserPoolId"], {}).values()
            ]
        }

    def update_user_pool_client(self, **kwargs):
        self._record("update_user_pool_client", **kwargs)
        clients = self.user_pool_clients.setdefault(kwargs["UserPoolId"], {})
        client = clients.setdefault(kwargs["ClientId"], {"ClientId": kwargs["ClientId"], "ClientName": "unknown"})
        client["SupportedIdentityProviders"] = kwargs.get("SupportedIdentityProviders")
        return {"UserPoolClient": {"ClientId": kwargs["ClientId"]}}

    def list_groups(self, **kwargs):
        self._record("list_groups", **kwargs)
        return {"Groups": [{"GroupName": group} for group in sorted(self.groups)]}

    def create_group(self, **kwargs):
        self._record("create_group", **kwargs)
        self.groups.add(kwargs["GroupName"])
        return {"Group": {"GroupName": kwargs["GroupName"]}}

    def describe_identity_provider(self, **kwargs):
        self._record("describe_identity_provider", **kwargs)
        return {}

    def create_identity_provider(self, **kwargs):
        self._record("create_identity_provider", **kwargs)
        return {"IdentityProvider": {"ProviderName": kwargs["ProviderName"]}}

    def update_identity_provider(self, **kwargs):
        self._record("update_identity_provider", **kwargs)
        return {"IdentityProvider": {"ProviderName": kwargs["ProviderName"]}}

    def initiate_auth(self, **kwargs):
        self._record("initiate_auth", **kwargs)
        return {"AuthenticationResult": {"IdToken": "id-token-value"}}

    def sign_up(self, **kwargs):
        self._record("sign_up", **kwargs)
        return {
            "UserConfirmed": False,
            "CodeDeliveryDetails": {
                "Destination": "n***@e***",
                "DeliveryMedium": "EMAIL",
                "AttributeName": "email",
            },
        }

    def admin_add_user_to_group(self, **kwargs):
        self._record("admin_add_user_to_group", **kwargs)
        return {}

    def forgot_password(self, **kwargs):
        self._record("forgot_password", **kwargs)
        return {
            "CodeDeliveryDetails": {
                "Destination": "n***@e***",
                "DeliveryMedium": "EMAIL",
                "AttributeName": "email",
            },
        }

    def confirm_sign_up(self, **kwargs):
        self._record("confirm_sign_up", **kwargs)
        return {}

    def resend_confirmation_code(self, **kwargs):
        self._record("resend_confirmation_code", **kwargs)
        return {
            "CodeDeliveryDetails": {
                "Destination": "n***@e***",
                "DeliveryMedium": "EMAIL",
                "AttributeName": "email",
            },
        }

    def confirm_forgot_password(self, **kwargs):
        self._record("confirm_forgot_password", **kwargs)
        return {}


class FakeDynamoClient:
    class exceptions:
        class ConditionalCheckFailedException(Exception):
            pass

    def __init__(self):
        self.items = {}
        self.calls = []
        self.fail_once_puts = []

    def get_item(self, **kwargs):
        self.calls.append(("get_item", kwargs))
        key = self._key(kwargs["Key"])
        item = self.items.get(key)
        return {"Item": item} if item else {}

    def put_item(self, **kwargs):
        self.calls.append(("put_item", kwargs))
        key = self._key(kwargs["Item"])
        self._enforce_condition(kwargs, key)
        self._maybe_fail_put(kwargs["Item"])
        self.items[key] = kwargs["Item"]
        return {}

    def fail_once_on_put(self, *, operation_id, status):
        self.fail_once_puts.append((operation_id, status))

    def seed_operation(self, plan, operation_id, outputs):
        operation = next(op for op in plan["operations"] if op["operationId"] == operation_id)
        key = auth._operation_state_key(plan, operation)
        self.items[(key["pk"], key["sk"])] = {
            "pk": {"S": key["pk"]},
            "sk": {"S": key["sk"]},
            "operationId": {"S": operation_id},
            "idempotencyKey": {"S": operation["idempotencyKey"]},
            "status": {"S": "succeeded"},
            "outputsJson": {"S": json.dumps(outputs, sort_keys=True, separators=(",", ":"))},
        }

    def _key(self, value):
        return (value["pk"]["S"], value["sk"]["S"])

    def _enforce_condition(self, kwargs, key):
        if "ConditionExpression" not in kwargs or key not in self.items:
            return
        current = self.items[key]
        current_status = (current.get("status") or {}).get("S")
        lock_expires_at = int((current.get("lockExpiresAt") or {}).get("N") or "0")
        now = int(((kwargs.get("ExpressionAttributeValues") or {}).get(":now") or {}).get("N") or "0")
        if current_status == "failed":
            return
        if current_status == "in-progress" and lock_expires_at < now:
            return
        raise FakeDynamoClient.exceptions.ConditionalCheckFailedException()

    def _maybe_fail_put(self, item):
        operation_id = (item.get("operationId") or {}).get("S")
        status = (item.get("status") or {}).get("S")
        failure = (operation_id, status)
        if failure in self.fail_once_puts:
            self.fail_once_puts.remove(failure)
            raise RuntimeError(f"Injected DynamoDB put failure for {operation_id}:{status}")


class FakeSsmClient:
    class exceptions:
        class ParameterNotFound(Exception):
            pass

    def __init__(self, values):
        self.values = values
        self.calls = []

    def get_parameter(self, **kwargs):
        self.calls.append(kwargs)
        name = kwargs["Name"]
        if name not in self.values:
            raise FakeSsmClient.exceptions.ParameterNotFound()
        return {"Parameter": {"Value": self.values[name]}}


class FakeSecretsClient:
    def __init__(self, values=None):
        self.values = values or {}
        self.calls = []

    def get_secret_value(self, **kwargs):
        self.calls.append(kwargs)
        secret_id = kwargs["SecretId"]
        if secret_id not in self.values:
            raise KeyError(secret_id)
        return {"SecretString": self.values[secret_id]}


class FakeBoto3:
    def __init__(self, *, cognito, dynamodb, ssm, secrets):
        self.cognito = cognito
        self.dynamodb = dynamodb
        self.ssm = ssm
        self.secrets = secrets

    def client(self, service_name):
        if service_name == "cognito-idp":
            return self.cognito
        if service_name == "dynamodb":
            return self.dynamodb
        if service_name == "ssm":
            return self.ssm
        if service_name == "secretsmanager":
            return self.secrets
        raise AssertionError(f"Unexpected client: {service_name}")


def fake_social_secret_values():
    return {
        "/zoolanding/auth/tenant-a/planned/facebook/client-id": "facebook-client-id-test",
        "/zoolanding/auth/tenant-a/planned/facebook/client-secret": "facebook-client-secret-test",
        "/zoolanding/auth/tenant-a/planned/google/client-id": "google-client-id-test",
        "/zoolanding/auth/tenant-a/planned/google/client-secret": "google-client-secret-test",
        "/zoolanding/auth/tenant-a/planned/oidc/client-id": "oidc-client-id-test",
        "/zoolanding/auth/tenant-a/planned/oidc/client-secret": "oidc-client-secret-test",
    }


def reset_auth_clients():
    auth._COGNITO_IDP_CLIENT = None
    auth._DYNAMODB_CLIENT = None
    auth._SSM_CLIENT = None
    auth._SECRETS_CLIENT = None


class TestAuthServiceProvisioningExecutor(unittest.TestCase):
    trusted_context = {
        "identity": {
            "userArn": "arn:aws:sts::123456789012:assumed-role/zoolanding-auth-planner/session"
        }
    }

    def trusted_event(self, body):
        return api_event(
            "/auth/provisioning-executor",
            body,
            request_context=self.trusted_context,
        )

    def apply_event(self, *, registry=None, extra_body=None):
        registry = registry or active_registry()
        plan = auth._cognito_plan("example.test", registry["profiles"][1])
        body = {
            "domain": "example.test",
            "authProfileId": "planned",
            "mode": "apply",
            "planKey": plan["planKey"],
            "idempotencyKey": auth._executor_idempotency_key(plan, "apply", None),
        }
        if extra_body:
            body.update(extra_body)
        return self.trusted_event(body), plan

    def apply_env(self):
        return {
            "AUTH_PROVISIONING_ALLOWED_ROLE_ARNS": self.trusted_context["identity"]["userArn"],
            "AUTH_PROVISIONING_ALLOWED_ROLE_NAMES": "",
            "AUTH_PROVISIONING_APPLY_ENABLED": "true",
            "AUTH_PROVISIONING_STATE_TABLE_NAME": "test-auth-state",
            "AUTH_PROVISIONING_APPLY_ALLOWED_DOMAINS": "example.test",
            "AUTH_PROVISIONING_APPLY_ALLOWED_TENANTS": "tenant-a",
            "AWS_REGION": "us-east-1",
        }

    def fake_aws(self, *, secrets=None):
        cognito = FakeCognitoClient()
        dynamodb = FakeDynamoClient()
        ssm = FakeSsmClient(secrets or fake_social_secret_values())
        secrets_client = FakeSecretsClient()
        return cognito, dynamodb, ssm, FakeBoto3(
            cognito=cognito,
            dynamodb=dynamodb,
            ssm=ssm,
            secrets=secrets_client,
        )

    def test_executor_dry_run_returns_sanitized_preview_without_aws_calls(self):
        event = self.trusted_event({
            "domain": "example.test",
            "authProfileId": "planned",
            "mode": "dry-run",
        })

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()) as load_registry, \
                patch.object(auth, "load_item") as load_item, \
                patch.dict(os.environ, {"AUTH_PROVISIONING_ALLOWED_ROLE_NAMES": "zoolanding-auth-planner"}):
            response = auth.auth_lambda_handler(event, Ctx())

        body = payload(response)
        serialized = json.dumps(body, sort_keys=True)
        self.assertEqual(response["statusCode"], 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["executor"]["mode"], "dry-run")
        self.assertEqual(body["executor"]["executionStatus"], "preview-only")
        self.assertEqual(body["executor"]["target"]["domain"], "example.test")
        self.assertEqual(body["executor"]["target"]["authProfileId"], "planned")
        self.assertGreater(len(body["executor"]["operations"]), 0)
        self.assertEqual(body["executor"]["operations"][0]["operationId"], "ensure-user-pool")
        self.assertNotIn("secretRefs", serialized)
        self.assertNotIn("clientSecret", serialized)
        self.assertNotIn("/zoolanding/auth", serialized)
        load_registry.assert_called_once_with("example.test")
        load_item.assert_not_called()

    def test_executor_apply_fails_closed_by_default_without_aws_calls(self):
        event = self.trusted_event({
            "domain": "example.test",
            "authProfileId": "planned",
            "mode": "apply",
        })

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()), \
                patch.object(auth, "load_item") as load_item, \
                patch.dict(os.environ, {"AUTH_PROVISIONING_ALLOWED_ROLE_NAMES": "zoolanding-auth-planner"}):
            response = auth.auth_lambda_handler(event, Ctx())

        body = payload(response)
        self.assertEqual(response["statusCode"], 501)
        self.assertFalse(body["ok"])
        self.assertEqual(body["executor"]["mode"], "apply")
        self.assertEqual(body["executor"]["executionStatus"], "manual-review-required")
        self.assertEqual(body["error"], "Cognito executor apply is disabled")
        self.assertEqual(body["executor"]["blockedReason"], "apply-disabled")
        self.assertEqual(body["executor"]["operations"], [])
        load_item.assert_not_called()

    def test_executor_apply_requires_explicit_plan_and_idempotency_keys(self):
        cases = [
            {"idempotencyKey": "0" * 64},
            {"planKey": "0" * 64},
        ]
        for body in cases:
            event = self.trusted_event({
                "domain": "example.test",
                "authProfileId": "planned",
                "mode": "apply",
                **body,
            })
            with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()), \
                    patch.dict(os.environ, self.apply_env()):
                response = auth.auth_lambda_handler(event, Ctx())

            self.assertEqual(response["statusCode"], 400)
            self.assertIn("requires", payload(response)["error"])

    def test_executor_apply_requires_exact_allowed_arn_not_role_name(self):
        event, _plan = self.apply_event()
        env = self.apply_env()
        env["AUTH_PROVISIONING_ALLOWED_ROLE_ARNS"] = ""
        env["AUTH_PROVISIONING_ALLOWED_ROLE_NAMES"] = "zoolanding-auth-planner"

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()), \
                patch.dict(os.environ, env):
            response = auth.auth_lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 403)
        self.assertEqual(payload(response)["error"], "Provisioning apply access denied")

    def test_executor_apply_flag_true_runs_cognito_apply_with_fake_clients_and_sanitized_success_summary(self):
        reset_auth_clients()
        event, _plan = self.apply_event()
        cognito, dynamodb, ssm, fake_boto3 = self.fake_aws()

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()), \
                patch.object(auth, "boto3", fake_boto3), \
                patch.dict(os.environ, self.apply_env()):
            response = auth.auth_lambda_handler(event, Ctx())

        body = payload(response)
        serialized = json.dumps(body, sort_keys=True)
        self.assertEqual(response["statusCode"], 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["executor"]["mode"], "apply")
        self.assertEqual(body["executor"]["executionStatus"], "applied")
        self.assertTrue(body["executor"]["auditEvent"]["mutationAttempted"])
        self.assertEqual(len(body["executor"]["operations"]), 6)
        self.assertEqual(
            [call[0] for call in cognito.calls],
            [
                "list_user_pools",
                "create_user_pool",
                "describe_user_pool_domain",
                "create_user_pool_domain",
                "list_user_pool_clients",
                "create_user_pool_client",
                "list_groups",
                "create_group",
                "describe_identity_provider",
                "create_identity_provider",
                "describe_identity_provider",
                "create_identity_provider",
                "describe_identity_provider",
                "create_identity_provider",
                "update_user_pool_client",
            ],
        )
        self.assertIn("/zoolanding/auth/tenant-a/planned/google/client-id", [call["Name"] for call in ssm.calls])
        self.assertGreaterEqual(len([call for call in dynamodb.calls if call[0] == "put_item"]), 7)
        facebook_call = next(kwargs for name, kwargs in cognito.calls if name == "create_identity_provider" and kwargs["ProviderName"] == "Facebook")
        google_call = next(kwargs for name, kwargs in cognito.calls if name == "create_identity_provider" and kwargs["ProviderName"] == "Google")
        self.assertEqual(facebook_call["ProviderDetails"]["authorize_scopes"], "public_profile,email")
        self.assertEqual(facebook_call["ProviderDetails"]["api_version"], "v17.0")
        self.assertEqual(google_call["ProviderDetails"]["authorize_scopes"], "openid email profile")
        self.assertEqual(body["executor"]["outputs"]["clientId"], "public-client-created")
        self.assertEqual(body["executor"]["outputs"]["hostedUiDomain"], "https://planned-auth.auth.us-east-1.amazoncognito.com")
        self.assertNotIn("secretRefs", serialized)
        self.assertNotIn("/zoolanding/auth", serialized)
        self.assertNotIn("google-client-secret-test", serialized)
        self.assertNotIn("facebook-client-secret-test", serialized)

    def test_executor_apply_fails_closed_before_social_idp_mutation_when_required_secret_refs_are_missing(self):
        reset_auth_clients()
        registry = active_registry()
        del registry["profiles"][1]["socialIdentityProviders"][1]["clientSecretRef"]
        event, _plan = self.apply_event(registry=registry)
        cognito, _dynamodb, _ssm, fake_boto3 = self.fake_aws()

        with patch.object(auth, "load_auth_registry_for_domain", return_value=registry), \
                patch.object(auth, "boto3", fake_boto3), \
                patch.dict(os.environ, self.apply_env()):
            response = auth.auth_lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(payload(response)["error"], "Social identity provider credential secret is not configured")
        self.assertEqual(cognito.calls, [])

    def test_executor_apply_fails_closed_before_social_idp_mutation_when_required_secret_values_are_missing(self):
        reset_auth_clients()
        event, _plan = self.apply_event()
        secret_values = fake_social_secret_values()
        del secret_values["/zoolanding/auth/tenant-a/planned/facebook/client-secret"]
        cognito, _dynamodb, _ssm, fake_boto3 = self.fake_aws(secrets=secret_values)

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()), \
                patch.object(auth, "boto3", fake_boto3), \
                patch.dict(os.environ, self.apply_env()):
            response = auth.auth_lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(payload(response)["error"], "Social identity provider credential secret is invalid")
        self.assertEqual(cognito.calls, [])

    def test_executor_apply_rejects_cross_tenant_secret_refs_before_mutation(self):
        reset_auth_clients()
        registry = active_registry()
        registry["profiles"][1]["socialIdentityProviders"][0]["clientIdRef"] = "/zoolanding/auth/other-tenant/planned/facebook/client-id"
        event, _plan = self.apply_event(registry=registry)
        cognito, _dynamodb, _ssm, fake_boto3 = self.fake_aws()

        with patch.object(auth, "load_auth_registry_for_domain", return_value=registry), \
                patch.object(auth, "boto3", fake_boto3), \
                patch.dict(os.environ, self.apply_env()):
            response = auth.auth_lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(payload(response)["error"], "Social identity provider credential reference is outside tenant scope")
        self.assertEqual(cognito.calls, [])

    def test_executor_apply_routes_secrets_manager_arn_refs_without_ssm_lookup(self):
        reset_auth_clients()
        registry = active_registry()
        google = registry["profiles"][1]["socialIdentityProviders"][1]
        google["clientIdRef"] = "arn:aws:secretsmanager:us-east-1:123456789012:secret:/zoolanding/auth/tenant-a/planned/google/client-id"
        google["clientSecretRef"] = "arn:aws:secretsmanager:us-east-1:123456789012:secret:/zoolanding/auth/tenant-a/planned/google/client-secret"
        event, _plan = self.apply_event(registry=registry)
        cognito = FakeCognitoClient()
        dynamodb = FakeDynamoClient()
        ssm = FakeSsmClient(fake_social_secret_values())
        secrets = FakeSecretsClient({
            google["clientIdRef"]: "google-client-id-from-secrets-manager",
            google["clientSecretRef"]: "google-client-secret-from-secrets-manager",
        })
        fake_boto3 = FakeBoto3(cognito=cognito, dynamodb=dynamodb, ssm=ssm, secrets=secrets)

        with patch.object(auth, "load_auth_registry_for_domain", return_value=registry), \
                patch.object(auth, "boto3", fake_boto3), \
                patch.dict(os.environ, self.apply_env()):
            response = auth.auth_lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 200)
        self.assertIn("create_identity_provider", [call[0] for call in cognito.calls])
        self.assertEqual([call["SecretId"] for call in secrets.calls], [
            google["clientIdRef"],
            google["clientSecretRef"],
        ])
        self.assertNotIn(google["clientIdRef"], [call["Name"] for call in ssm.calls])
        self.assertNotIn("google-client-secret-from-secrets-manager", response["body"])

    def test_executor_apply_resumes_without_repeating_already_succeeded_state_operations(self):
        reset_auth_clients()
        event, plan = self.apply_event()
        cognito, dynamodb, _ssm, fake_boto3 = self.fake_aws()
        dynamodb.seed_operation(plan, "ensure-user-pool", {
            "userPoolId": "us-east-1_EXISTING",
            "issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_EXISTING",
        })

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()), \
                patch.object(auth, "boto3", fake_boto3), \
                patch.dict(os.environ, self.apply_env()):
            response = auth.auth_lambda_handler(event, Ctx())

        body = payload(response)
        actions = [call[0] for call in cognito.calls]
        operation_statuses = {item["operationId"]: item["status"] for item in body["executor"]["operations"]}
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(body["executor"]["executionStatus"], "applied")
        self.assertEqual(operation_statuses["ensure-user-pool"], "skipped")
        self.assertNotIn("create_user_pool", actions)
        self.assertIn("create_user_pool_domain", actions)
        self.assertIn("update_user_pool_client", actions)
        self.assertGreaterEqual(len([call for call in dynamodb.calls if call[0] == "put_item"]), 6)

    def test_executor_rejects_extra_fields_and_browser_secret_material(self):
        for field_name in ("clientSecret", "adminOverride"):
            event = self.trusted_event({
                "domain": "example.test",
                "authProfileId": "planned",
                "mode": "dry-run",
                field_name: "must-not-pass",
            })

            with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()) as load_registry, \
                    patch.dict(os.environ, {"AUTH_PROVISIONING_ALLOWED_ROLE_NAMES": "zoolanding-auth-planner"}):
                response = auth.auth_lambda_handler(event, Ctx())

            self.assertEqual(response["statusCode"], 400)
            self.assertEqual(payload(response)["error"], "Unsupported auth provisioning executor option")
            self.assertNotIn("must-not-pass", response["body"])
            load_registry.assert_not_called()

    def test_executor_keys_are_deterministic_and_do_not_include_sensitive_material(self):
        event = self.trusted_event({
            "domain": "example.test",
            "authProfileId": "planned",
            "mode": "dry-run",
        })

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()), \
                patch.dict(os.environ, {"AUTH_PROVISIONING_ALLOWED_ROLE_NAMES": "zoolanding-auth-planner"}):
            response = auth.auth_lambda_handler(event, Ctx())
            repeated_response = auth.auth_lambda_handler(event, Ctx())

        body = payload(response)
        repeated_body = payload(repeated_response)
        serialized = json.dumps(body, sort_keys=True)
        self.assertEqual(body["executor"]["planKey"], repeated_body["executor"]["planKey"])
        self.assertEqual(body["executor"]["idempotencyKey"], repeated_body["executor"]["idempotencyKey"])
        self.assertEqual(body["executor"]["auditEvent"]["auditKey"], repeated_body["executor"]["auditEvent"]["auditKey"])
        self.assertRegex(body["executor"]["idempotencyKey"], r"^[0-9a-f]{64}$")
        self.assertRegex(body["executor"]["auditEvent"]["auditKey"], r"^[0-9a-f]{64}$")
        self.assertNotIn("tenant-a", body["executor"]["idempotencyKey"])
        self.assertNotIn("secret", serialized.lower())

    def test_executor_accepts_expected_idempotency_key_for_current_plan(self):
        initial_event = self.trusted_event({
            "domain": "example.test",
            "authProfileId": "planned",
            "mode": "dry-run",
        })

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()), \
                patch.dict(os.environ, {"AUTH_PROVISIONING_ALLOWED_ROLE_NAMES": "zoolanding-auth-planner"}):
            initial_response = auth.auth_lambda_handler(initial_event, Ctx())

        expected_key = payload(initial_response)["executor"]["idempotencyKey"]
        event = self.trusted_event({
            "domain": "example.test",
            "authProfileId": "planned",
            "mode": "dry-run",
            "idempotencyKey": expected_key,
        })

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()), \
                patch.dict(os.environ, {"AUTH_PROVISIONING_ALLOWED_ROLE_NAMES": "zoolanding-auth-planner"}):
            response = auth.auth_lambda_handler(event, Ctx())

        body = payload(response)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(body["executor"]["idempotencyKey"], expected_key)

    def test_executor_rejects_valid_hex_idempotency_key_that_does_not_match_current_plan(self):
        event = self.trusted_event({
            "domain": "example.test",
            "authProfileId": "planned",
            "mode": "dry-run",
            "idempotencyKey": "0" * 64,
        })

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()), \
                patch.dict(os.environ, {"AUTH_PROVISIONING_ALLOWED_ROLE_NAMES": "zoolanding-auth-planner"}):
            response = auth.auth_lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(
            payload(response)["error"],
            "Provisioning executor idempotencyKey does not match current plan",
        )

    def test_executor_rejects_mismatched_plan_key(self):
        event = self.trusted_event({
            "domain": "example.test",
            "authProfileId": "planned",
            "mode": "dry-run",
            "planKey": "not-the-generated-plan",
        })

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()), \
                patch.dict(os.environ, {"AUTH_PROVISIONING_ALLOWED_ROLE_NAMES": "zoolanding-auth-planner"}):
            response = auth.auth_lambda_handler(event, Ctx())

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(payload(response)["error"], "Provisioning executor planKey does not match current plan")

    def test_executor_apply_reconciles_existing_cognito_resources_without_operation_state(self):
        reset_auth_clients()
        event, plan = self.apply_event()
        cognito = FakeCognitoClient(
            user_pools=[
                {
                    "Name": auth._cognito_resource_name(plan, "user-pool"),
                    "Id": "us-east-1_EXISTING",
                    "Tags": auth._cognito_resource_tags(plan),
                }
            ],
            user_pool_clients={
                "us-east-1_EXISTING": [
                    {
                        "ClientName": auth._cognito_resource_name(plan, "public-client"),
                        "ClientId": "existing-public-client",
                    }
                ]
            },
        )
        dynamodb = FakeDynamoClient()
        ssm = FakeSsmClient(fake_social_secret_values())
        fake_boto3 = FakeBoto3(
            cognito=cognito,
            dynamodb=dynamodb,
            ssm=ssm,
            secrets=FakeSecretsClient(),
        )

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()), \
                patch.object(auth, "boto3", fake_boto3), \
                patch.dict(os.environ, self.apply_env()):
            response = auth.auth_lambda_handler(event, Ctx())

        body = payload(response)
        actions = [call[0] for call in cognito.calls]
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(body["executor"]["executionStatus"], "applied")
        self.assertEqual(body["executor"]["outputs"]["userPoolId"], "us-east-1_EXISTING")
        self.assertEqual(body["executor"]["outputs"]["clientId"], "existing-public-client")
        self.assertIn("list_user_pools", actions)
        self.assertIn("list_user_pool_clients", actions)
        self.assertNotIn("create_user_pool", actions)
        self.assertNotIn("create_user_pool_client", actions)
        self.assertIn("update_user_pool_client", actions)

    def test_executor_apply_retries_user_pool_after_succeeded_state_write_failure_without_duplicate_create(self):
        reset_auth_clients()
        event, _plan = self.apply_event()
        cognito, dynamodb, ssm, fake_boto3 = self.fake_aws()
        dynamodb.fail_once_on_put(operation_id="ensure-user-pool", status="succeeded")

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()), \
                patch.object(auth, "boto3", fake_boto3), \
                patch.dict(os.environ, self.apply_env()):
            failed_response = auth.auth_lambda_handler(event, Ctx())
            retry_response = auth.auth_lambda_handler(event, Ctx())

        failed_body = payload(failed_response)
        retry_body = payload(retry_response)
        actions = [call[0] for call in cognito.calls]
        self.assertEqual(failed_response["statusCode"], 500)
        self.assertEqual(failed_body["executor"]["executionStatus"], "failed")
        self.assertEqual(retry_response["statusCode"], 200)
        self.assertEqual(retry_body["executor"]["executionStatus"], "applied")
        self.assertEqual(actions.count("create_user_pool"), 1)
        self.assertIn("list_user_pools", actions)
        self.assertEqual(retry_body["executor"]["outputs"]["userPoolId"], "us-east-1_TESTPOOL")
        self.assertIn("/zoolanding/auth/tenant-a/planned/google/client-id", [call["Name"] for call in ssm.calls])

    def test_executor_apply_retries_public_client_after_succeeded_state_write_failure_without_duplicate_create(self):
        reset_auth_clients()
        event, _plan = self.apply_event()
        cognito, dynamodb, _ssm, fake_boto3 = self.fake_aws()
        dynamodb.fail_once_on_put(operation_id="ensure-public-client", status="succeeded")

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()), \
                patch.object(auth, "boto3", fake_boto3), \
                patch.dict(os.environ, self.apply_env()):
            failed_response = auth.auth_lambda_handler(event, Ctx())
            retry_response = auth.auth_lambda_handler(event, Ctx())

        failed_body = payload(failed_response)
        retry_body = payload(retry_response)
        actions = [call[0] for call in cognito.calls]
        self.assertEqual(failed_response["statusCode"], 500)
        self.assertEqual(failed_body["executor"]["executionStatus"], "failed")
        self.assertEqual(retry_response["statusCode"], 200)
        self.assertEqual(retry_body["executor"]["executionStatus"], "applied")
        self.assertEqual(actions.count("create_user_pool_client"), 1)
        self.assertIn("list_user_pool_clients", actions)
        self.assertEqual(retry_body["executor"]["outputs"]["clientId"], "public-client-created")

    def test_executor_apply_rejects_same_name_user_pool_without_matching_zoolanding_tags(self):
        reset_auth_clients()
        event, plan = self.apply_event()
        cognito = FakeCognitoClient(
            user_pools=[
                {
                    "Name": auth._cognito_resource_name(plan, "user-pool"),
                    "Id": "us-east-1_FOREIGN",
                    "Tags": {"managedBy": "other-system"},
                }
            ]
        )
        dynamodb = FakeDynamoClient()
        ssm = FakeSsmClient(fake_social_secret_values())
        fake_boto3 = FakeBoto3(
            cognito=cognito,
            dynamodb=dynamodb,
            ssm=ssm,
            secrets=FakeSecretsClient(),
        )

        with patch.object(auth, "load_auth_registry_for_domain", return_value=active_registry()), \
                patch.object(auth, "boto3", fake_boto3), \
                patch.dict(os.environ, self.apply_env()):
            response = auth.auth_lambda_handler(event, Ctx())

        actions = [call[0] for call in cognito.calls]
        self.assertEqual(response["statusCode"], 500)
        self.assertEqual(payload(response)["executor"]["executionStatus"], "failed")
        self.assertNotIn("create_user_pool", actions)


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

    def test_registry_adapter_uses_test_published_environment_for_shared_test_origin(self):
        metadata = {
            "published": {
                "versionId": "prod",
                "prefix": "sites/example.test/versions/prod",
            },
            "publishedEnvironments": {
                "test": {
                    "versionId": "test",
                    "prefix": "sites/example.test/versions/test",
                },
            },
        }

        previous_origin = auth._AUTH_REQUEST_ORIGIN
        try:
            auth._AUTH_REQUEST_ORIGIN = "https://test.zoolandingpage.com.mx"
            with patch.object(auth, "load_item", return_value=metadata), \
                    patch.object(auth, "load_json_from_s3", return_value=active_registry()) as load_json:
                result = auth.load_auth_registry_for_domain("example.test")
        finally:
            auth._AUTH_REQUEST_ORIGIN = previous_origin

        self.assertEqual(result["version"], 1)
        load_json.assert_called_once_with(
            "zoolanding-config-payloads",
            "sites/example.test/versions/test/example.test/server/auth-profile-registry.json",
        )

    def test_registry_adapter_uses_environment_alias_published_registry(self):
        metadata = {
            "published": {
                "versionId": "prod",
                "prefix": "sites/example.test/versions/prod",
            },
            "environmentAliases": {
                "test": ["test.example.test"],
            },
            "publishedEnvironments": {
                "test": {
                    "versionId": "test",
                    "prefix": "sites/example.test/versions/test",
                },
            },
        }

        previous_origin = auth._AUTH_REQUEST_ORIGIN
        try:
            auth._AUTH_REQUEST_ORIGIN = "https://test.example.test"
            with patch.object(auth, "load_item", return_value=metadata), \
                    patch.object(auth, "load_json_from_s3", return_value=active_registry()) as load_json:
                result = auth.load_auth_registry_for_domain("example.test")
        finally:
            auth._AUTH_REQUEST_ORIGIN = previous_origin

        self.assertEqual(result["version"], 1)
        load_json.assert_called_once_with(
            "zoolanding-config-payloads",
            "sites/example.test/versions/test/example.test/server/auth-profile-registry.json",
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

    def test_registry_validation_rejects_malformed_structured_social_provider_urls(self):
        registry = active_registry()
        registry["profiles"][1]["socialIdentityProviders"][2]["tokenUrl"] = "https://user:pass@idp.example.test/oauth2/token"

        with self.assertRaisesRegex(auth.AuthRegistryError, r"tokenUrl must be an absolute https URL"):
            auth.validate_auth_registry(registry)

    def test_registry_validation_requires_tenant_id_for_active_profiles(self):
        registry = active_registry()
        del registry["profiles"][0]["tenantId"]

        with self.assertRaises(auth.AuthRegistryError):
            auth.validate_auth_registry(registry)


if __name__ == "__main__":
    unittest.main()
