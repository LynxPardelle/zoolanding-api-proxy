import base64
import json
import os
from pathlib import Path
import re
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import thn_auth_runtime_v2 as runtime_v2
from tools import build_thn_auth_runtime_v2_artifact as artifact_builder


ADMIN_HOST = "admin-test.thehairnarrative.com"
ADMIN_ORIGIN = f"https://{ADMIN_HOST}"
COOKIE_NAMESPACE = "endefiz7dkk635k6di6k"
DESCRIPTOR = {
    "descriptorVersionId": "test-v1",
    "descriptorSha256": "a" * 64,
    "authPolicyVersion": "journal-owner-v1",
}
ENVIRONMENT = {
    "THN_AUTH_RUNTIME_V2_DESCRIPTOR_VERSION_ID": DESCRIPTOR["descriptorVersionId"],
    "THN_AUTH_RUNTIME_V2_DESCRIPTOR_SHA256": DESCRIPTOR["descriptorSha256"],
    "THN_AUTH_RUNTIME_V2_AUTH_POLICY_VERSION": DESCRIPTOR["authPolicyVersion"],
    "THN_AUTH_RUNTIME_V2_AWS_PARTITION": "aws",
    "THN_AUTH_RUNTIME_V2_AWS_ACCOUNT_ID": "123456789012",
    "THN_AUTH_RUNTIME_V2_AWS_REGION": "us-east-1",
    "THN_AUTH_RUNTIME_V2_AWS_URL_SUFFIX": "amazonaws.com",
    "THN_AUTH_RUNTIME_V2_COGNITO_USER_POOL_ID": "us-east-1_AbCdEf123",
    "THN_AUTH_RUNTIME_V2_COGNITO_CLIENT_ID": "1234567890exampleclient",
}


def event(method="POST", *, body=None, query=None, path="/auth-v2/runtime-config", headers=None):
    request_headers = {
        "origin": ADMIN_ORIGIN,
        "x-forwarded-host": ADMIN_HOST,
        "content-type": "application/json",
    }
    request_headers.update(headers or {})
    return {
        "path": path,
        "rawPath": path,
        "httpMethod": method,
        "headers": request_headers,
        "queryStringParameters": query,
        "body": json.dumps(body) if body is not None else None,
        "isBase64Encoded": False,
        "requestContext": {"http": {"method": method, "path": path}},
    }


def response_body(response):
    return json.loads(response["body"])


def active_binding():
    return {
        "environment": "test",
        "domain": "thehairnarrative.com",
        "serviceBindingId": "thn-journal-test-v2",
        "hubId": "thehairnarrative-com-journal",
        "tenantId": "thehairnarrative-com",
        "authProfileId": "journal-owner",
        "adminOrigin": ADMIN_ORIGIN,
        "cookieNamespace": COOKIE_NAMESPACE,
        "activationStatus": "active",
        "writerMode": "disabled",
        "writerEpoch": 1,
        "registryRevision": 1,
    }


class FakeDynamoDbClient:
    pass


class RuntimeHarness:
    def __init__(self, binding=None, error=None):
        self.binding = binding or active_binding()
        self.error = error
        self.calls = []
        self.client = FakeDynamoDbClient()

    def load(self, client, **kwargs):
        self.calls.append((client, kwargs))
        if self.error:
            raise self.error
        return dict(self.binding)

    def invoke(self, request):
        with (
            patch.dict(os.environ, ENVIRONMENT, clear=False),
            patch.object(runtime_v2, "_DYNAMODB_CLIENT", self.client),
            patch.object(runtime_v2, "load_active_service_binding", side_effect=self.load),
        ):
            return runtime_v2.lambda_handler(request, None)


class TestThnAuthRuntimeV2(unittest.TestCase):
    def test_post_returns_only_browser_safe_v2_runtime_metadata(self):
        harness = RuntimeHarness()
        response = harness.invoke(event(body={
            "domain": "thehairnarrative.com",
            "authProfileId": "journal-owner",
        }))

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(
            response["headers"],
            {
                "Access-Control-Allow-Origin": ADMIN_ORIGIN,
                "Cache-Control": "no-store",
                "Content-Type": "application/json; charset=utf-8",
                "Expires": "0",
                "Pragma": "no-cache",
                "Vary": "Origin",
                "X-Content-Type-Options": "nosniff",
            },
        )
        payload = response_body(response)
        self.assertEqual(set(payload), {"ok", "domain", "auth"})
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["domain"], "thehairnarrative.com")
        auth = payload["auth"]
        self.assertEqual(
            set(auth),
            {
                "enabled",
                "authProfileId",
                "provider",
                "issuer",
                "userPoolId",
                "clientId",
                "hostedUiDomain",
                "scopes",
                "redirectPath",
                "logoutPath",
                "loginPath",
                "groupsClaim",
                "allowedGroups",
                "session",
            },
        )
        self.assertEqual(auth["authProfileId"], "journal-owner")
        self.assertEqual(auth["provider"], "cognito")
        self.assertEqual(
            auth["issuer"],
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEf123",
        )
        self.assertEqual(auth["hostedUiDomain"], ADMIN_ORIGIN)
        self.assertEqual(auth["redirectPath"], "/admin/journal")
        self.assertEqual(auth["logoutPath"], "/admin/journal/access")
        self.assertEqual(auth["loginPath"], "/admin/journal/access")
        self.assertEqual(auth["allowedGroups"], ["journal-owner"])
        self.assertEqual(
            auth["session"],
            {
                "mode": "server-cookie",
                "signinPath": "/auth-v2/session/signin",
                "mePath": "/auth-v2/session/me",
                "logoutPath": "/auth-v2/session/logout",
                "challengeRespondPath": "/auth-v2/session/challenge/respond",
                "mfaSetupPath": "/auth-v2/session/mfa/setup",
                "mfaVerifyPath": "/auth-v2/session/mfa/verify",
                "csrfCookieName": f"zlp_csrf_{COOKIE_NAMESPACE}",
                "challengeCsrfCookieName": f"zlp_challenge_csrf_{COOKIE_NAMESPACE}",
                "mfaEnrollCsrfCookieName": f"zlp_mfa_enroll_csrf_{COOKIE_NAMESPACE}",
                "csrfHeaderName": "x-zlp-csrf",
                "routeAccessCacheMs": 0,
            },
        )
        serialized = json.dumps(payload, sort_keys=True)
        for forbidden in (
            '"tenantId"',
            '"writerMode"',
            '"writerEpoch"',
            '"registryRevision"',
            '"resourceBindings"',
            '"reservationOwner"',
            '"descriptorSha256"',
            '"cookieNamespace"',
            '"accountPurpose"',
            '"sessionVersion"',
            '"token"',
            '"password"',
            '"secret"',
            '"/auth/',
            '"/features/content-hub/',
        ):
            self.assertNotIn(forbidden, serialized)

        self.assertEqual(len(harness.calls), 1)
        client, kwargs = harness.calls[0]
        self.assertIs(client, harness.client)
        self.assertEqual(kwargs["expected_descriptor"], DESCRIPTOR)
        self.assertEqual(
            kwargs["trusted_resource_scope"],
            {"partition": "aws", "accountId": "123456789012", "region": "us-east-1"},
        )

    def test_get_accepts_only_the_exact_fixed_coordinates(self):
        harness = RuntimeHarness()
        response = harness.invoke(event(
            "GET",
            query={"domain": "thehairnarrative.com", "authProfileId": "journal-owner"},
        ))
        self.assertEqual(response["statusCode"], 200)

        rejected = (
            event("GET", query=None),
            event("GET", query={"domain": "thehairnarrative.com"}),
            event("GET", query={
                "domain": "thehairnarrative.com",
                "authProfileId": "journal-owner",
                "draftDomain": "thehairnarrative.com",
            }),
            event("GET", query={"domain": "zoositioweb.com.mx", "authProfileId": "journal-owner"}),
            event("GET", query={"domain": "thehairnarrative.com", "authProfileId": "staff"}),
        )
        for request in rejected:
            with self.subTest(request=request):
                denied = harness.invoke(request)
                self.assertEqual(denied["statusCode"], 400)
        self.assertEqual(len(harness.calls), 1)

    def test_post_rejects_unknown_fields_queries_invalid_json_and_oversized_body(self):
        harness = RuntimeHarness()
        valid = {"domain": "thehairnarrative.com", "authProfileId": "journal-owner"}
        cases = []
        cases.append(event(body={**valid, "draftDomain": "thehairnarrative.com"}))
        with_query = event(body=valid)
        with_query["queryStringParameters"] = {"lang": "en"}
        cases.append(with_query)
        invalid_json = event(body=valid)
        invalid_json["body"] = "{"
        cases.append(invalid_json)
        encoded = event(body=valid)
        encoded["isBase64Encoded"] = True
        encoded["body"] = base64.b64encode(json.dumps(valid).encode()).decode()
        cases.append({**encoded, "body": "%%%not-base64%%%"})
        oversized = event(body=valid)
        oversized["body"] = " " * 4097
        cases.append(oversized)

        for request in cases:
            with self.subTest(request=request):
                response = harness.invoke(request)
                self.assertEqual(response["statusCode"], 400)
        self.assertEqual(harness.calls, [])

    def test_base64_post_body_is_supported_without_relaxing_the_contract(self):
        harness = RuntimeHarness()
        payload = {"domain": "thehairnarrative.com", "authProfileId": "journal-owner"}
        request = event(body=payload)
        request["isBase64Encoded"] = True
        request["body"] = base64.b64encode(json.dumps(payload).encode()).decode()
        response = harness.invoke(request)
        self.assertEqual(response["statusCode"], 200)

    def test_wrong_origin_host_route_or_method_fails_before_registry_read(self):
        harness = RuntimeHarness()
        requests = (
            event(body={"domain": "thehairnarrative.com", "authProfileId": "journal-owner"}, headers={"origin": "https://test.zoolandingpage.com.mx"}),
            event(body={"domain": "thehairnarrative.com", "authProfileId": "journal-owner"}, headers={"x-forwarded-host": "test.zoolandingpage.com.mx"}),
            event(body={"domain": "thehairnarrative.com", "authProfileId": "journal-owner"}, headers={"origin": "*"}),
            event(body={"domain": "thehairnarrative.com", "authProfileId": "journal-owner"}, path="/auth/runtime-config"),
            event("OPTIONS", body=None),
            event("PUT", body={"domain": "thehairnarrative.com", "authProfileId": "journal-owner"}),
        )
        for request in requests:
            with self.subTest(request=request):
                response = harness.invoke(request)
                self.assertIn(response["statusCode"], {403, 404, 405})
                self.assertNotIn("Access-Control-Allow-Origin", response["headers"])
        self.assertEqual(harness.calls, [])

    def test_binding_or_activation_errors_collapse_to_one_no_store_response(self):
        for error in (
            RuntimeError("provider table and account detail"),
            runtime_v2.RegistryConsumerError("service binding is unavailable"),
        ):
            with self.subTest(error=error):
                response = RuntimeHarness(error=error).invoke(event(body={
                    "domain": "thehairnarrative.com",
                    "authProfileId": "journal-owner",
                }))
                self.assertEqual(response["statusCode"], 503)
                self.assertEqual(
                    response_body(response),
                    {"ok": False, "error": "Authentication temporarily unavailable", "errorCode": "auth_unavailable"},
                )
                self.assertEqual(response["headers"]["Cache-Control"], "no-store")
                self.assertNotIn("provider", response["body"])

    def test_runtime_environment_is_closed_and_validated_before_registry_read(self):
        harness = RuntimeHarness()
        valid_request = event(body={"domain": "thehairnarrative.com", "authProfileId": "journal-owner"})
        invalid_overrides = (
            {"THN_AUTH_RUNTIME_V2_DESCRIPTOR_VERSION_ID": ""},
            {"THN_AUTH_RUNTIME_V2_DESCRIPTOR_SHA256": "not-a-digest"},
            {"THN_AUTH_RUNTIME_V2_AUTH_POLICY_VERSION": "BLOCKED"},
            {"THN_AUTH_RUNTIME_V2_AWS_REGION": "eu-west-1"},
            {"THN_AUTH_RUNTIME_V2_COGNITO_USER_POOL_ID": "BLOCKED"},
            {"THN_AUTH_RUNTIME_V2_COGNITO_CLIENT_ID": "BLOCKED"},
        )
        for override in invalid_overrides:
            with self.subTest(override=override):
                with patch.dict(os.environ, {**ENVIRONMENT, **override}, clear=False):
                    with patch.object(runtime_v2, "_DYNAMODB_CLIENT", harness.client):
                        with patch.object(runtime_v2, "load_active_service_binding", side_effect=harness.load):
                            response = runtime_v2.lambda_handler(valid_request, None)
                self.assertEqual(response["statusCode"], 503)
        self.assertEqual(harness.calls, [])


class TestThnAuthRuntimeV2Template(unittest.TestCase):
    def setUp(self):
        self.template = (PROJECT_ROOT / "template.yaml").read_text(encoding="utf-8")

    def resource(self, name):
        match = re.search(
            rf"^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9]+:\n|\Z)",
            self.template,
            re.M | re.S,
        )
        if not match:
            self.fail(f"Template resource not found: {name}")
        return match.group("body")

    def test_template_declares_default_off_test_only_runtime_boundary(self):
        self.assertRegex(
            self.template,
            re.compile(r"EnableThnAuthRuntimeV2:\n(?: {4}.*\n)*? {4}Default: 'false'"),
        )
        self.assertIn("ThnAuthRuntimeV2ActivationRule:", self.template)
        self.assertIn("IsThnAuthRuntimeV2Enabled:", self.template)
        condition = re.search(
            r"^  IsThnAuthRuntimeV2Enabled:\n(?P<body>.*?)(?=^  [A-Za-z0-9]+:\n|^Globals:)",
            self.template,
            re.M | re.S,
        )
        self.assertIsNotNone(condition)
        self.assertIn("AuthRuntimeEnvironment", condition.group("body"))
        self.assertIn("- test", condition.group("body"))
        self.assertIn("EnableThnAuthRuntimeV2", condition.group("body"))

    def test_checked_in_sam_environments_do_not_enable_the_runtime(self):
        samconfig = (PROJECT_ROOT / "samconfig.toml").read_text(encoding="utf-8")
        self.assertNotRegex(
            samconfig,
            re.compile(r"(?:^|\s)EnableThnAuthRuntimeV2\s*=\s*(?:true|'true'|\"true\")"),
        )

    def test_template_adds_only_exact_get_and_post_v2_routes_to_a_separate_lambda(self):
        function = self.resource("ThnAuthRuntimeV2Function")
        self.assertIn("Condition: IsThnAuthRuntimeV2Enabled", function)
        self.assertIn("Handler: thn_auth_runtime_v2.lambda_handler", function)
        self.assertIn("BuildMethod: makefile", function)
        self.assertIn("AutoPublishAlias: test", function)
        routes = re.findall(r"Path: (/auth-v2/[^\s]+)\s+Method: ([A-Z]+)", function)
        self.assertEqual(
            set(routes),
            {("/auth-v2/runtime-config", "GET"), ("/auth-v2/runtime-config", "POST")},
        )
        self.assertNotIn("Method: OPTIONS", function)

    def test_runtime_lambda_has_only_exact_registry_read_authority(self):
        function = self.resource("ThnAuthRuntimeV2Function")
        self.assertIn("dynamodb:GetItem", function)
        self.assertNotRegex(function, r"dynamodb:(?:Put|Update|Delete|Transact|BatchWrite)")
        self.assertIn("zoolanding-content-hub-test-ServiceBindingRegistryV2", function)
        self.assertIn("SERVICE_BINDING#test#thn-journal-test-v2", function)
        for value in (
            "ThnAuthRuntimeV2DescriptorVersionId",
            "ThnAuthRuntimeV2DescriptorSha256",
            "ThnAuthRuntimeV2AuthPolicyVersion",
            "ThnAuthRuntimeV2CognitoUserPoolId",
            "ThnAuthRuntimeV2CognitoClientId",
            "AWS::Partition",
            "AWS::AccountId",
            "AWS::Region",
            "AWS::URLSuffix",
        ):
            self.assertIn(value, function)

        for legacy_name in (
            "ApiProxyFunction",
            "AuthProvisioningExecutorFunction",
            "AuthJwtAuthorizerFunction",
        ):
            legacy = self.resource(legacy_name)
            self.assertNotIn("THN_AUTH_RUNTIME_V2_", legacy)
            self.assertNotIn("ServiceBindingRegistryV2", legacy)

    def test_builder_allowlists_only_the_runtime_handler_and_registry_consumer(self):
        builder = (PROJECT_ROOT / "tools" / "build_thn_auth_runtime_v2_artifact.py").read_text(encoding="utf-8")
        self.assertIn('"thn_auth_runtime_v2.py"', builder)
        self.assertIn('"service_binding_registry_consumer_v2.py"', builder)
        for forbidden in (
            '"lambda_function.py"',
            '"auth_service.py"',
            '"tests"',
            '"samconfig.toml"',
            '".git"',
        ):
            self.assertNotIn(forbidden, builder)

    def test_builder_produces_an_exact_two_file_artifact_and_refuses_contamination(self):
        with TemporaryDirectory() as temp_dir:
            destination = Path(temp_dir)
            artifact_builder.build(destination)
            self.assertEqual(
                {entry.name for entry in destination.iterdir()},
                {"thn_auth_runtime_v2.py", "service_binding_registry_consumer_v2.py"},
            )
            with self.assertRaisesRegex(RuntimeError, "not empty"):
                artifact_builder.build(destination)


if __name__ == "__main__":
    unittest.main()
