import copy
import os
import re
import sys
import unittest
from unittest.mock import patch


CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import auth_service as auth

try:
    import service_binding_registry_consumer_v2 as consumer
except ModuleNotFoundError:
    consumer = None


TABLE_NAME = "zoolanding-content-hub-test-ServiceBindingRegistryV2"
BINDING_KEY = "SERVICE_BINDING#test#thn-journal-test-v2"
DESCRIPTOR = {
    "descriptorVersionId": "thn-descriptor-v2",
    "descriptorSha256": "a" * 64,
    "authPolicyVersion": "thn-owner-v2",
}
TRUSTED_SCOPE = {
    "partition": "aws",
    "accountId": "123456789012",
    "region": "us-east-1",
}
BINDING_DESCRIPTOR = {
    "bindingId": "journal-v2",
    "domain": "thehairnarrative.com",
    "environment": "test",
    "authProfileId": "journal-owner",
    "featureId": "journal",
    "hubId": "thehairnarrative-com-journal",
    "serviceBindingId": "thn-journal-test-v2",
    "authBasePath": "/auth-v2",
    "contentHubBasePath": "/features/content-hub-v2",
    "status": "active",
}


def ddb_value(value):
    if isinstance(value, str):
        return {"S": value}
    if type(value) is int:
        return {"N": str(value)}
    if isinstance(value, dict):
        return {"M": {key: ddb_value(item) for key, item in value.items()}}
    raise AssertionError(f"Unsupported test value type: {type(value)!r}")


def ddb_item(record):
    return {key: ddb_value(value) for key, value in record.items()}


def active_record():
    owner = {
        "environment": "test",
        "domain": "thehairnarrative.com",
        "serviceBindingId": "thn-journal-test-v2",
        "hubId": "thehairnarrative-com-journal",
        "tenantId": "thehairnarrative-com",
        "authProfileId": "journal-owner",
    }
    return {
        "pk": BINDING_KEY,
        "sk": "REGISTRY#V2",
        "recordType": "service-binding-registry-v2",
        "schemaVersion": 2,
        **owner,
        "descriptorVersionId": DESCRIPTOR["descriptorVersionId"],
        "descriptorSha256": DESCRIPTOR["descriptorSha256"],
        "registryRevision": 7,
        "activationStatus": "active",
        "writerMode": "client-owner",
        "writerEpoch": 3,
        "cookieNamespace": "endefiz7dkk635k6di6k",
        "authPolicyVersion": DESCRIPTOR["authPolicyVersion"],
        "adminOrigin": "https://admin-test.thehairnarrative.com",
        "resourceBindings": {
            "authoringFunctionArn": (
                "arn:aws:lambda:us-east-1:123456789012:"
                "function:zoolanding-content-hub-test-ThnContentHubV2Authoring"
            ),
            "metadataTableArn": (
                "arn:aws:dynamodb:us-east-1:123456789012:"
                "table/zoolanding-content-hub-test-ThnContentHubV2Metadata"
            ),
        },
        "reservationOwner": owner,
    }


class FakeDynamoDbClient:
    def __init__(self, response=None, error=None):
        self.response = response if response is not None else {}
        self.error = error
        self.calls = []

    def get_item(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return copy.deepcopy(self.response)


def load(client, **overrides):
    args = {
        "expected_descriptor": copy.deepcopy(DESCRIPTOR),
        "expected_registry_revision": 7,
        "trusted_resource_scope": copy.deepcopy(TRUSTED_SCOPE),
    }
    args.update(overrides)
    return consumer.load_active_service_binding(client, **args)


def template_resource_block(template, resource_name):
    match = re.search(
        rf"^  {re.escape(resource_name)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9]+:\n|\Z)",
        template,
        re.M | re.S,
    )
    if not match:
        raise AssertionError(f"Template resource not found: {resource_name}")
    return match.group("body")


class TestConsumerAvailability(unittest.TestCase):
    def test_consumer_and_auth_adapter_exist(self):
        self.assertIsNotNone(consumer)
        self.assertTrue(callable(getattr(consumer, "load_active_service_binding", None)))
        self.assertTrue(callable(getattr(auth, "load_thn_service_binding_v2", None)))


@unittest.skipUnless(
    consumer is not None and callable(getattr(consumer, "load_active_service_binding", None)),
    "consumer implementation is not available yet",
)
class TestServiceBindingRegistryConsumerV2(unittest.TestCase):
    def assert_unavailable(self, callback):
        with self.assertRaises(consumer.RegistryConsumerError) as caught:
            callback()
        self.assertEqual(str(caught.exception), "service binding is unavailable")

    def test_reads_only_the_exact_key_with_strong_consistency(self):
        client = FakeDynamoDbClient({"Item": ddb_item(active_record())})

        result = load(client)

        self.assertEqual(result, active_record())
        self.assertEqual(
            client.calls,
            [
                {
                    "TableName": TABLE_NAME,
                    "Key": {
                        "pk": {"S": BINDING_KEY},
                        "sk": {"S": "REGISTRY#V2"},
                    },
                    "ConsistentRead": True,
                }
            ],
        )
        result["resourceBindings"]["metadataTableArn"] = "changed"
        self.assertNotEqual(result, active_record())

    def test_missing_inactive_and_duplicate_shaped_responses_fail_closed(self):
        inactive = active_record()
        inactive["activationStatus"] = "inactive"
        responses = (
            {},
            {"Item": ddb_item(inactive)},
            {"Items": [ddb_item(active_record()), ddb_item(active_record())]},
            {"Item": ddb_item(active_record()), "Count": 2},
        )
        for response in responses:
            with self.subTest(response_keys=sorted(response)):
                self.assert_unavailable(lambda: load(FakeDynamoDbClient(response)))

    def test_stale_descriptor_or_registry_revision_fails_closed(self):
        for field, replacement in (
            ("descriptorVersionId", "stale-version"),
            ("descriptorSha256", "b" * 64),
            ("authPolicyVersion", "stale-policy"),
            ("registryRevision", 6),
        ):
            record = active_record()
            record[field] = replacement
            with self.subTest(field=field):
                self.assert_unavailable(
                    lambda record=record: load(FakeDynamoDbClient({"Item": ddb_item(record)}))
                )

    def test_full_ownership_tuple_and_server_coordinates_are_exact(self):
        mismatches = {
            "pk": "SERVICE_BINDING#test#other",
            "sk": "REGISTRY#V1",
            "recordType": "other",
            "schemaVersion": 1,
            "environment": "prod",
            "domain": "other.example",
            "serviceBindingId": "other",
            "hubId": "other-hub",
            "tenantId": "other-tenant",
            "authProfileId": "other-profile",
            "cookieNamespace": "other-cookie",
            "adminOrigin": "https://other.example",
        }
        for field, replacement in mismatches.items():
            record = active_record()
            record[field] = replacement
            with self.subTest(field=field):
                self.assert_unavailable(
                    lambda record=record: load(FakeDynamoDbClient({"Item": ddb_item(record)}))
                )

        record = active_record()
        record["reservationOwner"]["tenantId"] = "other-tenant"
        self.assert_unavailable(lambda: load(FakeDynamoDbClient({"Item": ddb_item(record)})))

    def test_resource_bindings_are_exact_and_scoped_to_trusted_aws_coordinates(self):
        for field, replacement in (
            (
                "authoringFunctionArn",
                "arn:aws:lambda:us-west-2:123456789012:"
                "function:zoolanding-content-hub-test-ThnContentHubV2Authoring",
            ),
            (
                "metadataTableArn",
                "arn:aws:dynamodb:us-east-1:999999999999:"
                "table/zoolanding-content-hub-test-ThnContentHubV2Metadata",
            ),
        ):
            record = active_record()
            record["resourceBindings"][field] = replacement
            with self.subTest(field=field):
                self.assert_unavailable(
                    lambda record=record: load(FakeDynamoDbClient({"Item": ddb_item(record)}))
                )

    def test_missing_unknown_or_malformed_record_fields_fail_closed(self):
        missing = active_record()
        missing.pop("writerEpoch")
        unknown = active_record()
        unknown["copiedActivationSwitch"] = "active"
        malformed = active_record()
        malformed["writerEpoch"] = "3"
        for record in (missing, unknown, malformed):
            self.assert_unavailable(
                lambda record=record: load(FakeDynamoDbClient({"Item": ddb_item(record)}))
            )

    def test_invalid_expectations_or_table_override_fail_before_storage(self):
        client = FakeDynamoDbClient({"Item": ddb_item(active_record())})
        invalid_descriptors = (
            {**DESCRIPTOR, "unexpected": "value"},
            {**DESCRIPTOR, "descriptorSha256": "not-a-digest"},
        )
        for descriptor in invalid_descriptors:
            with self.subTest(descriptor=descriptor):
                self.assert_unavailable(
                    lambda descriptor=descriptor: load(client, expected_descriptor=descriptor)
                )
        self.assert_unavailable(lambda: load(client, expected_registry_revision=0))
        self.assert_unavailable(
            lambda: load(client, trusted_resource_scope={**TRUSTED_SCOPE, "region": "invalid"})
        )
        with patch.dict(
            os.environ,
            {"SERVICE_BINDING_REGISTRY_V2_TABLE_NAME": "untrusted-table"},
        ):
            self.assert_unavailable(lambda: load(client))
        self.assertEqual(client.calls, [])

    def test_provider_and_decoder_errors_are_sanitized(self):
        self.assert_unavailable(
            lambda: load(FakeDynamoDbClient(error=RuntimeError("provider-secret-detail")))
        )
        malformed_item = ddb_item(active_record())
        malformed_item["writerEpoch"] = {"N": "not-an-integer"}
        self.assert_unavailable(lambda: load(FakeDynamoDbClient({"Item": malformed_item})))

    def test_auth_adapter_uses_low_level_client_and_server_owned_scope(self):
        sentinel = object()
        with patch.object(auth, "_dynamodb", return_value=sentinel), patch.object(
            auth.service_binding_registry_consumer_v2,
            "load_active_service_binding",
            return_value={"ok": True},
        ) as loader, patch.dict(
            os.environ,
            {
                "AUTH_RUNTIME_ENVIRONMENT": "test",
                "SERVICE_BINDING_REGISTRY_V2_PARTITION": "aws",
                "SERVICE_BINDING_REGISTRY_V2_ACCOUNT_ID": "123456789012",
                "SERVICE_BINDING_REGISTRY_V2_REGION": "us-east-1",
            },
        ):
            result = auth.load_thn_service_binding_v2(BINDING_DESCRIPTOR, DESCRIPTOR, 7)

        self.assertEqual(result, {"ok": True})
        loader.assert_called_once_with(
            sentinel,
            expected_descriptor=DESCRIPTOR,
            expected_registry_revision=7,
            trusted_resource_scope=TRUSTED_SCOPE,
        )

    def test_auth_adapter_rejects_inactive_unknown_or_mismatched_binding_descriptor(self):
        invalid_descriptors = []
        for field, replacement in (
            ("bindingId", "other"),
            ("domain", "other.example"),
            ("environment", "prod"),
            ("authProfileId", "other"),
            ("featureId", "other"),
            ("hubId", "other"),
            ("serviceBindingId", "other"),
            ("authBasePath", "/auth"),
            ("contentHubBasePath", "/features/content-hub"),
            ("status", "inactive"),
        ):
            descriptor = copy.deepcopy(BINDING_DESCRIPTOR)
            descriptor[field] = replacement
            invalid_descriptors.append(descriptor)
        with_unknown = copy.deepcopy(BINDING_DESCRIPTOR)
        with_unknown["tenantId"] = "browser-controlled"
        invalid_descriptors.append(with_unknown)

        with patch.dict(os.environ, {"AUTH_RUNTIME_ENVIRONMENT": "test"}), patch.object(
            auth,
            "_dynamodb",
            side_effect=AssertionError("storage must not be called for a bad descriptor"),
        ):
            for descriptor in invalid_descriptors:
                with self.subTest(descriptor=descriptor):
                    self.assert_unavailable(
                        lambda descriptor=descriptor: auth.load_thn_service_binding_v2(
                            descriptor,
                            DESCRIPTOR,
                            7,
                        )
                    )

    def test_auth_adapter_is_unavailable_outside_the_test_runtime(self):
        with patch.dict(os.environ, {"AUTH_RUNTIME_ENVIRONMENT": "prod"}), patch.object(
            auth,
            "_dynamodb",
            side_effect=AssertionError("storage must not be called outside TEST"),
        ):
            self.assert_unavailable(
                lambda: auth.load_thn_service_binding_v2(BINDING_DESCRIPTOR, DESCRIPTOR, 7)
            )


class TestServiceBindingRegistryConsumerV2Template(unittest.TestCase):
    def test_api_proxy_alone_gets_exact_key_registry_read_permission(self):
        with open(os.path.join(PROJECT_ROOT, "template.yaml"), encoding="utf-8") as template_file:
            template = template_file.read()

        api_proxy = template_resource_block(template, "ApiProxyFunction")
        executor = template_resource_block(template, "AuthProvisioningExecutorFunction")
        authorizer = template_resource_block(template, "AuthJwtAuthorizerFunction")

        self.assertIn("SERVICE_BINDING_REGISTRY_V2_TABLE_NAME:", api_proxy)
        self.assertIn(TABLE_NAME, api_proxy)
        self.assertIn("SERVICE_BINDING_REGISTRY_V2_PARTITION:", api_proxy)
        self.assertIn("Ref: AWS::Partition", api_proxy)
        self.assertIn("SERVICE_BINDING_REGISTRY_V2_ACCOUNT_ID:", api_proxy)
        self.assertIn("Ref: AWS::AccountId", api_proxy)
        self.assertIn("SERVICE_BINDING_REGISTRY_V2_REGION:", api_proxy)
        self.assertIn("Ref: AWS::Region", api_proxy)
        self.assertRegex(
            api_proxy,
            re.compile(
                r"Policies:.*?- Fn::If:\s+- IsTestRuntimeEnvironment\s+- Version:",
                re.S,
            ),
        )
        self.assertRegex(
            api_proxy,
            re.compile(
                r"Action:\s*- dynamodb:GetItem\s+"
                r"Resource:\s+Fn::Sub: "
                r"arn:\$\{AWS::Partition\}:dynamodb:\$\{AWS::Region\}:"
                r"\$\{AWS::AccountId\}:table/"
                + re.escape(TABLE_NAME)
                + r"\s+Condition:\s+ForAllValues:StringEquals:\s+"
                r"dynamodb:LeadingKeys:\s+- "
                + re.escape(BINDING_KEY),
                re.S,
            ),
        )
        registry_statement = re.search(
            r"- Effect: Allow\s+Action:\s+- dynamodb:GetItem\s+"
            r"Resource:\s+Fn::Sub:.*?ServiceBindingRegistryV2.*?"
            r"(?=\n\s+- Effect:|\n\s+Events:)",
            api_proxy,
            re.S,
        )
        self.assertIsNotNone(registry_statement)
        for forbidden in (
            "dynamodb:BatchGetItem",
            "dynamodb:ConditionCheckItem",
            "dynamodb:PutItem",
            "dynamodb:Query",
            "dynamodb:Scan",
            "dynamodb:TransactGetItems",
            "dynamodb:UpdateItem",
        ):
            self.assertNotIn(forbidden, registry_statement.group(0))
        self.assertNotIn("SERVICE_BINDING_REGISTRY_V2_TABLE_NAME", executor)
        self.assertNotIn("SERVICE_BINDING_REGISTRY_V2_TABLE_NAME", authorizer)
        self.assertRegex(
            template,
            re.compile(
                r"ApiProxyFunctionRoleArn:\s+"
                r"Description:.*?\s+Value:\s+Fn::GetAtt:\s+"
                r"- ApiProxyFunctionRole\s+- Arn",
                re.S,
            ),
        )


if __name__ == "__main__":
    unittest.main()
