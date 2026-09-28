"""Contract checks for the THN-only TEST runtime API stack."""

from pathlib import Path
from types import SimpleNamespace
import copy
import os
import unittest
from unittest.mock import patch

import yaml


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "template-thn-runtime-test.yaml"
FUNCTION = "ThnAuthRuntimeV2Function"
API = "ThnRuntimeApi"
PATH = "/auth-v2/runtime-config"


class DedicatedRuntimeStackTests(unittest.TestCase):
    def template(self):
        self.assertTrue(TEMPLATE.is_file(), "the dedicated TEST template is missing")
        return yaml.safe_load(TEMPLATE.read_text(encoding="utf-8"))

    def test_template_contains_only_dedicated_resources(self):
        template = self.template()
        self.assertEqual(template["Transform"], "AWS::Serverless-2016-10-31")
        self.assertEqual(set(template["Resources"]), {API, FUNCTION, "ThnRuntimeLogGroup"})
        self.assertNotIn("ApiProxyApi", TEMPLATE.read_text(encoding="utf-8"))
        self.assertNotIn("ApiProxyFunction", TEMPLATE.read_text(encoding="utf-8"))
        self.assertNotIn("AWS::CloudFormation::Stack", str(template))

    def test_api_has_exact_two_runtime_operations(self):
        template = self.template()
        api = template["Resources"][API]
        self.assertEqual(api["Type"], "AWS::Serverless::Api")
        self.assertEqual(api["Properties"]["StageName"], "Prod")
        self.assertEqual(api["Properties"]["EndpointConfiguration"], "REGIONAL")
        function = template["Resources"][FUNCTION]
        self.assertEqual(function["Type"], "AWS::Serverless::Function")
        self.assertEqual(function["Properties"]["Handler"], "thn_auth_runtime_v2.lambda_handler")
        self.assertEqual(function["Properties"]["AutoPublishAlias"], "test")
        events = function["Properties"]["Events"]
        self.assertEqual(set(events), {"RuntimeGet", "RuntimePost"})
        for label, method in (("RuntimeGet", "get"), ("RuntimePost", "post")):
            self.assertEqual(events[label], {"Type": "Api", "Properties": {
                "RestApiId": {"Ref": API}, "Path": PATH, "Method": method.upper()}})

    def test_registry_read_is_exact_key_and_logs_are_bounded(self):
        template = self.template()
        function = template["Resources"][FUNCTION]["Properties"]
        policies = function["Policies"]
        self.assertEqual(len(policies), 1)
        statement = policies[0]["Statement"]
        self.assertEqual(len(statement), 1)
        self.assertEqual(statement[0]["Action"], ["dynamodb:GetItem"])
        self.assertEqual(statement[0]["Condition"]["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"],
                         ["SERVICE_BINDING#test#thn-journal-test-v2"])
        self.assertEqual(template["Resources"]["ThnRuntimeLogGroup"]["Properties"]["RetentionInDays"], 7)
        self.assertEqual(function["Environment"]["Variables"]["SERVICE_BINDING_REGISTRY_V2_TABLE_NAME"],
                         "zoolanding-content-hub-test-ServiceBindingRegistryV2")

    def test_all_runtime_dependencies_are_explicit_and_not_blocked(self):
        template = self.template()
        parameters = template["Parameters"]
        self.assertEqual(set(parameters), {
            "DescriptorVersionId", "DescriptorSha256", "AuthPolicyVersion",
            "CognitoUserPoolId", "CognitoClientId"})
        for name, value in parameters.items():
            self.assertNotIn("Default", value, name)
            self.assertIs(value.get("NoEcho"), True, name)
        self.assertIn("ThnRuntimeInputsRequired", template["Rules"])

    def test_sam_translation_creates_no_shared_resources(self):
        from samtranslator.translator.transform import transform

        template = copy.deepcopy(self.template())
        template["Resources"][FUNCTION]["Properties"]["CodeUri"] = {
            "Bucket": "synthetic-private", "Key": "thn-runtime/reviewed.zip", "Version": "synthetic-version"}
        parameters = {
            "DescriptorVersionId": "reviewed-1",
            "DescriptorSha256": "1" * 64,
            "AuthPolicyVersion": "reviewed-1",
            "CognitoUserPoolId": "us-east-1_example",
            "CognitoClientId": "exampleclient",
        }
        loader = SimpleNamespace(load=lambda: {
            "AWSLambdaBasicExecutionRole": "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"})
        with patch.dict(os.environ, {"AWS_DEFAULT_REGION": "us-east-1"}):
            native = transform(template, parameters, loader)
        resources = native["Resources"]
        self.assertFalse(any(name.startswith("ApiProxy") or name.startswith("AuthProvisioning")
                             or name.startswith("AuthJwt") for name in resources))
        self.assertEqual(set(resources[API]["Properties"]["Body"]["paths"]), {PATH})
        self.assertEqual(set(resources[API]["Properties"]["Body"]["paths"][PATH]), {"get", "post"})
        self.assertEqual(resources["ThnRuntimeLogGroup"]["Properties"]["RetentionInDays"], 7)
        self.assertEqual(resources[FUNCTION]["Properties"]["Code"], {
            "S3Bucket": "synthetic-private", "S3Key": "thn-runtime/reviewed.zip",
            "S3ObjectVersion": "synthetic-version"})


if __name__ == "__main__":
    unittest.main()
