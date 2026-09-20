"""Fail-closed checks for creating only the THN runtime's own stack."""

import copy
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
import zipfile
from unittest.mock import patch

import yaml
from botocore.exceptions import ClientError


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = {"Bucket": "synthetic-private", "Key": "thn-runtime/reviewed.zip", "Version": "synthetic-version"}
PARAMETERS = {
    "DescriptorVersionId": "reviewed-1", "DescriptorSha256": "1" * 64,
    "AuthPolicyVersion": "reviewed-1", "CognitoUserPoolId": "us-east-1_example",
    "CognitoClientId": "exampleclient",
}


class DedicatedRuntimeReleaseTests(unittest.TestCase):
    def module(self):
        self.assertTrue((ROOT / "tools/thn_dedicated_runtime_test.py").is_file(), "dedicated release guard missing")
        return importlib.import_module("tools.thn_dedicated_runtime_test")

    def source(self):
        return yaml.safe_load((ROOT / "template-thn-runtime-test.yaml").read_text(encoding="utf-8"))

    def native(self):
        with patch.dict(os.environ, {"AWS_DEFAULT_REGION": "us-east-1"}):
            return self.module().render_native(self.source(), PACKAGE, PARAMETERS)

    def changes(self, native):
        return {"Status": "CREATE_COMPLETE", "ExecutionStatus": "AVAILABLE", "Changes": [
            {"ResourceChange": {"Action": "Add", "LogicalResourceId": name,
                                "ResourceType": resource["Type"]}}
            for name, resource in native["Resources"].items()]}

    def test_native_template_has_only_dedicated_resources_and_versioned_code(self):
        native = self.native()
        resources = native["Resources"]
        self.assertTrue(resources)
        self.assertFalse(any(name.startswith(("ApiProxy", "AuthJwt", "AuthProvisioning")) for name in resources))
        self.assertEqual(resources["ThnAuthRuntimeV2Function"]["Properties"]["Code"], {
            "S3Bucket": PACKAGE["Bucket"], "S3Key": PACKAGE["Key"], "S3ObjectVersion": PACKAGE["Version"]})
        self.assertEqual(set(resources["ThnRuntimeApi"]["Properties"]["Body"]["paths"]),
                         {"/auth-v2/runtime-config"})

    def test_rejects_shared_resource_or_unversioned_package(self):
        module = self.module()
        for package in ({"Bucket": "synthetic-private", "Key": "thn-runtime/reviewed.zip"},
                        {**PACKAGE, "Version": "null"}):
            with self.subTest(package=package), self.assertRaises(ValueError):
                module.render_native(self.source(), package, PARAMETERS)
        source = copy.deepcopy(self.source())
        source["Resources"]["ApiProxyFunction"] = {"Type": "AWS::Lambda::Function"}
        with self.assertRaises(ValueError):
            module.render_native(source, PACKAGE, PARAMETERS)

    def test_accepts_only_exact_create_changes(self):
        module = self.module()
        native = self.native()
        changes = self.changes(native)
        self.assertEqual(module.review_create_change_set(changes, native), sorted(native["Resources"]))
        for changed in (
            {**changes, "Status": "FAILED"},
            {**changes, "ExecutionStatus": "EXECUTE_COMPLETE"},
            {**changes, "NextToken": "another-page"},
            {**changes, "Changes": changes["Changes"][:-1]},
            {**changes, "Changes": changes["Changes"] + [
                {"ResourceChange": {"Action": "Modify", "LogicalResourceId": "ApiProxyFunction",
                                    "ResourceType": "AWS::Lambda::Function"}}]},
        ):
            with self.subTest(changed=changed.get("Status")), self.assertRaises(ValueError):
                module.review_create_change_set(changed, native)

    def test_rejects_replacement_and_unexpected_detail_even_on_add(self):
        module = self.module()
        native = self.native()
        changes = self.changes(native)
        for extra in ({"Replacement": "True"}, {"Details": [{"Target": {"Attribute": "Role"}}]},
                      {"PhysicalResourceId": "shared-resource"}):
            altered = copy.deepcopy(changes)
            altered["Changes"][0]["ResourceChange"].update(extra)
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                module.review_create_change_set(altered, native)

    def test_private_plan_is_canonical_and_source_package_pinned(self):
        module = self.module()
        self.assertTrue(hasattr(module, "validate_plan"), "private plan validation missing")
        plan = {
            "schemaVersion": 1, "environment": "test", "stackName": "zoolanding-thn-auth-runtime-test",
            "sourceSha": "a" * 40, "templateSha256": "b" * 64,
            "package": {"bucket": "synthetic-private", "key": "zoolanding-api-proxy-test/thn-runtime/reviewed/runtime-v2.zip",
                        "versionId": "version-1", "sha256": "c" * 64},
            "parameters": PARAMETERS,
        }
        raw = json.dumps(plan, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(raw.encode()).hexdigest()
        self.assertEqual(module.validate_plan(raw, digest, "a" * 40, "b" * 64,
                                              "synthetic-private"), plan)
        for altered in (
            raw.replace('"environment":"test"', '"environment":"prod"'),
            raw.replace('"sourceSha":"' + "a" * 40 + '"', '"sourceSha":"' + "d" * 40 + '"'),
            raw.replace('"bucket":"synthetic-private"', '"bucket":"other-bucket"'),
            raw.replace('"parameters":', '"unexpected":true,"parameters":'),
            raw.replace('"schemaVersion":1', '"schemaVersion":2'),
            '{ "schemaVersion":1 }',
        ):
            with self.subTest(altered=altered[:45]), self.assertRaises(ValueError):
                module.validate_plan(altered, hashlib.sha256(altered.encode()).hexdigest(),
                                     "a" * 40, "b" * 64, "synthetic-private")
        with self.assertRaises(ValueError):
            module.validate_plan(raw, "0" * 64, "a" * 40, "b" * 64, "synthetic-private")

    def test_package_is_exact_two_source_modules(self):
        module = self.module()
        self.assertTrue(hasattr(module, "verify_package"), "package readback guard missing")
        entries = {"thn_auth_runtime_v2.py": b"handler", "service_binding_registry_consumer_v2.py": b"registry"}

        def archive(files):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as output:
                for name, value in files.items():
                    output.writestr(name, value)
            return buffer.getvalue()

        good = archive(entries)
        digest = hashlib.sha256(good).hexdigest()
        self.assertEqual(module.verify_package(good, digest, entries), True)
        for data in (archive({**entries, "shared.py": b"shared"}),
                     archive({**entries, "thn_auth_runtime_v2.py": b"changed"}), b"not a zip"):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                module.verify_package(data, hashlib.sha256(data).hexdigest(), entries)
        with self.assertRaises(ValueError):
            module.verify_package(good, "0" * 64, entries)

    def test_derives_dedicated_selection_only_from_approved_first_plan(self):
        module = self.module()
        first = {
            "schema": "thn-first-runtime/v1", "service": "zoolanding-api-proxy",
            "environment": "test", "tooling": {"sha": "a" * 40, "workflowSha256": "b" * 64},
            "target": {"account": "765932874577", "region": "us-east-1",
                       "stackId": "arn:aws:cloudformation:us-east-1:765932874577:stack/zoolanding-api-proxy-test/synthetic"},
            "baselineSha256": "c" * 64, "snapshotSha256": "d" * 64,
            "templateSha256": "e" * 64,
            "package": {"Bucket": "synthetic-private",
                        "Key": "zoolanding-api-proxy-test/thn-runtime/reviewed.zip",
                        "Version": "synthetic-version"},
            "packageSha256": "f" * 64,
            "parameters": {
                "EnableThnAuthRuntimeV2": "true",
                "ThnAuthRuntimeV2DescriptorVersionId": "reviewed-1",
                "ThnAuthRuntimeV2DescriptorSha256": "1" * 64,
                "ThnAuthRuntimeV2AuthPolicyVersion": "reviewed-1",
                "ThnAuthRuntimeV2CognitoUserPoolId": "us-east-1_example",
                "ThnAuthRuntimeV2CognitoClientId": "exampleclient",
            },
        }
        selected = module.derive_plan(first, "2" * 40, "3" * 64, "synthetic-private")
        self.assertEqual(selected["package"], {
            "bucket": "synthetic-private", "key": first["package"]["Key"],
            "versionId": "synthetic-version", "sha256": "f" * 64})
        self.assertEqual(selected["parameters"], PARAMETERS)
        raw = json.dumps(selected, sort_keys=True, separators=(",", ":"))
        self.assertEqual(module.validate_plan(raw, hashlib.sha256(raw.encode()).hexdigest(),
                                              "2" * 40, "3" * 64, "synthetic-private"), selected)
        for changed in (
            {**first, "environment": "prod"},
            {**first, "package": {**first["package"], "Bucket": "other"}},
            {**first, "package": {**first["package"], "Key": "elsewhere/reviewed.zip"}},
            {**first, "parameters": {**first["parameters"], "EnableThnAuthRuntimeV2": "false"}},
            {**first, "target": {**first["target"], "account": "123456789012"}},
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                module.derive_plan(changed, "2" * 40, "3" * 64, "synthetic-private")

    def test_release_verify_is_read_only_and_create_reviews_before_execute(self):
        module = self.module()
        self.assertTrue(hasattr(module, "release"), "reviewed release sequence missing")
        native = self.native()
        plan = {"stackName": "zoolanding-thn-auth-runtime-test", "sourceSha": "a" * 40,
                "parameters": PARAMETERS}

        class Waiter:
            def __init__(self, owner, name):
                self.owner, self.name = owner, name

            def wait(self, **kwargs):
                self.owner.calls.append(("wait:" + self.name, kwargs))

        class FakeCloudFormation:
            def __init__(self, response):
                self.response, self.calls = response, []

            def create_change_set(self, **kwargs):
                self.calls.append(("create", kwargs))
                return {"Id": "arn:aws:cloudformation:us-east-1:123456789012:changeSet/synthetic/1"}

            def get_waiter(self, name):
                return Waiter(self, name)

            def describe_change_set(self, **kwargs):
                self.calls.append(("describe_change_set", kwargs))
                return self.response

            def execute_change_set(self, **kwargs):
                self.calls.append(("execute", kwargs))

            def update_termination_protection(self, **kwargs):
                self.calls.append(("protect", kwargs))

            def describe_stacks(self, **kwargs):
                self.calls.append(("describe_stacks", kwargs))
                return {"Stacks": [{"StackStatus": "CREATE_COMPLETE", "EnableTerminationProtection": True}]}

            def list_stack_resources(self, **kwargs):
                self.calls.append(("list_stack_resources", kwargs))
                return {"StackResourceSummaries": [{"LogicalResourceId": name, "ResourceType": item["Type"],
                                                    "ResourceStatus": "CREATE_COMPLETE"}
                                                   for name, item in native["Resources"].items()]}

        role = "arn:aws:iam::123456789012:role/zoolanding-deployer-thn-auth-runtime-test-cfn-exec"
        client = FakeCloudFormation(self.changes(native))
        self.assertEqual(module.release("verify", plan, native, client, role), "verified")
        self.assertEqual(client.calls, [])
        self.assertEqual(module.release("create", plan, native, client, role), "created")
        verbs = [item[0] for item in client.calls]
        self.assertLess(verbs.index("describe_change_set"), verbs.index("execute"))
        self.assertLess(verbs.index("execute"), verbs.index("protect"))
        self.assertEqual(client.calls[0][1]["ChangeSetType"], "CREATE")
        self.assertEqual(client.calls[0][1]["StackName"], plan["stackName"])
        self.assertEqual(client.calls[0][1]["RoleARN"], role)
        bad = FakeCloudFormation({**self.changes(native), "Changes": []})
        with self.assertRaises(ValueError):
            module.release("create", plan, native, bad, role)
        self.assertNotIn("execute", [item[0] for item in bad.calls])

    def test_existing_stack_or_unexpected_lookup_error_blocks_create(self):
        module = self.module()

        class Existing:
            def describe_stacks(self, **kwargs):
                return {"Stacks": [{"StackStatus": "CREATE_COMPLETE"}]}

        class Missing:
            def describe_stacks(self, **kwargs):
                raise ClientError({"Error": {"Code": "ValidationError",
                                             "Message": "Stack with id x does not exist"}},
                                  "DescribeStacks")

        class Denied:
            def describe_stacks(self, **kwargs):
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}},
                                  "DescribeStacks")

        self.assertTrue(module._stack_absent(Missing()))
        with self.assertRaises(ValueError):
            module._stack_absent(Existing())
        with self.assertRaises(ValueError):
            module._stack_absent(Denied())

    def test_full_verify_entrypoint_uses_existing_private_selection_without_writes(self):
        module = self.module()
        bucket = "aws-sam-cli-managed-default-samclisourcebucket-synthetic"
        key = "zoolanding-api-proxy-test/thn-runtime/reviewed.zip"
        version = "synthetic-version"
        entries = {name: (ROOT / name).read_bytes() for name in (
            "thn_auth_runtime_v2.py", "service_binding_registry_consumer_v2.py")}
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            for name, body in entries.items():
                archive.writestr(name, body)
        body = output.getvalue()
        first = {
            "schema": "thn-first-runtime/v1", "service": "zoolanding-api-proxy",
            "environment": "test", "tooling": {"sha": "a" * 40, "workflowSha256": "b" * 64},
            "target": {"account": "765932874577", "region": "us-east-1",
                       "stackId": "arn:aws:cloudformation:us-east-1:765932874577:stack/zoolanding-api-proxy-test/synthetic"},
            "baselineSha256": "c" * 64, "snapshotSha256": "d" * 64,
            "templateSha256": "e" * 64, "packageSha256": hashlib.sha256(body).hexdigest(),
            "package": {"Bucket": bucket, "Key": key, "Version": version},
            "parameters": {
                "EnableThnAuthRuntimeV2": "true",
                "ThnAuthRuntimeV2DescriptorVersionId": PARAMETERS["DescriptorVersionId"],
                "ThnAuthRuntimeV2DescriptorSha256": PARAMETERS["DescriptorSha256"],
                "ThnAuthRuntimeV2AuthPolicyVersion": PARAMETERS["AuthPolicyVersion"],
                "ThnAuthRuntimeV2CognitoUserPoolId": PARAMETERS["CognitoUserPoolId"],
                "ThnAuthRuntimeV2CognitoClientId": PARAMETERS["CognitoClientId"],
            },
        }

        class FakeSession:
            region_name = "us-east-1"

            def client(self, service):
                if service == "sts":
                    return SimpleNamespace(get_caller_identity=lambda: {"Account": "765932874577"})
                if service == "s3":
                    def get_object(**kwargs):
                        self_test.assertEqual(kwargs, {"Bucket": bucket, "Key": key,
                                                       "VersionId": version})
                        return {"VersionId": version, "ContentLength": len(body),
                                "Body": io.BytesIO(body)}
                    return SimpleNamespace(get_object=get_object)
                if service == "cloudformation":
                    def describe_stacks(**kwargs):
                        self_test.assertEqual(kwargs, {"StackName": module.STACK_NAME})
                        raise ClientError({"Error": {"Code": "ValidationError",
                                                     "Message": "Stack does not exist"}}, "DescribeStacks")
                    return SimpleNamespace(describe_stacks=describe_stacks)
                raise AssertionError("unexpected AWS client")

        self_test = self
        sha = "a" * 40
        values = {
            "GITHUB_REPOSITORY": "LynxPardelle/zoolanding-api-proxy",
            "GITHUB_REF": "refs/heads/test", "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_SHA": sha, "SOURCE_SHA": sha,
            "AWS_CLOUDFORMATION_ROLE_ARN":
                "arn:aws:iam::765932874577:role/zoolanding-deployer-thn-auth-runtime-test-cfn-exec",
            "AWS_REGION": "us-east-1", "AWS_DEFAULT_REGION": "us-east-1",
            "SAM_ARTIFACTS_BUCKET": bucket,
            "THN_TEMPLATE_SHA256": hashlib.sha256(
                (ROOT / "template-thn-runtime-test.yaml").read_bytes()).hexdigest(),
            "THN_FIRST_PLAN_REFERENCE_JSON": json.dumps({
                "bucket": bucket,
                "key": "zoolanding-api-proxy-test/first-provisioning/reviewed.json",
                "versionId": "synthetic-version"}),
        }
        with patch.dict(os.environ, values), patch("boto3.Session", return_value=FakeSession()), \
                patch("tools.thn_first_provisioning.load_plan", return_value=first), \
                patch("tools.thn_first_provisioning._prerequisites"):
            self.assertEqual(module.run_workflow("verify", os.environ), "verified")


if __name__ == "__main__":
    unittest.main()
