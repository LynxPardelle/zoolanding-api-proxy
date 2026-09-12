"""Exercise the actual recovery driver against a synthetic, SDK-shaped AWS boundary."""

import base64
import contextlib
import copy
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import warnings
import zipfile


ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = "123456789012"
STACK = "zoolanding-api-proxy-test"
STACK_ARN = f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/{STACK}/synthetic"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/zoolanding-deployer-api-proxy-test-cfn-exec"
FUNCTIONS = ("ApiProxyFunction", "AuthProvisioningExecutorFunction", "AuthJwtAuthorizerFunction")
TOOLING = {"sha": "1" * 40, "workflowSha256": "2" * 64}


def digest(value):
    if not isinstance(value, bytes):
        value = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(value).hexdigest()


def package(entries=None):
    result = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(result, "w") as archive:
        warnings.simplefilter("ignore", UserWarning)
        for name, body in entries or [("lambda_function.py", b"old original bytes\n"),
                                      ("auth_service.py", b"old auth bytes\n")]:
            archive.writestr(name, body)
    return result.getvalue()


class SyntheticAWS:
    """Only the external SDK transport is substituted; validation/composition are real."""

    region_name = "us-east-1"

    def __init__(self):
        self.account = ACCOUNT
        self.body = package()
        self.version = "original-version"
        self.bucket = "synthetic-private-artifacts"
        self.key = "synthetic-prior/package.zip"
        self.calls = []
        self.writes = []
        self.read_hook = None
        self.object_hook = None
        self.review_hook = None
        self.stack_reads = 0
        self.object_reads = 0
        self.stack = {"StackId": STACK_ARN, "StackName": STACK,
                      "StackStatus": "UPDATE_COMPLETE", "EnableTerminationProtection": True,
                      "RoleARN": ROLE, "Parameters": [
                          {"ParameterKey": "AuthRuntimeEnvironment", "ParameterValue": "test"},
                          {"ParameterKey": "PrivateSetting", "ParameterValue": "DO-NOT-EMIT"}]}
        self.original = {"AWSTemplateFormatVersion": "2010-09-09", "Parameters": {
            "AuthRuntimeEnvironment": {"Type": "String"}, "PrivateSetting": {"Type": "String"}},
            "Resources": {name: {"Type": "AWS::Serverless::Function", "Properties": {
                "CodeUri": f"s3://{self.bucket}/{self.key}", "Handler": "lambda_function.handler",
                "Environment": {"Variables": {"PRIVATE": "DO-NOT-EMIT"}}}}
                for name in FUNCTIONS}, "Outputs": {"Untouched": {"Value": "preserve"}}}
        self.original["Resources"]["KeptRole"] = {"Type": "AWS::IAM::Role", "Properties": {"Policy": "unchanged"}}
        self.processed = self.transform(self.original)
        self.resources = [{"LogicalResourceId": name, "PhysicalResourceId": name + "-physical",
                           "ResourceType": "AWS::Lambda::Function", "ResourceStatus": "UPDATE_COMPLETE"}
                          for name in FUNCTIONS]
        self.resources.append({"LogicalResourceId": "KeptRole", "PhysicalResourceId": "kept-role",
                               "ResourceType": "AWS::IAM::Role", "ResourceStatus": "CREATE_COMPLETE"})
        self.configs = {name + "-physical": {"FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:{name}-physical",
            "CodeSha256": base64.b64encode(hashlib.sha256(self.body).digest()).decode(),
            "RevisionId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "Version": "$LATEST",
            "State": "Active", "LastUpdateStatus": "Successful", "Environment": {"Variables": {"PRIVATE": "DO-NOT-EMIT"}}}
            for name in FUNCTIONS}
        self.snapshot_bytes = None

    def client(self, name, **kwargs):
        self.calls.append(("client", name))
        return self

    def get_caller_identity(self):
        return {"Account": self.account}

    def describe_stacks(self, **kwargs):
        self.stack_reads += 1
        if self.read_hook:
            self.read_hook(self)
        self.calls.append(("describe_stacks", kwargs))
        return {"Stacks": [copy.deepcopy(self.stack)], "ResponseMetadata": {"RequestId": str(self.stack_reads)}}

    def get_paginator(self, name):
        return self

    def paginate(self, **kwargs):
        yield {"StackResourceSummaries": copy.deepcopy(self.resources[:2])}
        yield {"StackResourceSummaries": copy.deepcopy(self.resources[2:])}

    def get_template(self, **kwargs):
        self.calls.append(("get_template", kwargs))
        template = self.pending_template if "ChangeSetName" in kwargs else self.original
        if kwargs["TemplateStage"] == "Processed":
            template = self.transform(template) if "ChangeSetName" in kwargs else self.processed
        return {"TemplateBody": copy.deepcopy(template)}

    def get_function_configuration(self, **kwargs):
        self.calls.append(("get_function_configuration", kwargs))
        name = kwargs["FunctionName"].split(":")[-1]
        result = copy.deepcopy(self.configs[name])
        result["ResponseMetadata"] = {"RequestId": str(len(self.calls)), "HTTPStatusCode": 200}
        return result

    def head_object(self, **kwargs):
        self.calls.append(("head_object", kwargs))
        return {"VersionId": self.version, "ContentLength": len(self.body)}

    def get_object(self, **kwargs):
        self.object_reads += 1
        self.calls.append(("get_object", kwargs))
        if self.object_hook:
            self.object_hook(self)
        body = self.snapshot_bytes if kwargs["Key"].endswith("snapshot.json") else self.body
        return {"Body": io.BytesIO(body), "VersionId": kwargs["VersionId"], "ContentLength": len(body),
                "ServerSideEncryption": "AES256"}

    def get_bucket_versioning(self, **kwargs):
        return {"Status": "Enabled"}

    def get_public_access_block(self, **kwargs):
        return {"PublicAccessBlockConfiguration": {key: True for key in (
            "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}}

    def get_bucket_ownership_controls(self, **kwargs):
        return {"OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}}

    def get_bucket_encryption(self, **kwargs):
        return {"ServerSideEncryptionConfiguration": {"Rules": [
            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}

    @staticmethod
    def transform(original):
        result = copy.deepcopy(original)
        for name in FUNCTIONS:
            resource = result["Resources"][name]
            resource["Type"] = "AWS::Lambda::Function"
            code = resource["Properties"].pop("CodeUri")
            if isinstance(code, str):
                bucket, key = code.removeprefix("s3://").split("/", 1)
                code = {"Bucket": bucket, "Key": key}
            resource["Properties"]["Code"] = {"S3Bucket": code["Bucket"], "S3Key": code["Key"]}
            if "Version" in code:
                resource["Properties"]["Code"]["S3ObjectVersion"] = code["Version"]
        return result

    def create_change_set(self, **kwargs):
        self.writes.append(("create_change_set", kwargs))
        self.pending_template = json.loads(kwargs["TemplateBody"])
        self.change_set_name = kwargs["ChangeSetName"]
        self.change_set_arn = f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:changeSet/{self.change_set_name}/synthetic"
        return {"Id": self.change_set_arn, "StackId": STACK_ARN}

    def get_waiter(self, name):
        return self

    def wait(self, **kwargs):
        return None

    def describe_change_set(self, **kwargs):
        result = {"StackId": STACK_ARN, "StackName": STACK, "ChangeSetId": self.change_set_arn,
            "ChangeSetName": self.change_set_name, "Status": "CREATE_COMPLETE", "ExecutionStatus": "AVAILABLE",
            "Parameters": copy.deepcopy(self.stack["Parameters"]), "Changes": [
                {"Type": "Resource", "ResourceChange": {"Action": "Modify", "Replacement": "False",
                 "ResourceType": "AWS::Lambda::Function", "LogicalResourceId": name,
                 "PhysicalResourceId": name + "-physical", "Scope": ["Properties"],
                 "Details": [{"Target": {"Attribute": "Properties", "Name": "Code", "RequiresRecreation": "Never"}}]}}
                for name in FUNCTIONS]}
        if self.review_hook:
            self.review_hook(self, result)
        return result

    def execute_change_set(self, **kwargs):
        self.writes.append(("execute_change_set", kwargs))
        self.original = copy.deepcopy(self.pending_template)
        self.processed = self.transform(self.original)
        for config in self.configs.values():
            config["CodeSha256"] = base64.b64encode(hashlib.sha256(self.body).digest()).decode()
            config["RevisionId"] = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


class AwsLiveSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue((ROOT / "tools/aws_live_snapshot.py").is_file(),
                        "missing explicit AWS-live-snapshot recovery driver")
        self.api = importlib.import_module("tools.aws_live_snapshot")
        self.aws = SyntheticAWS()
        self.policy = patch.multiple(self.api, ACCOUNT_SHA256=digest(ACCOUNT.encode()),
                                     APPROVED_ZIP_SHA256=digest(self.aws.body), APPROVED_ZIP_SIZE=len(self.aws.body),
                                     APPROVED_SELECTOR_SHA256=digest({"Bucket": self.aws.bucket, "Key": self.aws.key}),
                                     APPROVED_VERSION_SHA256=digest(self.aws.version.encode()))
        self.policy.start()
        self.addCleanup(self.policy.stop)

    def capture(self):
        return self.api.capture(self.aws, TOOLING)

    def prepared(self):
        record = self.capture()
        for config in self.aws.configs.values():
            config["CodeSha256"] = base64.b64encode(b"x" * 32).decode()
            config["RevisionId"] = "cccccccc-cccc-cccc-cccc-cccccccccccc"
        baseline = self.api.observe(self.aws)
        return record, self.api.baseline_digest(baseline)

    def recover(self, record, baseline_sha, **kwargs):
        return self.api.recover(self.aws, record, expected_snapshot_sha256=digest(record),
                                expected_baseline_sha256=baseline_sha, tooling=TOOLING,
                                execution_role=ROLE, **kwargs)

    def execute_cli(self, record, baseline_sha):
        self.aws.snapshot_bytes = self.api.canonical(record)
        env = {"TOOLING_SHA": TOOLING["sha"], "TOOLING_WORKFLOW_SHA256": digest(
                   (ROOT / ".github/workflows/recover-aws-test.yml").read_bytes().replace(b"\r\n", b"\n")),
               "GITHUB_REF": "refs/heads/test", "GITHUB_SHA": TOOLING["sha"],
               "RECOVERY_OPERATION": "execute", "SNAPSHOT_SHA256": digest(record),
               "CURRENT_BASELINE_SHA256": baseline_sha, "SAM_ARTIFACTS_BUCKET": self.aws.bucket,
               "AWS_CLOUDFORMATION_ROLE_ARN": ROLE,
               "AWS_LIVE_SNAPSHOT_REFERENCE_JSON": json.dumps({"bucket": self.aws.bucket,
                   "key": STACK + "/reviewed/snapshot.json", "versionId": "record-version"})}
        def git(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, TOOLING["sha"] + "\n" if "rev-parse" in args else "", "")
        output, errors = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, env, clear=True), \
             patch.dict(sys.modules, {"boto3": SimpleNamespace(Session=lambda **kwargs: self.aws)}), \
             patch.object(self.api.subprocess, "run", side_effect=git), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = self.api.main(["--operation", "execute"])
        for private in (ACCOUNT, STACK_ARN, ROLE, self.aws.bucket, self.aws.key, "DO-NOT-EMIT"):
            self.assertNotIn(private, output.getvalue() + errors.getvalue())
        return code, output.getvalue(), errors.getvalue()

    def test_capture_exact_bytes_double_read_and_unknown_git_source(self):
        record = self.capture()
        self.assertEqual(record["schema"], "AWS-live-snapshot/v1")
        self.assertEqual(record["sourceAttribution"], "aws-observed")
        self.assertNotIn("sourceSha", record)
        self.assertEqual(record["package"]["sha256"], digest(self.aws.body))
        self.assertEqual(record["package"]["versionId"], "original-version")
        self.assertEqual(set(record["functions"]), set(FUNCTIONS))
        version_reads = [args for call, args in self.aws.calls if call == "get_object"]
        self.assertEqual(len(version_reads), 2)
        self.assertTrue(all(args["VersionId"] == "original-version" for args in version_reads))
        self.assertEqual(self.aws.stack_reads, 2)
        self.assertFalse(self.aws.writes)
        public = json.dumps(self.api.summary(record))
        for private in (ACCOUNT, STACK_ARN, ROLE, self.aws.bucket, self.aws.key, "original-version", "DO-NOT-EMIT"):
            self.assertNotIn(private, public)

    def test_capture_rejects_account_region_stack_function_or_missing_version(self):
        mutations = [lambda: setattr(self.aws, "account", "999999999999"),
                     lambda: setattr(self.aws, "region_name", "eu-west-1"),
                     lambda: self.aws.stack.update(StackName="unapproved-test"),
                     lambda: self.aws.stack.update(StackId=STACK_ARN + "-substitute"),
                     lambda: self.aws.resources.pop(0),
                     lambda: self.aws.configs[FUNCTIONS[0] + "-physical"].update(FunctionArn="wrong"),
                     lambda: setattr(self.aws, "version", "null")]
        # Stack UUID is observed during capture, but substitution is rejected on the second read.
        mutations.pop(3)
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                self.aws = SyntheticAWS()
                mutation()
                with self.assertRaises(self.api.SnapshotError):
                    self.capture()
                self.assertFalse(self.aws.writes)

    def test_capture_rejects_zip_hash_size_lambda_sha_or_processed_pointer_substitution(self):
        for field in ("hash", "size", "lambda", "processed"):
            with self.subTest(field=field):
                self.aws = SyntheticAWS()
                if field == "hash": self.aws.body = self.aws.body.replace(b"old", b"new")
                if field == "size": self.aws.body += b"x"
                if field == "lambda": self.aws.configs[FUNCTIONS[0] + "-physical"]["CodeSha256"] = base64.b64encode(b"x" * 32).decode()
                if field == "processed": self.aws.processed["Resources"][FUNCTIONS[0]]["Properties"]["Code"]["S3Key"] = "other"
                with self.assertRaises(self.api.SnapshotError): self.capture()

    def test_capture_aborts_all_projected_baseline_drift(self):
        for field in ("stack", "original", "processed", "parameters", "inventory", "revision", "environment"):
            with self.subTest(field=field):
                self.aws = SyntheticAWS()
                def drift(aws):
                    if aws.stack_reads != 2: return
                    if field == "stack": aws.stack["StackId"] += "-new"
                    if field == "original": aws.original["Outputs"]["new"] = "new"
                    if field == "processed": aws.processed["Outputs"]["new"] = "new"
                    if field == "parameters": aws.stack["Parameters"][1]["ParameterValue"] = "changed"
                    if field == "inventory": aws.resources[-1]["PhysicalResourceId"] = "replacement"
                    if field == "revision": aws.configs[FUNCTIONS[0] + "-physical"]["RevisionId"] = "dddddddd-dddd-dddd-dddd-dddddddddddd"
                    if field == "environment": aws.configs[FUNCTIONS[0] + "-physical"]["Environment"] = {}
                self.aws.read_hook = drift
                with self.assertRaisesRegex(self.api.SnapshotError, "baseline_drift"):
                    self.capture()

    def test_capture_aborts_second_exact_version_payload_drift(self):
        self.aws.object_hook = lambda aws: setattr(aws, "body", aws.body + b"x") if aws.object_reads == 2 else None
        with self.assertRaises(self.api.SnapshotError): self.capture()

    def test_safe_zip_rejects_traversal_duplicates_absolute_null_and_symlink(self):
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        cases = [[("../escape", b"bad")], [("/escape", b"bad")], [("a\\b", b"bad")],
                 [("a", b"x"), ("a", b"y")], [("A", b"x"), ("a", b"y")],
                 [("C:escape", b"bad")], [(link, b"target")]]
        # ZipInfo normalizes a backslash on Windows before serialization. Inject
        # the hostile archive filename bytes to exercise the actual read boundary.
        cases.pop(2)
        for entries in cases:
            with self.subTest(entries=str(entries)), self.assertRaises(self.api.SnapshotError):
                self.api.zip_inventory(package(entries))
        for hostile in (b"a\\b", b"a\x00b"):
            with self.subTest(hostile=repr(hostile)), self.assertRaises(self.api.SnapshotError):
                self.api.zip_inventory(package([("a/b", b"bad")]).replace(b"a/b", hostile))

    def test_recovery_plan_changes_only_three_versioned_code_pointers(self):
        record, baseline_sha = self.prepared()
        before = copy.deepcopy(self.aws.original)
        plan = self.recover(record, baseline_sha, execute=False)
        for name in FUNCTIONS:
            code = plan["template"]["Resources"][name]["Properties"].pop("CodeUri")
            self.assertEqual(code, {"Bucket": self.aws.bucket, "Key": self.aws.key, "Version": "original-version"})
            before["Resources"][name]["Properties"].pop("CodeUri")
        self.assertEqual(plan["template"], before)
        self.assertEqual(plan["parameters"], [{"ParameterKey": key, "UsePreviousValue": True}
                                             for key in ("AuthRuntimeEnvironment", "PrivateSetting")])
        self.assertFalse(self.aws.writes)

    def test_actual_recovery_entrypoint_executes_exact_arn_then_checks_original_bytes_and_smoke(self):
        record, baseline_sha = self.prepared()
        result = self.recover(record, baseline_sha, execute=True)
        self.assertEqual(result["status"], "recovered")
        self.assertTrue(result["postDeploySmokePassed"])
        self.assertEqual([call for call, _ in self.aws.writes], ["create_change_set", "execute_change_set"])
        create = self.aws.writes[0][1]
        self.assertEqual(create["ChangeSetType"], "UPDATE")
        self.assertEqual(create["RoleARN"], ROLE)
        self.assertTrue(all(row.get("UsePreviousValue") is True for row in create["Parameters"]))
        self.assertEqual(self.aws.writes[1][1]["ChangeSetName"], self.aws.change_set_arn)
        self.assertEqual(self.aws.stack["Parameters"][1]["ParameterValue"], "DO-NOT-EMIT")

    def test_real_cli_executes_original_bytes_with_only_external_boundaries_injected(self):
        record, baseline_sha = self.prepared()
        code, output, errors = self.execute_cli(record, baseline_sha)
        self.assertEqual((code, errors), (0, ""))
        self.assertEqual(json.loads(output)["status"], "recovered")
        self.assertTrue(all(self.aws.configs[name + "-physical"]["CodeSha256"] ==
                            record["functions"][name]["codeSha256"] for name in FUNCTIONS))

    def test_real_cli_noop_requires_every_live_function_to_match_target_package(self):
        for changed in (*FUNCTIONS, None):
            with self.subTest(changed=changed):
                self.aws = SyntheticAWS()
                record = self.capture()
                self.aws.original = self.api._compose(self.aws.original, record["package"])
                self.aws.processed = self.aws.transform(self.aws.original)
                if changed:
                    self.aws.configs[changed + "-physical"].update(
                        CodeSha256=base64.b64encode(b"x" * 32).decode(),
                        RevisionId="cccccccc-cccc-cccc-cccc-cccccccccccc")
                baseline_sha = self.api.baseline_digest(self.api.observe(self.aws))
                def no_changes(aws, result):
                    result.update(Status="FAILED", ExecutionStatus="UNAVAILABLE", Changes=[],
                        StatusReason="The submitted information didn't contain changes. Submit different information to create a change set.")
                self.aws.review_hook = no_changes
                code, output, errors = self.execute_cli(record, baseline_sha)
                if changed:
                    self.assertEqual(code, 1)
                    self.assertEqual(output, "")
                    self.assertEqual(errors.strip(), "noop_target_not_live")
                else:
                    self.assertEqual((code, errors), (0, ""))
                    self.assertEqual(json.loads(output)["status"], "noop")
                self.assertEqual([name for name, _ in self.aws.writes], ["create_change_set"])

    def test_recovery_rejects_unauthenticated_snapshot_fields_tooling_and_current_baseline(self):
        record, baseline_sha = self.prepared()
        cases = [lambda item: item.update(sourceSha="f" * 40),
                 lambda item: item.update(schema="github-release/v1"),
                 lambda item: item["tooling"].update(sha="not-a-sha"),
                 lambda item: item["target"].update(stackId=STACK_ARN + "-wrong"),
                 lambda item: item["package"].update(versionId="null"),
                 lambda item: item["functions"].pop(FUNCTIONS[0])]
        for mutate in cases:
            changed = copy.deepcopy(record)
            mutate(changed)
            with self.subTest(mutation=cases.index(mutate)), self.assertRaises(self.api.SnapshotError):
                self.recover(changed, baseline_sha, execute=True)
        with self.assertRaises(self.api.SnapshotError): self.recover(record, "0" * 64, execute=True)
        with self.assertRaises(self.api.SnapshotError):
            self.api.recover(self.aws, record, expected_snapshot_sha256="0" * 64,
                             expected_baseline_sha256=baseline_sha, tooling=TOOLING, execution_role=ROLE, execute=True)
        self.assertFalse(self.aws.writes)

    def test_noop_remove_replace_iam_parameter_or_wrong_identity_cannot_execute(self):
        mutations = [lambda result: result["Changes"][0]["ResourceChange"].update(Action="Remove"),
                     lambda result: result["Changes"][0]["ResourceChange"].update(Replacement="True"),
                     lambda result: result["Changes"][0]["ResourceChange"].update(LogicalResourceId="KeptRole"),
                     lambda result: result["Parameters"].append({"ParameterKey": "Added", "ParameterValue": "x"}),
                     lambda result: result.update(StackId=STACK_ARN + "-wrong"),
                     lambda result: result["Changes"][0]["ResourceChange"]["Details"][0]["Target"].update(Name="Role")]
        for mutate in mutations:
            with self.subTest(mutation=mutations.index(mutate)):
                self.aws = SyntheticAWS()
                record, baseline_sha = self.prepared()
                self.aws.review_hook = lambda aws, result: mutate(result)
                with self.assertRaises(self.api.SnapshotError): self.recover(record, baseline_sha, execute=True)
                self.assertNotIn("execute_change_set", [name for name, _ in self.aws.writes])

    def test_recovery_rechecks_baseline_immediately_before_execute(self):
        record, baseline_sha = self.prepared()
        self.aws.review_hook = lambda aws, _: aws.stack["Parameters"][1].update(ParameterValue="drift")
        with self.assertRaisesRegex(self.api.SnapshotError, "baseline_drift"):
            self.recover(record, baseline_sha, execute=True)
        self.assertNotIn("execute_change_set", [name for name, _ in self.aws.writes])

    def test_existing_role_absence_is_preserved_without_adopting_configured_role(self):
        self.aws.stack.pop("RoleARN")
        record, baseline_sha = self.prepared()
        try:
            result = self.recover(record, baseline_sha, execute=True)
        except self.api.SnapshotError:
            self.fail("code-only recovery must preserve the existing absence of a service role")
        self.assertEqual(result["status"], "recovered")
        self.assertNotIn("RoleARN", self.aws.writes[0][1])

    def test_real_cli_preserves_exact_observed_cloudformation_capabilities(self):
        for capabilities in (["CAPABILITY_IAM"], ["CAPABILITY_NAMED_IAM"], [], None):
            with self.subTest(capabilities=capabilities):
                self.aws = SyntheticAWS()
                if capabilities is not None:
                    self.aws.stack["Capabilities"] = capabilities
                original_execute = self.aws.execute_change_set
                def persist_request_settings(**kwargs):
                    original_execute(**kwargs)
                    request = self.aws.writes[0][1]
                    if "Capabilities" in request:
                        self.aws.stack["Capabilities"] = copy.deepcopy(request["Capabilities"])
                self.aws.execute_change_set = persist_request_settings
                record, baseline_sha = self.prepared()
                code, output, errors = self.execute_cli(record, baseline_sha)
                self.assertEqual((code, errors), (0, ""))
                self.assertEqual(json.loads(output)["status"], "recovered")
                self.assertEqual(self.aws.writes[0][1].get("Capabilities"), capabilities)

    def test_private_read_does_not_require_new_bucket_control_permissions(self):
        record = self.capture()
        self.aws.snapshot_bytes = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        self.aws.get_bucket_versioning = lambda **_: (_ for _ in ()).throw(AssertionError("new read not authorized"))
        reference = {"bucket": self.aws.bucket, "key": STACK + "/reviewed/snapshot.json", "versionId": "record-version"}
        self.assertEqual(self.api.load_private_snapshot(self.aws, reference, digest(record), self.aws.bucket), record)

    def test_code_only_recovery_cannot_disable_enabled_v2_and_keeps_it_unchanged(self):
        record, _ = self.prepared()
        self.aws.stack["Parameters"].append({"ParameterKey": "EnableThnAuthRuntimeV2", "ParameterValue": "true"})
        self.aws.original["Parameters"]["EnableThnAuthRuntimeV2"] = {"Type": "String"}
        self.aws.processed = self.aws.transform(self.aws.original)
        baseline_sha = self.api.baseline_digest(self.api.observe(self.aws))
        plan = self.recover(record, baseline_sha, execute=False)
        self.assertIn({"ParameterKey": "EnableThnAuthRuntimeV2", "UsePreviousValue": True}, plan["parameters"])
        with self.assertRaisesRegex(self.api.SnapshotError, "code_only_operation_required"):
            self.recover(record, baseline_sha, execute=True, operation="disable")

    def test_private_snapshot_channel_exact_version_and_digest(self):
        record = self.capture()
        self.aws.snapshot_bytes = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        reference = {"bucket": self.aws.bucket, "key": STACK + "/reviewed/snapshot.json", "versionId": "record-version"}
        loaded = self.api.load_private_snapshot(self.aws, reference, digest(self.aws.snapshot_bytes), self.aws.bucket)
        self.assertEqual(loaded, record)
        with self.assertRaises(self.api.SnapshotError):
            self.api.load_private_snapshot(self.aws, reference, "0" * 64, self.aws.bucket)
        with self.assertRaises(self.api.SnapshotError):
            self.api.load_private_snapshot(self.aws, {**reference, "versionId": "null"}, digest(record), self.aws.bucket)
        self.assertFalse(self.aws.writes)

    def test_cli_is_sanitized_and_never_falls_back_to_github_or_accepts_disable(self):
        result = subprocess.run([sys.executable, str(ROOT / "tools/aws_live_snapshot.py"), "--operation", "disable"],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Traceback", result.stderr)
        with self.assertRaisesRegex(self.api.SnapshotError, "private_json_invalid"):
            self.api.private_json('{"schema":1,"schema":2}')

    def test_cli_rejects_unknown_arguments_without_echoing_private_values(self):
        result = subprocess.run([sys.executable, str(ROOT / "tools/aws_live_snapshot.py"),
                                 "--unexpected", "DO-NOT-EMIT"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("DO-NOT-EMIT", result.stdout + result.stderr)

    def test_workflow_boundary_rejects_old_tooling_dirty_tree_and_selections_before_cloud(self):
        workflow_hash = digest((ROOT / ".github/workflows/recover-aws-test.yml").read_bytes().replace(b"\r\n", b"\n"))
        env = {"TOOLING_SHA": TOOLING["sha"], "TOOLING_WORKFLOW_SHA256": workflow_hash,
               "GITHUB_REF": "refs/heads/test", "GITHUB_SHA": TOOLING["sha"], "RECOVERY_OPERATION": "verify",
               "SNAPSHOT_SHA256": "3" * 64, "CURRENT_BASELINE_SHA256": "4" * 64,
               "SAM_ARTIFACTS_BUCKET": self.aws.bucket,
               "AWS_LIVE_SNAPSHOT_REFERENCE_JSON": json.dumps({"bucket": self.aws.bucket,
                   "key": STACK + "/reviewed/snapshot.json", "versionId": "record-version"})}
        def git(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, TOOLING["sha"] + "\n" if "rev-parse" in args else "", "")
        with patch.object(self.api.subprocess, "run", side_effect=git):
            tooling, _ = self.api.workflow_context(env, ROOT)
            self.assertEqual(tooling["sha"], TOOLING["sha"])
            for key, value in (("TOOLING_SHA", "5" * 40), ("GITHUB_REF", "refs/heads/main"),
                               ("TOOLING_WORKFLOW_SHA256", "6" * 64), ("THN_V2_TEST_PARAMETERS_JSON", "{}"),
                               ("RECOVERY_OPERATION", "disable")):
                with self.subTest(key=key), self.assertRaises(self.api.SnapshotError):
                    self.api.workflow_context({**env, key: value}, ROOT)
        with patch.object(self.api.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, " M tools/aws_live_snapshot.py", "")):
            with self.assertRaises(self.api.SnapshotError): self.api.workflow_context(env, ROOT)

    def test_change_set_processed_template_substitution_aborts_before_execute(self):
        record, baseline_sha = self.prepared()
        self.aws.review_hook = lambda aws, _: aws.pending_template["Resources"]["KeptRole"]["Properties"].update(Policy="substituted")
        with self.assertRaisesRegex(self.api.SnapshotError, "change_set_template_drift"):
            self.recover(record, baseline_sha, execute=True)
        self.assertNotIn("execute_change_set", [name for name, _ in self.aws.writes])

    def test_capture_rejects_unknown_nested_business_drift_but_not_transport_request_ids(self):
        def drift(aws):
            if aws.stack_reads == 2:
                aws.configs[FUNCTIONS[0] + "-physical"]["NewBusinessField"] = {"ResponseMetadata": "business-value"}
        self.aws.read_hook = drift
        with self.assertRaisesRegex(self.api.SnapshotError, "baseline_drift"):
            self.capture()

    def test_live_stack_tag_or_notification_change_is_baseline_drift(self):
        for key in ("Tags", "NotificationARNs", "DisableRollback"):
            with self.subTest(key=key):
                self.aws = SyntheticAWS()
                self.aws.read_hook = lambda aws: aws.stack.update({key: "changed"}) if aws.stack_reads == 2 else None
                with self.assertRaisesRegex(self.api.SnapshotError, "baseline_drift"):
                    self.capture()

    def test_fresh_package_is_rejected_without_bypassing_approved_identity(self):
        self.policy.stop()
        with self.assertRaisesRegex(self.api.SnapshotError, "prior_package_selector_invalid"):
            self.api._approved_package({"bucket": self.aws.bucket, "key": self.aws.key,
                "versionId": self.aws.version, "sizeBytes": len(self.aws.body), "sha256": digest(self.aws.body),
                "inventorySha256": digest([]), "fileCount": 2})

    def test_workflow_keeps_current_tooling_separate_and_has_no_implicit_execution(self):
        path = ROOT / ".github/workflows/recover-aws-test.yml"
        self.assertTrue(path.is_file(), "missing explicit current-tooling AWS recovery workflow")
        workflow = path.read_text(encoding="utf-8")
        for value in ("workflow_dispatch:", "default: verify", "environment: test", "tooling_sha:",
                      "tooling_workflow_sha256:", "snapshot_sha256:", "current_baseline_sha256:",
                      "AWS_LIVE_SNAPSHOT_REFERENCE_JSON", "--check-workflow", "tools/aws_live_snapshot.py"):
            self.assertIn(value, workflow)
        for forbidden in ("upload-artifact@", "download-artifact@", "sam build", "sam package", "sam deploy", "pull_request_target"):
            self.assertNotIn(forbidden, workflow)
        strict = (ROOT / ".github/workflows/rollback-test.yml").read_text(encoding="utf-8")
        self.assertIn("getWorkflowRun", strict)
        self.assertIn("source_artifact_id:", strict)
        self.assertNotIn("AWS-live-snapshot", strict)


if __name__ == "__main__":
    unittest.main()
