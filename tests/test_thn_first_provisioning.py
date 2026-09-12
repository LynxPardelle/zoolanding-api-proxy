"""Native first provisioning uses real SAM translation, never a shared package."""
import copy
import importlib
import os
from pathlib import Path
import unittest
import base64
import hashlib
import io
import json
import zipfile
import subprocess
import contextlib
from unittest.mock import patch
import yaml
from test_aws_live_snapshot import SyntheticAWS, ACCOUNT, STACK_ARN, TOOLING, package as zip_package

ROOT = Path(__file__).resolve().parents[1]
FN = "ThnAuthRuntimeV2Function"
API, STAGE, PATH = "ApiProxyApi", "ApiProxyApiProdStage", "/auth-v2/runtime-config"
PACKAGE = {"Bucket": "synthetic-private", "Key": "zoolanding-api-proxy-test/thn-runtime/reviewed.zip", "Version": "synthetic-version"}


def stable_zip(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, body in entries:
            archive.writestr(zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0)), body)
    return buffer.getvalue()


def source():
    return yaml.safe_load((ROOT / "template.yaml").read_text(encoding="utf-8"))


def baseline():
    return {"AWSTemplateFormatVersion": "2010-09-09", "Parameters": {
        "AuthRuntimeEnvironment": {"Type": "String", "Default": "production"},
        "LogLevel": {"Type": "String", "Default": "INFO"}}, "Conditions": {"Keep": {"Fn::Equals": ["a", "a"]}},
        "Outputs": {"Untouched": {"Value": "keep"}}, "Resources": {
        API: {"Type": "AWS::ApiGateway::RestApi", "Properties": {"Body": {"swagger": "2.0", "paths": {
            "/auth/runtime-config": {"get": {"responses": {"200": {"description": "existing"}}}}},
            "securityDefinitions": {"Existing": {"unchanged": True}}}}},
        STAGE: {"Type": "AWS::ApiGateway::Stage", "Properties": {"RestApiId": {"Ref": API}, "StageName": "Prod",
            "DeploymentId": {"Ref": "OriginalDeployment"}, "Variables": {"retain": "original"}}},
        "OriginalDeployment": {"Type": "AWS::ApiGateway::Deployment", "Properties": {"RestApiId": {"Ref": API}}},
        **{name: {"Type": "AWS::Lambda::Function", "Properties": {"Code": {"S3Bucket": "synthetic-private", "S3Key": "original.zip"},
            "Handler": "shared.handler"}} for name in ("ApiProxyFunction", "AuthProvisioningExecutorFunction", "AuthJwtAuthorizerFunction")},
        "ExistingRole": {"Type": "AWS::IAM::Role", "Properties": {"RoleName": "synthetic-existing"}}}}


class NativeFirstProvisioningTests(unittest.TestCase):
    def module(self):
        self.assertTrue((ROOT / "tools/thn_first_provisioning.py").is_file(), "native first provisioning is missing")
        os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
        return importlib.import_module("tools.thn_first_provisioning")

    def test_real_sam_translation_adds_exactly_seven_retained_resources(self):
        module, original = self.module(), baseline()
        before = copy.deepcopy(original)
        result, additions = module.compose(original, source(), PACKAGE, "1" * 64)
        self.assertEqual(original, before)
        self.assertEqual(len(additions), 7)
        self.assertEqual(set(result["Resources"]) - set(original["Resources"]), set(additions))
        self.assertEqual(sorted(result["Resources"][name]["Type"] for name in additions), sorted([
            "AWS::Lambda::Function", "AWS::IAM::Role", "AWS::Lambda::Version", "AWS::Lambda::Alias",
            "AWS::Lambda::Permission", "AWS::Lambda::Permission", "AWS::ApiGateway::Deployment"]))
        for name in additions:
            self.assertEqual(result["Resources"][name]["DeletionPolicy"], "Retain")
            self.assertEqual(result["Resources"][name]["UpdateReplacePolicy"], "Retain")
        for name, value in original["Resources"].items():
            if name not in {API, STAGE}: self.assertEqual(result["Resources"][name], value)
        self.assertEqual(result["Outputs"], original["Outputs"])
        for name, value in original["Parameters"].items(): self.assertEqual(result["Parameters"][name], value)
        self.assertEqual(result["Conditions"]["Keep"], original["Conditions"]["Keep"])
        self.assertEqual(result["Resources"][FN]["Properties"]["Code"], {
            "S3Bucket": PACKAGE["Bucket"], "S3Key": PACKAGE["Key"], "S3ObjectVersion": PACKAGE["Version"]})

    def test_new_routes_are_compatible_with_retained_close_reopen(self):
        module = self.module()
        from tools import thn_runtime_routes as routes
        result, additions = module.compose(baseline(), source(), PACKAGE, "1" * 64)
        record = routes.capture_routes(result)
        closed, first = routes.compose(result, record, "close", "2" * 64)
        reopened, second = routes.compose(closed, record, "reopen", "3" * 64)
        self.assertEqual(reopened["Resources"][API], result["Resources"][API])
        self.assertTrue(set(result["Resources"]) | {first, second} == set(reopened["Resources"]))

    def test_shared_api_and_stage_properties_are_preserved(self):
        module, original = self.module(), baseline()
        result, _ = module.compose(original, source(), PACKAGE, "1" * 64)
        restored = copy.deepcopy(result)
        del restored["Resources"][API]["Properties"]["Body"]["paths"][PATH]
        restored["Resources"][STAGE]["Properties"]["DeploymentId"] = original["Resources"][STAGE]["Properties"]["DeploymentId"]
        self.assertEqual(restored["Resources"][API], original["Resources"][API])
        self.assertEqual(restored["Resources"][STAGE], original["Resources"][STAGE])

    def test_rejects_non_native_drift_collisions_and_nonversioned_package(self):
        module = self.module()
        for change in ("transform", "merge", "stage", "route", "parameter", "resource", "sam"):
            original = baseline()
            if change == "transform": original["Transform"] = "AWS::Serverless-2016-10-31"
            if change == "merge": original["Resources"][API]["Properties"]["Mode"] = "merge"
            if change == "stage": original["Resources"][STAGE]["Properties"]["StageName"] = "test"
            if change == "route": original["Resources"][API]["Properties"]["Body"]["paths"][PATH] = {}
            if change == "parameter": original["Parameters"]["EnableThnAuthRuntimeV2"] = {"Type": "String"}
            if change == "resource": original["Resources"][FN] = {"Type": "AWS::Lambda::Function"}
            if change == "sam": original["Resources"]["ApiProxyFunction"]["Type"] = "AWS::Serverless::Function"
            with self.subTest(change=change), self.assertRaises(ValueError):
                module.compose(original, source(), PACKAGE, "1" * 64)
        for package in (PACKAGE | {"Version": "null"}, {k: v for k, v in PACKAGE.items() if k != "Version"}, PACKAGE | {"Unexpected": True}):
            with self.assertRaises(ValueError): module.compose(baseline(), source(), package, "1" * 64)

    def test_rejects_unknown_template_source_runtime_routes(self):
        module = self.module()
        for mutate in (
            lambda value: value["Resources"][FN]["Properties"]["Events"]["ThnAuthRuntimeV2Get"]["Properties"].update(Method="DELETE"),
            lambda value: value["Resources"][FN]["Properties"].update(FunctionName="a-shared-function"),
            lambda value: value["Globals"]["Function"].update(Runtime="python2.7"),
        ):
            altered = source(); mutate(altered)
            with self.assertRaises(ValueError): module.compose(baseline(), altered, PACKAGE, "1" * 64)


class FirstAWS(SyntheticAWS):
    """Only the AWS SDK transport is replaced; SAM and all guards execute."""
    def __init__(self):
        super().__init__()
        self.body = stable_zip([("lambda_function.py", b"old original bytes\n"), ("auth_service.py", b"old auth bytes\n")])
        for config in self.configs.values(): config["CodeSha256"] = base64.b64encode(hashlib.sha256(self.body).digest()).decode()
        self.original = baseline()
        for name in self.configs:
            logical = name.removesuffix("-physical")
            self.original["Resources"][logical]["Properties"]["Code"] = {"S3Bucket": self.bucket, "S3Key": self.key}
        self.processed = copy.deepcopy(self.original)
        self.stack["RoleARN"] = None
        self.stack["Capabilities"] = ["CAPABILITY_IAM"]
        self.stack["Parameters"] = [{"ParameterKey": "AuthRuntimeEnvironment", "ParameterValue": "test"}, {"ParameterKey": "LogLevel", "ParameterValue": "INFO"}]
        self.resources = [{"LogicalResourceId": name, "PhysicalResourceId": "abc123test" if name == API else name + "-physical",
            "ResourceType": value["Type"], "ResourceStatus": "CREATE_COMPLETE"} for name, value in self.original["Resources"].items()]
        self.forward_body = stable_zip([(name, (ROOT / name).read_bytes()) for name in ("thn_auth_runtime_v2.py", "service_binding_registry_consumer_v2.py")])
        self.export_hook = None
        self.prerequisite_ready = True
        self.auth_stack = {"StackName": "zoolanding-auth-admin-test", "StackStatus": "UPDATE_COMPLETE", "EnableTerminationProtection": True,
            "StackId": f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/zoolanding-auth-admin-test/synthetic"}

    def describe_stacks(self, **kwargs):
        if kwargs["StackName"] == "zoolanding-auth-admin-test": return {"Stacks": [copy.deepcopy(self.auth_stack)]}
        return super().describe_stacks(**kwargs)

    def get_template(self, **kwargs):
        return {"TemplateBody": copy.deepcopy(self.pending_template if "ChangeSetName" in kwargs else self.original)}

    def get_object(self, **kwargs):
        if kwargs["Key"] == PACKAGE["Key"]:
            return {"Body": io.BytesIO(self.forward_body), "VersionId": PACKAGE["Version"], "ContentLength": len(self.forward_body), "ServerSideEncryption": "AES256"}
        return super().get_object(**kwargs)

    def get_stage(self, **kwargs):
        logical = self.original["Resources"][STAGE]["Properties"]["DeploymentId"]["Ref"]
        return {"stageName": "Prod", "deploymentId": logical + "-physical", "variables": {"keep": "same"}}

    def get_export(self, **kwargs):
        result = copy.deepcopy(self.original["Resources"][API]["Properties"]["Body"])
        if PATH in result["paths"]:
            uri = f"arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:{ACCOUNT}:function:{FN}-physical:test/invocations"
            result["paths"][PATH] = {m: {"x-amazon-apigateway-integration": {"type": "aws_proxy", "httpMethod": "POST", "uri": uri}} for m in ("get", "post")}
        if self.export_hook: self.export_hook(result)
        return {"body": io.BytesIO(json.dumps(result).encode())}

    def describe_stack_resource(self, **kwargs):
        assert kwargs["StackName"] == "zoolanding-auth-admin-test"
        logical = kwargs["LogicalResourceId"]
        kind, value = ("AWS::Cognito::UserPool", "us-east-1_synthetic") if logical == "ThnAuthAdminV2UserPool" else ("AWS::Cognito::UserPoolClient", "syntheticclient")
        return {"StackResourceDetail": {"LogicalResourceId": logical, "ResourceType": kind,
            "StackId": f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/zoolanding-auth-admin-test/synthetic",
            "PhysicalResourceId": value if self.prerequisite_ready else "unexpected", "ResourceStatus": "CREATE_COMPLETE"}}

    def create_change_set(self, **kwargs):
        result = super().create_change_set(**kwargs)
        existing = {p["ParameterKey"]: p["ParameterValue"] for p in self.stack["Parameters"]}
        self.pending_parameters = [{"ParameterKey": p["ParameterKey"], "ParameterValue": existing[p["ParameterKey"]] if p.get("UsePreviousValue") else p["ParameterValue"]} for p in kwargs["Parameters"]]
        return result

    def describe_change_set(self, **kwargs):
        changes = []
        for name, resource in self.pending_template["Resources"].items():
            if self.original["Resources"].get(name) == resource: continue
            new = name not in self.original["Resources"]
            change = {"Action": "Add" if new else "Modify", "LogicalResourceId": name, "ResourceType": resource["Type"], "Replacement": "False"}
            if not new:
                change.update(Scope=["Properties"], PhysicalResourceId=next(r["PhysicalResourceId"] for r in self.resources if r["LogicalResourceId"] == name),
                    Details=[{"Target": {"Attribute": "Properties", "Name": "Body" if name == API else "DeploymentId", "RequiresRecreation": "Never"}}])
            changes.append({"Type": "Resource", "ResourceChange": change})
        result = {"StackId": STACK_ARN, "StackName": self.stack["StackName"], "ChangeSetName": self.change_set_name, "ChangeSetId": self.change_set_arn,
            "Status": "CREATE_COMPLETE", "ExecutionStatus": "AVAILABLE", "Parameters": copy.deepcopy(self.pending_parameters), "Changes": changes}
        if self.review_hook: self.review_hook(self, result)
        return result

    def execute_change_set(self, **kwargs):
        self.writes.append(("execute_change_set", kwargs))
        for name, value in self.pending_template["Resources"].items():
            if name not in self.original["Resources"]:
                physical = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:{FN}-physical:1" if value["Type"] == "AWS::Lambda::Version" else name + "-physical"
                self.resources.append({"LogicalResourceId": name, "PhysicalResourceId": physical, "ResourceType": value["Type"], "ResourceStatus": "CREATE_COMPLETE"})
        self.original = copy.deepcopy(self.pending_template); self.processed = copy.deepcopy(self.pending_template)
        self.stack["Parameters"] = copy.deepcopy(self.pending_parameters)
        self.configs[FN + "-physical"] = {"FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:{FN}-physical",
            "CodeSha256": base64.b64encode(hashlib.sha256(self.forward_body).digest()).decode(), "State": "Active", "LastUpdateStatus": "Successful",
            "Version": "$LATEST", "RevisionId": "synthetic-new-revision"}

    def get_function_configuration(self, **kwargs):
        result = super().get_function_configuration(**kwargs)
        if kwargs.get("Qualifier") == "test": result.update(Version="1", FunctionArn=result["FunctionArn"] + ":test")
        return result


class FirstProvisioningOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.module = NativeFirstProvisioningTests().module()
        self.assertTrue(hasattr(self.module, "provision"), "guarded first provisioning is missing")
        self.aws = FirstAWS()
        from tools import aws_live_snapshot as recovery
        self.recovery = recovery
        self.anchor_patch = patch.multiple(recovery, ACCOUNT_SHA256=self.module.digest(ACCOUNT.encode()),
            APPROVED_ZIP_SHA256=self.module.digest(self.aws.body), APPROVED_ZIP_SIZE=len(self.aws.body),
            APPROVED_SELECTOR_SHA256=self.module.digest({"Bucket": self.aws.bucket, "Key": self.aws.key}),
            APPROVED_VERSION_SHA256=self.module.digest(self.aws.version.encode()))
        self.anchor_patch.start(); self.addCleanup(self.anchor_patch.stop)
        self.snapshot = recovery.capture(self.aws, TOOLING)
        self.parameters = {"EnableThnAuthRuntimeV2": "true", "ThnAuthRuntimeV2DescriptorVersionId": "approved-v1", "ThnAuthRuntimeV2DescriptorSha256": "a" * 64,
            "ThnAuthRuntimeV2AuthPolicyVersion": "policy-v1", "ThnAuthRuntimeV2CognitoUserPoolId": "us-east-1_synthetic", "ThnAuthRuntimeV2CognitoClientId": "syntheticclient"}
        self.plan = self.module.prepare_plan(self.aws, source(), PACKAGE, self.module.digest(self.aws.forward_body), self.parameters, TOOLING, self.snapshot)

    def run_operation(self, execute=True):
        return self.module.provision(self.aws, self.plan, self.snapshot, source(), execute=execute, tooling=TOOLING,
            expected_plan_sha256=self.module.digest(self.plan), expected_baseline_sha256=self.plan["baselineSha256"])

    def test_verify_has_no_writes_and_execute_preserves_shared_state(self):
        original, shared = copy.deepcopy(self.aws.original), copy.deepcopy(self.aws.configs)
        self.assertEqual(self.run_operation(False)["status"], "verified")
        self.assertEqual(self.aws.writes, [])
        result = self.run_operation()
        self.assertEqual(result["status"], "provisioned")
        self.assertTrue(result["apiDefinitionVerified"])
        self.assertEqual(len(self.aws.original["Resources"]), len(original["Resources"]) + 7)
        for name, config in shared.items(): self.assertEqual(self.aws.configs[name], config)
        self.assertTrue(all("RoleARN" not in kwargs for _, kwargs in self.aws.writes))

    def test_rejects_role_prerequisite_package_or_plan_drift_before_writes(self):
        cases = ("role", "prerequisite", "package", "parameter", "baseline", "template", "extra")
        for case in cases:
            with self.subTest(case=case):
                self.aws = FirstAWS(); self.plan = self.module.prepare_plan(self.aws, source(), PACKAGE, self.module.digest(self.aws.forward_body), self.parameters, TOOLING, self.snapshot)
                if case == "role": self.aws.stack["RoleARN"] = "arn:aws:iam::123456789012:role/unapproved"
                if case == "prerequisite": self.aws.prerequisite_ready = False
                if case == "package": self.aws.forward_body = zip_package([("wrong.py", b"bad")])
                if case == "parameter": self.plan["parameters"]["EnableThnAuthRuntimeV2"] = "false"
                if case == "baseline": self.plan["baselineSha256"] = "0" * 64
                if case == "template": self.plan["templateSha256"] = "0" * 64
                if case == "extra": self.plan["ignoreChanges"] = True
                with self.assertRaises(ValueError): self.run_operation()
                self.assertEqual(self.aws.writes, [])

    def test_rejects_unsafe_native_change_set_before_execution(self):
        for case in ("delete", "replace", "extra", "role", "nested", "parameter", "property", "shared-drift"):
            with self.subTest(case=case):
                self.aws = FirstAWS()
                def mutate(aws, result):
                    if case == "delete": result["Changes"][-1]["ResourceChange"]["Action"] = "Remove"
                    if case == "replace": result["Changes"][0]["ResourceChange"]["Replacement"] = "True"
                    if case == "extra": result["Changes"].append({"Type": "Resource", "ResourceChange": {"Action": "Add", "LogicalResourceId": "Extra"}})
                    if case == "role": result["RoleARN"] = "unapproved"
                    if case == "nested": result["IncludeNestedStacks"] = True
                    if case == "parameter": result["Parameters"][0]["ParameterValue"] = "tampered"
                    if case == "property": result["Changes"][0]["ResourceChange"]["Details"][0]["Target"]["Name"] = "Policy"
                    if case == "shared-drift": aws.configs["ApiProxyFunction-physical"]["RevisionId"] = "drift"
                self.aws.review_hook = mutate
                with self.assertRaises(ValueError): self.run_operation()
                self.assertFalse(any(name == "execute_change_set" for name, _ in self.aws.writes))

    def test_wrong_live_export_is_not_reported_as_accepted(self):
        self.aws.export_hook = lambda value: value["paths"].pop(PATH, None)
        with self.assertRaises(ValueError): self.run_operation()

    def test_auth_stack_must_be_stable_protected_and_own_both_resources(self):
        for change in ({"StackStatus": "UPDATE_IN_PROGRESS"}, {"StackStatus": "DELETE_IN_PROGRESS"},
            {"EnableTerminationProtection": False}, {"StackId": self.aws.auth_stack["StackId"] + "different"}, {"StackName": "foreign"}):
            with self.subTest(change=change):
                self.aws = FirstAWS()
                self.aws.auth_stack.update(change)
                with self.assertRaises(ValueError): self.run_operation()
                self.assertEqual(self.aws.writes, [])

    def test_auth_stack_drift_during_change_set_review_blocks_execution(self):
        self.aws.review_hook = lambda aws, result: aws.auth_stack.update(EnableTerminationProtection=False)
        with self.assertRaises(ValueError): self.run_operation()
        self.assertFalse(any(name == "execute_change_set" for name, _ in self.aws.writes))


class FirstPlanReadTests(unittest.TestCase):
    def setUp(self):
        self.module = NativeFirstProvisioningTests().module()
        self.reference = {"bucket": "synthetic-private", "key": "zoolanding-api-proxy-test/first-provisioning/plan.json", "versionId": "plan-version"}
        self.plan = {"package": {"Bucket": "synthetic-private"}, "schema": "synthetic-read-test"}
        self.body = self.module.recovery.canonical(self.plan)
        self.responses = None
        self.calls = []
        outer = self
        class Provider:
            region_name = "us-east-1"
            def client(self, name):
                outer.assertIn(name, {"sts", "s3"})
                return self
            def get_caller_identity(self): return {"Account": ACCOUNT}
            def get_object(self, **request):
                outer.calls.append(request)
                outer.assertEqual(request, {"Bucket": outer.reference["bucket"], "Key": outer.reference["key"],
                    "VersionId": outer.reference["versionId"], "ExpectedBucketOwner": ACCOUNT})
                body, version = outer.responses.pop(0) if outer.responses else (outer.body, "plan-version")
                return {"VersionId": version, "ContentLength": len(body), "Body": io.BytesIO(body)}
        self.session = Provider()

    def load(self, expected=None):
        with patch.object(self.module.recovery, "ACCOUNT_SHA256", self.module.digest(ACCOUNT.encode())):
            return self.module.load_plan(self.session, self.reference, expected or self.module.digest(self.body))

    def test_reads_the_same_exact_private_version_twice(self):
        self.assertEqual(self.load(), self.plan)
        self.assertEqual(len(self.calls), 2)

    def test_rejects_content_version_channel_and_noncanonical_or_duplicate_json(self):
        for case in ("version", "digest", "readback", "channel", "noncanonical", "duplicate"):
            with self.subTest(case=case):
                self.setUp()
                if case == "version": self.responses = [(self.body, "other-version")]
                if case == "readback": self.responses = [(self.body, "plan-version"), (self.body + b" ", "plan-version")]
                if case == "channel": self.body = self.module.recovery.canonical({"package": {"Bucket": "another-private"}})
                if case == "noncanonical": self.body += b" "
                if case == "duplicate": self.body = b'{"package":{},"package":{}}'
                with self.assertRaises(ValueError): self.load("0" * 64 if case == "digest" else None)

    def test_rejects_foreign_region_before_an_object_read(self):
        self.session.region_name = "us-west-2"
        with self.assertRaises(ValueError): self.load()
        self.assertEqual(self.calls, [])


class FirstProvisioningWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.module = NativeFirstProvisioningTests().module()
        self.assertTrue(hasattr(self.module, "workflow_context"), "sealed workflow context is missing")
        self.workflow = ROOT / ".github/workflows/thn-first-provision-test.yml"
        self.env = {"TOOLING_SHA": TOOLING["sha"], "TOOLING_WORKFLOW_SHA256": self.module.digest(self.workflow.read_bytes().replace(b"\r\n", b"\n")),
            "GITHUB_REF": "refs/heads/test", "GITHUB_SHA": TOOLING["sha"], "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "LynxPardelle/zoolanding-api-proxy", "FIRST_EXECUTION": "verify", "FIRST_PLAN_SHA256": "3" * 64,
            "SNAPSHOT_SHA256": "4" * 64, "CURRENT_BASELINE_SHA256": "5" * 64, "SAM_ARTIFACTS_BUCKET": "synthetic-private",
            "THN_FIRST_PLAN_REFERENCE_JSON": json.dumps({"bucket": "synthetic-private", "key": "zoolanding-api-proxy-test/first-provisioning/plan.json", "versionId": "plan-version"}),
            "AWS_LIVE_SNAPSHOT_REFERENCE_JSON": json.dumps({"bucket": "synthetic-private", "key": "zoolanding-api-proxy-test/recovery/snapshot.json", "versionId": "snapshot-version"})}

    def check(self, env=None, dirty=False):
        def git(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, TOOLING["sha"] if "rev-parse" in args else (" M dirty.py" if dirty else ""), "")
        with patch.object(self.module.subprocess, "run", side_effect=git):
            return self.module.workflow_context(self.env if env is None else env, ROOT)

    def test_exact_context_and_bounded_private_references_are_accepted(self):
        tooling, plan, snapshot = self.check()
        self.assertEqual(tooling["sha"], TOOLING["sha"])
        self.assertEqual(plan["versionId"], "plan-version")
        self.assertEqual(snapshot["versionId"], "snapshot-version")

    def test_rejects_wrong_context_role_digest_or_private_channel(self):
        for key, value in (("GITHUB_REF", "refs/heads/main"), ("GITHUB_ACTIONS", "false"), ("GITHUB_SHA", "6" * 40),
            ("GITHUB_REPOSITORY", "another/repository"), ("GITHUB_EVENT_NAME", "push"), ("FIRST_EXECUTION", "force"),
            ("AWS_CLOUDFORMATION_ROLE_ARN", "unapproved"), ("AWS_REGION", "us-west-2"), ("TOOLING_WORKFLOW_SHA256", "0" * 64),
            ("FIRST_PLAN_SHA256", "short"), ("THN_V2_TEST_PARAMETERS_JSON", "unapproved"), ("SAM_ARTIFACTS_BUCKET", "wrong")):
            with self.subTest(key=key), self.assertRaises(ValueError): self.check(self.env | {key: value})
        with self.assertRaises(ValueError): self.check(dirty=True)
        for name in ("THN_FIRST_PLAN_REFERENCE_JSON", "AWS_LIVE_SNAPSHOT_REFERENCE_JSON"):
            for change in ({"versionId": "null"}, {"bucket": "different"}, {"key": "outside/plan.json"}, {"extra": True}):
                altered = json.loads(self.env[name]) | change
                with self.assertRaises(ValueError): self.check(self.env | {name: json.dumps(altered)})

    def test_workflow_checks_context_before_credentials_and_never_builds_shared_packages(self):
        workflow = yaml.safe_load(self.workflow.read_text(encoding="utf-8"))
        job = workflow["jobs"]["provision"]
        self.assertEqual(job["environment"], "test")
        self.assertEqual(workflow["concurrency"]["group"], "zoolanding-api-proxy-test")
        steps = job["steps"]
        check = next(i for i, step in enumerate(steps) if "--check-workflow" in step.get("run", ""))
        credentials = next(i for i, step in enumerate(steps) if "configure-aws-credentials" in step.get("uses", ""))
        self.assertLess(check, credentials)
        self.assertNotIn("sam deploy", str(steps)); self.assertNotIn("sam package", str(steps))
        self.assertNotIn("AWS_CLOUDFORMATION_ROLE_ARN", job["env"])

    def test_invalid_cli_never_emits_supplied_values(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = self.module.main(["--unapproved-private-marker"])
        self.assertEqual(code, 2); self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("private-marker", stderr.getvalue()); self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__": unittest.main()
