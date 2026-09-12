"""Retained THN route transitions; the native template is never a shared redeploy."""
import copy
import contextlib
import importlib
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from test_aws_live_snapshot import SyntheticAWS, ACCOUNT, STACK_ARN, TOOLING


ROOT = Path(__file__).resolve().parents[1]
FN = "ThnAuthRuntimeV2Function"
ALIAS = FN + "Aliastest"
PATH = "/auth-v2/runtime-config"


def api():
    assert (ROOT / "tools/thn_runtime_routes.py").is_file(), "missing retained route controller"
    return importlib.import_module("tools.thn_runtime_routes")


def template():
    integration = {"type": "aws_proxy", "httpMethod": "POST", "uri": {
        "Fn::Sub": "arn:${AWS::Partition}:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${"
        + ALIAS + "}/invocations"}}
    methods = {method: {"responses": {}, "x-amazon-apigateway-integration": copy.deepcopy(integration)}
               for method in ("get", "post")}
    resources = {
        "ApiProxyApi": {"Type": "AWS::ApiGateway::RestApi", "Properties": {"Body": {
            "swagger": "2.0", "paths": {PATH: methods, "/auth/runtime-config": {"get": {"shared": True}}},
            "securityDefinitions": {"Existing": {"unchanged": True}}}}},
        "ApiProxyApiProdStage": {"Type": "AWS::ApiGateway::Stage", "Properties": {
            "RestApiId": {"Ref": "ApiProxyApi"}, "StageName": "Prod", "DeploymentId": {"Ref": "PriorDeployment"}}},
        "PriorDeployment": {"Type": "AWS::ApiGateway::Deployment", "Properties": {
            "RestApiId": {"Ref": "ApiProxyApi"}, "Description": "keep"}},
        FN: {"Type": "AWS::Lambda::Function", "Properties": {
            "Code": {"S3Bucket": "synthetic-private", "S3Key": "code.zip", "S3ObjectVersion": "original"},
            "Role": {"Fn::GetAtt": [FN + "Role", "Arn"]}, "Environment": {"Variables": {"keep": "unchanged"}}}},
        FN + "Role": {"Type": "AWS::IAM::Role", "Properties": {"AssumeRolePolicyDocument": {"keep": True}}},
        FN + "VersionOriginal": {"Type": "AWS::Lambda::Version", "DeletionPolicy": "Retain",
                                 "Properties": {"FunctionName": {"Ref": FN}}},
        ALIAS: {"Type": "AWS::Lambda::Alias", "Properties": {"FunctionName": {"Ref": FN},
            "FunctionVersion": {"Fn::GetAtt": [FN + "VersionOriginal", "Version"]}, "Name": "test"}},
    }
    for method in ("Get", "Post"):
        resources[FN + "ThnAuthRuntimeV2" + method + "PermissionProd"] = {
            "Type": "AWS::Lambda::Permission", "Properties": {"FunctionName": {"Ref": ALIAS},
            "Action": "lambda:InvokeFunction", "Principal": "apigateway.amazonaws.com",
            "SourceArn": {"Fn::Sub": "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${ApiProxyApi}/Prod/"
                          + method.upper() + PATH}}}
    for name in ("ApiProxyFunction", "AuthProvisioningExecutorFunction", "AuthJwtAuthorizerFunction"):
        resources[name] = {"Type": "AWS::Lambda::Function", "Properties": {"Code": {
            "S3Bucket": "synthetic-private", "S3Key": "shared.zip"}, "Handler": "shared.handler"}}
    return {"AWSTemplateFormatVersion": "2010-09-09", "Parameters": {
        "AuthRuntimeEnvironment": {"Type": "String"}, "EnableThnAuthRuntimeV2": {"Type": "String"}},
        "Conditions": {"IsThnAuthRuntimeV2Enabled": {"Fn::Equals": [{"Ref": "EnableThnAuthRuntimeV2"}, "true"]}},
        "Resources": resources, "Outputs": {"Keep": {"Value": "unchanged"}}}


class RetainedRouteCompositionTests(unittest.TestCase):
    def test_accepts_actual_sam_triple_wrapped_partition_resolved_integration(self):
        module, original = api(), template()
        paths = original["Resources"]["ApiProxyApi"]["Properties"]["Body"]["paths"]
        methods = paths[PATH]
        for name, value in list(methods.items()):
            integration = value["x-amazon-apigateway-integration"]
            integration["uri"]["Fn::Sub"] = integration["uri"]["Fn::Sub"].replace("${AWS::Partition}", "aws")
            integration["uri"] = {"Fn::If": ["IsThnAuthRuntimeV2Enabled", integration["uri"], {"Ref": "AWS::NoValue"}]}
            methods[name] = {"Fn::If": ["IsThnAuthRuntimeV2Enabled", value, {"Ref": "AWS::NoValue"}]}
        paths[PATH] = {"Fn::If": ["IsThnAuthRuntimeV2Enabled", methods, {"Ref": "AWS::NoValue"}]}
        self.assertEqual(module.capture_routes(original)["methods"], paths[PATH])

    def test_close_only_removes_two_operations_and_adds_one_retained_deployment(self):
        module, original = api(), template()
        before = copy.deepcopy(original)
        record = module.capture_routes(original)
        closed, deployment = module.compose(original, record, "close", "1" * 64)
        self.assertEqual(original, before)
        self.assertEqual(set(closed["Resources"]) - set(original["Resources"]), {deployment})
        self.assertNotIn(PATH, closed["Resources"]["ApiProxyApi"]["Properties"]["Body"]["paths"])
        self.assertEqual(closed["Resources"][deployment], {"Type": "AWS::ApiGateway::Deployment",
            "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain", "DependsOn": ["ApiProxyApi"],
            "Properties": {"RestApiId": {"Ref": "ApiProxyApi"}, "Description": "THN retained runtime routes close"}})
        for key, value in original["Resources"].items():
            if key not in {"ApiProxyApi", "ApiProxyApiProdStage"}:
                self.assertEqual(closed["Resources"][key], value)
        self.assertEqual(closed["Parameters"], original["Parameters"])
        self.assertEqual(closed["Outputs"], original["Outputs"])

    def test_reopen_restores_exact_raw_methods_without_removing_any_deployment(self):
        module, original = api(), template()
        record = module.capture_routes(original)
        closed, first = module.compose(original, record, "close", "1" * 64)
        reopened, second = module.compose(closed, record, "reopen", "2" * 64)
        self.assertNotEqual(first, second)
        self.assertIn(first, reopened["Resources"])
        self.assertEqual(reopened["Resources"]["ApiProxyApi"], original["Resources"]["ApiProxyApi"])
        self.assertEqual(reopened["Resources"]["ApiProxyApiProdStage"]["Properties"]["DeploymentId"], {"Ref": second})

    def test_rejects_unknown_path_method_without_deleting_it(self):
        original = template()
        original["Resources"]["ApiProxyApi"]["Properties"]["Body"]["paths"][PATH]["options"] = {"keep": True}
        with self.assertRaisesRegex(ValueError, "thn_routes_"):
            api().capture_routes(original)

    def test_rejects_transform_merge_mode_or_non_native_function(self):
        for alteration in ("transform", "merge", "sam", "wrong-stage", "foreign-alias", "missing-permission"):
            with self.subTest(alteration=alteration):
                original = template()
                if alteration == "transform": original["Transform"] = "AWS::Serverless-2016-10-31"
                if alteration == "merge": original["Resources"]["ApiProxyApi"]["Properties"]["Mode"] = "merge"
                if alteration == "sam": original["Resources"][FN]["Type"] = "AWS::Serverless::Function"
                if alteration == "wrong-stage": original["Resources"]["ApiProxyApiProdStage"]["Properties"]["StageName"] = "test"
                if alteration == "foreign-alias": original["Resources"][ALIAS]["Properties"]["FunctionName"] = {"Ref": "ApiProxyFunction"}
                if alteration == "missing-permission": del original["Resources"][FN + "ThnAuthRuntimeV2GetPermissionProd"]
                with self.assertRaisesRegex(ValueError, "thn_routes_"):
                    api().capture_routes(original)

    def test_rejects_method_substitution_and_duplicate_operations(self):
        module, original = api(), template()
        record = module.capture_routes(original)
        for operation in ("reopen", "enable", "disable"):
            with self.subTest(operation=operation), self.assertRaisesRegex(ValueError, "thn_routes_"):
                module.compose(original, record, operation, "1" * 64)
        original["Resources"]["ApiProxyApi"]["Properties"]["Body"]["paths"][PATH]["get"]["responses"] = {"substituted": True}
        with self.assertRaisesRegex(ValueError, "thn_routes_"):
            module.compose(original, record, "close", "1" * 64)

    def test_preserves_supported_sam_condition_wrappers_exactly(self):
        module, original = api(), template()
        routes = original["Resources"]["ApiProxyApi"]["Properties"]["Body"]["paths"]
        for method in ("get", "post"):
            routes[PATH][method] = {"Fn::If": ["IsThnAuthRuntimeV2Enabled", routes[PATH][method], {"Ref": "AWS::NoValue"}]}
        record = module.capture_routes(original)
        closed, _ = module.compose(original, record, "close", "1" * 64)
        reopened, _ = module.compose(closed, record, "reopen", "2" * 64)
        self.assertEqual(reopened["Resources"]["ApiProxyApi"], original["Resources"]["ApiProxyApi"])

    def test_rejects_collision_and_bad_digest(self):
        module, original = api(), template()
        record = module.capture_routes(original)
        closed, deployment = module.compose(original, record, "close", "1" * 64)
        original["Resources"][deployment] = closed["Resources"][deployment]
        for digest in ("1" * 64, "oops"):
            with self.subTest(digest=digest), self.assertRaisesRegex(ValueError, "thn_routes_"):
                module.compose(original, record, "close", digest)


class RouteAWS(SyntheticAWS):
    def __init__(self):
        super().__init__()
        self.stack.pop("RoleARN")
        self.stack["Parameters"] = [{"ParameterKey": "AuthRuntimeEnvironment", "ParameterValue": "test"},
                                    {"ParameterKey": "EnableThnAuthRuntimeV2", "ParameterValue": "true"}]
        self.original = template()
        self.processed = copy.deepcopy(self.original)
        self.export_hook = None
        self.resources = [{"LogicalResourceId": name, "PhysicalResourceId": name + "-physical",
                           "ResourceType": resource["Type"], "ResourceStatus": "CREATE_COMPLETE"}
                          for name, resource in self.original["Resources"].items()]
        self.resources[0]["PhysicalResourceId"] = "abc123test"
        next(r for r in self.resources if r["LogicalResourceId"] == FN + "VersionOriginal")["PhysicalResourceId"] = (
            f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:{FN}-physical:7")
        self.alias_version = "7"
        self.configs[FN + "-physical"] = copy.deepcopy(self.configs["ApiProxyFunction-physical"])
        self.configs[FN + "-physical"]["FunctionArn"] = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:{FN}-physical"

    def get_function_configuration(self, **kwargs):
        result = super().get_function_configuration(**kwargs)
        if kwargs.get("Qualifier") == "test":
            result["Version"] = self.alias_version
            result["FunctionArn"] += ":test"
        return result

    def get_export(self, **kwargs):
        assert kwargs == {"restApiId": "abc123test", "stageName": "Prod", "exportType": "oas30",
                          "parameters": {"extensions": "integrations"}}
        result = copy.deepcopy(self.original["Resources"]["ApiProxyApi"]["Properties"]["Body"])
        if self.export_hook: self.export_hook(result)
        return {"body": io.BytesIO(json.dumps(result).encode())}

    def get_stage(self, **kwargs):
        assert kwargs == {"restApiId": "abc123test", "stageName": "Prod"}
        logical = self.original["Resources"]["ApiProxyApiProdStage"]["Properties"]["DeploymentId"]["Ref"]
        return {"stageName": "Prod", "deploymentId": logical + "-physical"}

    def get_template(self, **kwargs):
        self.calls.append(("get_template", kwargs))
        value = self.pending if "ChangeSetName" in kwargs else (
            self.original if kwargs["TemplateStage"] == "Original" else self.processed)
        return {"TemplateBody": copy.deepcopy(value)}

    def create_change_set(self, **kwargs):
        self.writes.append(("create_change_set", kwargs))
        assert "RoleARN" not in kwargs
        self.pending = json.loads(kwargs["TemplateBody"])
        self.change_name = kwargs["ChangeSetName"]
        self.change_arn = f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:changeSet/{self.change_name}/synthetic"
        self.executed = False
        return {"StackId": STACK_ARN, "Id": self.change_arn}

    def describe_change_set(self, **kwargs):
        changes = []
        for name, resource in self.pending["Resources"].items():
            if self.original["Resources"].get(name) == resource:
                continue
            add = name not in self.original["Resources"]
            item = {"Action": "Add" if add else "Modify", "LogicalResourceId": name,
                    "ResourceType": resource["Type"], "Replacement": "False", "Scope": ["Properties"]}
            if not add:
                item["PhysicalResourceId"] = next(r["PhysicalResourceId"] for r in self.resources if r["LogicalResourceId"] == name)
                item["Details"] = [{"Target": {"Attribute": "Properties", "Name": "Body" if name == "ApiProxyApi" else "DeploymentId",
                                              "RequiresRecreation": "Never"}}]
            changes.append({"Type": "Resource", "ResourceChange": item})
        result = {"StackName": self.stack["StackName"], "StackId": STACK_ARN, "ChangeSetName": self.change_name,
                  "ChangeSetId": self.change_arn, "Status": "CREATE_COMPLETE",
                  "ExecutionStatus": "EXECUTE_COMPLETE" if self.executed else "AVAILABLE",
                  "Parameters": copy.deepcopy(self.stack["Parameters"]), "Changes": changes}
        if self.review_hook: self.review_hook(result)
        return result

    def execute_change_set(self, **kwargs):
        self.writes.append(("execute_change_set", kwargs))
        self.executed = True
        for name, resource in self.pending["Resources"].items():
            if name not in self.original["Resources"]:
                self.resources.append({"LogicalResourceId": name, "PhysicalResourceId": name + "-physical",
                                       "ResourceType": resource["Type"], "ResourceStatus": "CREATE_COMPLETE"})
        self.original = copy.deepcopy(self.pending)
        self.processed = copy.deepcopy(self.pending)


class RetainedRouteOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.module = api()
        self.assertTrue(hasattr(self.module, "transition"), "missing guarded route orchestration")
        self.aws = RouteAWS()
        from tools import aws_live_snapshot
        self.account_patch = patch.object(aws_live_snapshot, "ACCOUNT_SHA256", self.module.digest(ACCOUNT.encode()))
        self.account_patch.start()
        self.addCleanup(self.account_patch.stop)
        self.record = self.module.capture(self.aws, TOOLING)

    def execute(self, operation="close", execute=True):
        observed = self.module.observe(self.aws)
        return self.module.transition(self.aws, self.record, operation=operation, execute=execute, tooling=TOOLING,
            expected_record_sha256=self.module.digest(self.record), expected_baseline_sha256=self.module.digest(observed))

    def test_real_close_and_reopen_orchestration_preserves_shared_code_roles_and_parameters(self):
        before = copy.deepcopy(self.aws.original)
        configs = copy.deepcopy(self.aws.configs)
        result = self.execute()
        self.assertEqual(result["status"], "closed")
        self.assertTrue(result["apiDefinitionVerified"])
        self.assertNotIn(PATH, self.aws.original["Resources"]["ApiProxyApi"]["Properties"]["Body"]["paths"])
        self.assertEqual(self.execute("reopen")["status"], "reopened")
        self.assertEqual(len(self.aws.original["Resources"]), len(before["Resources"]) + 2)
        self.assertEqual(self.aws.original["Resources"]["ApiProxyApi"], before["Resources"]["ApiProxyApi"])
        self.assertEqual(self.aws.configs, configs)
        self.assertTrue(all("RoleARN" not in row[1] for row in self.aws.writes))

    def test_verify_performs_no_mutation(self):
        self.assertEqual(self.execute(execute=False)["status"], "verified")
        self.assertEqual(self.aws.writes, [])

    def test_rejects_role_association_or_native_removal_before_execute(self):
        for case in ("role", "removal", "wrong-stack", "unapproved-property"):
            with self.subTest(case=case):
                self.aws = RouteAWS()
                if case == "role": self.aws.stack["RoleARN"] = f"arn:aws:iam::{ACCOUNT}:role/broad"
                if case == "removal": self.aws.review_hook = lambda r: r["Changes"][0]["ResourceChange"].update(Action="Remove")
                if case == "wrong-stack": self.aws.review_hook = lambda r: r.update(StackId=STACK_ARN + "-other")
                if case == "unapproved-property": self.aws.review_hook = lambda r: r["Changes"][0]["ResourceChange"]["Details"][0]["Target"].update(Name="Policy")
                with self.assertRaises(ValueError): self.execute()
                self.assertFalse(any(name == "execute_change_set" for name, _ in self.aws.writes))

    def test_missing_retained_resource_is_rejected(self):
        self.aws.resources = [r for r in self.aws.resources if r["LogicalResourceId"] != ALIAS]
        with self.assertRaises(ValueError): self.execute()
        self.assertEqual(self.aws.writes, [])

    def test_nested_change_sets_are_rejected_before_execute(self):
        for field in ("IncludeNestedStacks", "ParentChangeSetId", "RootChangeSetId", "nested-resource"):
            with self.subTest(field=field):
                self.aws = RouteAWS()
                def nested(result):
                    if field == "nested-resource":
                        result["Changes"][0]["ResourceChange"]["ChangeSetId"] = "foreign-nested"
                    else:
                        result[field] = True if field == "IncludeNestedStacks" else "foreign-nested"
                self.aws.review_hook = nested
                with self.assertRaises(ValueError): self.execute()
                self.assertFalse(any(name == "execute_change_set" for name, _ in self.aws.writes))

    def test_live_alias_version_drift_is_rejected_before_any_mutation(self):
        self.aws.alias_version = "8"
        with self.assertRaises(ValueError): self.execute()
        self.assertEqual(self.aws.writes, [])

    def test_export_still_open_is_not_reported_as_success(self):
        before = copy.deepcopy(self.aws.original["Resources"]["ApiProxyApi"]["Properties"]["Body"]["paths"][PATH])
        self.aws.export_hook = lambda export: export["paths"].update({PATH: before})
        with self.assertRaises(ValueError): self.execute()

    def test_stale_baseline_and_substituted_capture_are_rejected_without_writes(self):
        for key in ("expected_baseline_sha256", "expected_record_sha256"):
            values = {"expected_record_sha256": self.module.digest(self.record),
                      "expected_baseline_sha256": self.module.digest(self.module.observe(self.aws))}
            values[key] = "0" * 64
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.module.transition(self.aws, self.record, operation="close", execute=True, tooling=TOOLING, **values)
            self.assertEqual(self.aws.writes, [])

    def test_late_runtime_drift_and_transformed_template_drift_never_execute(self):
        self.aws.review_hook = lambda _: self.aws.configs[FN + "-physical"].update(RevisionId="late-drift")
        with self.assertRaises(ValueError): self.execute()
        self.assertFalse(any(name == "execute_change_set" for name, _ in self.aws.writes))

    def test_record_cannot_restore_foreign_paths_or_ignore_changes(self):
        for case in ("shared-path", "function", "settings", "parameter", "extra-resource", "record-key"):
            with self.subTest(case=case):
                self.aws = RouteAWS()
                self.record = self.module.capture(self.aws, TOOLING)
                if case == "shared-path": self.aws.original["Resources"]["ApiProxyApi"]["Properties"]["Body"]["paths"]["/auth/runtime-config"] = {}
                if case == "function": self.aws.configs["ApiProxyFunction-physical"]["Handler"] = "different.handler"
                if case == "settings": self.aws.stack["NotificationARNs"] = ["unapproved"]
                if case == "parameter": self.aws.stack["Parameters"].append({"ParameterKey": "Extra", "ParameterValue": "x"})
                if case == "extra-resource":
                    self.aws.processed["Resources"]["ThnRuntimeRoutesClose" + "1" * 40] = {"Type": "AWS::Lambda::Function"}
                if case == "record-key": self.record["ignoreChanges"] = True
                with self.assertRaises(ValueError): self.execute()
                self.assertEqual(self.aws.writes, [])

    def test_postcondition_rejects_changed_stage_settings_or_missing_deployment(self):
        original = self.aws.execute_change_set
        def transport(**kwargs):
            original(**kwargs)
            self.aws.resources = [r for r in self.aws.resources if not r["LogicalResourceId"].startswith("ThnRuntimeRoutes")]
        self.aws.execute_change_set = transport
        with self.assertRaises(ValueError): self.execute()


class RetainedRouteWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.module = api()
        self.assertTrue(hasattr(self.module, "workflow_context"), "missing closed workflow interface")
        self.root = ROOT
        workflow = ROOT / ".github/workflows/thn-retained-routes-test.yml"
        self.assertTrue(workflow.is_file(), "missing explicit retained-route workflow")
        self.env = {"TOOLING_SHA": "1" * 40, "GITHUB_SHA": "1" * 40, "GITHUB_REF": "refs/heads/test",
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": "LynxPardelle/zoolanding-api-proxy",
            "TOOLING_WORKFLOW_SHA256": self.module.digest(workflow.read_bytes().replace(b"\r\n", b"\n")),
            "ROUTE_OPERATION": "close", "ROUTE_EXECUTION": "verify", "ROUTE_RECORD_SHA256": "3" * 64,
            "CURRENT_BASELINE_SHA256": "4" * 64, "SAM_ARTIFACTS_BUCKET": "synthetic-private",
            "THN_RETAINED_ROUTES_REFERENCE_JSON": json.dumps({"bucket": "synthetic-private",
                "key": "zoolanding-api-proxy-test/retained-routes/record.json", "versionId": "private-version"})}

    def git(self, args, **kwargs):
        return SimpleNamespace(returncode=0, stdout="1" * 40 + "\n" if args[1:3] == ["rev-parse", "HEAD"] else "")

    def test_default_verify_is_sealed_to_test_tooling_and_private_version(self):
        with patch("tools.thn_runtime_routes.subprocess.run", side_effect=self.git):
            tooling, reference = self.module.workflow_context(self.env, self.root)
        self.assertEqual(tooling["sha"], "1" * 40)
        self.assertEqual(reference["versionId"], "private-version")

    def test_rejects_wrong_context_no_version_or_legacy_execution_role(self):
        for key, value in (("GITHUB_REF", "refs/heads/prod"), ("GITHUB_SHA", "2" * 40),
            ("GITHUB_EVENT_NAME", "push"), ("GITHUB_REPOSITORY", "other/repo"), ("AWS_REGION", "us-west-2"),
            ("ROUTE_OPERATION", "enable"), ("ROUTE_EXECUTION", "yes"), ("TOOLING_WORKFLOW_SHA256", "0" * 64),
            ("AWS_CLOUDFORMATION_ROLE_ARN", "DO-NOT-EMIT"),
            ("THN_RETAINED_ROUTES_REFERENCE_JSON", '{"bucket":"a","bucket":"b"}')):
            with self.subTest(key=key), patch("tools.thn_runtime_routes.subprocess.run", side_effect=self.git):
                with self.assertRaises(ValueError): self.module.workflow_context({**self.env, key: value}, self.root)

    def test_cli_never_emits_private_values_on_preflight_failure(self):
        output, errors = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {"ROUTE_OPERATION": "DO-NOT-EMIT"}, clear=True), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            self.assertEqual(self.module.main(["--check-workflow"]), 1)
        self.assertNotIn("DO-NOT-EMIT", output.getvalue() + errors.getvalue())


if __name__ == "__main__":
    unittest.main()
