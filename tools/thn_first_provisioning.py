"""Isolated native first provisioning of the THN TEST runtime.

Composed templates and SDK-shaped observations are private, never CLI output.
This does not package or deploy the three shared Lambda functions.
"""
from __future__ import annotations

import copy
import base64
import argparse
import logging
import os
import subprocess
import sys
from pathlib import Path
import re
from types import SimpleNamespace

try:
    from tools import aws_live_snapshot as recovery
    from tools import thn_runtime_routes as routes
    from tools.build_thn_auth_runtime_v2_artifact import ALLOWED_FILES
except ModuleNotFoundError:
    import aws_live_snapshot as recovery
    import thn_runtime_routes as routes
    from build_thn_auth_runtime_v2_artifact import ALLOWED_FILES

API, STAGE, FUNCTION, PATH = routes.API, routes.STAGE, routes.FUNCTION, routes.PATH
PARAMETERS = ("EnableThnAuthRuntimeV2", "ThnAuthRuntimeV2DescriptorVersionId", "ThnAuthRuntimeV2DescriptorSha256",
              "ThnAuthRuntimeV2AuthPolicyVersion", "ThnAuthRuntimeV2CognitoUserPoolId", "ThnAuthRuntimeV2CognitoClientId")
RULE = "ThnAuthRuntimeV2ActivationRule"
require = recovery.require
digest = recovery.sha256
SCHEMA = "thn-first-runtime/v1"
ROOT = Path(__file__).resolve().parents[1]


def _baseline(template):
    require(isinstance(template, dict) and "Transform" not in template and isinstance(template.get("Resources"), dict),
            "thn_first_native_required")
    resources = template["Resources"]
    require(all(isinstance(r, dict) and isinstance(r.get("Type"), str) and not r["Type"].startswith("AWS::Serverless::")
                for r in resources.values()), "thn_first_native_required")
    require(not any(name.startswith("Thn") for name in resources)
            and not set(PARAMETERS) & set(template.get("Parameters", {}))
            and RULE not in template.get("Rules", {}) and routes.CONDITION not in template.get("Conditions", {}),
            "thn_first_absent_baseline_required")
    require(all(template.get("Parameters", {}).get(name, {}).get("Type") == "String" for name in ("AuthRuntimeEnvironment", "LogLevel")),
            "thn_first_shared_parameters_missing")
    for name, kind in {API: "AWS::ApiGateway::RestApi", STAGE: "AWS::ApiGateway::Stage",
                       **{f: "AWS::Lambda::Function" for f in recovery.FUNCTIONS}}.items():
        require(resources.get(name, {}).get("Type") == kind, "thn_first_baseline_resource_invalid")
    properties = resources[API].get("Properties", {})
    require(properties.get("Mode") in (None, "overwrite") and "BodyS3Location" not in properties
            and isinstance(properties.get("Body"), dict) and isinstance(properties["Body"].get("paths"), dict)
            and PATH not in properties["Body"]["paths"], "thn_first_api_baseline_invalid")
    stage = resources[STAGE].get("Properties", {})
    prior = stage.get("DeploymentId", {}).get("Ref")
    require(stage.get("StageName") == "Prod" and stage.get("RestApiId") == {"Ref": API}
            and resources.get(prior, {}).get("Type") == "AWS::ApiGateway::Deployment"
            and resources[prior].get("Properties", {}).get("RestApiId") == {"Ref": API}, "thn_first_stage_baseline_invalid")


def _translate(source, package):
    from samtranslator.translator.transform import transform
    require(isinstance(package, dict) and set(package) == {"Bucket", "Key", "Version"}
            and package["Version"] != "null", "thn_first_versioned_package_required")
    for value in package.values(): recovery.text_value(value)
    require(isinstance(source, dict) and source.get("Globals", {}).get("Function", {}).get("Runtime") == "python3.13",
            "thn_first_source_invalid")
    reviewed = copy.deepcopy(source)
    function = reviewed.get("Resources", {}).get(FUNCTION, {})
    properties = function.get("Properties", {})
    require(function.get("Type") == "AWS::Serverless::Function" and function.get("Condition") == routes.CONDITION
            and properties.get("Handler") == "thn_auth_runtime_v2.lambda_handler" and properties.get("AutoPublishAlias") == "test"
            and "FunctionName" not in properties and "Role" not in properties
            and set(properties.get("Events", {})) == {"ThnAuthRuntimeV2Get", "ThnAuthRuntimeV2Post"}, "thn_first_source_invalid")
    for method in ("Get", "Post"):
        require(properties["Events"]["ThnAuthRuntimeV2" + method] == {"Type": "Api", "Properties": {
            "RestApiId": {"Ref": API}, "Path": PATH, "Method": method.upper()}}, "thn_first_source_routes_invalid")
    # Translate the reviewed SAM source without packaging any shared file. Only
    # the six THN-native resources and its method AST are ever taken from this result.
    for name, value in reviewed["Resources"].items():
        if value.get("Type") == "AWS::Serverless::Function":
            value["Properties"]["CodeUri"] = copy.deepcopy(package) if name == FUNCTION else "s3://synthetic-unused/shared-not-packaged.zip"
    values = {key: value["Default"] for key, value in reviewed.get("Parameters", {}).items() if "Default" in value}
    values.update(AuthRuntimeEnvironment="test", EnableThnAuthRuntimeV2="true")
    loader = SimpleNamespace(load=lambda: {"AWSLambdaBasicExecutionRole": "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"})
    native = transform(reviewed, values, loader)
    routes.capture_routes(native)
    return native


def compose(baseline, source, package, transition_sha256):
    """Preserve the observed native template and add only the reviewed extension."""
    _baseline(baseline)
    recovery.hex_digest(transition_sha256)
    native = _translate(source, package)
    resources = native["Resources"]
    version = resources[routes.ALIAS]["Properties"]["FunctionVersion"]["Fn::GetAtt"][0]
    names = {FUNCTION, FUNCTION + "Role", routes.ALIAS, version,
             *(FUNCTION + "ThnAuthRuntimeV2" + method + "PermissionProd" for method in ("Get", "Post"))}
    require(len(names) == 6 and {name for name in resources if name.startswith("Thn")} == names,
            "thn_first_unexpected_native_resources")
    deployment = "ThnRuntimeFirst" + transition_sha256[:40]
    require(deployment not in baseline["Resources"], "thn_first_deployment_collision")
    result = copy.deepcopy(baseline)
    for name in names:
        result["Resources"][name] = copy.deepcopy(resources[name])
        result["Resources"][name].update(DeletionPolicy="Retain", UpdateReplacePolicy="Retain")
    result["Resources"][deployment] = {"Type": "AWS::ApiGateway::Deployment", "DeletionPolicy": "Retain",
        "UpdateReplacePolicy": "Retain", "DependsOn": [API], "Properties": {
            "RestApiId": {"Ref": API}, "Description": "THN retained first runtime deployment"}}
    result["Resources"][API]["Properties"]["Body"]["paths"][PATH] = copy.deepcopy(resources[API]["Properties"]["Body"]["paths"][PATH])
    result["Resources"][STAGE]["Properties"]["DeploymentId"] = {"Ref": deployment}
    for name in PARAMETERS:
        require(source.get("Parameters", {}).get(name, {}).get("Type") == "String", "thn_first_source_parameters_invalid")
        result["Parameters"][name] = copy.deepcopy(source["Parameters"][name])
    result.setdefault("Rules", {})[RULE] = copy.deepcopy(source["Rules"][RULE])
    result.setdefault("Conditions", {})[routes.CONDITION] = copy.deepcopy(source["Conditions"][routes.CONDITION])
    routes.capture_routes(result)
    require(len(recovery.canonical(result)) <= 51200, "thn_first_private_template_transport_required")
    return result, sorted(names | {deployment})


def observe(session):
    """Read the untouched TEST stack and deployed shared API; private return value."""
    current = recovery.observe(session)
    require(not current["state"]["RoleARN"] and current["original"] == current["processed"], "thn_first_no_role_native_required")
    _baseline(current["processed"])
    api_id = current["inventory"].get(API, {}).get("physicalId")
    require(isinstance(api_id, str) and re.fullmatch(r"[a-z0-9]{8,12}", api_id), "thn_first_api_identity_invalid")
    current["api"] = routes._export(session, api_id, current["inventory"], current["processed"])
    require(PATH not in current["api"]["paths"], "thn_first_route_already_deployed")
    return current


def _parameters(source, values):
    recovery.closed(values, PARAMETERS)
    require(values["EnableThnAuthRuntimeV2"] == "true", "thn_first_enabled_parameters_required")
    for name, value in values.items():
        recovery.text_value(value, 128)
        definition = source["Parameters"][name]
        require(value not in {"BLOCKED", "0" * 64} and (not definition.get("AllowedPattern")
            or re.fullmatch(definition["AllowedPattern"], value)), "thn_first_parameters_invalid")
    return dict(values)


def _prerequisites(session, parameters, account):
    # Resource identity comes from the dedicated owning stack, not a user-supplied
    # pool/client pair. No customer/account reads or Cognito mutations are needed.
    client = session.client("cloudformation")
    stacks = client.describe_stacks(StackName="zoolanding-auth-admin-test").get("Stacks")
    require(isinstance(stacks, list) and len(stacks) == 1, "thn_first_auth_stack_invalid")
    stack = stacks[0]
    require(stack.get("StackName") == "zoolanding-auth-admin-test" and stack.get("StackStatus") in recovery.STABLE
            and stack.get("EnableTerminationProtection") is True and isinstance(stack.get("StackId"), str)
            and re.fullmatch(rf"arn:aws:cloudformation:us-east-1:{account}:stack/zoolanding-auth-admin-test/[A-Za-z0-9-]+", stack["StackId"]),
            "thn_first_auth_stack_invalid")
    for logical, kind, parameter in (
        ("ThnAuthAdminV2UserPool", "AWS::Cognito::UserPool", "ThnAuthRuntimeV2CognitoUserPoolId"),
        ("ThnAuthAdminV2UserPoolClient", "AWS::Cognito::UserPoolClient", "ThnAuthRuntimeV2CognitoClientId"),
    ):
        detail = client.describe_stack_resource(StackName="zoolanding-auth-admin-test", LogicalResourceId=logical).get("StackResourceDetail", {})
        require(detail.get("LogicalResourceId") == logical and detail.get("ResourceType") == kind
                and detail.get("PhysicalResourceId") == parameters[parameter] and detail.get("ResourceStatus") in recovery.STABLE
                and detail.get("StackId") == stack["StackId"],
                "thn_first_auth_prerequisite_invalid")


def _package(session, package, expected_sha256, account):
    recovery.closed(package, {"Bucket", "Key", "Version"})
    for value in package.values(): recovery.text_value(value)
    require(package["Version"] != "null" and re.fullmatch(recovery.STACK_NAME + r"/thn-runtime/[A-Za-z0-9_/-]+\.zip", package["Key"])
            and not any(part in {".", "..", ""} for part in package["Key"].split("/")), "thn_first_package_scope_invalid")
    recovery.hex_digest(expected_sha256)
    request = {"Bucket": package["Bucket"], "Key": package["Key"], "VersionId": package["Version"]}
    payload = recovery._version_bytes(session, request, account, 2 * 1024 * 1024)
    require(digest(payload) == expected_sha256, "thn_first_package_digest_invalid")
    inventory = recovery.zip_inventory(payload)
    expected = sorted([{"path": name, "sizeBytes": (ROOT / name).stat().st_size, "sha256": digest((ROOT / name).read_bytes())}
                       for name in ALLOWED_FILES], key=lambda row: row["path"])
    require(inventory == expected, "thn_first_exact_two_file_package_required")
    require(recovery._version_bytes(session, request, account, 2 * 1024 * 1024) == payload, "thn_first_package_readback_invalid")


def _recovery(session, snapshot, current, expected_sha256):
    recovery.validate_record(snapshot, expected_sha256)
    require(snapshot["target"] == current["target"] and snapshot["baseline"] == recovery.baseline_hashes(current)
            and snapshot["functions"] == current["functions"], "thn_first_recovery_baseline_invalid")
    recovery._verify_package(session, snapshot["package"], current["target"]["account"])


def prepare_plan(session, source, package, package_sha256, parameters, tooling, snapshot):
    """Produce a private review document with no mutation; publication is separate."""
    recovery.validate_tooling(tooling)
    parameters = _parameters(source, parameters)
    current = observe(session)
    _recovery(session, snapshot, current, digest(snapshot))
    _package(session, package, package_sha256, current["target"]["account"])
    _prerequisites(session, parameters, current["target"]["account"])
    plan = {"schema": SCHEMA, "service": recovery.SERVICE, "environment": "test", "tooling": dict(tooling),
        "target": current["target"], "baselineSha256": digest(current), "snapshotSha256": digest(snapshot),
        "package": dict(package), "packageSha256": package_sha256, "parameters": parameters}
    template, _ = compose(current["processed"], source, package, digest(plan))
    plan["templateSha256"] = digest(template)
    require(digest(observe(session)) == plan["baselineSha256"], "thn_first_baseline_drift")
    return plan


def _review(description, current, name, arn, template, additions, parameters):
    require(description.get("StackId") == current["target"]["stackId"] and description.get("StackName") == recovery.STACK_NAME
            and description.get("ChangeSetName") == name and description.get("ChangeSetId") == arn
            and not description.get("NextToken") and not description.get("RoleARN")
            and description.get("IncludeNestedStacks") in (None, False) and description.get("ChangeSetType") in (None, "UPDATE")
            and not description.get("ParentChangeSetId") and not description.get("RootChangeSetId")
            and description.get("Status") == "CREATE_COMPLETE" and description.get("ExecutionStatus") == "AVAILABLE"
            and recovery._parameters(description) == parameters, "thn_first_change_set_invalid")
    changes, seen = description.get("Changes"), set()
    require(isinstance(changes, list) and len(changes) == len(additions) + 2, "thn_first_exact_changes_required")
    for change in changes:
        require(change.get("Type") == "Resource" and isinstance(change.get("ResourceChange"), dict), "thn_first_change_invalid")
        item = change["ResourceChange"]; key = item.get("LogicalResourceId")
        require(key in {*additions, API, STAGE} and key not in seen and not item.get("ModuleInfo") and not item.get("ChangeSetId"), "thn_first_unapproved_change")
        seen.add(key)
        require(item.get("ResourceType") == template["Resources"][key]["Type"], "thn_first_type_invalid")
        if key in additions:
            require(item.get("Action") == "Add" and item.get("Replacement") in (None, "False") and not item.get("PhysicalResourceId"), "thn_first_add_required")
        else:
            require(item.get("Action") == "Modify" and item.get("Replacement") == "False" and item.get("Scope") == ["Properties"]
                    and item.get("PhysicalResourceId") == current["inventory"][key]["physicalId"]
                    and isinstance(item.get("Details"), list) and item["Details"], "thn_first_exact_modify_required")
            for detail in item["Details"]:
                target = detail.get("Target", {})
                require(target.get("Attribute") == "Properties" and target.get("Name") == ("Body" if key == API else "DeploymentId")
                        and target.get("RequiresRecreation") == "Never", "thn_first_exact_property_required")


def provision(session, plan, snapshot, source, *, execute, tooling, expected_plan_sha256, expected_baseline_sha256):
    """Verify or apply exactly one sealed first-provisioning plan, without a role."""
    require(type(execute) is bool, "thn_first_operation_invalid")
    recovery.closed(plan, {"schema", "service", "environment", "tooling", "target", "baselineSha256", "snapshotSha256",
                           "package", "packageSha256", "parameters", "templateSha256"})
    recovery.validate_tooling(tooling)
    for value in (expected_plan_sha256, expected_baseline_sha256): recovery.hex_digest(value)
    require(digest(plan) == expected_plan_sha256 and plan["schema"] == SCHEMA and plan["service"] == recovery.SERVICE
            and plan["environment"] == "test" and plan["tooling"] == tooling and plan["baselineSha256"] == expected_baseline_sha256,
            "thn_first_plan_binding_invalid")
    current = observe(session)
    require(digest(current) == expected_baseline_sha256 and current["target"] == plan["target"], "thn_first_baseline_drift")
    _recovery(session, snapshot, current, plan["snapshotSha256"])
    _parameters(source, plan["parameters"])
    _package(session, plan["package"], plan["packageSha256"], current["target"]["account"])
    _prerequisites(session, plan["parameters"], current["target"]["account"])
    token = digest({k: v for k, v in plan.items() if k != "templateSha256"})
    template, additions = compose(current["processed"], source, plan["package"], token)
    require(digest(template) == plan["templateSha256"], "thn_first_template_digest_invalid")
    require(digest(observe(session)) == expected_baseline_sha256, "thn_first_baseline_drift")
    result = {"status": "verified", "executed": False, "planSha256": expected_plan_sha256,
              "baselineSha256": expected_baseline_sha256, "templateSha256": digest(template), "addedResourceCount": len(additions)}
    if not execute: return result
    cfn, stack_id = session.client("cloudformation"), current["target"]["stackId"]
    name = "thn-first-" + token[:40]
    parameters = current["parameters"] | plan["parameters"]
    capabilities = current["state"]["Capabilities"]
    require(isinstance(capabilities, list) and "CAPABILITY_IAM" in capabilities, "thn_first_original_iam_capability_required")
    created = cfn.create_change_set(StackName=stack_id, ChangeSetName=name, ChangeSetType="UPDATE", ClientToken=token,
        Description="Isolated retained THN TEST first runtime", TemplateBody=recovery.canonical(template).decode(),
        Parameters=[{"ParameterKey": k, "UsePreviousValue": True} if k in current["parameters"]
                    else {"ParameterKey": k, "ParameterValue": parameters[k]} for k in sorted(parameters)], Capabilities=capabilities)
    arn = created.get("Id")
    require(created.get("StackId") == stack_id and isinstance(arn, str) and re.fullmatch(
        rf"arn:aws:cloudformation:{recovery.REGION}:{current['target']['account']}:changeSet/{name}/[A-Za-z0-9-]+", arn), "thn_first_change_set_identity_invalid")
    cfn.get_waiter("change_set_create_complete").wait(StackName=stack_id, ChangeSetName=arn, WaiterConfig={"Delay": 5, "MaxAttempts": 60})
    _review(cfn.describe_change_set(StackName=stack_id, ChangeSetName=arn, IncludePropertyValues=True), current, name, arn, template, additions, parameters)
    for stage in ("Original", "Processed"):
        require(recovery._template(cfn.get_template(StackName=stack_id, ChangeSetName=arn, TemplateStage=stage)["TemplateBody"]) == template,
                "thn_first_change_set_template_drift")
    require(digest(observe(session)) == expected_baseline_sha256, "thn_first_baseline_drift")
    _prerequisites(session, plan["parameters"], current["target"]["account"])
    cfn.execute_change_set(StackName=stack_id, ChangeSetName=arn, ClientRequestToken="execute-" + token)
    cfn.get_waiter("stack_update_complete").wait(StackName=stack_id, WaiterConfig={"Delay": 5, "MaxAttempts": 120})
    after = routes.observe(session)
    require(after["original"] == template and after["processed"] == template and after["parameters"] == parameters
            and {k: after["state"][k] for k in recovery.STACK_SETTINGS} == {k: current["state"][k] for k in recovery.STACK_SETTINGS}
            and set(after["inventory"]) == set(current["inventory"]) | set(additions)
            and all(after["inventory"][k] == v for k, v in current["inventory"].items())
            and all(after["functions"][k] == v for k, v in current["functions"].items()), "thn_first_post_state_invalid")
    require(after["functions"][FUNCTION]["codeSha256"] == base64.b64encode(bytes.fromhex(plan["packageSha256"])).decode()
            and after["api"]["stage"] == current["api"]["stage"]
            and {k: v for k, v in after["api"]["paths"].items() if k != PATH} == current["api"]["paths"], "thn_first_post_runtime_invalid")
    methods = after["api"]["paths"].get(PATH)
    require(isinstance(methods, dict) and set(methods) == {"get", "post"}, "thn_first_deployed_methods_invalid")
    uri = f"arn:aws:apigateway:{recovery.REGION}:lambda:path/2015-03-31/functions/{after['functions'][FUNCTION]['arn']}:test/invocations"
    for method in methods.values():
        integration = method.get("x-amazon-apigateway-integration", {})
        require(integration.get("type") == "aws_proxy" and integration.get("httpMethod") == "POST" and integration.get("uri") == uri,
                "thn_first_deployed_integration_invalid")
    return {**result, "status": "provisioned", "executed": True, "apiDefinitionVerified": True}


def workflow_context(env, root):
    """Check immutable tooling and private selectors before acquiring credentials."""
    tooling = {"sha": env.get("TOOLING_SHA"), "workflowSha256": env.get("TOOLING_WORKFLOW_SHA256")}
    recovery.validate_tooling(tooling)
    require(env.get("GITHUB_ACTIONS") == "true" and env.get("GITHUB_REF") == "refs/heads/test"
            and env.get("GITHUB_SHA") == tooling["sha"] and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("GITHUB_REPOSITORY") == "LynxPardelle/zoolanding-api-proxy"
            and env.get("FIRST_EXECUTION") in {"verify", "execute"} and not env.get("AWS_CLOUDFORMATION_ROLE_ARN")
            and not env.get("THN_V2_TEST_PARAMETERS_JSON"), "thn_first_workflow_context_invalid")
    for name in ("AWS_REGION", "AWS_DEFAULT_REGION"):
        require(env.get(name, recovery.REGION) == recovery.REGION, "thn_first_region_invalid")
    for name in ("FIRST_PLAN_SHA256", "SNAPSHOT_SHA256", "CURRENT_BASELINE_SHA256"): recovery.hex_digest(env.get(name))
    workflow = root / ".github/workflows/thn-first-provision-test.yml"
    require(digest(workflow.read_bytes().replace(b"\r\n", b"\n")) == tooling["workflowSha256"], "thn_first_workflow_digest_invalid")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=15, check=False)
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=root, capture_output=True, text=True, timeout=15, check=False)
    require(head.returncode == 0 and head.stdout.strip() == tooling["sha"] and dirty.returncode == 0 and not dirty.stdout.strip(),
            "thn_first_clean_tooling_required")
    references = []
    for name, prefix in (("THN_FIRST_PLAN_REFERENCE_JSON", recovery.STACK_NAME + "/first-provisioning/"),
                         ("AWS_LIVE_SNAPSHOT_REFERENCE_JSON", recovery.STACK_NAME + "/")):
        ref = recovery.private_json(env.get(name, ""))
        recovery.closed(ref, {"bucket", "key", "versionId"})
        for value in ref.values(): recovery.text_value(value)
        require(ref["bucket"] == env.get("SAM_ARTIFACTS_BUCKET") and ref["versionId"] != "null"
                and ref["key"].startswith(prefix) and ref["key"].endswith(".json")
                and not any(part in {"", ".", ".."} for part in ref["key"].split("/")), "thn_first_private_channel_invalid")
        references.append(ref)
    require(references[0]["key"] != references[1]["key"], "thn_first_private_reference_collision")
    return tooling, *references


def load_plan(session, reference, expected_sha256):
    """Read only the canonical independently reviewed private plan version."""
    account = session.client("sts").get_caller_identity().get("Account")
    require(session.region_name == recovery.REGION and isinstance(account, str) and digest(account.encode()) == recovery.ACCOUNT_SHA256,
            "thn_first_account_invalid")
    request = {"Bucket": reference["bucket"], "Key": reference["key"], "VersionId": reference["versionId"]}
    body = recovery._version_bytes(session, request, account, recovery.MAX_RECORD)
    require(digest(body) == expected_sha256, "thn_first_plan_digest_invalid")
    plan = recovery.private_json(body)
    require(recovery.canonical(plan) == body and recovery._version_bytes(session, request, account, recovery.MAX_RECORD) == body,
            "thn_first_plan_readback_invalid")
    require(plan.get("package", {}).get("Bucket") == reference["bucket"], "thn_first_package_channel_invalid")
    return plan


def main(argv=None):
    class SafeParser(argparse.ArgumentParser):
        def error(self, message): raise ValueError("thn_first_arguments_invalid")
    try:
        parser = SafeParser(description="Verify or execute an isolated THN TEST first-provisioning plan.")
        parser.add_argument("--check-workflow", action="store_true")
        args = parser.parse_args(argv)
        tooling, plan_reference, snapshot_reference = workflow_context(os.environ, ROOT)
        if args.check_workflow:
            print("thn_first_workflow_valid")
            return 0
        # SDK/translator diagnostics may contain private resource coordinates.
        logging.disable(logging.CRITICAL)
        import boto3
        import yaml
        session = boto3.Session(region_name=recovery.REGION)
        plan = load_plan(session, plan_reference, os.environ["FIRST_PLAN_SHA256"])
        snapshot = recovery.load_private_snapshot(session, snapshot_reference, os.environ["SNAPSHOT_SHA256"], os.environ["SAM_ARTIFACTS_BUCKET"])
        result = provision(session, plan, snapshot, yaml.safe_load((ROOT / "template.yaml").read_text(encoding="utf-8")),
            execute=os.environ["FIRST_EXECUTION"] == "execute", tooling=tooling, expected_plan_sha256=os.environ["FIRST_PLAN_SHA256"],
            expected_baseline_sha256=os.environ["CURRENT_BASELINE_SHA256"])
        print(recovery.canonical(result).decode())
        return 0
    except Exception:
        print("thn_first_verification_failed", file=sys.stderr)
        return 2


if __name__ == "__main__": raise SystemExit(main())
