#!/usr/bin/env python3
"""Exact retained THN TEST route transitions. Library values are PRIVATE.

Never feed the composed native template to an ordinary shared SAM deployment.
Only the closed orchestration below may apply a reviewed transition.
"""
from __future__ import annotations

import copy
import argparse
import hashlib
import json
import os
from pathlib import Path as FilePath
import re
import subprocess
import sys

try:
    from tools import aws_live_snapshot as recovery
except ModuleNotFoundError:
    import aws_live_snapshot as recovery


API = "ApiProxyApi"
STAGE = "ApiProxyApiProdStage"
FUNCTION = "ThnAuthRuntimeV2Function"
ALIAS = FUNCTION + "Aliastest"
PATH = "/auth-v2/runtime-config"
CONDITION = "IsThnAuthRuntimeV2Enabled"
SCHEMA = "thn-retained-runtime-routes/v1"


class RouteGuardError(ValueError):
    """Only static reason codes may cross an output boundary."""


def require(value, reason="thn_routes_guard_failed"):
    if not value:
        raise RouteGuardError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def _unwrap(value):
    if isinstance(value, dict) and set(value) == {"Fn::If"}:
        branches = value["Fn::If"]
        require(isinstance(branches, list) and len(branches) == 3 and branches[0] == CONDITION
                and branches[2] == {"Ref": "AWS::NoValue"}, "thn_routes_condition_invalid")
        value = branches[1]
    require(isinstance(value, dict), "thn_routes_shape_invalid")
    return value


def _native(template):
    require(isinstance(template, dict) and "Transform" not in template
            and isinstance(template.get("Resources"), dict), "thn_routes_native_required")
    resources = template["Resources"]
    require(all(isinstance(r, dict) and isinstance(r.get("Type"), str)
                and not r["Type"].startswith("AWS::Serverless::") for r in resources.values()),
            "thn_routes_native_required")
    required = {API: "AWS::ApiGateway::RestApi", STAGE: "AWS::ApiGateway::Stage",
                FUNCTION: "AWS::Lambda::Function", FUNCTION + "Role": "AWS::IAM::Role",
                ALIAS: "AWS::Lambda::Alias"}
    for name, kind in required.items():
        require(resources.get(name, {}).get("Type") == kind
                and isinstance(resources[name].get("Properties"), dict), "thn_routes_resource_invalid")
    properties = resources[API]["Properties"]
    require(properties.get("Mode") in (None, "overwrite") and "BodyS3Location" not in properties
            and isinstance(properties.get("Body"), dict)
            and isinstance(properties["Body"].get("paths"), dict), "thn_routes_definition_invalid")
    stage = resources[STAGE]["Properties"]
    require(stage.get("RestApiId") == {"Ref": API} and stage.get("StageName") == "Prod"
            and isinstance(stage.get("DeploymentId"), dict) and set(stage["DeploymentId"]) == {"Ref"},
            "thn_routes_stage_invalid")
    prior = resources.get(stage["DeploymentId"]["Ref"], {})
    require(prior.get("Type") == "AWS::ApiGateway::Deployment"
            and prior.get("Properties", {}).get("RestApiId") == {"Ref": API}, "thn_routes_deployment_invalid")
    require(resources[FUNCTION]["Properties"].get("Role") == {"Fn::GetAtt": [FUNCTION + "Role", "Arn"]},
            "thn_routes_role_invalid")
    alias = resources[ALIAS]["Properties"]
    require(alias.get("FunctionName") == {"Ref": FUNCTION} and alias.get("Name") == "test",
            "thn_routes_alias_invalid")
    version = alias.get("FunctionVersion", {}).get("Fn::GetAtt")
    require(isinstance(version, list) and len(version) == 2 and version[1] == "Version"
            and resources.get(version[0], {}).get("Type") == "AWS::Lambda::Version"
            and resources[version[0]].get("Properties", {}).get("FunctionName") == {"Ref": FUNCTION},
            "thn_routes_version_invalid")
    for method in ("Get", "Post"):
        permission = resources.get(FUNCTION + "ThnAuthRuntimeV2" + method + "PermissionProd", {})
        value = permission.get("Properties", {})
        require(permission.get("Type") == "AWS::Lambda::Permission"
                and value.get("FunctionName") == {"Ref": ALIAS}
                and value.get("Action") == "lambda:InvokeFunction"
                and value.get("Principal") == "apigateway.amazonaws.com", "thn_routes_permission_invalid")
    return properties["Body"]["paths"]


def _validate_methods(raw):
    methods = _unwrap(raw)
    require(set(methods) == {"get", "post"}, "thn_routes_exact_methods_required")
    expected = "arn:${AWS::Partition}:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${" + ALIAS + "}/invocations"
    for method in methods.values():
        integration = _unwrap(method).get("x-amazon-apigateway-integration", {})
        require(integration.get("type") == "aws_proxy" and integration.get("httpMethod") == "POST"
                and _unwrap(integration.get("uri")).get("Fn::Sub") in
                (expected, expected.replace("${AWS::Partition}", "aws"))
                and set(_unwrap(integration["uri"])) == {"Fn::Sub"}, "thn_routes_integration_invalid")


def capture_routes(template):
    """Return the private raw method AST, preserving supported SAM conditions."""
    paths = _native(template)
    require(PATH in paths, "thn_routes_open_required")
    _validate_methods(paths[PATH])
    return {"schema": SCHEMA, "path": PATH, "methods": copy.deepcopy(paths[PATH])}


def compose(template, record, operation, transition_sha256):
    require(operation in {"close", "reopen"}, "thn_routes_operation_invalid")
    require(isinstance(transition_sha256, str) and re.fullmatch(r"[a-f0-9]{64}", transition_sha256),
            "thn_routes_digest_invalid")
    require(isinstance(record, dict) and set(record) == {"schema", "path", "methods"}
            and record["schema"] == SCHEMA and record["path"] == PATH, "thn_routes_record_invalid")
    _validate_methods(record["methods"])
    paths = _native(template)
    if operation == "close":
        require(paths.get(PATH) == record["methods"], "thn_routes_open_baseline_invalid")
    else:
        require(PATH not in paths, "thn_routes_closed_baseline_invalid")
    logical = "ThnRuntimeRoutes" + operation.title() + transition_sha256[:40]
    require(logical not in template["Resources"], "thn_routes_deployment_collision")
    result = copy.deepcopy(template)
    paths = result["Resources"][API]["Properties"]["Body"]["paths"]
    if operation == "close":
        del paths[PATH]
    else:
        paths[PATH] = copy.deepcopy(record["methods"])
    result["Resources"][logical] = {"Type": "AWS::ApiGateway::Deployment",
        "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain", "DependsOn": [API],
        "Properties": {"RestApiId": {"Ref": API}, "Description": "THN retained runtime routes " + operation}}
    result["Resources"][STAGE]["Properties"]["DeploymentId"] = {"Ref": logical}
    return result, logical


def _export(session, api_id, inventory, template):
    client = session.client("apigateway")
    stage = client.get_stage(restApiId=api_id, stageName="Prod")
    deployment = template["Resources"][STAGE]["Properties"]["DeploymentId"]["Ref"]
    require(stage.get("stageName") == "Prod" and deployment in inventory
            and stage.get("deploymentId") == inventory[deployment]["physicalId"], "thn_routes_stage_drift")
    stream = client.get_export(restApiId=api_id, stageName="Prod", exportType="oas30",
                               parameters={"extensions": "integrations"})["body"]
    try:
        body = stream.read(recovery.MAX_RECORD + 1)
    finally:
        stream.close()
    definition = recovery.private_json(body)
    require(isinstance(definition, dict) and isinstance(definition.get("paths"), dict),
            "thn_routes_export_invalid")
    # Only volatile stage timestamps and the pointer this operation changes are
    # excluded. Variables, canary settings, caches and method settings are bound.
    settings = {k: v for k, v in stage.items() if k not in {
        "ResponseMetadata", "createdDate", "lastUpdatedDate", "deploymentId"}}
    return {"paths": definition["paths"], "stage": settings,
            "deploymentId": stage["deploymentId"]}


def observe(session):
    """Private, double-checkable runtime baseline. Never print this value."""
    state = recovery.observe(session)
    require(not state["state"]["RoleARN"] and state["parameters"].get("EnableThnAuthRuntimeV2") == "true",
            "thn_routes_retained_enabled_stack_required")
    _native(state["processed"])
    resources, inventory = state["processed"]["Resources"], state["inventory"]
    required = {API, STAGE, FUNCTION, FUNCTION + "Role", ALIAS,
                resources[ALIAS]["Properties"]["FunctionVersion"]["Fn::GetAtt"][0],
                resources[STAGE]["Properties"]["DeploymentId"]["Ref"],
                *(FUNCTION + "ThnAuthRuntimeV2" + m + "PermissionProd" for m in ("Get", "Post"))}
    require(all(name in inventory and inventory[name]["type"] == resources[name]["Type"] for name in required),
            "thn_routes_retained_inventory_invalid")
    require(all(name in resources and row["type"] == resources[name]["Type"] for name, row in inventory.items()),
            "thn_routes_inventory_invalid")
    physical = inventory[FUNCTION]["physicalId"]
    state["functions"][FUNCTION] = recovery._function(
        session.client("lambda").get_function_configuration(FunctionName=physical), state["target"]["account"], physical)
    version_logical = resources[ALIAS]["Properties"]["FunctionVersion"]["Fn::GetAtt"][0]
    function_arn = state["functions"][FUNCTION]["arn"]
    version_arn = inventory[version_logical]["physicalId"]
    require(version_arn.startswith(function_arn + ":") and re.fullmatch(r"[1-9][0-9]*", version_arn.split(":")[-1]),
            "thn_routes_version_identity_invalid")
    qualified = session.client("lambda").get_function_configuration(FunctionName=physical, Qualifier="test")
    require(qualified.get("Version") == version_arn.split(":")[-1]
            and qualified.get("FunctionArn") in {function_arn, version_arn, function_arn + ":test"}
            and qualified.get("State") == "Active" and qualified.get("LastUpdateStatus") == "Successful",
            "thn_routes_live_alias_drift")
    state["retainedVersionSha256"] = digest({key: value for key, value in qualified.items()
        if key not in {"ResponseMetadata", "LastModified"}})
    api_id = inventory[API]["physicalId"]
    require(re.fullmatch(r"[a-z0-9]{8,12}", api_id), "thn_routes_api_invalid")
    state["api"] = _export(session, api_id, inventory, state["processed"])
    return state


def _invariant(template, original_names):
    result = copy.deepcopy(template)
    resources = result["Resources"]
    require(set(original_names) <= set(resources), "thn_routes_resource_removed")
    for name in set(resources) - set(original_names):
        match = re.fullmatch(r"ThnRuntimeRoutes(Close|Reopen)[a-f0-9]{40}", name)
        require(match is not None, "thn_routes_unapproved_resource")
        operation = match[1].lower()
        require(resources[name] == {"Type": "AWS::ApiGateway::Deployment",
            "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain", "DependsOn": [API],
            "Properties": {"RestApiId": {"Ref": API}, "Description": "THN retained runtime routes " + operation}},
            "thn_routes_retained_deployment_invalid")
        del resources[name]
    resources[API]["Properties"]["Body"]["paths"].pop(PATH, None)
    resources[STAGE]["Properties"].pop("DeploymentId")
    return digest(result)


def _other_paths(paths):
    return digest({key: value for key, value in paths.items() if key != PATH})


def capture(session, tooling):
    """Capture a PRIVATE version-bound reopening record; do not write it publicly."""
    recovery.validate_tooling(tooling)
    first = observe(session)
    routes = capture_routes(first["processed"])
    methods = first["api"]["paths"].get(PATH)
    require(isinstance(methods, dict) and set(_unwrap(methods)) == {"get", "post"}, "thn_routes_export_open_required")
    require(digest(first) == digest(observe(session)), "thn_routes_baseline_drift")
    names = sorted(first["processed"]["Resources"])
    return {"schema": SCHEMA, "service": recovery.SERVICE, "environment": "test", "tooling": dict(tooling),
            "target": first["target"], "routes": routes, "resourceNames": names,
            "inventory": first["inventory"], "invariantSha256": _invariant(first["processed"], names),
            "parametersSha256": digest(first["parameters"]),
            "settingsSha256": digest({key: first["state"][key] for key in recovery.STACK_SETTINGS}),
            "retainedVersionSha256": first["retainedVersionSha256"],
            "functions": first["functions"], "stage": first["api"]["stage"],
            "otherPathsSha256": _other_paths(first["api"]["paths"]), "deployedMethods": methods}


def _validate_record(record, tooling, expected_sha256, current):
    require(isinstance(record, dict) and set(record) == {"schema", "service", "environment", "tooling",
        "target", "routes", "resourceNames", "inventory", "invariantSha256", "parametersSha256",
        "settingsSha256", "retainedVersionSha256", "functions", "stage", "otherPathsSha256", "deployedMethods"}, "thn_routes_record_invalid")
    recovery.hex_digest(expected_sha256)
    require(digest(record) == expected_sha256 and record["schema"] == SCHEMA
            and record["service"] == recovery.SERVICE and record["environment"] == "test"
            and record["tooling"] == tooling and record["target"] == current["target"], "thn_routes_record_binding_invalid")
    names = record["resourceNames"]
    require(isinstance(names, list) and all(isinstance(n, str) for n in names)
            and names == sorted(set(names)) and isinstance(record["inventory"], dict), "thn_routes_record_invalid")
    require(_invariant(current["processed"], names) == record["invariantSha256"]
            and digest(current["parameters"]) == record["parametersSha256"]
            and digest({key: current["state"][key] for key in recovery.STACK_SETTINGS}) == record["settingsSha256"]
            and current["functions"] == record["functions"] and current["api"]["stage"] == record["stage"]
            and current["retainedVersionSha256"] == record["retainedVersionSha256"]
            and _other_paths(current["api"]["paths"]) == record["otherPathsSha256"], "thn_routes_record_baseline_drift")
    require(all(current["inventory"].get(name) == row for name, row in record["inventory"].items()),
            "thn_routes_physical_inventory_drift")
    extra = set(current["inventory"]) - set(record["inventory"])
    require(all(name not in names and re.fullmatch(r"ThnRuntimeRoutes(Close|Reopen)[a-f0-9]{40}", name)
                for name in extra), "thn_routes_inventory_addition_invalid")


def _review(description, current, name, arn, logical):
    require(description.get("StackId") == current["target"]["stackId"]
            and description.get("StackName") == recovery.STACK_NAME and description.get("ChangeSetName") == name
            and description.get("ChangeSetId") == arn and not description.get("NextToken")
            and description.get("IncludeNestedStacks") in (None, False)
            and description.get("ChangeSetType") in (None, "UPDATE")
            and not description.get("ParentChangeSetId") and not description.get("RootChangeSetId")
            and not description.get("RoleARN") and description.get("Status") == "CREATE_COMPLETE"
            and description.get("ExecutionStatus") == "AVAILABLE"
            and recovery._parameters(description) == current["parameters"], "thn_routes_change_set_invalid")
    changes = description.get("Changes")
    require(isinstance(changes, list) and len(changes) == 3, "thn_routes_exact_change_set_required")
    expected, seen = {API: ("AWS::ApiGateway::RestApi", "Body"),
                      STAGE: ("AWS::ApiGateway::Stage", "DeploymentId")}, set()
    for change in changes:
        require(change.get("Type") == "Resource" and isinstance(change.get("ResourceChange"), dict),
                "thn_routes_change_set_invalid")
        item = change["ResourceChange"]
        key = item.get("LogicalResourceId")
        require(key in {*expected, logical} and key not in seen and not item.get("ModuleInfo")
                and not item.get("ChangeSetId"),
                "thn_routes_unapproved_change")
        seen.add(key)
        if key == logical:
            require(item.get("Action") == "Add" and item.get("ResourceType") == "AWS::ApiGateway::Deployment"
                    and item.get("Replacement") in (None, "False") and not item.get("PhysicalResourceId"),
                    "thn_routes_retained_add_required")
        else:
            kind, prop = expected[key]
            require(item.get("Action") == "Modify" and item.get("ResourceType") == kind
                    and item.get("Replacement") == "False" and item.get("Scope") == ["Properties"]
                    and item.get("PhysicalResourceId") == current["inventory"][key]["physicalId"]
                    and isinstance(item.get("Details"), list) and item["Details"], "thn_routes_exact_modify_required")
            for detail in item["Details"]:
                target = detail.get("Target", {})
                require(target.get("Attribute") == "Properties" and target.get("Name") == prop
                        and target.get("RequiresRecreation") == "Never", "thn_routes_exact_property_required")


def transition(session, record, *, operation, execute, tooling, expected_record_sha256, expected_baseline_sha256):
    """All writes follow exact native-template, inventory, role and drift checks."""
    require(type(execute) is bool and operation in {"close", "reopen"}, "thn_routes_operation_invalid")
    recovery.validate_tooling(tooling)
    recovery.hex_digest(expected_baseline_sha256)
    current = observe(session)
    require(digest(current) == expected_baseline_sha256, "thn_routes_baseline_drift")
    _validate_record(record, tooling, expected_record_sha256, current)
    require((current["api"]["paths"].get(PATH) == record["deployedMethods"] if operation == "close"
             else PATH not in current["api"]["paths"]), "thn_routes_export_baseline_invalid")
    token = digest({"record": expected_record_sha256, "baseline": expected_baseline_sha256,
                    "tooling": tooling, "operation": operation})
    template, logical = compose(current["processed"], record["routes"], operation, token)
    body = canonical(template)
    require(len(body) <= 51200, "thn_routes_private_template_transport_required")
    require(digest(observe(session)) == expected_baseline_sha256, "thn_routes_baseline_drift")
    result = {"status": "verified", "operation": operation, "recordSha256": expected_record_sha256,
              "baselineSha256": expected_baseline_sha256, "templateSha256": digest(template), "executed": False}
    if not execute:
        return result
    cfn, stack_id = session.client("cloudformation"), current["target"]["stackId"]
    name = "thn-routes-" + operation + "-" + token[:40]
    capabilities = current["state"]["Capabilities"]
    created = cfn.create_change_set(StackName=stack_id, ChangeSetName=name, ChangeSetType="UPDATE",
        ClientToken=token, Description="Retained THN TEST runtime routes " + operation, TemplateBody=body.decode(),
        Parameters=[{"ParameterKey": k, "UsePreviousValue": True} for k in sorted(current["parameters"])],
        **({"Capabilities": capabilities} if capabilities is not None else {}))
    arn = created.get("Id")
    require(created.get("StackId") == stack_id and isinstance(arn, str)
            and re.fullmatch(rf"arn:aws:cloudformation:{recovery.REGION}:{current['target']['account']}:changeSet/{name}/[A-Za-z0-9-]+", arn),
            "thn_routes_change_set_identity_invalid")
    cfn.get_waiter("change_set_create_complete").wait(StackName=stack_id, ChangeSetName=arn,
        WaiterConfig={"Delay": 5, "MaxAttempts": 60})
    _review(cfn.describe_change_set(StackName=stack_id, ChangeSetName=arn, IncludePropertyValues=True),
            current, name, arn, logical)
    for stage in ("Original", "Processed"):
        require(recovery._template(cfn.get_template(StackName=stack_id, ChangeSetName=arn, TemplateStage=stage)["TemplateBody"])
                == template, "thn_routes_change_set_template_drift")
    require(digest(observe(session)) == expected_baseline_sha256, "thn_routes_baseline_drift")
    cfn.execute_change_set(StackName=stack_id, ChangeSetName=arn, ClientRequestToken="execute-" + token)
    cfn.get_waiter("stack_update_complete").wait(StackName=stack_id, WaiterConfig={"Delay": 5, "MaxAttempts": 120})
    after = observe(session)
    _validate_record(record, tooling, expected_record_sha256, after)
    require(after["original"] == template and after["processed"] == template
            and set(after["inventory"]) == set(current["inventory"]) | {logical}
            and all(after["inventory"][k] == v for k, v in current["inventory"].items()),
            "thn_routes_post_inventory_invalid")
    require((PATH not in after["api"]["paths"] if operation == "close"
             else after["api"]["paths"].get(PATH) == record["deployedMethods"]), "thn_routes_deployed_definition_invalid")
    return {**result, "status": "closed" if operation == "close" else "reopened", "executed": True,
            "apiDefinitionVerified": True}


def workflow_context(env, root):
    tooling = {"sha": env.get("TOOLING_SHA"), "workflowSha256": env.get("TOOLING_WORKFLOW_SHA256")}
    recovery.validate_tooling(tooling)
    require(env.get("GITHUB_REF") == "refs/heads/test" and env.get("GITHUB_SHA") == tooling["sha"]
            and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("GITHUB_REPOSITORY") == "LynxPardelle/zoolanding-api-proxy"
            and env.get("ROUTE_OPERATION") in {"close", "reopen"}
            and env.get("ROUTE_EXECUTION") in {"verify", "execute"}
            and not env.get("AWS_CLOUDFORMATION_ROLE_ARN") and not env.get("THN_V2_TEST_PARAMETERS_JSON"),
            "thn_routes_workflow_context_invalid")
    for key in ("AWS_REGION", "AWS_DEFAULT_REGION"):
        require(env.get(key, recovery.REGION) == recovery.REGION, "thn_routes_region_invalid")
    for key in ("ROUTE_RECORD_SHA256", "CURRENT_BASELINE_SHA256"):
        recovery.hex_digest(env.get(key))
    workflow = root / ".github/workflows/thn-retained-routes-test.yml"
    require(digest(workflow.read_bytes().replace(b"\r\n", b"\n")) == tooling["workflowSha256"],
            "thn_routes_workflow_digest_invalid")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=15, check=False)
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=root,
                           capture_output=True, text=True, timeout=15, check=False)
    require(head.returncode == 0 and head.stdout.strip() == tooling["sha"] and dirty.returncode == 0
            and not dirty.stdout.strip(), "thn_routes_clean_tooling_required")
    reference = recovery.private_json(env.get("THN_RETAINED_ROUTES_REFERENCE_JSON", ""))
    recovery.closed(reference, {"bucket", "key", "versionId"})
    for value in reference.values():
        recovery.text_value(value)
    require(reference["bucket"] == env.get("SAM_ARTIFACTS_BUCKET") and reference["versionId"] != "null"
            and re.fullmatch(recovery.STACK_NAME + r"/retained-routes/[A-Za-z0-9_-]+\.json", reference["key"]),
            "thn_routes_private_channel_invalid")
    return tooling, reference


def load_record(session, reference, expected_sha256):
    # Reference and immutable workflow context are checked before this call.
    # Only an independently reviewed version in the existing private channel is
    # read. This controller does not create buckets or publish its capture.
    account = session.client("sts").get_caller_identity().get("Account")
    require(session.region_name == recovery.REGION and isinstance(account, str)
            and digest(account.encode()) == recovery.ACCOUNT_SHA256, "thn_routes_account_invalid")
    request = {"Bucket": reference["bucket"], "Key": reference["key"], "VersionId": reference["versionId"]}
    body = recovery._version_bytes(session, request, account, recovery.MAX_RECORD)
    require(digest(body) == expected_sha256, "thn_routes_record_digest_invalid")
    record = recovery.private_json(body)
    require(digest(record) == expected_sha256
            and recovery._version_bytes(session, request, account, recovery.MAX_RECORD) == body,
            "thn_routes_record_readback_invalid")
    return record


def main(argv=None):
    class SafeParser(argparse.ArgumentParser):
        def error(self, message):
            raise RouteGuardError("thn_routes_arguments_invalid")
    try:
        parser = SafeParser(description="Explicit retained THN TEST route transitions; sanitized output only.")
        parser.add_argument("--check-workflow", action="store_true")
        args = parser.parse_args(argv)
        tooling, reference = workflow_context(os.environ, FilePath(__file__).resolve().parents[1])
        if args.check_workflow:
            print("thn_routes_workflow_valid")
            return 0
        import boto3
        session = boto3.Session(region_name=recovery.REGION)
        record = load_record(session, reference, os.environ["ROUTE_RECORD_SHA256"])
        result = transition(session, record, operation=os.environ["ROUTE_OPERATION"],
            execute=os.environ["ROUTE_EXECUTION"] == "execute", tooling=tooling,
            expected_record_sha256=os.environ["ROUTE_RECORD_SHA256"],
            expected_baseline_sha256=os.environ["CURRENT_BASELINE_SHA256"])
        print(json.dumps(result, sort_keys=True))
        return 0
    except (RouteGuardError, recovery.SnapshotError) as exc:
        print(str(exc), file=sys.stderr)
    except Exception:
        print("thn_routes_operation_failed", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
