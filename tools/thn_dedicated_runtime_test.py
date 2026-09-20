"""Pure, fail-closed guards for the dedicated THN TEST runtime stack.

This module does not call AWS or execute a change set. Deployment orchestration
must invoke these guards before any mutable provider operation.
"""

from __future__ import annotations

import copy
import argparse
import hashlib
import io
import json
import os
import re
from pathlib import Path
import zipfile
from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any


API = "ThnRuntimeApi"
FUNCTION = "ThnAuthRuntimeV2Function"
LOG_GROUP = "ThnRuntimeLogGroup"
PATH = "/auth-v2/runtime-config"
PARAMETERS = frozenset({"DescriptorVersionId", "DescriptorSha256", "AuthPolicyVersion",
                        "CognitoUserPoolId", "CognitoClientId"})
SOURCE_RESOURCES = frozenset({API, FUNCTION, LOG_GROUP})
ALLOWED_TYPES = frozenset({"AWS::ApiGateway::RestApi", "AWS::ApiGateway::Deployment",
                           "AWS::ApiGateway::Stage", "AWS::Lambda::Function",
                           "AWS::Lambda::Version", "AWS::Lambda::Alias",
                           "AWS::Lambda::Permission", "AWS::IAM::Role", "AWS::Logs::LogGroup"})
STACK_NAME = "zoolanding-thn-auth-runtime-test"
ROLE_NAME = "zoolanding-deployer-thn-auth-runtime-test-cfn-exec"
APPROVED_FIRST_PLAN_SHA256 = "43125fcc1a882927d99bb088b8dcac53385da668f12e4ee16c07a796614e7979"
FIRST_PARAMETER_MAP = {
    "DescriptorVersionId": "ThnAuthRuntimeV2DescriptorVersionId",
    "DescriptorSha256": "ThnAuthRuntimeV2DescriptorSha256",
    "AuthPolicyVersion": "ThnAuthRuntimeV2AuthPolicyVersion",
    "CognitoUserPoolId": "ThnAuthRuntimeV2CognitoUserPoolId",
    "CognitoClientId": "ThnAuthRuntimeV2CognitoClientId",
}


def _require(value: bool, message: str) -> None:
    if not value:
        raise ValueError(message)


def validate_context(values: Mapping[str, str], expected_account: str) -> str:
    """Reject a non-TEST or substituted GitHub run before credentials are assumed."""

    _require(isinstance(values, Mapping) and re.fullmatch(r"[0-9]{12}", expected_account or "")
             and values.get("GITHUB_REPOSITORY") == "LynxPardelle/zoolanding-api-proxy"
             and values.get("GITHUB_REF") == "refs/heads/test"
             and values.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
             and re.fullmatch(r"[a-f0-9]{40}", values.get("GITHUB_SHA", "")) is not None
             and values.get("SOURCE_SHA") == values.get("GITHUB_SHA"),
             "dedicated_workflow_context_invalid")
    role = values.get("AWS_CLOUDFORMATION_ROLE_ARN", "")
    _require(role == f"arn:aws:iam::{expected_account}:role/{ROLE_NAME}",
             "dedicated_execution_role_invalid")
    return role


def render_native(source: dict[str, Any], package: dict[str, str], parameters: dict[str, str]) -> dict[str, Any]:
    """Translate only a reviewed standalone THN template and versioned package."""

    from samtranslator.translator.transform import transform

    _require(isinstance(source, dict) and source.get("Transform") == "AWS::Serverless-2016-10-31",
             "dedicated_source_invalid")
    resources = source.get("Resources")
    _require(isinstance(resources, dict) and set(resources) == SOURCE_RESOURCES,
             "dedicated_source_resources_invalid")
    _require(source.get("Globals", {}).get("Function", {}).get("Runtime") == "python3.13",
             "dedicated_runtime_invalid")
    function = resources[FUNCTION]
    properties = function.get("Properties", {})
    _require(function.get("Type") == "AWS::Serverless::Function"
             and properties.get("Handler") == "thn_auth_runtime_v2.lambda_handler"
             and properties.get("AutoPublishAlias") == "test"
             and "Role" not in properties and "FunctionName" not in properties
             and set(properties.get("Events", {})) == {"RuntimeGet", "RuntimePost"},
             "dedicated_function_invalid")
    for label, method in (("RuntimeGet", "GET"), ("RuntimePost", "POST")):
        _require(properties["Events"][label] == {"Type": "Api", "Properties": {
            "RestApiId": {"Ref": API}, "Path": PATH, "Method": method}},
            "dedicated_route_invalid")
    _require(resources[API].get("Type") == "AWS::Serverless::Api"
             and resources[API].get("Properties", {}).get("StageName") == "Prod"
             and resources[API]["Properties"].get("EndpointConfiguration") == "REGIONAL",
             "dedicated_api_invalid")
    _require(isinstance(package, dict) and set(package) == {"Bucket", "Key", "Version"}
             and all(isinstance(item, str) and item and item != "null" for item in package.values())
             and re.fullmatch(r"[A-Za-z0-9_.+/-]{1,1024}", package["Version"]) is not None,
             "dedicated_package_invalid")
    _require(isinstance(parameters, dict) and set(parameters) == PARAMETERS
             and all(isinstance(value, str) and value and value != "BLOCKED" for value in parameters.values())
             and re.fullmatch(r"[a-f0-9]{64}", parameters["DescriptorSha256"]) is not None
             and parameters["DescriptorSha256"] != "0" * 64,
             "dedicated_parameters_invalid")

    reviewed = copy.deepcopy(source)
    reviewed["Resources"][FUNCTION]["Properties"]["CodeUri"] = copy.deepcopy(package)
    policy_loader = SimpleNamespace(load=lambda: {
        "AWSLambdaBasicExecutionRole": "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"})
    native = transform(reviewed, parameters, policy_loader)
    translated = native.get("Resources", {})
    _require(isinstance(translated, dict) and set(translated) >= SOURCE_RESOURCES,
             "dedicated_native_invalid")
    for name, resource in translated.items():
        _require((name.startswith(API) or name.startswith(FUNCTION) or name == LOG_GROUP)
                 and resource.get("Type") in ALLOWED_TYPES,
                 "dedicated_native_resource_invalid")
    _require(set(translated[API]["Properties"]["Body"]["paths"]) == {PATH}
             and set(translated[API]["Properties"]["Body"]["paths"][PATH]) == {"get", "post"}
             and translated[FUNCTION]["Properties"]["Code"] == {
                 "S3Bucket": package["Bucket"], "S3Key": package["Key"],
                 "S3ObjectVersion": package["Version"]},
             "dedicated_native_contract_invalid")
    return native


def review_create_change_set(change_set: dict[str, Any], native: dict[str, Any]) -> list[str]:
    """Accept only one complete CREATE change set of exact THN resource Adds."""

    _require(isinstance(change_set, dict) and change_set.get("Status") == "CREATE_COMPLETE"
             and change_set.get("ExecutionStatus") == "AVAILABLE"
             and not change_set.get("NextToken"),
             "dedicated_change_set_unavailable")
    resources = native.get("Resources") if isinstance(native, dict) else None
    changes = change_set.get("Changes")
    _require(isinstance(resources, dict) and isinstance(changes, list)
             and len(changes) == len(resources), "dedicated_change_set_count_invalid")
    seen = set()
    for item in changes:
        _require(isinstance(item, dict) and item.get("Type", "Resource") == "Resource",
                 "dedicated_change_type_invalid")
        change = item.get("ResourceChange")
        _require(isinstance(change, dict), "dedicated_resource_change_invalid")
        name = change.get("LogicalResourceId")
        _require(name in resources and name not in seen and change.get("Action") == "Add"
                 and change.get("ResourceType") == resources[name].get("Type")
                 and change.get("Replacement") in (None, False, "False")
                 and change.get("Scope") in (None, [])
                 and change.get("Details") in (None, [])
                 and change.get("PhysicalResourceId") in (None, ""),
                 "dedicated_resource_delta_invalid")
        seen.add(name)
    _require(seen == set(resources), "dedicated_resource_inventory_invalid")
    return sorted(seen)


def validate_plan(raw: str, expected_digest: str, source_sha: str, template_digest: str,
                  approved_bucket: str) -> dict[str, Any]:
    """Validate one private canonical selection without echoing its contents."""

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            _require(key not in result, "dedicated_plan_duplicate_key")
            result[key] = value
        return result

    _require(isinstance(raw, str) and 0 < len(raw.encode("utf-8")) <= 8192
             and isinstance(expected_digest, str)
             and hashlib.sha256(raw.encode("utf-8")).hexdigest() == expected_digest,
             "dedicated_plan_digest_invalid")
    try:
        plan = json.loads(raw, object_pairs_hook=unique_pairs)
    except (ValueError, TypeError) as exc:
        raise ValueError("dedicated_plan_json_invalid") from exc
    _require(isinstance(plan, dict) and raw == json.dumps(plan, sort_keys=True, separators=(",", ":")),
             "dedicated_plan_canonical_invalid")
    _require(set(plan) == {"schemaVersion", "environment", "stackName", "sourceSha", "templateSha256",
                           "package", "parameters"}
             and plan["schemaVersion"] == 1 and plan["environment"] == "test"
             and plan["stackName"] == "zoolanding-thn-auth-runtime-test"
             and plan["sourceSha"] == source_sha
             and re.fullmatch(r"[a-f0-9]{40}", source_sha) is not None
             and plan["templateSha256"] == template_digest
             and re.fullmatch(r"[a-f0-9]{64}", template_digest) is not None,
             "dedicated_plan_identity_invalid")
    package = plan["package"]
    _require(isinstance(package, dict) and set(package) == {"bucket", "key", "versionId", "sha256"}
             and package["bucket"] == approved_bucket
             and isinstance(package["key"], str)
             and package["key"].startswith("zoolanding-api-proxy-test/thn-runtime/")
             and re.fullmatch(r"zoolanding-api-proxy-test/thn-runtime/[A-Za-z0-9_/-]+\.zip",
                              package["key"]) is not None
             and len(package["key"]) <= 1024
             and all(part not in ("", ".", "..") for part in package["key"].split("/"))
             and re.fullmatch(r"[A-Za-z0-9_./-]+", package["key"]) is not None
             and isinstance(package["versionId"], str)
             and re.fullmatch(r"[A-Za-z0-9_.+/-]{1,1024}", package["versionId"]) is not None
             and package["versionId"] != "null"
             and isinstance(package["sha256"], str)
             and re.fullmatch(r"[a-f0-9]{64}", package["sha256"]) is not None,
             "dedicated_plan_package_invalid")
    parameters = plan["parameters"]
    _require(isinstance(parameters, dict) and set(parameters) == PARAMETERS
             and all(isinstance(value, str) and value and value != "BLOCKED"
                     for value in parameters.values())
             and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
                              parameters["DescriptorVersionId"]) is not None
             and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
                              parameters["AuthPolicyVersion"]) is not None
             and re.fullmatch(r"[a-f0-9]{64}", parameters["DescriptorSha256"]) is not None
             and parameters["DescriptorSha256"] != "0" * 64
             and re.fullmatch(r"us-east-1_[A-Za-z0-9]+", parameters["CognitoUserPoolId"]) is not None
             and re.fullmatch(r"[a-z0-9]{1,128}", parameters["CognitoClientId"]) is not None,
             "dedicated_plan_parameters_invalid")
    return plan


def derive_plan(first: dict[str, Any], source_sha: str, template_digest: str,
                approved_bucket: str) -> dict[str, Any]:
    """Translate only the previously sealed first plan into an in-memory selection."""

    _require(isinstance(first, dict) and set(first) == {
        "schema", "service", "environment", "tooling", "target", "baselineSha256",
        "snapshotSha256", "templateSha256", "package", "packageSha256", "parameters"}
        and first["schema"] == "thn-first-runtime/v1"
        and first["service"] == "zoolanding-api-proxy" and first["environment"] == "test"
        and isinstance(first["tooling"], dict)
        and set(first["tooling"]) == {"sha", "workflowSha256"}
        and re.fullmatch(r"[a-f0-9]{40}", first["tooling"]["sha"]) is not None
        and all(re.fullmatch(r"[a-f0-9]{64}", first[name]) is not None for name in (
            "baselineSha256", "snapshotSha256", "templateSha256", "packageSha256")),
        "dedicated_first_plan_identity_invalid")
    target = first["target"]
    _require(isinstance(target, dict) and set(target) == {"account", "region", "stackId"}
             and target["account"] == "765932874577" and target["region"] == "us-east-1"
             and re.fullmatch(
                 r"arn:aws:cloudformation:us-east-1:765932874577:stack/zoolanding-api-proxy-test/[A-Za-z0-9-]+",
                 target["stackId"]) is not None,
             "dedicated_first_target_invalid")
    old_package = first["package"]
    _require(isinstance(old_package, dict) and set(old_package) == {"Bucket", "Key", "Version"}
             and old_package["Bucket"] == approved_bucket,
             "dedicated_first_package_invalid")
    old_parameters = first["parameters"]
    _require(isinstance(old_parameters, dict)
             and set(old_parameters) == set(FIRST_PARAMETER_MAP.values()) | {"EnableThnAuthRuntimeV2"}
             and old_parameters["EnableThnAuthRuntimeV2"] == "true",
             "dedicated_first_parameters_invalid")
    selected = {
        "schemaVersion": 1, "environment": "test", "stackName": STACK_NAME,
        "sourceSha": source_sha, "templateSha256": template_digest,
        "package": {"bucket": old_package["Bucket"], "key": old_package["Key"],
                    "versionId": old_package["Version"], "sha256": first["packageSha256"]},
        "parameters": {name: old_parameters[old_name]
                       for name, old_name in FIRST_PARAMETER_MAP.items()},
    }
    raw = json.dumps(selected, sort_keys=True, separators=(",", ":"))
    return validate_plan(raw, hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                         source_sha, template_digest, approved_bucket)


def verify_package(body: bytes, expected_digest: str, source_entries: dict[str, bytes]) -> bool:
    """Read back a private versioned ZIP without logging its content."""

    expected_names = {"thn_auth_runtime_v2.py", "service_binding_registry_consumer_v2.py"}
    _require(isinstance(body, bytes) and 0 < len(body) <= 1_048_576
             and hashlib.sha256(body).hexdigest() == expected_digest
             and isinstance(source_entries, dict) and set(source_entries) == expected_names,
             "dedicated_package_readback_invalid")
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            infos = archive.infolist()
            _require(len(infos) == 2 and {entry.filename for entry in infos} == expected_names
                     and all(not entry.is_dir() for entry in infos),
                     "dedicated_package_inventory_invalid")
            for name in expected_names:
                _require(archive.read(name) == source_entries[name],
                         "dedicated_package_source_mismatch")
    except (zipfile.BadZipFile, KeyError, RuntimeError) as exc:
        raise ValueError("dedicated_package_zip_invalid") from exc
    return True


def release(operation: str, plan: dict[str, Any], native: dict[str, Any],
            cloudformation: Any, role_arn: str) -> str:
    """Verify or create one independent stack; never update another stack."""

    _require(operation in {"verify", "create"}
             and isinstance(plan, dict)
             and plan.get("stackName") == "zoolanding-thn-auth-runtime-test"
             and isinstance(plan.get("sourceSha"), str)
             and re.fullmatch(r"[a-f0-9]{40}", plan["sourceSha"]) is not None
             and isinstance(native, dict) and isinstance(native.get("Resources"), dict)
             and isinstance(role_arn, str)
             and re.fullmatch(
                 r"arn:aws:iam::[0-9]{12}:role/zoolanding-deployer-thn-auth-runtime-test-cfn-exec",
                 role_arn) is not None,
             "dedicated_release_context_invalid")
    if operation == "verify":
        return "verified"

    stack_name = plan["stackName"]
    change_set_name = "thn-dedicated-" + plan["sourceSha"][:12]
    result = cloudformation.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        ChangeSetType="CREATE",
        TemplateBody=json.dumps(native, sort_keys=True, separators=(",", ":")),
        Parameters=[{"ParameterKey": name, "ParameterValue": plan["parameters"][name]}
                    for name in sorted(PARAMETERS)],
        Capabilities=["CAPABILITY_IAM"],
        RoleARN=role_arn,
        Description="Create only the dedicated THN TEST auth-runtime API stack",
    )
    change_set_id = result["Id"]
    cloudformation.get_waiter("change_set_create_complete").wait(
        ChangeSetName=change_set_id, StackName=stack_name)
    review_create_change_set(
        cloudformation.describe_change_set(ChangeSetName=change_set_id, StackName=stack_name), native)
    cloudformation.execute_change_set(ChangeSetName=change_set_id, StackName=stack_name)
    cloudformation.get_waiter("stack_create_complete").wait(StackName=stack_name)
    cloudformation.update_termination_protection(
        StackName=stack_name, EnableTerminationProtection=True)
    stacks = cloudformation.describe_stacks(StackName=stack_name).get("Stacks", [])
    _require(len(stacks) == 1 and stacks[0].get("StackStatus") == "CREATE_COMPLETE"
             and stacks[0].get("EnableTerminationProtection") is True,
             "dedicated_stack_not_protected")
    summaries = cloudformation.list_stack_resources(StackName=stack_name).get("StackResourceSummaries", [])
    observed = {item.get("LogicalResourceId"): item for item in summaries}
    _require(len(summaries) == len(native["Resources"])
             and set(observed) == set(native["Resources"])
             and all(item.get("ResourceType") == native["Resources"][logical]["Type"]
                     and item.get("ResourceStatus") == "CREATE_COMPLETE"
                     for logical, item in observed.items()),
             "dedicated_stack_resource_mismatch")
    return "created"


def _stack_absent(cloudformation: Any) -> bool:
    """A CREATE release must not adopt or update any pre-existing stack."""

    from botocore.exceptions import ClientError

    try:
        cloudformation.describe_stacks(StackName=STACK_NAME)
    except ClientError as exc:
        _require(exc.response.get("Error", {}).get("Code") == "ValidationError"
                 and "does not exist" in exc.response.get("Error", {}).get("Message", ""),
                 "dedicated_stack_lookup_failed")
        return True
    raise ValueError("dedicated_stack_already_exists")


def run_workflow(operation: str, values: dict[str, str]) -> str:
    """Derive the selection in memory, then optionally create only the new stack."""

    import boto3
    import yaml
    try:
        from tools import aws_live_snapshot as recovery
        from tools import thn_first_provisioning as first_release
    except ModuleNotFoundError:
        import aws_live_snapshot as recovery
        import thn_first_provisioning as first_release

    role = validate_context(values, "765932874577")
    _require(operation in {"verify", "create"}
             and values.get("AWS_REGION") == "us-east-1"
             and values.get("AWS_DEFAULT_REGION") == "us-east-1"
             and isinstance(values.get("SAM_ARTIFACTS_BUCKET"), str)
             and values["SAM_ARTIFACTS_BUCKET"].startswith("aws-sam-cli-managed-default-samclisourcebucket-")
             and re.fullmatch(r"[a-f0-9]{64}", values.get("THN_TEMPLATE_SHA256", "")) is not None,
             "dedicated_workflow_inputs_invalid")
    root = Path(__file__).resolve().parents[1]
    template_bytes = (root / "template-thn-runtime-test.yaml").read_bytes()
    _require(hashlib.sha256(template_bytes).hexdigest() == values["THN_TEMPLATE_SHA256"],
             "dedicated_template_digest_invalid")
    reference = recovery.private_json(values.get("THN_FIRST_PLAN_REFERENCE_JSON", ""))
    recovery.closed(reference, {"bucket", "key", "versionId"})
    _require(reference["bucket"] == values["SAM_ARTIFACTS_BUCKET"]
             and isinstance(reference["key"], str)
             and reference["key"].startswith("zoolanding-api-proxy-test/first-provisioning/")
             and reference["key"].endswith(".json")
             and 0 < len(reference["key"]) <= 1024
             and re.fullmatch(r"[\x21-\x7e]+", reference["key"]) is not None
             and not any(part in {"", ".", ".."} for part in reference["key"].split("/"))
             and isinstance(reference["versionId"], str)
             and re.fullmatch(r"[A-Za-z0-9_.+/-]{1,1024}", reference["versionId"]) is not None
             and reference["versionId"] != "null",
             "dedicated_first_reference_invalid")
    session = boto3.Session(region_name="us-east-1")
    _require(session.client("sts").get_caller_identity().get("Account") == "765932874577",
             "dedicated_aws_account_invalid")
    try:
        first_plan = first_release.load_plan(session, reference, APPROVED_FIRST_PLAN_SHA256)
    except Exception:
        raise ValueError("dedicated_first_plan_readback_failed") from None
    try:
        first_release._parameters(yaml.safe_load((root / "template.yaml").read_bytes()),
                                  first_plan["parameters"])
    except Exception:
        raise ValueError("dedicated_first_plan_parameters_invalid") from None
    plan = derive_plan(first_plan, values["SOURCE_SHA"], values["THN_TEMPLATE_SHA256"],
                       values["SAM_ARTIFACTS_BUCKET"])
    try:
        first_release._prerequisites(session, first_plan["parameters"], "765932874577")
    except Exception:
        raise ValueError("dedicated_auth_prerequisite_invalid") from None
    source = yaml.safe_load(template_bytes)
    package = plan["package"]
    native = render_native(source, {"Bucket": package["bucket"], "Key": package["key"],
                                    "Version": package["versionId"]}, plan["parameters"])
    try:
        result = session.client("s3").get_object(Bucket=package["bucket"], Key=package["key"],
                                                  VersionId=package["versionId"])
    except Exception:
        raise ValueError("dedicated_package_readback_failed") from None
    _require(result.get("VersionId") == package["versionId"]
             and result.get("ContentLength", 0) <= 1_048_576,
             "dedicated_package_version_invalid")
    try:
        body = result["Body"].read(1_048_577)
    except Exception:
        raise ValueError("dedicated_package_readback_failed") from None
    source_entries = {name: (root / name).read_bytes() for name in (
        "thn_auth_runtime_v2.py", "service_binding_registry_consumer_v2.py")}
    verify_package(body, package["sha256"], source_entries)
    cloudformation = session.client("cloudformation")
    _stack_absent(cloudformation)
    return release(operation, plan, native, cloudformation, role)


def main() -> int:
    parser = argparse.ArgumentParser(description="Guarded, dedicated THN TEST runtime release")
    parser.add_argument("--check-context", action="store_true")
    parser.add_argument("--operation", choices=("verify", "create"), default="verify")
    args = parser.parse_args()
    try:
        if args.check_context:
            validate_context(os.environ, "765932874577")
            print("dedicated_runtime_context_verified")
        else:
            print("dedicated_runtime_" + run_workflow(args.operation, os.environ))
    except ValueError as exc:
        print(str(exc) if str(exc).startswith("dedicated_") else "dedicated_runtime_gate_failed")
        return 1
    except Exception:
        # Never print a private plan, package response or provider exception body.
        print("dedicated_runtime_provider_failed; inspect the single stack's AWS events")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
