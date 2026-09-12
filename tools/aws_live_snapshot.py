#!/usr/bin/env python3
"""Explicit, private, original-byte TEST recovery; never a GitHub-provenance fallback.

Library results may contain PRIVATE selectors/templates and must stay in memory or
an independently approved private channel. The CLI emits only closed summaries.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from urllib.parse import urlsplit
import zipfile

try:
    from tools.review_test_change_set import ChangeSetReviewError, review_change_set
except ModuleNotFoundError:
    from review_test_change_set import ChangeSetReviewError, review_change_set


SCHEMA = "AWS-live-snapshot/v1"
SERVICE = "zoolanding-api-proxy"
STACK_NAME = SERVICE + "-test"
REGION = "us-east-1"
FUNCTIONS = ("ApiProxyFunction", "AuthProvisioningExecutorFunction", "AuthJwtAuthorizerFunction")
# Approved observations are hashes, not raw operational selectors or Git claims.
ACCOUNT_SHA256 = "3e19eeb25ac142d015c5a4d347dc58784b0a79a124f1353b5e92d90673810a8f"
APPROVED_ZIP_SHA256 = "669c8d8fcb335899e7f4e2cda7e62b0fa74f5387588793897f27fad87f1304a4"
APPROVED_ZIP_SIZE = 5119114
APPROVED_SELECTOR_SHA256 = "1a860d67a954ad8ceb0786421cb2b62a796f9eab54f436544d3739536ca1c4c0"
APPROVED_VERSION_SHA256 = "3ded86cf20709eb9cffe17774eb1361544d70581bcbb91bdb4969cbeaf3d4e13"
STABLE = {"CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE"}
STACK_SETTINGS = ("RoleARN", "EnableTerminationProtection", "DisableRollback", "NotificationARNs", "Tags", "TimeoutInMinutes", "Capabilities")
MAX_ZIP = 32 * 1024 * 1024
MAX_UNCOMPRESSED = 128 * 1024 * 1024
MAX_RECORD = 65536


class SnapshotError(ValueError):
    """Only fixed, non-sensitive reason codes cross the CLI boundary."""


def require(condition, code):
    if not condition:
        raise SnapshotError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def closed(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys), "snapshot_shape_invalid")


def hex_digest(value, length=64):
    require(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{" + str(length) + r"}", value), "digest_invalid")
    return value


def text_value(value, limit=2048):
    require(isinstance(value, str) and 0 < len(value) <= limit
            and re.fullmatch(r"[\x21-\x7e]+", value), "selector_invalid")
    return value


def private_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "private_json_invalid")
            result[key] = value
        return result
    try:
        require(isinstance(raw, (str, bytes)) and len(raw) <= MAX_RECORD, "private_json_invalid")
        return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise SnapshotError("private_json_invalid") from None


def validate_tooling(tooling):
    closed(tooling, {"sha", "workflowSha256"})
    hex_digest(tooling["sha"], 40)
    hex_digest(tooling["workflowSha256"])


def _template(value):
    if not isinstance(value, dict):
        import yaml
        value = yaml.safe_load(value)
    require(isinstance(value, dict) and isinstance(value.get("Resources"), dict), "template_invalid")
    return copy.deepcopy(value)


def _parameters(stack):
    result = {}
    require(isinstance(stack.get("Parameters"), list), "parameters_invalid")
    for item in stack["Parameters"]:
        key, value = item.get("ParameterKey"), item.get("ParameterValue")
        require(isinstance(key, str) and key not in result and isinstance(value, str)
                and value != "****" and not item.get("ResolvedValue"), "parameters_invalid")
        result[key] = value
    require(result.get("AuthRuntimeEnvironment") == "test", "test_environment_required")
    return result


def _code(resource):
    kind = resource.get("Type")
    require(kind in {"AWS::Serverless::Function", "AWS::Lambda::Function"}, "function_type_invalid")
    value = resource.get("Properties", {}).get("CodeUri" if kind == "AWS::Serverless::Function" else "Code")
    if isinstance(value, str):
        parsed = urlsplit(value)
        require(parsed.scheme == "s3" and parsed.netloc and parsed.path.startswith("/")
                and not parsed.query and not parsed.fragment and not parsed.username
                and not parsed.password and not parsed.port, "package_pointer_invalid")
        result = {"Bucket": parsed.netloc, "Key": parsed.path[1:]}
    else:
        require(isinstance(value, dict), "package_pointer_invalid")
        if kind == "AWS::Serverless::Function":
            require(set(value) in ({"Bucket", "Key"}, {"Bucket", "Key", "Version"}), "package_pointer_invalid")
            result = {"Bucket": value["Bucket"], "Key": value["Key"]}
            if "Version" in value: result["VersionId"] = value["Version"]
        else:
            require(set(value) in ({"S3Bucket", "S3Key"}, {"S3Bucket", "S3Key", "S3ObjectVersion"}), "package_pointer_invalid")
            result = {"Bucket": value["S3Bucket"], "Key": value["S3Key"]}
            if "S3ObjectVersion" in value: result["VersionId"] = value["S3ObjectVersion"]
    for item in result.values(): text_value(item)
    return result


def _function(config, account, physical):
    arn = config.get("FunctionArn")
    require(arn == f"arn:aws:lambda:{REGION}:{account}:function:{physical}", "function_identity_invalid")
    require(config.get("State") == "Active" and config.get("LastUpdateStatus") == "Successful"
            and config.get("Version") == "$LATEST", "lambda_runtime_not_ready")
    code = config.get("CodeSha256")
    try:
        require(isinstance(code, str) and len(base64.b64decode(code, validate=True)) == 32, "lambda_sha_invalid")
    except ValueError:
        raise SnapshotError("lambda_sha_invalid") from None
    revision = text_value(config.get("RevisionId"), 128)
    settings = {key: value for key, value in config.items() if key not in {
        "ResponseMetadata", "CodeSha256", "RevisionId", "LastModified", "State", "StateReason", "StateReasonCode",
        "LastUpdateStatus", "LastUpdateStatusReason", "LastUpdateStatusReasonCode", "CodeSize"}}
    return {"arn": arn, "codeSha256": code, "revisionId": revision, "settingsSha256": sha256(settings)}


def observe(session):
    """Read a projected private baseline, excluding volatile SDK metadata."""
    require(session.region_name == REGION, "region_invalid")
    account = session.client("sts").get_caller_identity().get("Account")
    require(isinstance(account, str) and sha256(account.encode()) == ACCOUNT_SHA256, "account_invalid")
    cfn = session.client("cloudformation")
    stacks = cfn.describe_stacks(StackName=STACK_NAME).get("Stacks")
    require(isinstance(stacks, list) and len(stacks) == 1, "stack_invalid")
    stack = stacks[0]
    stack_id = stack.get("StackId")
    require(stack.get("StackName") == STACK_NAME and isinstance(stack_id, str)
            and re.fullmatch(rf"arn:aws:cloudformation:{REGION}:{account}:stack/{STACK_NAME}/[A-Za-z0-9-]+", stack_id)
            and stack.get("StackStatus") in STABLE and stack.get("EnableTerminationProtection") is True,
            "stack_invalid")
    original = _template(cfn.get_template(StackName=stack_id, TemplateStage="Original")["TemplateBody"])
    processed = _template(cfn.get_template(StackName=stack_id, TemplateStage="Processed")["TemplateBody"])
    inventory = {}
    for page in cfn.get_paginator("list_stack_resources").paginate(StackName=stack_id):
        for item in page["StackResourceSummaries"]:
            logical = item.get("LogicalResourceId")
            require(isinstance(logical, str) and logical not in inventory
                    and item.get("ResourceStatus") in STABLE, "inventory_invalid")
            inventory[logical] = {"physicalId": text_value(item.get("PhysicalResourceId")),
                                  "type": text_value(item.get("ResourceType"))}
    require(all(name in inventory and inventory[name]["type"] == "AWS::Lambda::Function"
                and name in original["Resources"] and name in processed["Resources"] for name in FUNCTIONS),
            "function_inventory_invalid")
    functions = {}
    for name in FUNCTIONS:
        physical = inventory[name]["physicalId"]
        functions[name] = _function(session.client("lambda").get_function_configuration(FunctionName=physical), account, physical)
    return {"target": {"account": account, "region": REGION, "stackId": stack_id},
            "state": {key: stack.get(key) for key in ("StackStatus", *STACK_SETTINGS)},
            "original": original, "processed": processed, "parameters": _parameters(stack),
            "inventory": inventory, "functions": functions}


def baseline_hashes(baseline):
    return {name + "Sha256": sha256(baseline[name]) for name in ("original", "processed", "parameters", "inventory", "state")}


def baseline_digest(baseline):
    return sha256({"target": baseline["target"], "baseline": baseline_hashes(baseline), "functions": baseline["functions"]})


def zip_inventory(payload):
    """Hash safe file entries in memory; do not extract, rebuild, or execute them."""
    require(isinstance(payload, bytes) and 0 < len(payload) <= MAX_ZIP, "zip_size_invalid")
    result, seen, total = [], set(), 0
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            require(0 < len(archive.infolist()) <= 5000, "zip_inventory_invalid")
            for item in archive.infolist():
                name = item.filename
                require(item.orig_filename == name and re.fullmatch(r"[A-Za-z0-9_.@+/-]+", name)
                        and not name.startswith("/") and not any(part in {"", ".", ".."} for part in name.rstrip("/").split("/"))
                        and name.rstrip("/").casefold() not in seen, "zip_path_invalid")
                seen.add(name.rstrip("/").casefold())
                mode = stat.S_IFMT(item.external_attr >> 16)
                require(mode in {0, stat.S_IFREG, stat.S_IFDIR} and not (item.flag_bits & 1)
                        and item.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}, "zip_entry_invalid")
                if item.is_dir():
                    require(item.file_size == 0 and mode in {0, stat.S_IFDIR}, "zip_entry_invalid")
                    continue
                require(mode != stat.S_IFDIR, "zip_entry_invalid")
                total += item.file_size
                require(total <= MAX_UNCOMPRESSED, "zip_expansion_invalid")
                body = archive.read(item)
                require(len(body) == item.file_size, "zip_entry_invalid")
                result.append({"path": name, "sizeBytes": len(body), "sha256": sha256(body)})
    except (zipfile.BadZipFile, RuntimeError, OSError, NotImplementedError):
        raise SnapshotError("zip_invalid") from None
    require(result, "zip_inventory_invalid")
    return sorted(result, key=lambda row: row["path"])


def _approved_package(package):
    closed(package, {"bucket", "key", "versionId", "sizeBytes", "sha256", "inventorySha256", "fileCount"})
    request = {"Bucket": text_value(package["bucket"]), "Key": text_value(package["key"])}
    version = text_value(package["versionId"])
    require(version != "null" and sha256(version.encode()) == APPROVED_VERSION_SHA256
            and sha256(request) == APPROVED_SELECTOR_SHA256, "prior_package_selector_invalid")
    require(type(package["sizeBytes"]) is int and package["sizeBytes"] == APPROVED_ZIP_SIZE
            and package["sha256"] == APPROVED_ZIP_SHA256, "prior_package_identity_invalid")
    hex_digest(package["inventorySha256"])
    require(type(package["fileCount"]) is int and 0 < package["fileCount"] <= 5000, "zip_inventory_invalid")
    return {**request, "VersionId": version}


def _version_bytes(session, request, account, limit):
    require(request.get("VersionId") not in (None, "", "null"), "object_version_required")
    response = session.client("s3").get_object(**request, ExpectedBucketOwner=account)
    require(response.get("VersionId") == request["VersionId"]
            and type(response.get("ContentLength")) is int and 0 < response["ContentLength"] <= limit,
            "object_identity_invalid")
    stream = response["Body"]
    try:
        body = stream.read(limit + 1)
    finally:
        stream.close()
    require(len(body) == response["ContentLength"] and len(body) <= limit, "object_size_invalid")
    return body


def _verify_package(session, package, account):
    request = _approved_package(package)
    body = _version_bytes(session, request, account, MAX_ZIP)
    require(len(body) == package["sizeBytes"] and sha256(body) == package["sha256"], "prior_package_bytes_invalid")
    inventory = zip_inventory(body)
    require(sha256(inventory) == package["inventorySha256"] and len(inventory) == package["fileCount"], "zip_inventory_mismatch")


def capture(session, tooling):
    """Return a PRIVATE record only after two exact-version reads and live baselines."""
    validate_tooling(tooling)
    first = observe(session)
    pointers = [_code(first[stage]["Resources"][name]) for stage in ("original", "processed") for name in FUNCTIONS]
    require(all(value == pointers[0] for value in pointers), "shared_package_pointer_mismatch")
    pointer = pointers[0]
    request = {key: pointer[key] for key in ("Bucket", "Key")}
    require(sha256(request) == APPROVED_SELECTOR_SHA256, "prior_package_selector_invalid")
    version = pointer.get("VersionId")
    if not version:
        version = session.client("s3").head_object(**request, ExpectedBucketOwner=first["target"]["account"]).get("VersionId")
    require(isinstance(version, str) and sha256(version.encode()) == APPROVED_VERSION_SHA256, "prior_package_version_invalid")
    body = _version_bytes(session, {**request, "VersionId": version}, first["target"]["account"], MAX_ZIP)
    require(sha256(body) == APPROVED_ZIP_SHA256 and len(body) == APPROVED_ZIP_SIZE, "prior_package_bytes_invalid")
    inventory = zip_inventory(body)
    package = {"bucket": request["Bucket"], "key": request["Key"], "versionId": version,
               "sizeBytes": len(body), "sha256": sha256(body), "inventorySha256": sha256(inventory), "fileCount": len(inventory)}
    expected_code = base64.b64encode(bytes.fromhex(package["sha256"])).decode()
    require(all(row["codeSha256"] == expected_code for row in first["functions"].values()), "lambda_payload_mismatch")
    _verify_package(session, package, first["target"]["account"])
    second = observe(session)
    require(baseline_digest(first) == baseline_digest(second), "baseline_drift")
    return {"schema": SCHEMA, "service": SERVICE, "environment": "test", "sourceAttribution": "aws-observed",
            "tooling": dict(tooling), "target": first["target"], "baseline": baseline_hashes(first),
            "package": package, "functions": first["functions"]}


def validate_record(record, expected_sha256):
    hex_digest(expected_sha256)
    closed(record, {"schema", "service", "environment", "sourceAttribution", "tooling", "target", "baseline", "package", "functions"})
    require(sha256(record) == expected_sha256, "snapshot_digest_mismatch")
    require(record["schema"] == SCHEMA and record["service"] == SERVICE and record["environment"] == "test"
            and record["sourceAttribution"] == "aws-observed", "snapshot_provenance_invalid")
    validate_tooling(record["tooling"])
    closed(record["target"], {"account", "region", "stackId"})
    target = record["target"]
    require(isinstance(target["account"], str) and sha256(target["account"].encode()) == ACCOUNT_SHA256
            and target["region"] == REGION and isinstance(target["stackId"], str)
            and re.fullmatch(rf"arn:aws:cloudformation:{REGION}:{target['account']}:stack/{STACK_NAME}/[A-Za-z0-9-]+", target["stackId"]),
            "snapshot_target_invalid")
    closed(record["baseline"], {name + "Sha256" for name in ("original", "processed", "parameters", "inventory", "state")})
    for value in record["baseline"].values(): hex_digest(value)
    _approved_package(record["package"])
    closed(record["functions"], FUNCTIONS)
    code = base64.b64encode(bytes.fromhex(APPROVED_ZIP_SHA256)).decode()
    for row in record["functions"].values():
        closed(row, {"arn", "codeSha256", "revisionId", "settingsSha256"})
        require(isinstance(row["arn"], str) and row["arn"].startswith(f"arn:aws:lambda:{REGION}:{target['account']}:function:")
                and row["codeSha256"] == code, "snapshot_function_invalid")
        text_value(row["revisionId"], 128)
        hex_digest(row["settingsSha256"])


def summary(record):
    """Only this closed projection is safe for logs and public/local evidence."""
    validate_record(record, sha256(record))
    return {"schema": SCHEMA, "service": SERVICE, "sourceAttribution": "aws-observed",
            "snapshotSha256": sha256(record), "packageSha256": record["package"]["sha256"],
            "packageSizeBytes": record["package"]["sizeBytes"], "fileCount": record["package"]["fileCount"],
            "inventorySha256": record["package"]["inventorySha256"], "logicalFunctionCount": len(FUNCTIONS),
            "baselineHashes": record["baseline"]}


def _compose(template, package):
    result = copy.deepcopy(template)
    for name in FUNCTIONS:
        resource = result["Resources"][name]
        _code(resource)
        if resource["Type"] == "AWS::Serverless::Function":
            resource["Properties"]["CodeUri"] = {"Bucket": package["bucket"], "Key": package["key"], "Version": package["versionId"]}
        else:
            resource["Properties"]["Code"] = {"S3Bucket": package["bucket"], "S3Key": package["key"], "S3ObjectVersion": package["versionId"]}
    return result


def _review(description, baseline, name, arn):
    require(description.get("StackId") == baseline["target"]["stackId"] and not description.get("NextToken"), "change_set_identity_invalid")
    require(_parameters(description) == baseline["parameters"], "change_set_parameter_drift")
    try:
        decision = review_change_set(description, expected_stack_name=STACK_NAME, expected_change_set_name=name,
            expected_change_set_arn=arn, expected_change_set_type="UPDATE", expected_parameters=baseline["parameters"], required_parameters=set())
    except ChangeSetReviewError:
        raise SnapshotError("change_set_review_rejected") from None
    if decision == "noop": return decision
    seen = set()
    for change in description["Changes"]:
        item = change["ResourceChange"]
        logical = item.get("LogicalResourceId")
        require(logical in FUNCTIONS and logical not in seen and item.get("Action") == "Modify"
                and item.get("Replacement") == "False" and item.get("ResourceType") == "AWS::Lambda::Function"
                and item.get("PhysicalResourceId") == baseline["inventory"][logical]["physicalId"]
                and item.get("Scope") == ["Properties"], "code_only_change_required")
        seen.add(logical)
        require(isinstance(item.get("Details"), list) and item["Details"], "change_set_details_required")
        for detail in item["Details"]:
            target = detail.get("Target", {})
            require(target.get("Attribute") == "Properties" and target.get("Name") == "Code"
                    and target.get("RequiresRecreation") == "Never", "code_only_change_required")
    return decision


def recover(session, record, *, expected_snapshot_sha256, expected_baseline_sha256, tooling,
            execution_role, execute=False, operation="code-only"):
    """Plan or explicitly execute code-only recovery. No runtime-disable operation exists."""
    require(operation == "code-only", "code_only_operation_required")
    require(type(execute) is bool, "execution_selection_invalid")
    validate_tooling(tooling)
    validate_record(record, expected_snapshot_sha256)
    hex_digest(expected_baseline_sha256)
    first = observe(session)
    require(first["target"] == record["target"], "snapshot_target_mismatch")
    require(baseline_digest(first) == expected_baseline_sha256, "baseline_drift")
    require(all(first["functions"][name]["arn"] == record["functions"][name]["arn"] for name in FUNCTIONS), "function_identity_drift")
    _verify_package(session, record["package"], first["target"]["account"])
    template = _compose(first["original"], record["package"])
    processed = _compose(first["processed"], record["package"])
    parameters = [{"ParameterKey": key, "UsePreviousValue": True} for key in sorted(first["parameters"])]
    require(baseline_digest(observe(session)) == expected_baseline_sha256, "baseline_drift")
    _verify_package(session, record["package"], first["target"]["account"])
    if not execute:
        return {"status": "verified", "template": template, "parameters": parameters,
                "currentBaselineSha256": expected_baseline_sha256, "composedTemplateSha256": sha256(template)}
    account = first["target"]["account"]
    existing_role = first["state"]["RoleARN"]
    if existing_role:
        require(execution_role == f"arn:aws:iam::{account}:role/zoolanding-deployer-api-proxy-test-cfn-exec"
                and existing_role == execution_role, "existing_execution_role_required")
    # Omit RoleARN when the existing stack has none. An environment variable is
    # not permission to adopt a service role; existing IAM may reject this path.
    role_arguments = {"RoleARN": existing_role} if existing_role else {}
    capabilities = first["state"]["Capabilities"]
    capability_arguments = {"Capabilities": capabilities} if capabilities is not None else {}
    body = canonical(template)
    require(len(body) <= 51200, "private_template_transport_required")
    cfn = session.client("cloudformation")
    token = sha256({"snapshot": expected_snapshot_sha256, "baseline": expected_baseline_sha256, "tooling": tooling})
    name = "aws-recovery-" + token[:40]
    created = cfn.create_change_set(StackName=first["target"]["stackId"], ChangeSetName=name, ChangeSetType="UPDATE",
        ClientToken=token, Description="Explicit AWS-observed code-only TEST recovery", TemplateBody=body.decode(),
        Parameters=parameters, **capability_arguments, **role_arguments)
    arn = created.get("Id")
    require(created.get("StackId") == first["target"]["stackId"] and isinstance(arn, str)
            and re.fullmatch(rf"arn:aws:cloudformation:{REGION}:{account}:changeSet/{name}/[A-Za-z0-9-]+", arn), "change_set_identity_invalid")
    try:
        cfn.get_waiter("change_set_create_complete").wait(StackName=first["target"]["stackId"], ChangeSetName=arn)
    except Exception:
        # Only the owning review may recognize the exact AWS no-change status.
        pass
    description = cfn.describe_change_set(StackName=first["target"]["stackId"], ChangeSetName=arn, IncludePropertyValues=True)
    decision = _review(description, first, name, arn)
    require(_template(cfn.get_template(StackName=first["target"]["stackId"], ChangeSetName=arn, TemplateStage="Original")["TemplateBody"]) == template,
            "change_set_template_drift")
    require(_template(cfn.get_template(StackName=first["target"]["stackId"], ChangeSetName=arn, TemplateStage="Processed")["TemplateBody"]) == processed,
            "change_set_processed_drift")
    _verify_package(session, record["package"], account)
    current = observe(session)
    require(baseline_digest(current) == expected_baseline_sha256, "baseline_drift")
    if decision == "noop":
        require(all(current["functions"][name]["codeSha256"] == record["functions"][name]["codeSha256"]
                    for name in FUNCTIONS), "noop_target_not_live")
        return {"status": "noop", "executed": False, "snapshotSha256": expected_snapshot_sha256}
    cfn.execute_change_set(StackName=first["target"]["stackId"], ChangeSetName=arn, ClientRequestToken="execute-" + token)
    cfn.get_waiter("stack_update_complete").wait(StackName=first["target"]["stackId"])
    after = observe(session)
    require(after["target"] == first["target"] and after["original"] == template and after["processed"] == processed
            and after["parameters"] == first["parameters"] and after["inventory"] == first["inventory"]
            and all(after["state"][key] == first["state"][key] for key in STACK_SETTINGS), "post_recovery_baseline_invalid")
    for name in FUNCTIONS:
        require(after["functions"][name]["codeSha256"] == record["functions"][name]["codeSha256"]
                and after["functions"][name]["settingsSha256"] == first["functions"][name]["settingsSha256"], "post_recovery_function_invalid")
    # Same all-Lambda readiness contract as smoke_test_stack.sh, kept in memory.
    for row in after["inventory"].values():
        if row["type"] == "AWS::Lambda::Function":
            config = session.client("lambda").get_function_configuration(FunctionName=row["physicalId"])
            require(config.get("State") == "Active" and config.get("LastUpdateStatus") == "Successful", "lambda_runtime_not_ready")
    return {"status": "recovered", "snapshotSha256": expected_snapshot_sha256, "postDeploySmokePassed": True}


def load_private_snapshot(session, reference, expected_sha256, channel_bucket):
    """Read a version-pinned record only from the existing private TEST artifact channel."""
    closed(reference, {"bucket", "key", "versionId"})
    hex_digest(expected_sha256)
    for value in reference.values(): text_value(value)
    require(reference["bucket"] == channel_bucket and reference["key"].startswith(STACK_NAME + "/")
            and reference["versionId"] != "null", "private_channel_invalid")
    account = session.client("sts").get_caller_identity().get("Account")
    require(isinstance(account, str) and sha256(account.encode()) == ACCOUNT_SHA256 and session.region_name == REGION, "account_invalid")
    # This consumes an independently approved record in the existing private
    # channel; it does not publish one or introduce bucket-hardening permissions.
    request = {"Bucket": reference["bucket"], "Key": reference["key"], "VersionId": reference["versionId"]}
    body = _version_bytes(session, request, account, MAX_RECORD)
    require(sha256(body) == expected_sha256, "snapshot_digest_mismatch")
    record = private_json(body)
    validate_record(record, expected_sha256)
    require(_version_bytes(session, request, account, MAX_RECORD) == body, "snapshot_readback_drift")
    return record


def workflow_context(env, root):
    """Fail before credentials unless current reviewed tooling/workflow and inputs agree."""
    tooling = {"sha": env.get("TOOLING_SHA"), "workflowSha256": env.get("TOOLING_WORKFLOW_SHA256")}
    validate_tooling(tooling)
    require(env.get("GITHUB_REF") == "refs/heads/test" and env.get("GITHUB_SHA") == tooling["sha"]
            and env.get("RECOVERY_OPERATION") in {"verify", "execute"}, "workflow_context_invalid")
    for key in ("AWS_REGION", "AWS_DEFAULT_REGION"):
        require(env.get(key, REGION) == REGION, "region_invalid")
    for key in ("SNAPSHOT_SHA256", "CURRENT_BASELINE_SHA256"): hex_digest(env.get(key))
    workflow = root / ".github/workflows/recover-aws-test.yml"
    require(sha256(workflow.read_bytes().replace(b"\r\n", b"\n")) == tooling["workflowSha256"], "tooling_workflow_mismatch")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=15, check=False)
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=root,
                           capture_output=True, text=True, timeout=15, check=False)
    require(head.returncode == 0 and head.stdout.strip() == tooling["sha"] and dirty.returncode == 0
            and not dirty.stdout.strip(), "current_tooling_checkout_required")
    reference = private_json(env.get("AWS_LIVE_SNAPSHOT_REFERENCE_JSON", ""))
    closed(reference, {"bucket", "key", "versionId"})
    for value in reference.values(): text_value(value)
    require(reference["bucket"] == env.get("SAM_ARTIFACTS_BUCKET") and reference["key"].startswith(STACK_NAME + "/")
            and reference["versionId"] != "null", "private_channel_invalid")
    require(not env.get("THN_V2_TEST_PARAMETERS_JSON"), "code_only_operation_required")
    return tooling, reference


def main(argv=None):
    class SafeParser(argparse.ArgumentParser):
        def error(self, message):
            raise SnapshotError("arguments_invalid")
    try:
        parser = SafeParser(description="Explicit AWS-observed TEST recovery; sanitized output only.")
        parser.add_argument("--operation", choices=("verify", "execute"))
        parser.add_argument("--check-workflow", action="store_true")
        args = parser.parse_args(argv)
        root = Path(__file__).resolve().parents[1]
        tooling, reference = workflow_context(os.environ, root)
        if args.check_workflow:
            print("aws_live_snapshot_workflow_valid")
            return 0
        require(args.operation == os.environ["RECOVERY_OPERATION"], "execution_selection_invalid")
        import boto3
        session = boto3.Session(region_name=REGION)
        record = load_private_snapshot(session, reference, os.environ["SNAPSHOT_SHA256"], os.environ["SAM_ARTIFACTS_BUCKET"])
        result = recover(session, record, expected_snapshot_sha256=os.environ["SNAPSHOT_SHA256"],
                         expected_baseline_sha256=os.environ["CURRENT_BASELINE_SHA256"], tooling=tooling,
                         execution_role=os.environ.get("AWS_CLOUDFORMATION_ROLE_ARN", ""), execute=args.operation == "execute")
        safe = {key: result[key] for key in ("status", "snapshotSha256", "postDeploySmokePassed", "composedTemplateSha256") if key in result}
        print(json.dumps(safe, sort_keys=True))
        return 0
    except SnapshotError as exc:
        print(str(exc), file=sys.stderr)
    except Exception:
        # Provider messages, paths, JSON content, selectors and tracebacks stay private.
        print("aws_live_snapshot_failed", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
