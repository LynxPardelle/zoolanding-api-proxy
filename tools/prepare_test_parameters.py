#!/usr/bin/env python3
"""Materialize fail-closed API Proxy TEST parameters."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Mapping


class ParameterPreparationError(ValueError):
    pass


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ParameterPreparationError(f"{name.lower()}_required")
    return value



def _thn_defaults() -> dict[str, str]:
    return {
        "EnableThnAuthRuntimeV2": "false",
        "ThnAuthRuntimeV2DescriptorVersionId": "BLOCKED",
        "ThnAuthRuntimeV2DescriptorSha256": "0" * 64,
        "ThnAuthRuntimeV2AuthPolicyVersion": "BLOCKED",
        "ThnAuthRuntimeV2CognitoUserPoolId": "BLOCKED",
        "ThnAuthRuntimeV2CognitoClientId": "BLOCKED",
    }


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ParameterPreparationError("thn_test_selection_invalid")
        result[key] = value
    return result


def _deployment_account(env: Mapping[str, str]) -> str:
    match = re.fullmatch(
        r"arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+",
        env.get("AWS_ROLE_ARN", ""),
    )
    if match is None:
        raise ParameterPreparationError("thn_test_deployment_role_invalid")
    return match.group(1)


def _thn_parameters(env: Mapping[str, str]) -> dict[str, str]:
    """Only a complete TEST selection may override the six THN-only fields."""
    raw = env.get("THN_V2_TEST_PARAMETERS_JSON", "")
    if raw == "":
        return _thn_defaults()
    try:
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > 16384:
            raise ValueError()
        envelope = json.loads(raw, object_pairs_hook=_unique_object)
        if (not isinstance(envelope, dict)
                or set(envelope) != {"schemaVersion", "environment", "parameters"}
                or type(envelope["schemaVersion"]) is not int
                or envelope["schemaVersion"] != 1 or envelope["environment"] != "test"):
            raise ValueError()
        values = envelope["parameters"]
        if not isinstance(values, dict) or set(values) != set(_thn_defaults()):
            raise ValueError()
        if any(not isinstance(value, str) or len(value) > 256
               or re.fullmatch(r"[\x20-\x7e]*", value) is None for value in values.values()):
            raise ValueError()
        if values["EnableThnAuthRuntimeV2"] not in {"false", "true"}:
            raise ValueError()
        for key in ("ThnAuthRuntimeV2DescriptorVersionId", "ThnAuthRuntimeV2AuthPolicyVersion"):
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", values[key]) is None:
                raise ValueError()
        if re.fullmatch(r"[a-f0-9]{64}", values["ThnAuthRuntimeV2DescriptorSha256"]) is None:
            raise ValueError()
        if re.fullmatch(r"BLOCKED|us-east-1_[A-Za-z0-9]+", values["ThnAuthRuntimeV2CognitoUserPoolId"]) is None:
            raise ValueError()
        if re.fullmatch(r"BLOCKED|[a-z0-9]{1,128}", values["ThnAuthRuntimeV2CognitoClientId"]) is None:
            raise ValueError()
        if values["EnableThnAuthRuntimeV2"] == "true" and any(value in {"BLOCKED", "0" * 64} for value in values.values()):
            raise ValueError()
        _deployment_account(env)
        return dict(values)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ParameterPreparationError("thn_test_selection_invalid") from None



def _aws_cli_read(service: str, operation: str, query: str, *arguments: str, runner):
    """Read only projected fields; neither provider output nor errors are logged."""
    result = runner(
        ["aws", service, operation, *arguments, "--query", query,
         "--region", "us-east-1", "--output", "json", "--no-cli-pager"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode or len(result.stdout.encode("utf-8")) > 16384:
        raise ValueError()
    return json.loads(result.stdout)


def verify_cloud_guards(env: Mapping[str, str], *, runner=None) -> None:
    """Verify exact TEST dependencies without changing AWS or creating files."""
    values = _thn_parameters(env)
    if not env.get("THN_V2_TEST_PARAMETERS_JSON"):
        return
    if any(env.get(key, "us-east-1") != "us-east-1" for key in ("AWS_REGION", "AWS_DEFAULT_REGION")):
        raise ParameterPreparationError("thn_test_region_invalid")
    expected_account = _deployment_account(env)
    runner = subprocess.run if runner is None else runner
    stable = {"CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE"}
    try:
        identity = _aws_cli_read("sts", "get-caller-identity", "{Account:Account}", runner=runner)
        if identity.get("Account") != expected_account:
            raise ValueError()
        if values["EnableThnAuthRuntimeV2"] == "true":
            stacks = _aws_cli_read(
                "cloudformation", "describe-stacks",
                "Stacks[].[StackName,StackStatus,EnableTerminationProtection]",
                "--stack-name", "zoolanding-auth-admin-test", runner=runner,
            )
            if (not isinstance(stacks, list) or len(stacks) != 1
                    or not isinstance(stacks[0], list) or len(stacks[0]) != 3
                    or stacks[0][0] != "zoolanding-auth-admin-test"
                    or stacks[0][1] not in stable or stacks[0][2] is not True):
                raise ValueError()
            resources = _aws_cli_read(
                "cloudformation", "list-stack-resources",
                "StackResourceSummaries[?LogicalResourceId=='ThnAuthAdminV2UserPool' || LogicalResourceId=='ThnAuthAdminV2UserPoolClient'].{logicalId:LogicalResourceId,id:PhysicalResourceId,type:ResourceType,status:ResourceStatus}",
                "--stack-name", "zoolanding-auth-admin-test", runner=runner,
            )
            expected = {
                "ThnAuthAdminV2UserPool": ("AWS::Cognito::UserPool", values["ThnAuthRuntimeV2CognitoUserPoolId"]),
                "ThnAuthAdminV2UserPoolClient": ("AWS::Cognito::UserPoolClient", values["ThnAuthRuntimeV2CognitoClientId"]),
            }
            if not isinstance(resources, list) or len(resources) != 2:
                raise ValueError()
            for resource in resources:
                logical_id = resource["logicalId"]
                if (logical_id not in expected or resource["status"] not in stable
                        or (resource["type"], resource["id"]) != expected.pop(logical_id)):
                    raise ValueError()
            if expected:
                raise ValueError()
            registry = _aws_cli_read(
                "cloudformation", "describe-stack-resource",
                "StackResourceDetail.[ResourceType,PhysicalResourceId,ResourceStatus]",
                "--stack-name", "zoolanding-content-hub-test",
                "--logical-resource-id", "ServiceBindingRegistryV2Table", runner=runner,
            )
            if (not isinstance(registry, list) or len(registry) != 3
                    or registry[:2] != ["AWS::DynamoDB::Table", "zoolanding-content-hub-test-ServiceBindingRegistryV2"]
                    or registry[2] not in stable):
                raise ValueError()
    except Exception:
        raise ParameterPreparationError("thn_test_cloud_guard_failed") from None


def build_parameters(env: Mapping[str, str]) -> tuple[dict[str, str], set[str]]:
    role_arns = _required(env, "AUTH_PROVISIONING_ALLOWED_ROLE_ARNS")
    for value in role_arns.split(","):
        if re.fullmatch(r"arn:(?:aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+", value.strip()) is None:
            raise ParameterPreparationError("auth_provisioning_allowed_role_arns_invalid")
    return {
        "ConfigTableName": env.get("CONFIG_TABLE_NAME", "zoolanding-config-registry"),
        "ConfigPayloadsBucketName": env.get("CONFIG_PAYLOADS_BUCKET_NAME", "zoolanding-config-payloads"),
        "ApiStageName": "Prod",
        "AuthRuntimeEnvironment": "test",
        "AllowedCorsOrigins": "https://test.zoolandingpage.com.mx",
        "SecretNamePrefix": "zoolanding/api/",
        "AuthRegistryFileName": "auth-profile-registry.json",
        "AuthProvisioningAllowedRoleNames": env.get("AUTH_PROVISIONING_ALLOWED_ROLE_NAMES", ""),
        "AuthProvisioningAllowedRoleArns": role_arns,
        "AuthProvisioningStateTableName": env.get("AUTH_PROVISIONING_STATE_TABLE_NAME", "zoolanding-auth-provisioning-state"),
        "AuthProvisioningStateTableMode": "existing",
        "AuthProvisioningApplyEnabled": "false",
        "AuthProvisioningApplyAllowedDomains": env.get("AUTH_PROVISIONING_APPLY_ALLOWED_DOMAINS", "zoositioweb.com.mx"),
        "AuthProvisioningApplyAllowedTenants": env.get("AUTH_PROVISIONING_APPLY_ALLOWED_TENANTS", "zoosite"),
        "AuthProvisioningSecretParameterPrefix": "zoolanding/auth/",
        "AuthProvisioningSecretNamePrefix": "/zoolanding/auth/",
        "LogLevel": "INFO",
        **_thn_parameters(env),
    }, set()


def write_parameter_files(output: Path, parameters: Mapping[str, str], sensitive: set[str]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    if any(not key or not isinstance(value, str) or "\n" in value or "\r" in value for key, value in parameters.items()):
        raise ParameterPreparationError("test_parameter_invalid")
    (output / "parameters.json").write_text(json.dumps([{"ParameterKey": key, "ParameterValue": value} for key, value in parameters.items()], separators=(",", ":")), encoding="utf-8")
    (output / "expected-parameters.txt").write_text("".join(f"{key}={parameters[key]}\n" for key in sorted(parameters) if key not in sensitive), encoding="utf-8")
    (output / "required-parameters.txt").write_text("".join(f"{key}\n" for key in sorted(sensitive) if parameters.get(key)), encoding="utf-8")


def main() -> int:
    if sys.argv[1:] == ["--thn-selection-contract"]:
        print("thn-test-selection/v1")
        return 0
    if sys.argv[1:] == ["--verify-cloud-guards"]:
        verify_cloud_guards(os.environ)
        return 0
    if sys.argv[1:]:
        raise ParameterPreparationError("test_parameter_arguments_invalid")
    parameters, sensitive = build_parameters(os.environ)
    write_parameter_files(Path(os.environ["RUNNER_TEMP"]) / "test-release-parameters", parameters, sensitive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
