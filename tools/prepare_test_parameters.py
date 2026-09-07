#!/usr/bin/env python3
"""Materialize fail-closed API Proxy TEST parameters."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
from typing import Mapping


class ParameterPreparationError(ValueError):
    pass


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ParameterPreparationError(f"{name.lower()}_required")
    return value


def build_parameters(env: Mapping[str, str]) -> tuple[dict[str, str], set[str]]:
    role_arns = _required(env, "AUTH_PROVISIONING_ALLOWED_ROLE_ARNS")
    for value in role_arns.split(","):
        if re.fullmatch(r"arn:(?:aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+", value.strip()) is None:
            raise ParameterPreparationError("auth_provisioning_allowed_role_arns_invalid")
    zeros = "0" * 64
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
        "EnableThnAuthRuntimeV2": "false",
        "ThnAuthRuntimeV2DescriptorVersionId": "BLOCKED",
        "ThnAuthRuntimeV2DescriptorSha256": zeros,
        "ThnAuthRuntimeV2AuthPolicyVersion": "BLOCKED",
        "ThnAuthRuntimeV2CognitoUserPoolId": "BLOCKED",
        "ThnAuthRuntimeV2CognitoClientId": "BLOCKED",
    }, set()


def write_parameter_files(output: Path, parameters: Mapping[str, str], sensitive: set[str]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    if any(not key or not isinstance(value, str) or "\n" in value or "\r" in value for key, value in parameters.items()):
        raise ParameterPreparationError("test_parameter_invalid")
    (output / "parameters.json").write_text(json.dumps([{"ParameterKey": key, "ParameterValue": value} for key, value in parameters.items()], separators=(",", ":")), encoding="utf-8")
    (output / "expected-parameters.txt").write_text("".join(f"{key}={parameters[key]}\n" for key in sorted(parameters) if key not in sensitive), encoding="utf-8")
    (output / "required-parameters.txt").write_text("".join(f"{key}\n" for key in sorted(sensitive) if parameters.get(key)), encoding="utf-8")


def main() -> int:
    parameters, sensitive = build_parameters(os.environ)
    write_parameter_files(Path(os.environ["RUNNER_TEMP"]) / "test-release-parameters", parameters, sensitive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

