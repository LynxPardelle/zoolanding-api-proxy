"""Fail-closed read-only consumer for the authoritative THN v2 binding.

The Content Hub stack owns the registry record.  This module performs one
strongly consistent ``GetItem`` against its exact key and never persists a
local copy or activation switch.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import os
import re
from typing import Any


APPROVED_TABLE_NAME = "zoolanding-content-hub-test-ServiceBindingRegistryV2"
APPROVED_PARTITIONS = frozenset({"aws", "aws-us-gov", "aws-cn"})
APPROVED_ENVIRONMENT = "test"
APPROVED_DOMAIN = "thehairnarrative.com"
APPROVED_SERVICE_BINDING_ID = "thn-journal-test-v2"
APPROVED_HUB_ID = "thehairnarrative-com-journal"
APPROVED_TENANT_ID = "thehairnarrative-com"
APPROVED_AUTH_PROFILE_ID = "journal-owner"
APPROVED_ADMIN_ORIGIN = "https://admin-test.thehairnarrative.com"
APPROVED_COOKIE_NAMESPACE = "endefiz7dkk635k6di6k"
RECORD_SORT_KEY = "REGISTRY#V2"
RECORD_TYPE = "service-binding-registry-v2"
SCHEMA_VERSION = 2
ALLOWED_WRITER_MODES = frozenset({"disabled", "qa-only", "client-owner"})

BINDING_PARTITION_KEY = (
    f"SERVICE_BINDING#{APPROVED_ENVIRONMENT}#{APPROVED_SERVICE_BINDING_ID}"
)
EXPECTED_DESCRIPTOR_FIELDS = frozenset(
    {"descriptorVersionId", "descriptorSha256", "authPolicyVersion"}
)
BINDING_DESCRIPTOR = {
    "bindingId": "journal-v2",
    "domain": APPROVED_DOMAIN,
    "environment": APPROVED_ENVIRONMENT,
    "authProfileId": APPROVED_AUTH_PROFILE_ID,
    "featureId": "journal",
    "hubId": APPROVED_HUB_ID,
    "serviceBindingId": APPROVED_SERVICE_BINDING_ID,
    "authBasePath": "/auth-v2",
    "contentHubBasePath": "/features/content-hub-v2",
    "status": "active",
}
TRUSTED_SCOPE_FIELDS = frozenset({"partition", "accountId", "region"})
RECORD_FIELDS = frozenset(
    {
        "pk",
        "sk",
        "recordType",
        "schemaVersion",
        "environment",
        "domain",
        "serviceBindingId",
        "descriptorVersionId",
        "descriptorSha256",
        "registryRevision",
        "activationStatus",
        "writerMode",
        "writerEpoch",
        "hubId",
        "tenantId",
        "cookieNamespace",
        "authProfileId",
        "authPolicyVersion",
        "adminOrigin",
        "resourceBindings",
        "reservationOwner",
    }
)
RESOURCE_BINDING_RESOURCES = {
    "authoringFunctionArn": (
        "lambda",
        "function:zoolanding-content-hub-test-ThnContentHubV2Authoring",
    ),
    "metadataTableArn": (
        "dynamodb",
        "table/zoolanding-content-hub-test-ThnContentHubV2Metadata",
    ),
}

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_ACCOUNT_ID_RE = re.compile(r"^[0-9]{12}$")
_REGION_RE = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z0-9-]+-[0-9]+$")
_INTEGER_RE = re.compile(r"^-?(?:0|[1-9][0-9]*)$")
_UNAVAILABLE_MESSAGE = "service binding is unavailable"


class RegistryConsumerError(RuntimeError):
    """The authoritative service binding cannot be safely consumed."""


def _fail() -> RegistryConsumerError:
    return RegistryConsumerError(_UNAVAILABLE_MESSAGE)


def _require_positive_integer(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise _fail()
    return value


def _require_safe_id(value: Any) -> str:
    if not isinstance(value, str) or not _SAFE_ID_RE.fullmatch(value):
        raise _fail()
    return value


def _validate_expected_descriptor(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != EXPECTED_DESCRIPTOR_FIELDS:
        raise _fail()
    version_id = _require_safe_id(value.get("descriptorVersionId"))
    digest = value.get("descriptorSha256")
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        raise _fail()
    auth_policy_version = _require_safe_id(value.get("authPolicyVersion"))
    return {
        "descriptorVersionId": version_id,
        "descriptorSha256": digest,
        "authPolicyVersion": auth_policy_version,
    }


def validate_active_binding_descriptor(value: Any) -> dict[str, str]:
    """Validate the complete immutable server-only THN feature binding."""

    try:
        if not isinstance(value, Mapping) or set(value) != set(BINDING_DESCRIPTOR):
            raise _fail()
        if any(value.get(field) != expected for field, expected in BINDING_DESCRIPTOR.items()):
            raise _fail()
        return deepcopy(BINDING_DESCRIPTOR)
    except RegistryConsumerError:
        raise _fail() from None


def _validate_trusted_scope(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != TRUSTED_SCOPE_FIELDS:
        raise _fail()
    partition = value.get("partition")
    account_id = value.get("accountId")
    region = value.get("region")
    if partition not in APPROVED_PARTITIONS:
        raise _fail()
    if not isinstance(account_id, str) or not _ACCOUNT_ID_RE.fullmatch(account_id):
        raise _fail()
    if not isinstance(region, str) or not _REGION_RE.fullmatch(region):
        raise _fail()
    return {"partition": partition, "accountId": account_id, "region": region}


def _decode_attribute(value: Any) -> Any:
    """Decode the small AttributeValue subset allowed by the registry schema."""

    if not isinstance(value, Mapping) or len(value) != 1:
        raise _fail()
    attribute_type, encoded = next(iter(value.items()))
    if attribute_type == "S":
        if not isinstance(encoded, str):
            raise _fail()
        return encoded
    if attribute_type == "N":
        if not isinstance(encoded, str) or not _INTEGER_RE.fullmatch(encoded):
            raise _fail()
        return int(encoded)
    if attribute_type == "M":
        if not isinstance(encoded, Mapping) or any(not isinstance(key, str) for key in encoded):
            raise _fail()
        return {key: _decode_attribute(item) for key, item in encoded.items()}
    raise _fail()


def _decode_item(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise _fail()
    return {key: _decode_attribute(item) for key, item in value.items()}


def _expected_owner() -> dict[str, str]:
    return {
        "environment": APPROVED_ENVIRONMENT,
        "domain": APPROVED_DOMAIN,
        "serviceBindingId": APPROVED_SERVICE_BINDING_ID,
        "hubId": APPROVED_HUB_ID,
        "tenantId": APPROVED_TENANT_ID,
        "authProfileId": APPROVED_AUTH_PROFILE_ID,
    }


def _expected_resource_bindings(trusted_scope: Mapping[str, str]) -> dict[str, str]:
    prefix = (
        f"arn:{trusted_scope['partition']}:{{service}}:{trusted_scope['region']}:"
        f"{trusted_scope['accountId']}:{{resource}}"
    )
    return {
        name: prefix.format(service=service, resource=resource)
        for name, (service, resource) in RESOURCE_BINDING_RESOURCES.items()
    }


def _validate_record(
    record: Any,
    *,
    expected_descriptor: Mapping[str, str],
    expected_registry_revision: int,
    trusted_scope: Mapping[str, str],
) -> dict[str, Any]:
    if not isinstance(record, Mapping) or set(record) != RECORD_FIELDS:
        raise _fail()
    fixed_coordinates = {
        "pk": BINDING_PARTITION_KEY,
        "sk": RECORD_SORT_KEY,
        "recordType": RECORD_TYPE,
        "schemaVersion": SCHEMA_VERSION,
        "environment": APPROVED_ENVIRONMENT,
        "domain": APPROVED_DOMAIN,
        "serviceBindingId": APPROVED_SERVICE_BINDING_ID,
        "hubId": APPROVED_HUB_ID,
        "tenantId": APPROVED_TENANT_ID,
        "cookieNamespace": APPROVED_COOKIE_NAMESPACE,
        "authProfileId": APPROVED_AUTH_PROFILE_ID,
        "adminOrigin": APPROVED_ADMIN_ORIGIN,
    }
    if any(record.get(field) != value for field, value in fixed_coordinates.items()):
        raise _fail()
    if any(record.get(field) != value for field, value in expected_descriptor.items()):
        raise _fail()
    if record.get("registryRevision") != expected_registry_revision:
        raise _fail()
    if record.get("activationStatus") != "active":
        raise _fail()
    if record.get("writerMode") not in ALLOWED_WRITER_MODES:
        raise _fail()
    _require_positive_integer(record.get("writerEpoch"))
    _require_positive_integer(record.get("registryRevision"))
    _require_safe_id(record.get("descriptorVersionId"))
    _require_safe_id(record.get("authPolicyVersion"))
    digest = record.get("descriptorSha256")
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        raise _fail()
    if record.get("reservationOwner") != _expected_owner():
        raise _fail()
    if record.get("resourceBindings") != _expected_resource_bindings(trusted_scope):
        raise _fail()
    return deepcopy(dict(record))


def load_active_service_binding(
    client,
    *,
    expected_descriptor,
    expected_registry_revision,
    trusted_resource_scope,
):
    """Strongly read and validate the one approved THN v2 binding.

    All validation and provider failures intentionally collapse to one public
    error.  Callers therefore cannot distinguish missing records from policy,
    ownership, descriptor, revision, or storage failures.
    """

    try:
        descriptor = _validate_expected_descriptor(expected_descriptor)
        registry_revision = _require_positive_integer(expected_registry_revision)
        trusted_scope = _validate_trusted_scope(trusted_resource_scope)
        configured_table = os.getenv(
            "SERVICE_BINDING_REGISTRY_V2_TABLE_NAME",
            APPROVED_TABLE_NAME,
        )
        if configured_table != APPROVED_TABLE_NAME:
            raise _fail()
        if not callable(getattr(client, "get_item", None)):
            raise _fail()
        response = client.get_item(
            TableName=APPROVED_TABLE_NAME,
            Key={
                "pk": {"S": BINDING_PARTITION_KEY},
                "sk": {"S": RECORD_SORT_KEY},
            },
            ConsistentRead=True,
        )
        if not isinstance(response, Mapping) or any(
            field in response
            for field in ("Items", "Count", "ScannedCount", "LastEvaluatedKey")
        ):
            raise _fail()
        item = response.get("Item")
        if not item:
            raise _fail()
        record = _decode_item(item)
        return _validate_record(
            record,
            expected_descriptor=descriptor,
            expected_registry_revision=registry_revision,
            trusted_scope=trusted_scope,
        )
    except RegistryConsumerError:
        raise _fail() from None
    except Exception:
        raise _fail() from None

