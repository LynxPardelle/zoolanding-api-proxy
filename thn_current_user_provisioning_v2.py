"""Pure, dormant THN v2 current-user provisioning contract.

The future dedicated administrator flow can use these transformations to
prepare one initial current-user record or a compare-and-swap disable update.
This module deliberately performs no provider, persistence, or v1 handler
work; the caller remains responsible for the conditional write.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import re
from typing import Any


CONTRACT_VERSION = 1
THN_SCOPE = {
    "environment": "test",
    "domain": "thehairnarrative.com",
    "tenantId": "thehairnarrative-com",
    "hubId": "thehairnarrative-com-journal",
    "authProfileId": "journal-owner",
    "serviceBindingId": "thn-journal-test-v2",
}
ACCOUNT_PURPOSES = frozenset({"qa", "client-owner"})

_COMMON_FIELDS = frozenset(
    {"contractVersion", "scope", "subject", "accountPurpose"}
)
_PROVISION_FIELDS = _COMMON_FIELDS
_DISABLE_FIELDS = _COMMON_FIELDS | {"expectedSessionVersion"}
_CURRENT_USER_FIELDS = _COMMON_FIELDS | {"sessionVersion", "enabled"}
_SUBJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$")
_INVALID_MESSAGE = "current user provisioning request is invalid"


class CurrentUserProvisioningError(ValueError):
    """The server-owned provisioning command is invalid."""


def _fail() -> CurrentUserProvisioningError:
    return CurrentUserProvisioningError(_INVALID_MESSAGE)


def _require_exact_mapping(value: Any, fields: frozenset[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise _fail()
    return value


def _validate_scope(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != set(THN_SCOPE):
        raise _fail()
    if any(value.get(field) != expected for field, expected in THN_SCOPE.items()):
        raise _fail()
    return deepcopy(THN_SCOPE)


def _validate_subject(value: Any) -> str:
    if not isinstance(value, str) or not _SUBJECT_RE.fullmatch(value):
        raise _fail()
    return value


def _validate_account_purpose(value: Any) -> str:
    if value not in ACCOUNT_PURPOSES:
        raise _fail()
    return value


def _validate_contract_version(value: Any) -> int:
    if type(value) is not int or value != CONTRACT_VERSION:
        raise _fail()
    return value


def _validate_positive_version(value: Any) -> int:
    if type(value) is not int or value < 1:
        raise _fail()
    return value


def _validate_common(value: Any, fields: frozenset[str]) -> dict[str, Any]:
    record = _require_exact_mapping(value, fields)
    return {
        "contractVersion": _validate_contract_version(record.get("contractVersion")),
        "scope": _validate_scope(record.get("scope")),
        "subject": _validate_subject(record.get("subject")),
        "accountPurpose": _validate_account_purpose(record.get("accountPurpose")),
    }


def _validate_current_user(value: Any) -> dict[str, Any]:
    record = _require_exact_mapping(value, _CURRENT_USER_FIELDS)
    result = _validate_common(record, _CURRENT_USER_FIELDS)
    result["sessionVersion"] = _validate_positive_version(record.get("sessionVersion"))
    enabled = record.get("enabled")
    if type(enabled) is not bool:
        raise _fail()
    result["enabled"] = enabled
    return result


def provision_current_user(request: Any, *, existing_user: Any = None) -> dict[str, Any]:
    """Build the only valid initial state for a dedicated THN account.

    An existing record always fails closed, even if its purpose matches.  That
    prevents this entry point from becoming an account-purpose update surface.
    """

    try:
        if existing_user is not None:
            raise _fail()
        result = _validate_common(request, _PROVISION_FIELDS)
        result.update({"sessionVersion": 1, "enabled": False})
        return result
    except CurrentUserProvisioningError:
        raise _fail() from None
    except Exception:
        raise _fail() from None


def disable_current_user(request: Any, *, current_user: Any) -> dict[str, Any]:
    """Build a purpose-preserving disable update with monotonic session CAS."""

    try:
        command = _validate_common(request, _DISABLE_FIELDS)
        expected_version = _validate_positive_version(
            request.get("expectedSessionVersion")
        )
        current = _validate_current_user(current_user)
        if any(command[field] != current[field] for field in _COMMON_FIELDS):
            raise _fail()
        if expected_version != current["sessionVersion"]:
            raise _fail()
        current["sessionVersion"] += 1
        current["enabled"] = False
        return current
    except CurrentUserProvisioningError:
        raise _fail() from None
    except Exception:
        raise _fail() from None
