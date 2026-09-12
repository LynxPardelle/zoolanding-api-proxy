"""Dedicated TEST-only runtime auth discovery for The Hair Narrative.

This handler is intentionally isolated from the shared v1 API Proxy handler.
It exposes only browser-safe routing metadata after a strongly consistent read
of the one Content-Hub-owned service-binding registry record.
"""

from __future__ import annotations

import base64
import json
import os
import re
from typing import Any, Mapping

from service_binding_registry_consumer_v2 import (
    APPROVED_ADMIN_ORIGIN,
    APPROVED_AUTH_PROFILE_ID,
    APPROVED_COOKIE_NAMESPACE,
    APPROVED_DOMAIN,
    APPROVED_ENVIRONMENT,
    APPROVED_HUB_ID,
    APPROVED_SERVICE_BINDING_ID,
    RegistryConsumerError,
    load_active_service_binding,
)


ADMIN_ORIGIN = APPROVED_ADMIN_ORIGIN
ADMIN_HOST = "admin-test.thehairnarrative.com"
RUNTIME_PATH = "/auth-v2/runtime-config"
ALLOWED_METHODS = frozenset({"GET", "POST"})
REQUEST_FIELDS = frozenset({"domain", "authProfileId"})
MAX_BODY_BYTES = 4096
APPROVED_REGION = "us-east-1"
APPROVED_PARTITION = "aws"
APPROVED_URL_SUFFIX = "amazonaws.com"

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_ACCOUNT_ID_RE = re.compile(r"^[0-9]{12}$")
_USER_POOL_ID_RE = re.compile(r"^us-east-1_[A-Za-z0-9]+$")
_CLIENT_ID_RE = re.compile(r"^[a-z0-9]{1,128}$")
_DYNAMODB_CLIENT = None


class RuntimeV2Error(RuntimeError):
    status_code = 400
    public_error = "Invalid request"
    error_code = "invalid_request"
    allow_origin = True


class RuntimeV2OriginDenied(RuntimeV2Error):
    status_code = 403
    public_error = "Request origin denied"
    error_code = "origin_denied"
    allow_origin = False


class RuntimeV2NotFound(RuntimeV2Error):
    status_code = 404
    public_error = "Not found"
    error_code = "not_found"
    allow_origin = False


class RuntimeV2MethodDenied(RuntimeV2Error):
    status_code = 405
    public_error = "Method not allowed"
    error_code = "method_not_allowed"
    allow_origin = False


class RuntimeV2Unavailable(RuntimeV2Error):
    status_code = 503
    public_error = "Authentication temporarily unavailable"
    error_code = "auth_unavailable"


def lambda_handler(event: Any, context: Any) -> dict[str, Any]:
    """Return the one safe THN v2 auth profile or fail closed."""

    del context
    try:
        if not isinstance(event, Mapping):
            raise RuntimeV2Error()
        _require_admin_origin(event)
        method, payload = _request_contract(event)
        del method
        _require_fixed_request_coordinates(payload)
        runtime_environment = _runtime_environment()
        binding = load_active_service_binding(
            _dynamodb_client(),
            expected_descriptor=runtime_environment["descriptor"],
            trusted_resource_scope=runtime_environment["trustedScope"],
        )
        cookie_namespace = _binding_cookie_namespace(binding)
        auth = _public_auth_payload(runtime_environment, cookie_namespace)
        return _json_response(
            200,
            {"ok": True, "domain": APPROVED_DOMAIN, "auth": auth},
            allow_origin=True,
        )
    except RuntimeV2Error as exc:
        return _json_response(
            exc.status_code,
            {"ok": False, "error": exc.public_error, "errorCode": exc.error_code},
            allow_origin=exc.allow_origin,
        )
    except RegistryConsumerError:
        return _unavailable_response()
    except Exception:
        return _unavailable_response()


def _unavailable_response() -> dict[str, Any]:
    return _json_response(
        503,
        {
            "ok": False,
            "error": RuntimeV2Unavailable.public_error,
            "errorCode": RuntimeV2Unavailable.error_code,
        },
        allow_origin=True,
    )


def _headers(event: Mapping[str, Any]) -> dict[str, str]:
    value = event.get("headers")
    if not isinstance(value, Mapping):
        return {}
    return {
        str(key).strip().lower(): str(item).strip()
        for key, item in value.items()
        if item is not None
    }


def _require_admin_origin(event: Mapping[str, Any]) -> None:
    headers = _headers(event)
    if headers.get("origin") != ADMIN_ORIGIN:
        raise RuntimeV2OriginDenied()
    if headers.get("x-forwarded-host", "").lower() != ADMIN_HOST:
        raise RuntimeV2OriginDenied()


def _request_method(event: Mapping[str, Any]) -> str:
    direct = str(event.get("httpMethod") or "").strip().upper()
    context = event.get("requestContext")
    context_method = ""
    if isinstance(context, Mapping) and isinstance(context.get("http"), Mapping):
        context_method = str(context["http"].get("method") or "").strip().upper()
    if direct and context_method and direct != context_method:
        raise RuntimeV2Error()
    return direct or context_method


def _request_path(event: Mapping[str, Any]) -> str:
    path = str(event.get("rawPath") or event.get("path") or "").strip()
    if path != RUNTIME_PATH:
        raise RuntimeV2NotFound()
    return path


def _request_contract(event: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    _request_path(event)
    method = _request_method(event)
    if method not in ALLOWED_METHODS:
        raise RuntimeV2MethodDenied()
    if method == "GET":
        if event.get("body") not in (None, ""):
            raise RuntimeV2Error()
        query = event.get("queryStringParameters")
        if not isinstance(query, Mapping):
            raise RuntimeV2Error()
        payload = dict(query)
    else:
        query = event.get("queryStringParameters")
        if query not in (None, {}):
            raise RuntimeV2Error()
        payload = _json_body(event)
    if set(payload) != REQUEST_FIELDS:
        raise RuntimeV2Error()
    return method, payload


def _json_body(event: Mapping[str, Any]) -> dict[str, Any]:
    body = event.get("body")
    if not isinstance(body, str) or not body:
        raise RuntimeV2Error()
    try:
        encoded = body.encode("utf-8")
        if len(encoded) > MAX_BODY_BYTES:
            raise RuntimeV2Error()
        if event.get("isBase64Encoded") is True:
            encoded = base64.b64decode(encoded, validate=True)
            if len(encoded) > MAX_BODY_BYTES:
                raise RuntimeV2Error()
        value = json.loads(encoded.decode("utf-8"))
    except RuntimeV2Error:
        raise
    except Exception as exc:
        raise RuntimeV2Error() from exc
    if not isinstance(value, dict):
        raise RuntimeV2Error()
    return value


def _require_fixed_request_coordinates(payload: Mapping[str, Any]) -> None:
    if payload.get("domain") != APPROVED_DOMAIN:
        raise RuntimeV2Error()
    if payload.get("authProfileId") != APPROVED_AUTH_PROFILE_ID:
        raise RuntimeV2Error()


def _required_env(name: str) -> str:
    value = str(os.getenv(name) or "").strip()
    if not value or value == "BLOCKED":
        raise RuntimeV2Unavailable()
    return value


def _runtime_environment() -> dict[str, Any]:
    descriptor_version = _required_env("THN_AUTH_RUNTIME_V2_DESCRIPTOR_VERSION_ID")
    descriptor_sha256 = _required_env("THN_AUTH_RUNTIME_V2_DESCRIPTOR_SHA256")
    auth_policy_version = _required_env("THN_AUTH_RUNTIME_V2_AUTH_POLICY_VERSION")
    partition = _required_env("THN_AUTH_RUNTIME_V2_AWS_PARTITION")
    account_id = _required_env("THN_AUTH_RUNTIME_V2_AWS_ACCOUNT_ID")
    region = _required_env("THN_AUTH_RUNTIME_V2_AWS_REGION")
    url_suffix = _required_env("THN_AUTH_RUNTIME_V2_AWS_URL_SUFFIX")
    user_pool_id = _required_env("THN_AUTH_RUNTIME_V2_COGNITO_USER_POOL_ID")
    client_id = _required_env("THN_AUTH_RUNTIME_V2_COGNITO_CLIENT_ID")
    if (
        not _SAFE_ID_RE.fullmatch(descriptor_version)
        or not _SHA256_RE.fullmatch(descriptor_sha256)
        or not _SAFE_ID_RE.fullmatch(auth_policy_version)
        or partition != APPROVED_PARTITION
        or not _ACCOUNT_ID_RE.fullmatch(account_id)
        or region != APPROVED_REGION
        or url_suffix != APPROVED_URL_SUFFIX
        or not _USER_POOL_ID_RE.fullmatch(user_pool_id)
        or not _CLIENT_ID_RE.fullmatch(client_id)
    ):
        raise RuntimeV2Unavailable()
    return {
        "descriptor": {
            "descriptorVersionId": descriptor_version,
            "descriptorSha256": descriptor_sha256,
            "authPolicyVersion": auth_policy_version,
        },
        "trustedScope": {
            "partition": partition,
            "accountId": account_id,
            "region": region,
        },
        "region": region,
        "urlSuffix": url_suffix,
        "userPoolId": user_pool_id,
        "clientId": client_id,
    }


def _binding_cookie_namespace(binding: Any) -> str:
    if not isinstance(binding, Mapping):
        raise RuntimeV2Unavailable()
    required = {
        "environment": APPROVED_ENVIRONMENT,
        "domain": APPROVED_DOMAIN,
        "serviceBindingId": APPROVED_SERVICE_BINDING_ID,
        "hubId": APPROVED_HUB_ID,
        "authProfileId": APPROVED_AUTH_PROFILE_ID,
        "adminOrigin": ADMIN_ORIGIN,
        "activationStatus": "active",
        "cookieNamespace": APPROVED_COOKIE_NAMESPACE,
    }
    if any(binding.get(key) != expected for key, expected in required.items()):
        raise RuntimeV2Unavailable()
    return str(binding["cookieNamespace"])


def _public_auth_payload(runtime: Mapping[str, Any], cookie_namespace: str) -> dict[str, Any]:
    region = str(runtime["region"])
    url_suffix = str(runtime["urlSuffix"])
    user_pool_id = str(runtime["userPoolId"])
    return {
        "enabled": True,
        "authProfileId": APPROVED_AUTH_PROFILE_ID,
        "provider": "cognito",
        "issuer": f"https://cognito-idp.{region}.{url_suffix}/{user_pool_id}",
        "userPoolId": user_pool_id,
        "clientId": str(runtime["clientId"]),
        "hostedUiDomain": ADMIN_ORIGIN,
        "scopes": ["openid", "email", "profile"],
        "redirectPath": "/admin/journal",
        "logoutPath": "/admin/journal/access",
        "loginPath": "/admin/journal/access",
        "groupsClaim": "cognito:groups",
        "allowedGroups": [APPROVED_AUTH_PROFILE_ID],
        "session": {
            "mode": "server-cookie",
            "signinPath": "/auth-v2/session/signin",
            "mePath": "/auth-v2/session/me",
            "logoutPath": "/auth-v2/session/logout",
            "challengeRespondPath": "/auth-v2/session/challenge/respond",
            "mfaSetupPath": "/auth-v2/session/mfa/setup",
            "mfaVerifyPath": "/auth-v2/session/mfa/verify",
            "csrfCookieName": f"zlp_csrf_{cookie_namespace}",
            "challengeCsrfCookieName": f"zlp_challenge_csrf_{cookie_namespace}",
            "mfaEnrollCsrfCookieName": f"zlp_mfa_enroll_csrf_{cookie_namespace}",
            "csrfHeaderName": "x-zlp-csrf",
            "routeAccessCacheMs": 0,
        },
    }


def _dynamodb_client():
    global _DYNAMODB_CLIENT
    if _DYNAMODB_CLIENT is None:
        try:
            import boto3  # type: ignore

            _DYNAMODB_CLIENT = boto3.client("dynamodb")
        except Exception as exc:
            raise RuntimeV2Unavailable() from exc
    return _DYNAMODB_CLIENT


def _json_response(status_code: int, payload: Mapping[str, Any], *, allow_origin: bool) -> dict[str, Any]:
    headers = {
        "Cache-Control": "no-store",
        "Content-Type": "application/json; charset=utf-8",
        "Expires": "0",
        "Pragma": "no-cache",
        "Vary": "Origin",
        "X-Content-Type-Options": "nosniff",
    }
    if allow_origin:
        headers["Access-Control-Allow-Origin"] = ADMIN_ORIGIN
    return {
        "statusCode": status_code,
        "headers": dict(sorted(headers.items())),
        "body": json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
    }
