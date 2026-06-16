import json
import os
from pathlib import Path
import re
import hashlib
import time
import urllib.parse
from typing import Any, Dict, Optional

from zoolanding_lambda_common import (
    alias_pk,
    default_version_prefix,
    get_request_id,
    join_s3_key,
    is_local_cors_origin,
    load_item,
    load_json_from_s3,
    log,
    normalize_domain,
    origin_hostname,
    resolve_cors_origin,
    set_request_cors_origin,
    site_pk,
)

try:
    import jwt  # type: ignore
    from jwt import PyJWKClient  # type: ignore
except Exception:  # pragma: no cover - dependency is validated in tests/audit
    jwt = None
    PyJWKClient = None

try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover - local fallback when boto3 is unavailable
    boto3 = None


CONFIG_TABLE_NAME = os.getenv("CONFIG_TABLE_NAME", "zoolanding-config-registry")
CONFIG_PAYLOADS_BUCKET_NAME = os.getenv("CONFIG_PAYLOADS_BUCKET_NAME", "zoolanding-config-payloads")
AUTH_REGISTRY_FILE_NAME = os.getenv("AUTH_REGISTRY_FILE_NAME", "auth-profile-registry.json")
AUTH_PROVISIONING_ALLOWED_ROLE_NAMES = os.getenv("AUTH_PROVISIONING_ALLOWED_ROLE_NAMES", "")
AUTH_PROVISIONING_ALLOWED_ROLE_ARNS = os.getenv("AUTH_PROVISIONING_ALLOWED_ROLE_ARNS", "")
AUTH_PROVISIONING_STATE_TABLE_NAME = os.getenv("AUTH_PROVISIONING_STATE_TABLE_NAME", "")
AUTH_PROVISIONING_APPLY_ENABLED = os.getenv("AUTH_PROVISIONING_APPLY_ENABLED", "false")
AUTH_PROVISIONING_APPLY_ALLOWED_DOMAINS = os.getenv("AUTH_PROVISIONING_APPLY_ALLOWED_DOMAINS", "")
AUTH_PROVISIONING_APPLY_ALLOWED_TENANTS = os.getenv("AUTH_PROVISIONING_APPLY_ALLOWED_TENANTS", "")
_AUTH_REQUEST_ORIGIN = None
_COGNITO_IDP_CLIENT = None
_DYNAMODB_CLIENT = None
_SSM_CLIENT = None
_SECRETS_CLIENT = None

AUTH_PATHS = {
    "/auth/runtime-config",
    "/auth/provisioning-plan",
    "/auth/provisioning-executor",
    "/auth/signin",
    "/auth/signup",
    "/auth/confirm-signup",
    "/auth/resend-confirmation",
    "/auth/forgot-password",
    "/auth/confirm-forgot-password",
}
AUTH_PROFILE_STATUSES = {"active", "planned", "provisioning", "suspended", "failed"}
AUTH_PROVISIONING_PLAN_SCHEMA_VERSION = "2026-06-10.v1"
AUTH_PROVISIONING_EXECUTOR_SCHEMA_VERSION = "2026-06-10.executor.v1"
TEST_PREVIEW_ORIGIN_HOST = "test.zoolandingpage.com.mx"
CONTROL_OR_WHITESPACE_RE = re.compile(r"[\s\x00-\x1f\x7f]")
RAW_SECRET_KEY_RE = re.compile(r"(secret|token|password|private[_-]?key|credential|api[_-]?key)", re.I)
RUNTIME_CONFIG_ALLOWED_KEYS = {"domain", "authProfileId"}
PROVISIONING_PLAN_ALLOWED_KEYS = {"domain", "authProfileId"}
PROVISIONING_EXECUTOR_ALLOWED_KEYS = {"domain", "authProfileId", "mode", "planKey", "idempotencyKey"}
CUSTOM_SIGNIN_ALLOWED_KEYS = {"domain", "authProfileId", "email", "password", "language"}
CUSTOM_SIGNUP_ALLOWED_KEYS = {"domain", "authProfileId", "email", "password", "language"}
CUSTOM_CONFIRM_SIGNUP_ALLOWED_KEYS = {"domain", "authProfileId", "email", "code", "language"}
CUSTOM_RESEND_CONFIRMATION_ALLOWED_KEYS = {"domain", "authProfileId", "email", "language"}
CUSTOM_PASSWORD_RECOVERY_ALLOWED_KEYS = {"domain", "authProfileId", "email", "language"}
CUSTOM_CONFIRM_PASSWORD_RECOVERY_ALLOWED_KEYS = {"domain", "authProfileId", "email", "code", "password", "language"}
PROVISIONING_EXECUTOR_MODES = {"dry-run", "apply"}
ALIAS_TARGET_KEYS = (
    "domain",
    "canonicalDomain",
    "targetDomain",
    "siteDomain",
    "resolvedDomain",
)
LOCAL_AUTH_REGISTRY_FILE_ENV = "LOCAL_AUTH_REGISTRY_FILE"
LOCAL_AUTH_REGISTRY_DIR_ENV = "LOCAL_AUTH_REGISTRY_DIR"
ALLOWED_SECRET_REFERENCE_KEYS = {
    "credentialRef",
    "credentialRefs",
    "secretRef",
    "secretRefs",
    "socialIdpSecretRefs",
    "providerSecretRefs",
    "providerSecretRef",
    "clientIdRef",
    "clientSecretRef",
    "clientIdRefs",
    "clientSecretRefs",
}
SAFE_PUBLIC_AUTH_METADATA_KEYS = {
    "tokenUrl",
    "tokenEndpoint",
    "tokenEndpointUrl",
}


class AuthServiceError(Exception):
    status_code = 400
    public_message = "Invalid auth service request"

    def __init__(self, message: Optional[str] = None):
        super().__init__(message or self.public_message)
        if message:
            self.public_message = message


class AuthRegistryError(AuthServiceError):
    status_code = 500
    public_message = "Auth registry is invalid"


class AuthNotFoundError(AuthServiceError):
    status_code = 404
    public_message = "Auth profile not found"


class AuthUnauthorizedError(AuthServiceError):
    status_code = 403
    public_message = "Provisioning plan access denied"


class AuthJwtError(AuthServiceError):
    status_code = 401
    public_message = "Unauthorized"


def auth_lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    request_id = get_request_id(context)
    global _AUTH_REQUEST_ORIGIN
    _AUTH_REQUEST_ORIGIN = _request_origin(event)
    set_request_cors_origin(_AUTH_REQUEST_ORIGIN)

    if _is_options_request(event):
        return _auth_response(200, {"ok": True})

    path = _auth_route_path(event)
    method = _request_method(event)
    try:
        if path == "/auth/runtime-config" and method in {"GET", "POST"}:
            payload = _request_payload(event)
            return _runtime_config_response(payload)
        if path == "/auth/provisioning-plan" and method == "POST":
            payload = _request_payload(event)
            return _provisioning_plan_response(event, payload)
        if path == "/auth/provisioning-executor" and method == "POST":
            payload = _request_payload(event)
            return _provisioning_executor_response(event, payload)
        if path == "/auth/signin" and method == "POST":
            payload = _request_payload(event)
            return _custom_signin_response(payload)
        if path == "/auth/signup" and method == "POST":
            payload = _request_payload(event)
            return _custom_signup_response(payload)
        if path == "/auth/confirm-signup" and method == "POST":
            payload = _request_payload(event)
            return _custom_confirm_signup_response(payload)
        if path == "/auth/resend-confirmation" and method == "POST":
            payload = _request_payload(event)
            return _custom_resend_confirmation_response(payload)
        if path == "/auth/forgot-password" and method == "POST":
            payload = _request_payload(event)
            return _custom_forgot_password_response(payload)
        if path == "/auth/confirm-forgot-password" and method == "POST":
            payload = _request_payload(event)
            return _custom_confirm_forgot_password_response(payload)
        return _auth_response(404, {"ok": False, "error": "Auth service route not found"})
    except ValueError as exc:
        return _auth_response(400, {"ok": False, "error": str(exc)})
    except AuthServiceError as exc:
        return _auth_response(exc.status_code, {"ok": False, "error": exc.public_message})
    except Exception as exc:
        log("ERROR", "Auth service request failed", requestId=request_id, path=path, errorType=type(exc).__name__)
        return _auth_response(500, {"ok": False, "error": "Internal error"})


def is_auth_service_path(event: Dict[str, Any]) -> bool:
    return _auth_route_path(event) in AUTH_PATHS


def _auth_route_path(event: Dict[str, Any]) -> str:
    path = _request_path(event)
    for auth_path in AUTH_PATHS:
        if path == auth_path or path.endswith(auth_path):
            return auth_path
    return path


def load_auth_registry_for_domain(domain: str) -> Dict[str, Any]:
    canonical_domain = normalize_domain(domain)
    if not canonical_domain:
        raise ValueError("Missing domain")

    local_registry = _load_local_auth_registry_for_domain(canonical_domain)
    if local_registry is not None:
        validate_auth_registry(local_registry)
        return local_registry

    metadata = load_item(CONFIG_TABLE_NAME, site_pk(canonical_domain))
    if not isinstance(metadata, dict):
        raise AuthNotFoundError("Site metadata not found")

    published = _auth_registry_published_config(metadata)
    if not published:
        raise AuthNotFoundError("Published configuration not found")

    version_id = str(published.get("versionId") or "").strip()
    prefix = str(published.get("prefix") or default_version_prefix(canonical_domain, version_id)).strip()
    if not prefix:
        raise AuthNotFoundError("Published configuration prefix is missing")

    registry_key = join_s3_key(prefix, canonical_domain, "server", AUTH_REGISTRY_FILE_NAME)
    registry = load_json_from_s3(CONFIG_PAYLOADS_BUCKET_NAME, registry_key)
    if not isinstance(registry, dict):
        raise AuthNotFoundError("Auth profile registry not found")
    validate_auth_registry(registry)
    return registry


def _auth_registry_published_config(metadata: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    environment = _auth_registry_environment_for_origin(metadata, _AUTH_REQUEST_ORIGIN)
    if environment:
        published_environments = metadata.get("publishedEnvironments")
        if isinstance(published_environments, dict):
            published = published_environments.get(environment)
            if isinstance(published, dict):
                return published
        if environment == "test":
            draft = metadata.get("draft")
            if isinstance(draft, dict):
                return draft

    published = metadata.get("published")
    return published if isinstance(published, dict) else None


def _auth_registry_environment_for_origin(metadata: Dict[str, Any], origin: Optional[str]) -> str:
    if not origin:
        return ""
    if is_local_cors_origin(origin):
        return ""

    origin_domain = normalize_domain(origin_hostname(origin))
    if not origin_domain:
        return ""
    if origin_domain == TEST_PREVIEW_ORIGIN_HOST:
        return "test"

    environments = metadata.get("environments")
    if isinstance(environments, dict):
        for environment_name, environment in environments.items():
            if not isinstance(environment, dict):
                continue
            aliases = _string_list(environment.get("aliases")) + _string_list(environment.get("domains"))
            if origin_domain in {normalize_domain(alias) for alias in aliases}:
                return str(environment_name).strip()

    environment_aliases = metadata.get("environmentAliases")
    if isinstance(environment_aliases, dict):
        for environment_name, aliases in environment_aliases.items():
            if origin_domain in {normalize_domain(alias) for alias in _string_list(aliases)}:
                return str(environment_name).strip()

    return ""


def validate_auth_registry(registry: Dict[str, Any]) -> None:
    _reject_raw_secret_material(registry)
    profiles = _profiles(registry)
    if not profiles:
        raise AuthRegistryError("Auth registry must contain profiles")

    seen: set[str] = set()
    for profile in profiles:
        profile_id = _profile_id(profile)
        if not profile_id:
            raise AuthRegistryError("Auth profile requires authProfileId")
        if profile_id in seen:
            raise AuthRegistryError("Auth profile ids must be unique")
        seen.add(profile_id)

        status = _profile_status(profile)
        if status not in AUTH_PROFILE_STATUSES:
            raise AuthRegistryError("Auth profile status is invalid")
        _validate_social_identity_provider_metadata(profile)
        if status == "active":
            if not str(profile.get("tenantId") or "").strip():
                raise AuthRegistryError("Active auth profile requires tenantId")
            _validate_https_url(str(profile.get("issuer") or ""), "issuer")
            _validate_https_url(str(profile.get("hostedUiDomain") or ""), "hostedUiDomain")
            _validate_same_origin_path(str(profile.get("loginPath") or "/login"), "loginPath")
            _runtime_path_from_profile(profile, "redirectPath", "callbackUrls", "redirectPath")
            _runtime_path_from_profile(profile, "logoutPath", "logoutUrls", "logoutPath")
            for optional_path in ("postLoginPath", "postLogoutPath"):
                if profile.get(optional_path):
                    _validate_same_origin_path(str(profile.get(optional_path)), optional_path)
            if not _audiences(profile):
                raise AuthRegistryError("Active auth profile requires an audience/clientId")
            for callback_url in _string_list(profile.get("callbackUrls")):
                _validate_https_url(callback_url, "callbackUrl")
            for logout_url in _string_list(profile.get("logoutUrls")):
                _validate_https_url(logout_url, "logoutUrl")


def verify_jwt(token: str, *, issuer: str, audiences: list[str], jwks_url: Optional[str] = None) -> Dict[str, Any]:
    if jwt is None or PyJWKClient is None:
        raise AuthJwtError("JWT verification dependency is not installed")
    if not token:
        raise AuthJwtError()
    if not audiences:
        raise AuthJwtError("JWT audience policy is missing")

    resolved_jwks_url = jwks_url or _jwks_url(issuer)
    signing_key = PyJWKClient(resolved_jwks_url).get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        issuer=issuer,
        options={"require": ["exp", "iss"], "verify_aud": False},
    )
    if not isinstance(claims, dict):
        raise AuthJwtError()
    if not _claims_match_audience(claims, audiences):
        raise AuthJwtError()
    return claims


def authorize_bearer_for_domain(
    *,
    domain: str,
    auth_profile_id: str,
    token: str,
    allowed_groups: Optional[list[str]] = None,
) -> Dict[str, str]:
    registry = load_auth_registry_for_domain(domain)
    profile = _find_profile(registry, str(auth_profile_id or registry.get("defaultAuthProfileId") or ""))
    profile = _profile_with_effective_auth_state(domain, profile)
    if _profile_status(profile) != "active":
        raise AuthJwtError()

    issuer = str(profile.get("issuer") or "")
    claims = verify_jwt(
        token,
        issuer=issuer,
        audiences=_audiences(profile),
        jwks_url=str(profile.get("jwksUrl") or _jwks_url(issuer)),
    )
    if not _claims_allowed_for_profile(claims, profile):
        raise AuthJwtError()

    narrowed_groups = set(_string_list(allowed_groups))
    if narrowed_groups:
        group_claim = str(profile.get("groupClaim") or "cognito:groups")
        actual_groups = set(_string_list(claims.get(group_claim)))
        if not actual_groups.intersection(narrowed_groups):
            raise AuthJwtError()

    return {
        "principalId": str(claims.get("sub") or claims.get("username") or "authenticated"),
        "domain": normalize_domain(domain),
        "authProfileId": _profile_id(profile),
        "tenantId": str(profile.get("tenantId") or ""),
    }


def jwt_authorizer_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    method_arn = str(event.get("methodArn") or event.get("routeArn") or "*")
    token = _bearer_token(event)
    try:
        domain = _authorizer_domain(event)
        auth_profile_id = _authorizer_profile_id(event)
        registry = load_auth_registry_for_domain(domain)
        profile = _find_profile(registry, auth_profile_id)
        profile = _profile_with_effective_auth_state(domain, profile)
        if _profile_status(profile) != "active":
            raise AuthJwtError()

        issuer = str(profile.get("issuer") or "")
        claims = verify_jwt(
            token,
            issuer=issuer,
            audiences=_audiences(profile),
            jwks_url=str(profile.get("jwksUrl") or _jwks_url(issuer)),
        )
        if not _claims_allowed_for_profile(claims, profile):
            raise AuthJwtError()

        principal_id = str(claims.get("sub") or claims.get("username") or "authenticated")
        return _authorizer_policy("Allow", method_arn, principal_id, {
            "domain": normalize_domain(domain),
            "authProfileId": _profile_id(profile),
            "tenantId": str(profile.get("tenantId") or ""),
        })
    except Exception as exc:
        log("WARNING", "JWT authorizer denied request", requestId=get_request_id(context), errorType=type(exc).__name__)
        return _authorizer_policy("Deny", method_arn, "anonymous", {})


def _runtime_config_response(payload: Dict[str, Any]) -> Dict[str, Any]:
    _reject_unsupported_runtime_options(payload)
    domain = normalize_domain(payload.get("domain"))
    _enforce_runtime_origin_domain(_AUTH_REQUEST_ORIGIN, domain)
    registry = load_auth_registry_for_domain(domain)
    profile = _find_profile(registry, str(payload.get("authProfileId") or registry.get("defaultAuthProfileId") or ""))
    profile = _profile_with_effective_auth_state(domain, profile)
    status = _profile_status(profile)
    auth_payload = _public_runtime_auth(profile, enabled=status == "active")
    return _auth_response(200, {"ok": True, "domain": domain, "auth": auth_payload})


def _custom_signin_response(payload: Dict[str, Any]) -> Dict[str, Any]:
    _reject_unsupported_custom_signin_options(payload)
    domain, profile = _custom_auth_profile(payload, "signin")
    email = _email(payload.get("email"))
    password = _password(payload.get("password"))
    language = _language(payload.get("language"))
    client_id = _custom_auth_client_id(profile)

    try:
        response = _cognito_idp().initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": email,
                "PASSWORD": password,
            },
            ClientMetadata=_custom_auth_client_metadata(domain, profile, language),
        )
    except Exception as exc:
        log("WARNING", "Custom Cognito signin failed", domain=domain, authProfileId=_profile_id(profile), errorType=type(exc).__name__)
        raise AuthServiceError("Sign-in failed") from exc

    challenge_name = str(response.get("ChallengeName") or "").strip()
    if challenge_name:
        return _auth_response(200, {
            "ok": True,
            "domain": domain,
            "authProfileId": _profile_id(profile),
            "status": "challenge-required",
            "challengeName": challenge_name,
        })

    auth_result = response.get("AuthenticationResult")
    id_token = str(auth_result.get("IdToken") or "").strip() if isinstance(auth_result, dict) else ""
    if not id_token:
        raise AuthServiceError("Sign-in failed")

    try:
        claims = verify_jwt(
            id_token,
            issuer=str(profile.get("issuer") or ""),
            audiences=_audiences(profile),
            jwks_url=str(profile.get("jwksUrl") or _jwks_url(str(profile.get("issuer") or ""))),
        )
    except Exception as exc:
        log("WARNING", "Custom Cognito signin token validation failed", domain=domain, authProfileId=_profile_id(profile), errorType=type(exc).__name__)
        raise AuthServiceError("Sign-in failed") from exc

    if not _claims_allowed_for_profile(claims, profile):
        raise AuthServiceError("Sign-in failed")

    session = _public_session_from_claims(profile, claims)
    return _auth_response(200, {
        "ok": True,
        "domain": domain,
        "authProfileId": _profile_id(profile),
        "status": "signed-in",
        "session": session,
    })


def _custom_signup_response(payload: Dict[str, Any]) -> Dict[str, Any]:
    _reject_unsupported_custom_signup_options(payload)
    domain, profile = _custom_auth_profile(payload, "signup")
    email = _email(payload.get("email"))
    password = _password(payload.get("password"))
    language = _language(payload.get("language"))
    signup_policy = _custom_auth_policy(profile, "signup")
    client_id = _custom_auth_client_id(profile)
    user_pool_id = _profile_user_pool_id(profile)
    tenant_claim = str(profile.get("tenantClaim") or "custom:tenant_id").strip()
    tenant_id = str(profile.get("tenantId") or "").strip()

    user_attributes = [{"Name": "email", "Value": email}]
    if signup_policy.get("setTenantClaim", True) is not False and tenant_claim and tenant_id:
        user_attributes.append({"Name": tenant_claim, "Value": tenant_id})

    metadata = _custom_auth_client_metadata(domain, profile, language)
    try:
        response = _cognito_idp().sign_up(
            ClientId=client_id,
            Username=email,
            Password=password,
            UserAttributes=user_attributes,
            ClientMetadata=metadata,
        )
        for group_name in _custom_signup_default_groups(profile, signup_policy):
            _cognito_idp().admin_add_user_to_group(
                UserPoolId=user_pool_id,
                Username=email,
                GroupName=group_name,
            )
    except Exception as exc:
        log("WARNING", "Custom Cognito signup failed", domain=domain, authProfileId=_profile_id(profile), errorType=type(exc).__name__)
        raise AuthServiceError("Signup failed") from exc

    return _auth_response(200, {
        "ok": True,
        "domain": domain,
        "authProfileId": _profile_id(profile),
        "status": "signed-up" if response.get("UserConfirmed") is True else "confirmation-required",
        **_code_delivery_response(response.get("CodeDeliveryDetails")),
    })


def _custom_forgot_password_response(payload: Dict[str, Any]) -> Dict[str, Any]:
    _reject_unsupported_custom_password_recovery_options(payload)
    domain, profile = _custom_auth_profile(payload, "passwordRecovery")
    email = _email(payload.get("email"))
    language = _language(payload.get("language"))
    client_id = _custom_auth_client_id(profile)

    try:
        response = _cognito_idp().forgot_password(
            ClientId=client_id,
            Username=email,
            ClientMetadata=_custom_auth_client_metadata(domain, profile, language),
        )
    except Exception as exc:
        log("WARNING", "Custom Cognito forgot-password failed", domain=domain, authProfileId=_profile_id(profile), errorType=type(exc).__name__)
        raise AuthServiceError("Password recovery failed") from exc

    return _auth_response(200, {
        "ok": True,
        "domain": domain,
        "authProfileId": _profile_id(profile),
        "status": "code-sent",
        **_code_delivery_response(response.get("CodeDeliveryDetails")),
    })


def _custom_confirm_signup_response(payload: Dict[str, Any]) -> Dict[str, Any]:
    _reject_unsupported_custom_confirm_signup_options(payload)
    domain, profile = _custom_auth_profile(payload, "signup")
    email = _email(payload.get("email"))
    code = _code(payload.get("code"))
    language = _language(payload.get("language"))

    try:
        _cognito_idp().confirm_sign_up(
            ClientId=_custom_auth_client_id(profile),
            Username=email,
            ConfirmationCode=code,
            ClientMetadata=_custom_auth_client_metadata(domain, profile, language),
        )
    except Exception as exc:
        log("WARNING", "Custom Cognito confirm-signup failed", domain=domain, authProfileId=_profile_id(profile), errorType=type(exc).__name__)
        raise AuthServiceError("Signup confirmation failed") from exc

    return _auth_response(200, {
        "ok": True,
        "domain": domain,
        "authProfileId": _profile_id(profile),
        "status": "confirmed",
    })


def _custom_resend_confirmation_response(payload: Dict[str, Any]) -> Dict[str, Any]:
    _reject_unsupported_custom_resend_confirmation_options(payload)
    domain, profile = _custom_auth_profile(payload, "signup")
    email = _email(payload.get("email"))
    language = _language(payload.get("language"))

    try:
        response = _cognito_idp().resend_confirmation_code(
            ClientId=_custom_auth_client_id(profile),
            Username=email,
            ClientMetadata=_custom_auth_client_metadata(domain, profile, language),
        )
    except Exception as exc:
        log("WARNING", "Custom Cognito resend-confirmation failed", domain=domain, authProfileId=_profile_id(profile), errorType=type(exc).__name__)
        raise AuthServiceError("Confirmation resend failed") from exc

    return _auth_response(200, {
        "ok": True,
        "domain": domain,
        "authProfileId": _profile_id(profile),
        "status": "code-sent",
        **_code_delivery_response(response.get("CodeDeliveryDetails")),
    })


def _custom_confirm_forgot_password_response(payload: Dict[str, Any]) -> Dict[str, Any]:
    _reject_unsupported_custom_confirm_password_recovery_options(payload)
    domain, profile = _custom_auth_profile(payload, "passwordRecovery")
    email = _email(payload.get("email"))
    code = _code(payload.get("code"))
    password = _password(payload.get("password"))
    language = _language(payload.get("language"))

    try:
        _cognito_idp().confirm_forgot_password(
            ClientId=_custom_auth_client_id(profile),
            Username=email,
            ConfirmationCode=code,
            Password=password,
            ClientMetadata=_custom_auth_client_metadata(domain, profile, language),
        )
    except Exception as exc:
        log("WARNING", "Custom Cognito confirm-forgot-password failed", domain=domain, authProfileId=_profile_id(profile), errorType=type(exc).__name__)
        raise AuthServiceError("Password reset failed") from exc

    return _auth_response(200, {
        "ok": True,
        "domain": domain,
        "authProfileId": _profile_id(profile),
        "status": "password-reset",
    })


def _enforce_runtime_origin_domain(origin: Optional[str], domain: str) -> None:
    if not domain:
        raise ValueError("Missing domain")
    if not origin:
        return
    if is_local_cors_origin(origin):
        return

    origin_domain = origin_hostname(origin)
    if origin_domain == TEST_PREVIEW_ORIGIN_HOST:
        return
    if origin_domain == domain:
        return
    if _origin_aliases_requested_domain(origin_domain, domain):
        return

    raise ValueError("Origin is not allowed for requested domain")


def _origin_aliases_requested_domain(origin_domain: str, requested_domain: str) -> bool:
    origin_domain = normalize_domain(origin_domain)
    requested_domain = normalize_domain(requested_domain)
    if not origin_domain or not requested_domain:
        return False

    metadata = _load_site_metadata_for_origin_check(requested_domain)
    if _metadata_lists_origin_alias(metadata, origin_domain):
        return True

    alias_metadata = _load_alias_metadata_for_origin_check(origin_domain)
    return _alias_metadata_targets_domain(alias_metadata, requested_domain)


def _load_site_metadata_for_origin_check(domain: str) -> Optional[Dict[str, Any]]:
    try:
        metadata = load_item(CONFIG_TABLE_NAME, site_pk(domain))
    except Exception as exc:
        log("WARNING", "Unable to resolve auth runtime origin site metadata", domain=domain, errorType=type(exc).__name__)
        return None
    return metadata if isinstance(metadata, dict) else None


def _load_alias_metadata_for_origin_check(origin_domain: str) -> Optional[Dict[str, Any]]:
    try:
        metadata = load_item(CONFIG_TABLE_NAME, alias_pk(origin_domain), "SITE")
    except Exception as exc:
        log("WARNING", "Unable to resolve auth runtime origin alias metadata", originDomain=origin_domain, errorType=type(exc).__name__)
        return None
    return metadata if isinstance(metadata, dict) else None


def _metadata_lists_origin_alias(metadata: Optional[Dict[str, Any]], origin_domain: str) -> bool:
    if not isinstance(metadata, dict):
        return False

    alias_values = _string_list(metadata.get("aliases")) + _string_list(metadata.get("domains"))
    environments = metadata.get("environments")
    if isinstance(environments, dict):
        for environment in environments.values():
            if isinstance(environment, dict):
                alias_values.extend(_string_list(environment.get("aliases")))
                alias_values.extend(_string_list(environment.get("domains")))
    environment_aliases = metadata.get("environmentAliases")
    if isinstance(environment_aliases, dict):
        for aliases in environment_aliases.values():
            alias_values.extend(_string_list(aliases))

    return normalize_domain(origin_domain) in {normalize_domain(alias) for alias in alias_values}


def _alias_metadata_targets_domain(metadata: Optional[Dict[str, Any]], requested_domain: str) -> bool:
    if not isinstance(metadata, dict):
        return False

    requested_domain = normalize_domain(requested_domain)
    for key in ALIAS_TARGET_KEYS:
        target = normalize_domain(metadata.get(key))
        if target == requested_domain:
            return True
    return False


def _provisioning_plan_response(event: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    if not _is_trusted_server_request(event):
        raise AuthUnauthorizedError()
    _reject_unsupported_provisioning_options(payload)

    domain = normalize_domain(payload.get("domain"))
    registry = load_auth_registry_for_domain(domain)
    profile = _find_profile(registry, str(payload.get("authProfileId") or registry.get("defaultAuthProfileId") or ""))
    return _auth_response(200, {"ok": True, "domain": domain, "plan": _cognito_plan(domain, profile)})


def _provisioning_executor_response(event: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    if not _is_trusted_server_request(event):
        raise AuthUnauthorizedError()
    _reject_unsupported_provisioning_executor_options(payload)

    mode = _executor_mode(payload)
    domain = normalize_domain(payload.get("domain"))
    registry = load_auth_registry_for_domain(domain)
    profile = _find_profile(registry, str(payload.get("authProfileId") or registry.get("defaultAuthProfileId") or ""))
    plan = _cognito_plan(domain, profile)
    if mode != "apply":
        _validate_executor_plan_key(payload, plan)

    if mode == "apply":
        if not _auth_provisioning_apply_enabled():
            executor = _cognito_executor_preview(plan, mode=mode, requested_idempotency_key=payload.get("idempotencyKey"))
            executor["operations"] = []
            executor["blockedReason"] = "apply-disabled"
            return _auth_response(501, {
                "ok": False,
                "error": "Cognito executor apply is disabled",
                "executor": executor,
        })
        _validate_apply_request(event, payload, plan)
        applied = _cognito_executor_apply(plan, requested_idempotency_key=payload.get("idempotencyKey"))
        status_code = 200 if applied["executionStatus"] == "applied" else 500
        return _auth_response(status_code, {
            "ok": status_code == 200,
            "domain": domain,
            "executor": applied,
            **({} if status_code == 200 else {"error": "Cognito provisioning apply failed"}),
        })

    executor = _cognito_executor_preview(plan, mode=mode, requested_idempotency_key=payload.get("idempotencyKey"))
    return _auth_response(200, {"ok": True, "domain": domain, "executor": executor})


def _public_runtime_auth(profile: Dict[str, Any], *, enabled: bool = True) -> Dict[str, Any]:
    issuer = str(profile.get("issuer") or "").strip()
    audiences = _audiences(profile)
    client_id = str(profile.get("clientId") or (audiences[0] if audiences else "")).strip()
    if not client_id and not enabled:
        client_id = str(
            profile.get("desiredClientId")
            or profile.get("desiredClientAlias")
            or profile.get("clientAlias")
            or "pending-cognito-client-id"
        ).strip()
    if not client_id:
        raise AuthRegistryError("Auth profile requires clientId")
    auth_payload = {
        "enabled": enabled,
        "authProfileId": _profile_id(profile),
        "provider": "cognito",
        "issuer": issuer,
        "userPoolId": str(profile.get("userPoolId") or "").strip(),
        "hostedUiDomain": str(profile.get("hostedUiDomain") or "").strip(),
        "clientId": client_id,
        "scopes": _string_list(profile.get("scopes")) or ["openid", "email", "profile"],
        "redirectPath": _runtime_path_from_profile(profile, "redirectPath", "callbackUrls", "redirectPath"),
        "logoutPath": _runtime_path_from_profile(profile, "logoutPath", "logoutUrls", "logoutPath"),
        "loginPath": str(profile.get("loginPath") or "/login").strip(),
        "groupsClaim": str(profile.get("groupClaim") or "cognito:groups").strip(),
        "allowedGroups": _string_list(profile.get("allowedGroups")),
    }
    for optional_key in ("loginPageId", "logoutPageId", "callbackPageId", "accountPageId"):
        optional_value = str(profile.get(optional_key) or "").strip()
        if optional_value:
            auth_payload[optional_key] = optional_value
    for optional_path in ("postLoginPath", "postLogoutPath"):
        optional_value = str(profile.get(optional_path) or "").strip()
        if optional_value:
            _validate_same_origin_path(optional_value, optional_path)
            auth_payload[optional_path] = optional_value
    if not auth_payload["userPoolId"]:
        del auth_payload["userPoolId"]
    return auth_payload


def _load_local_auth_registry_for_domain(domain: str) -> Optional[Dict[str, Any]]:
    if not _dry_run_enabled():
        return None

    explicit_file = str(os.getenv(LOCAL_AUTH_REGISTRY_FILE_ENV, "") or "").strip()
    if explicit_file:
        return _read_local_registry_file(Path(explicit_file).expanduser())

    configured_dir = str(os.getenv(LOCAL_AUTH_REGISTRY_DIR_ENV, "") or "").strip()
    if not configured_dir:
        return None

    base_dir = Path(configured_dir).expanduser().resolve()
    candidates = [
        base_dir / domain / "server" / AUTH_REGISTRY_FILE_NAME,
        base_dir / domain / AUTH_REGISTRY_FILE_NAME,
        base_dir / AUTH_REGISTRY_FILE_NAME,
    ]

    for candidate in candidates:
        resolved = candidate.resolve()
        if not _path_is_inside(resolved, base_dir):
            continue
        if resolved.is_file():
            return _read_local_registry_file(resolved)

    raise AuthNotFoundError("Local auth profile registry not found")


def _read_local_registry_file(path: Path) -> Dict[str, Any]:
    resolved = path.resolve()
    if not resolved.is_file():
        raise AuthNotFoundError("Local auth profile registry not found")

    with resolved.open("r", encoding="utf-8") as registry_file:
        registry = json.load(registry_file)
    if not isinstance(registry, dict):
        raise AuthNotFoundError("Auth profile registry not found")
    return registry


def _path_is_inside(path: Path, base_dir: Path) -> bool:
    try:
        path.relative_to(base_dir)
        return True
    except ValueError:
        return False


def _dry_run_enabled() -> bool:
    return str(os.getenv("DRY_RUN", "0")).strip().lower() in {"1", "true", "yes", "on"}


def _cognito_plan(domain: str, profile: Dict[str, Any]) -> Dict[str, Any]:
    _validate_provisioning_profile(profile)
    normalized_domain = normalize_domain(domain)
    auth_profile_id = _profile_id(profile)
    status = _profile_status(profile)
    issuer = str(profile.get("issuer") or "").strip()
    lifecycle = _plan_lifecycle(status)
    public_runtime_auth = _public_runtime_auth(profile, enabled=status == "active")
    social_identity_providers = _social_identity_providers(profile)
    config_hash = _provisioning_config_hash(
        domain=normalized_domain,
        profile=profile,
        social_identity_providers=social_identity_providers,
    )
    operations = _provisioning_operations(
        domain=normalized_domain,
        auth_profile_id=auth_profile_id,
        tenant_id=str(profile.get("tenantId") or "").strip(),
        status=status,
        social_identity_providers=social_identity_providers,
        config_hash=config_hash,
    )
    plan_key = _stable_key("plan", AUTH_PROVISIONING_PLAN_SCHEMA_VERSION, config_hash)
    return {
        "mode": "plan-only",
        "planVersion": AUTH_PROVISIONING_PLAN_SCHEMA_VERSION,
        "planKey": plan_key,
        "configHash": config_hash,
        "provider": "cognito",
        "domain": normalized_domain,
        "authProfileId": auth_profile_id,
        "tenantId": str(profile.get("tenantId") or "").strip(),
        "status": status,
        "trustedCallerRequired": True,
        "lifecycle": lifecycle,
        "runtimeAuth": {
            "enabledWhenStatus": "active",
            "currentEnabled": status == "active",
            "publicClient": {
                "clientId": public_runtime_auth["clientId"],
                "audiences": _audiences(profile),
                "scopes": public_runtime_auth["scopes"],
                "callbackUrls": _string_list(profile.get("callbackUrls")),
                "logoutUrls": _string_list(profile.get("logoutUrls")),
                "redirectPath": public_runtime_auth["redirectPath"],
                "logoutPath": public_runtime_auth["logoutPath"],
                "loginPath": public_runtime_auth["loginPath"],
                "allowedGroups": public_runtime_auth["allowedGroups"],
            },
        },
        "hostedUi": _hosted_ui_details(profile),
        "groups": {
            "claim": str(profile.get("groupClaim") or "cognito:groups"),
            "allowed": _string_list(profile.get("allowedGroups")),
        },
        "socialIdentityProviders": social_identity_providers,
        "operations": operations,
        "expectedOutputs": {
            "status": "active",
            "issuer": issuer,
            "jwksUrl": str(profile.get("jwksUrl") or _jwks_url(issuer)) if issuer else "",
            "hostedUiDomain": str(profile.get("hostedUiDomain") or "").strip(),
            "userPoolId": str(profile.get("userPoolId") or "").strip(),
            "publicClientId": public_runtime_auth["clientId"],
            "audiences": _audiences(profile),
            "callbackUrls": _string_list(profile.get("callbackUrls")),
            "logoutUrls": _string_list(profile.get("logoutUrls")),
            "runtimeAuthEnabled": True,
        },
        "jwtAuthorizer": {
            "audienceMode": "aud-or-client_id",
            "tenantClaim": str(profile.get("tenantClaim") or "custom:tenant_id"),
            "groupClaim": str(profile.get("groupClaim") or "cognito:groups"),
        },
    }


def _find_profile(registry: Dict[str, Any], auth_profile_id: str) -> Dict[str, Any]:
    profiles = _profiles(registry)
    requested_id = str(auth_profile_id or "").strip()
    if not requested_id and len(profiles) == 1:
        return profiles[0]
    for profile in profiles:
        if _profile_id(profile) == requested_id:
            return profile
    raise AuthNotFoundError()


def _profiles(registry: Dict[str, Any]) -> list[Dict[str, Any]]:
    raw_profiles = registry.get("profiles") or registry.get("authProfiles")
    if not isinstance(raw_profiles, list):
        return []
    return [profile for profile in raw_profiles if isinstance(profile, dict)]


def _profile_id(profile: Dict[str, Any]) -> str:
    return str(profile.get("authProfileId") or profile.get("id") or "").strip()


def _profile_status(profile: Dict[str, Any]) -> str:
    return str(profile.get("status") or "planned").strip().lower()


def _audiences(profile: Dict[str, Any]) -> list[str]:
    values = _string_list(profile.get("audiences")) + _string_list(profile.get("audience"))
    client_id = str(profile.get("clientId") or "").strip()
    if client_id:
        values.append(client_id)
    deduped: list[str] = []
    for value in values:
        if value and value not in deduped:
            deduped.append(value)
    return deduped


def _claims_allowed_for_profile(claims: Dict[str, Any], profile: Dict[str, Any]) -> bool:
    issuer = str(profile.get("issuer") or "").strip()
    if issuer and claims.get("iss") != issuer:
        return False
    if not _claims_match_audience(claims, _audiences(profile)):
        return False

    tenant_id = str(profile.get("tenantId") or "").strip()
    if tenant_id:
        tenant_claim = str(profile.get("tenantClaim") or "custom:tenant_id")
        if str(claims.get(tenant_claim) or "") != tenant_id:
            return False

    allowed_groups = set(_string_list(profile.get("allowedGroups")))
    if allowed_groups:
        group_claim = str(profile.get("groupClaim") or "cognito:groups")
        actual_groups = set(_string_list(claims.get(group_claim)))
        if not actual_groups.intersection(allowed_groups):
            return False
    return True


def _claims_match_audience(claims: Dict[str, Any], audiences: list[str]) -> bool:
    expected = set(audiences)
    actual = set(_string_list(claims.get("aud")))
    client_id = str(claims.get("client_id") or "").strip()
    if client_id:
        actual.add(client_id)
    return bool(expected.intersection(actual))


def _provisioning_config_hash(
    *,
    domain: str,
    profile: Dict[str, Any],
    social_identity_providers: list[Dict[str, Any]],
) -> str:
    sanitized = {
        "domain": normalize_domain(domain),
        "authProfileId": _profile_id(profile),
        "tenantId": str(profile.get("tenantId") or "").strip(),
        "status": _profile_status(profile),
        "issuer": str(profile.get("issuer") or "").strip(),
        "hostedUi": _hosted_ui_details(profile),
        "runtimePaths": {
            "redirectPath": _runtime_path_from_profile(profile, "redirectPath", "callbackUrls", "redirectPath"),
            "logoutPath": _runtime_path_from_profile(profile, "logoutPath", "logoutUrls", "logoutPath"),
            "loginPath": str(profile.get("loginPath") or "/login").strip(),
            "postLoginPath": str(profile.get("postLoginPath") or "").strip(),
            "postLogoutPath": str(profile.get("postLogoutPath") or "").strip(),
        },
        "publicClient": {
            "desiredClientId": str(profile.get("clientId") or profile.get("desiredClientId") or "").strip(),
            "desiredClientAlias": str(profile.get("desiredClientAlias") or profile.get("clientAlias") or "").strip(),
            "audiences": _audiences(profile),
            "scopes": _string_list(profile.get("scopes")) or ["openid", "email", "profile"],
            "callbackUrls": sorted(_string_list(profile.get("callbackUrls"))),
            "logoutUrls": sorted(_string_list(profile.get("logoutUrls"))),
        },
        "groups": {
            "claim": str(profile.get("groupClaim") or "cognito:groups").strip(),
            "allowed": sorted(_string_list(profile.get("allowedGroups"))),
        },
        "jwtAuthorizer": {
            "tenantClaim": str(profile.get("tenantClaim") or "custom:tenant_id").strip(),
        },
        "socialIdentityProviders": _hashable_social_identity_providers(social_identity_providers),
    }
    return _stable_json_hash(sanitized)


def _hashable_social_identity_providers(providers: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    hashable = []
    for provider in providers:
        secret_refs = provider.get("secretRefs") if isinstance(provider.get("secretRefs"), dict) else {}
        entry = {
            "providerId": str(provider.get("providerId") or "").strip(),
            "providerType": str(provider.get("providerType") or "").strip(),
            "scopes": sorted(_string_list(provider.get("scopes"))),
            "metadata": {
                key: str(provider.get(key) or "").strip()
                for key in ("issuer", "discoveryUrl", "authorizeUrl", "tokenUrl", "userInfoUrl", "jwksUrl")
                if str(provider.get(key) or "").strip()
            },
            "secretRefHashes": {
                key: _stable_key("secret-ref", str(value))
                for key, value in sorted(secret_refs.items())
                if str(value or "").strip()
            },
        }
        hashable.append(entry)
    return sorted(hashable, key=lambda entry: (entry["providerId"], entry["providerType"]))


def _stable_json_hash(value: Any) -> str:
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _reject_unsupported_runtime_options(payload: Dict[str, Any]) -> None:
    if not all(str(key) in RUNTIME_CONFIG_ALLOWED_KEYS for key in payload.keys()):
        raise AuthServiceError("Unsupported auth runtime option")


def _reject_unsupported_provisioning_options(payload: Dict[str, Any]) -> None:
    if not all(str(key) in PROVISIONING_PLAN_ALLOWED_KEYS for key in payload.keys()):
        raise AuthServiceError("Unsupported auth provisioning option")


def _reject_unsupported_provisioning_executor_options(payload: Dict[str, Any]) -> None:
    if not all(str(key) in PROVISIONING_EXECUTOR_ALLOWED_KEYS for key in payload.keys()):
        raise AuthServiceError("Unsupported auth provisioning executor option")


def _reject_unsupported_custom_signin_options(payload: Dict[str, Any]) -> None:
    if not all(str(key) in CUSTOM_SIGNIN_ALLOWED_KEYS for key in payload.keys()):
        raise AuthServiceError("Unsupported signin option")


def _reject_unsupported_custom_signup_options(payload: Dict[str, Any]) -> None:
    if not all(str(key) in CUSTOM_SIGNUP_ALLOWED_KEYS for key in payload.keys()):
        raise AuthServiceError("Unsupported signup option")


def _reject_unsupported_custom_confirm_signup_options(payload: Dict[str, Any]) -> None:
    if not all(str(key) in CUSTOM_CONFIRM_SIGNUP_ALLOWED_KEYS for key in payload.keys()):
        raise AuthServiceError("Unsupported signup confirmation option")


def _reject_unsupported_custom_resend_confirmation_options(payload: Dict[str, Any]) -> None:
    if not all(str(key) in CUSTOM_RESEND_CONFIRMATION_ALLOWED_KEYS for key in payload.keys()):
        raise AuthServiceError("Unsupported confirmation resend option")


def _reject_unsupported_custom_password_recovery_options(payload: Dict[str, Any]) -> None:
    if not all(str(key) in CUSTOM_PASSWORD_RECOVERY_ALLOWED_KEYS for key in payload.keys()):
        raise AuthServiceError("Unsupported password recovery option")


def _reject_unsupported_custom_confirm_password_recovery_options(payload: Dict[str, Any]) -> None:
    if not all(str(key) in CUSTOM_CONFIRM_PASSWORD_RECOVERY_ALLOWED_KEYS for key in payload.keys()):
        raise AuthServiceError("Unsupported password reset option")


def _custom_auth_profile(payload: Dict[str, Any], policy_key: str) -> tuple[str, Dict[str, Any]]:
    domain = normalize_domain(payload.get("domain"))
    _enforce_runtime_origin_domain(_AUTH_REQUEST_ORIGIN, domain)
    registry = load_auth_registry_for_domain(domain)
    profile = _find_profile(registry, str(payload.get("authProfileId") or registry.get("defaultAuthProfileId") or ""))
    profile = _profile_with_effective_auth_state(domain, profile)
    if _profile_status(profile) != "active":
        raise AuthServiceError("Auth profile is not active")
    policy = _custom_auth_policy(profile, policy_key)
    if policy.get("enabled") is not True:
        raise AuthServiceError(f"Custom auth {policy_key} is disabled")
    return domain, profile


def _custom_auth_policy(profile: Dict[str, Any], policy_key: str) -> Dict[str, Any]:
    custom_auth = profile.get("customAuth")
    if not isinstance(custom_auth, dict):
        return {}
    policy = custom_auth.get(policy_key)
    return policy if isinstance(policy, dict) else {}


def _custom_auth_client_id(profile: Dict[str, Any]) -> str:
    client_id = str(profile.get("clientId") or "").strip()
    if not client_id:
        audiences = _audiences(profile)
        client_id = audiences[0] if audiences else ""
    if not client_id:
        raise AuthRegistryError("Custom auth profile requires clientId")
    return client_id


def _profile_user_pool_id(profile: Dict[str, Any]) -> str:
    explicit = str(profile.get("userPoolId") or "").strip()
    if explicit:
        return explicit
    issuer = str(profile.get("issuer") or "").strip()
    try:
        parsed = urllib.parse.urlparse(issuer)
        pool_id = parsed.path.strip("/").split("/")[-1]
    except Exception:
        pool_id = ""
    if not pool_id:
        raise AuthRegistryError("Custom auth profile requires userPoolId")
    return pool_id


def _custom_signup_default_groups(profile: Dict[str, Any], signup_policy: Dict[str, Any]) -> list[str]:
    groups = _string_list(signup_policy.get("defaultGroups"))
    allowed_groups = set(_string_list(profile.get("allowedGroups")))
    if any(group not in allowed_groups for group in groups):
        raise AuthRegistryError("Custom signup default groups must be allowed groups")
    return groups


def _custom_auth_client_metadata(domain: str, profile: Dict[str, Any], language: str) -> Dict[str, str]:
    metadata = {
        "domain": normalize_domain(domain),
        "authProfileId": _profile_id(profile),
    }
    if language:
        metadata["language"] = language
    return metadata


def _public_session_from_claims(profile: Dict[str, Any], claims: Dict[str, Any]) -> Dict[str, Any]:
    subject = str(claims.get("sub") or claims.get("username") or "").strip()
    expires_at_epoch_seconds = int(claims.get("exp") or 0)
    if not subject or expires_at_epoch_seconds <= int(time.time()):
        raise AuthServiceError("Sign-in failed")

    group_claim = str(profile.get("groupClaim") or "cognito:groups")
    public_profile: Dict[str, Any] = {
        "subject": subject,
        "roles": _string_list(claims.get(group_claim)),
    }
    display_name = str(claims.get("name") or claims.get("preferred_username") or "").strip()
    email = str(claims.get("email") or "").strip()
    if display_name:
        public_profile["displayName"] = display_name
    if email:
        public_profile["email"] = email

    return {
        "profile": public_profile,
        "provider": str(profile.get("provider") or "cognito"),
        "expiresAtEpochMs": expires_at_epoch_seconds * 1000,
    }


def _email(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if not normalized or len(normalized) > 320 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", normalized):
        raise AuthServiceError("Invalid email")
    return normalized


def _password(value: Any) -> str:
    password = str(value or "")
    if len(password) < 1 or CONTROL_OR_WHITESPACE_RE.search(password):
        raise AuthServiceError("Invalid password")
    return password


def _code(value: Any) -> str:
    code = str(value or "").strip()
    if not code or len(code) > 128 or CONTROL_OR_WHITESPACE_RE.search(code):
        raise AuthServiceError("Invalid confirmation code")
    return code


def _language(value: Any) -> str:
    normalized = str(value or "").strip().replace("_", "-")
    if not normalized:
        return ""
    return normalized if re.fullmatch(r"[a-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,3}", normalized) else ""


def _code_delivery_response(details: Any) -> Dict[str, Any]:
    if not isinstance(details, dict):
        return {}
    safe_details = {
        key: str(details.get(key) or "").strip()
        for key in ("AttributeName", "DeliveryMedium", "Destination")
        if str(details.get(key) or "").strip()
    }
    return {"delivery": safe_details} if safe_details else {}


def _executor_mode(payload: Dict[str, Any]) -> str:
    mode = str(payload.get("mode") or "").strip().lower()
    if mode not in PROVISIONING_EXECUTOR_MODES:
        raise AuthServiceError("Unsupported auth provisioning executor mode")
    return mode


def _validate_executor_plan_key(payload: Dict[str, Any], plan: Dict[str, Any]) -> None:
    requested_plan_key = str(payload.get("planKey") or "").strip()
    if requested_plan_key and requested_plan_key != str(plan.get("planKey") or ""):
        raise AuthServiceError("Provisioning executor planKey does not match current plan")


def _executor_idempotency_key(plan: Dict[str, Any], mode: str, requested_idempotency_key: Any) -> str:
    expected = _stable_key(
        "executor",
        AUTH_PROVISIONING_EXECUTOR_SCHEMA_VERSION,
        str(plan.get("planVersion") or ""),
        str(plan.get("planKey") or ""),
        str(plan.get("configHash") or ""),
        mode,
    )
    requested = str(requested_idempotency_key or "").strip()
    if requested:
        if not re.fullmatch(r"[0-9a-f]{64}", requested):
            raise AuthServiceError("Provisioning executor idempotencyKey is invalid")
        if requested != expected:
            raise AuthServiceError("Provisioning executor idempotencyKey does not match current plan")
    return expected


def _validate_apply_request(event: Dict[str, Any], payload: Dict[str, Any], plan: Dict[str, Any]) -> None:
    if not str(payload.get("planKey") or "").strip():
        raise AuthServiceError("Provisioning executor apply requires planKey")
    if not str(payload.get("idempotencyKey") or "").strip():
        raise AuthServiceError("Provisioning executor apply requires idempotencyKey")
    _validate_executor_plan_key(payload, plan)
    _executor_idempotency_key(plan, "apply", payload.get("idempotencyKey"))
    caller_arn = _caller_arn(event)
    allowed_arns = set(_csv_env("AUTH_PROVISIONING_ALLOWED_ROLE_ARNS", AUTH_PROVISIONING_ALLOWED_ROLE_ARNS))
    if not caller_arn or caller_arn not in allowed_arns:
        raise AuthUnauthorizedError("Provisioning apply access denied")
    _validate_apply_domain_and_tenant(plan)
    _validate_apply_redirect_ownership(plan)


def _validate_apply_domain_and_tenant(plan: Dict[str, Any]) -> None:
    allowed_domains = set(_csv_env("AUTH_PROVISIONING_APPLY_ALLOWED_DOMAINS", AUTH_PROVISIONING_APPLY_ALLOWED_DOMAINS))
    allowed_tenants = set(_csv_env("AUTH_PROVISIONING_APPLY_ALLOWED_TENANTS", AUTH_PROVISIONING_APPLY_ALLOWED_TENANTS))
    domain = str(plan.get("domain") or "").strip()
    tenant_id = str(plan.get("tenantId") or "").strip()
    if allowed_domains and domain not in allowed_domains:
        raise AuthServiceError("Provisioning apply domain is not allowed")
    if allowed_tenants and tenant_id not in allowed_tenants:
        raise AuthServiceError("Provisioning apply tenant is not allowed")


def _validate_apply_redirect_ownership(plan: Dict[str, Any]) -> None:
    domain = str(plan.get("domain") or "").strip()
    expected_outputs = plan.get("expectedOutputs") if isinstance(plan.get("expectedOutputs"), dict) else {}
    for field_name in ("callbackUrls", "logoutUrls"):
        for url in _string_list((expected_outputs or {}).get(field_name)):
            parsed = urllib.parse.urlparse(url)
            host = normalize_domain(parsed.hostname or "")
            if not host:
                raise AuthServiceError("Provisioning apply URL host is invalid")
            if host == domain or host.endswith(f".{domain}"):
                continue
            if _origin_aliases_requested_domain(host, domain):
                continue
            raise AuthServiceError("Provisioning apply URL host is not allowed for domain")


def _cognito_executor_preview(
    plan: Dict[str, Any],
    *,
    mode: str,
    requested_idempotency_key: Any = None,
) -> Dict[str, Any]:
    idempotency_key = _executor_idempotency_key(plan, mode, requested_idempotency_key)
    operations = [_executor_operation_preview(operation) for operation in plan.get("operations", []) if isinstance(operation, dict)]
    execution_status = "preview-only" if mode == "dry-run" else "manual-review-required"
    audit_event = {
        "eventType": "cognito-provisioning-executor",
        "auditKey": _stable_key(
            "audit",
            AUTH_PROVISIONING_EXECUTOR_SCHEMA_VERSION,
            str(plan.get("planKey") or ""),
            idempotency_key,
            mode,
            execution_status,
        ),
        "schemaVersion": AUTH_PROVISIONING_EXECUTOR_SCHEMA_VERSION,
        "mode": mode,
        "executionStatus": execution_status,
        "planKey": str(plan.get("planKey") or ""),
        "configHash": str(plan.get("configHash") or ""),
        "idempotencyKey": idempotency_key,
        "domain": str(plan.get("domain") or ""),
        "authProfileId": str(plan.get("authProfileId") or ""),
        "operationCount": len(operations),
        "mutationAttempted": False,
    }
    return {
        "schemaVersion": AUTH_PROVISIONING_EXECUTOR_SCHEMA_VERSION,
        "provider": "cognito",
        "mode": mode,
        "executionStatus": execution_status,
        "planVersion": str(plan.get("planVersion") or ""),
        "planKey": str(plan.get("planKey") or ""),
        "configHash": str(plan.get("configHash") or ""),
        "idempotencyKey": idempotency_key,
        "target": {
            "domain": str(plan.get("domain") or ""),
            "authProfileId": str(plan.get("authProfileId") or ""),
        },
        "operations": operations,
        "auditEvent": audit_event,
    }


def _cognito_executor_apply(plan: Dict[str, Any], *, requested_idempotency_key: Any = None) -> Dict[str, Any]:
    idempotency_key = _executor_idempotency_key(plan, "apply", requested_idempotency_key)
    operations = [operation for operation in plan.get("operations", []) if isinstance(operation, dict)]
    operation_outputs = _load_existing_operation_outputs(plan, operations)
    provider_credentials = _preflight_social_identity_provider_credentials(plan)
    applied_operations: list[Dict[str, Any]] = []

    for operation in operations:
        existing = _load_operation_state(plan, operation)
        if _operation_state_succeeded(existing, operation):
            outputs = _state_outputs(existing)
            operation_outputs.update(outputs)
            applied_operations.append(_applied_operation_result(operation, status="skipped", outputs=outputs))
            continue

        try:
            _write_operation_state(plan, operation, status="in-progress", outputs={})
            outputs = _execute_cognito_operation(
                operation,
                plan,
                operation_outputs=operation_outputs,
                provider_credentials=provider_credentials,
            )
            operation_outputs.update(outputs)
            _write_operation_state(plan, operation, status="succeeded", outputs=outputs)
            applied_operations.append(_applied_operation_result(operation, status="succeeded", outputs=outputs))
        except Exception as exc:
            if str(exc) != "Cognito provisioning operation is already in progress":
                _write_operation_state(
                    plan,
                    operation,
                    status="failed",
                    outputs={},
                    error_type=type(exc).__name__,
                )
            applied_operations.append(_applied_operation_result(
                operation,
                status="failed",
                error_type=type(exc).__name__,
            ))
            return _executor_apply_response(
                plan,
                idempotency_key=idempotency_key,
                execution_status="failed",
                operations=applied_operations,
                operation_outputs=operation_outputs,
                error_type=type(exc).__name__,
            )

    _write_effective_auth_state(plan, operation_outputs)
    return _executor_apply_response(
        plan,
        idempotency_key=idempotency_key,
        execution_status="applied",
        operations=applied_operations,
        operation_outputs=operation_outputs,
    )


def _executor_apply_response(
    plan: Dict[str, Any],
    *,
    idempotency_key: str,
    execution_status: str,
    operations: list[Dict[str, Any]],
    operation_outputs: Dict[str, Any],
    error_type: str = "",
) -> Dict[str, Any]:
    audit_event = {
        "eventType": "cognito-provisioning-executor",
        "auditKey": _stable_key(
            "audit",
            AUTH_PROVISIONING_EXECUTOR_SCHEMA_VERSION,
            str(plan.get("planKey") or ""),
            idempotency_key,
            "apply",
            execution_status,
        ),
        "schemaVersion": AUTH_PROVISIONING_EXECUTOR_SCHEMA_VERSION,
        "mode": "apply",
        "executionStatus": execution_status,
        "planKey": str(plan.get("planKey") or ""),
        "configHash": str(plan.get("configHash") or ""),
        "idempotencyKey": idempotency_key,
        "domain": str(plan.get("domain") or ""),
        "authProfileId": str(plan.get("authProfileId") or ""),
        "operationCount": len(operations),
        "mutationAttempted": True,
    }
    if error_type:
        audit_event["errorType"] = error_type

    response = {
        "schemaVersion": AUTH_PROVISIONING_EXECUTOR_SCHEMA_VERSION,
        "provider": "cognito",
        "mode": "apply",
        "executionStatus": execution_status,
        "planVersion": str(plan.get("planVersion") or ""),
        "planKey": str(plan.get("planKey") or ""),
        "configHash": str(plan.get("configHash") or ""),
        "idempotencyKey": idempotency_key,
        "target": {
            "domain": str(plan.get("domain") or ""),
            "authProfileId": str(plan.get("authProfileId") or ""),
        },
        "operations": operations,
        "outputs": _sanitize_apply_outputs(operation_outputs),
        "auditEvent": audit_event,
    }
    if error_type:
        response["errorType"] = error_type
    return response


def _execute_cognito_operation(
    operation: Dict[str, Any],
    plan: Dict[str, Any],
    *,
    operation_outputs: Dict[str, Any],
    provider_credentials: Dict[str, Dict[str, str]],
) -> Dict[str, Any]:
    operation_id = str(operation.get("operationId") or "")
    if operation_id == "ensure-user-pool":
        return _ensure_cognito_user_pool(plan, operation_outputs)
    if operation_id == "ensure-hosted-ui-domain":
        return _ensure_cognito_hosted_ui_domain(plan, operation_outputs)
    if operation_id == "ensure-public-client":
        return _ensure_cognito_public_client(plan, operation_outputs)
    if operation_id == "ensure-user-groups":
        return _ensure_cognito_user_groups(plan, operation_outputs)
    if operation_id == "ensure-social-identity-providers":
        return _ensure_cognito_social_identity_providers(plan, operation_outputs, provider_credentials)
    if operation_id == "finalize-runtime-activation":
        return _finalize_cognito_runtime_activation(plan, operation_outputs)
    raise AuthServiceError("Unsupported Cognito provisioning operation")


def _ensure_cognito_user_pool(plan: Dict[str, Any], operation_outputs: Dict[str, Any]) -> Dict[str, Any]:
    existing_pool_id = str(operation_outputs.get("userPoolId") or "").strip()
    if existing_pool_id:
        _cognito_idp().describe_user_pool(UserPoolId=existing_pool_id)
        return {"userPoolId": existing_pool_id}

    pool_name = _cognito_resource_name(plan, "user-pool")
    reconciled_pool_id = _find_cognito_user_pool_by_name(plan, pool_name)
    if reconciled_pool_id:
        return {
            "userPoolId": reconciled_pool_id,
            "issuer": f"https://cognito-idp.{_aws_region()}.amazonaws.com/{reconciled_pool_id}",
        }

    response = _cognito_idp().create_user_pool(
        PoolName=pool_name,
        UsernameAttributes=["email"],
        AutoVerifiedAttributes=["email"],
        Schema=[
            {
                "Name": "email",
                "AttributeDataType": "String",
                "Mutable": True,
                "Required": True,
            },
            {
                "Name": "tenant_id",
                "AttributeDataType": "String",
                "Mutable": True,
                "Required": False,
                "StringAttributeConstraints": {"MinLength": "1", "MaxLength": "80"},
            },
        ],
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 12,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
                "RequireUppercase": True,
            },
        },
        UserPoolTags=_cognito_resource_tags(plan),
    )
    user_pool_id = str(((response.get("UserPool") or {}).get("Id")) or "").strip()
    if not user_pool_id:
        raise AuthServiceError("Cognito user pool creation did not return an id")
    return {
        "userPoolId": user_pool_id,
        "issuer": f"https://cognito-idp.{_aws_region()}.amazonaws.com/{user_pool_id}",
    }


def _ensure_cognito_hosted_ui_domain(plan: Dict[str, Any], operation_outputs: Dict[str, Any]) -> Dict[str, Any]:
    user_pool_id = _required_output(operation_outputs, "userPoolId")
    domain_prefix = _hosted_ui_domain_prefix(plan)
    describe = _safe_cognito_call(
        "describe_user_pool_domain",
        Domain=domain_prefix,
    )
    domain_description = describe.get("DomainDescription") if isinstance(describe, dict) else {}
    existing_pool_id = str((domain_description or {}).get("UserPoolId") or "").strip()
    if existing_pool_id:
        if existing_pool_id != user_pool_id:
            raise AuthServiceError("Hosted UI domain belongs to another user pool")
    else:
        _cognito_idp().create_user_pool_domain(Domain=domain_prefix, UserPoolId=user_pool_id)
    return {
        "hostedUiDomainPrefix": domain_prefix,
        "hostedUiDomain": f"https://{domain_prefix}.auth.{_aws_region()}.amazoncognito.com",
    }


def _ensure_cognito_public_client(plan: Dict[str, Any], operation_outputs: Dict[str, Any]) -> Dict[str, Any]:
    user_pool_id = _required_output(operation_outputs, "userPoolId")
    existing_client_id = str(operation_outputs.get("userPoolClientId") or "").strip()
    supported_providers = _supported_identity_provider_names(plan, include_social=False)
    if existing_client_id:
        _validate_cognito_public_client(user_pool_id, existing_client_id)
        _update_cognito_public_client(plan, user_pool_id, existing_client_id, supported_providers)
        return {"userPoolClientId": existing_client_id, "clientId": existing_client_id}

    public_client = (plan.get("runtimeAuth") or {}).get("publicClient") if isinstance(plan.get("runtimeAuth"), dict) else {}
    client_name = _cognito_resource_name(plan, "public-client")
    reconciled_client_id = _find_cognito_user_pool_client_by_name(user_pool_id, client_name)
    if reconciled_client_id:
        _validate_cognito_public_client(user_pool_id, reconciled_client_id)
        _update_cognito_public_client(plan, user_pool_id, reconciled_client_id, supported_providers)
        return {"userPoolClientId": reconciled_client_id, "clientId": reconciled_client_id}

    response = _cognito_idp().create_user_pool_client(
        UserPoolId=user_pool_id,
        ClientName=client_name,
        GenerateSecret=False,
        PreventUserExistenceErrors="ENABLED",
        SupportedIdentityProviders=supported_providers,
        AllowedOAuthFlowsUserPoolClient=True,
        AllowedOAuthFlows=["code"],
        AllowedOAuthScopes=_string_list((public_client or {}).get("scopes")) or ["openid", "email", "profile"],
        CallbackURLs=_string_list((public_client or {}).get("callbackUrls")),
        LogoutURLs=_string_list((public_client or {}).get("logoutUrls")),
        ExplicitAuthFlows=["ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_SRP_AUTH"],
    )
    client_id = str(((response.get("UserPoolClient") or {}).get("ClientId")) or "").strip()
    if not client_id:
        raise AuthServiceError("Cognito app client creation did not return an id")
    return {"userPoolClientId": client_id, "clientId": client_id}


def _ensure_cognito_user_groups(plan: Dict[str, Any], operation_outputs: Dict[str, Any]) -> Dict[str, Any]:
    user_pool_id = _required_output(operation_outputs, "userPoolId")
    desired_groups = _string_list((plan.get("groups") or {}).get("allowed") if isinstance(plan.get("groups"), dict) else [])
    existing_groups = _list_cognito_groups(user_pool_id)
    created: list[str] = []
    for group_name in desired_groups:
        if group_name in existing_groups:
            continue
        _cognito_idp().create_group(
            UserPoolId=user_pool_id,
            GroupName=group_name,
            Description=f"Zoolanding auth group {group_name}",
        )
        created.append(group_name)
    return {"groups": desired_groups, "createdGroups": created}


def _ensure_cognito_social_identity_providers(
    plan: Dict[str, Any],
    operation_outputs: Dict[str, Any],
    provider_credentials: Dict[str, Dict[str, str]],
) -> Dict[str, Any]:
    user_pool_id = _required_output(operation_outputs, "userPoolId")
    client_id = _required_output(operation_outputs, "userPoolClientId")
    provider_names: list[str] = []
    for provider in plan.get("socialIdentityProviders") or []:
        if not isinstance(provider, dict) or not provider.get("enabled", True):
            continue
        provider_name = _cognito_provider_name(provider)
        credentials = provider_credentials.get(str(provider.get("providerId") or ""))
        if not credentials:
            raise AuthServiceError("Social identity provider credentials are missing")
        provider_details = _cognito_provider_details(provider, credentials)
        attribute_mapping = _cognito_provider_attribute_mapping(provider)
        existing = _safe_cognito_call(
            "describe_identity_provider",
            UserPoolId=user_pool_id,
            ProviderName=provider_name,
        )
        if existing:
            _cognito_idp().update_identity_provider(
                UserPoolId=user_pool_id,
                ProviderName=provider_name,
                ProviderDetails=provider_details,
                AttributeMapping=attribute_mapping,
            )
        else:
            _cognito_idp().create_identity_provider(
                UserPoolId=user_pool_id,
                ProviderName=provider_name,
                ProviderType=_cognito_provider_type(provider),
                ProviderDetails=provider_details,
                AttributeMapping=attribute_mapping,
            )
        provider_names.append(provider_name)

    _update_cognito_public_client(
        plan,
        user_pool_id,
        client_id,
        _supported_identity_provider_names(plan, include_social=True),
    )
    return {"identityProviders": provider_names}


def _finalize_cognito_runtime_activation(plan: Dict[str, Any], operation_outputs: Dict[str, Any]) -> Dict[str, Any]:
    user_pool_id = _required_output(operation_outputs, "userPoolId")
    client_id = _required_output(operation_outputs, "userPoolClientId")
    hosted_ui_domain = _required_output(operation_outputs, "hostedUiDomain")
    return {
        "activation": {
            "status": "active",
            "issuer": f"https://cognito-idp.{_aws_region()}.amazonaws.com/{user_pool_id}",
            "clientId": client_id,
            "hostedUiDomain": hosted_ui_domain,
        }
    }


def _executor_operation_preview(operation: Dict[str, Any]) -> Dict[str, Any]:
    sanitized = {
        "operationId": str(operation.get("operationId") or ""),
        "operationKey": str(operation.get("operationKey") or ""),
        "idempotencyKey": str(operation.get("idempotencyKey") or ""),
        "stage": str(operation.get("stage") or ""),
        "expectedStatusAfterCompletion": str(operation.get("expectedStatusAfterCompletion") or ""),
        "willMutate": False,
    }
    depends_on = _string_list(operation.get("dependsOn"))
    if depends_on:
        sanitized["dependsOn"] = depends_on
    target = operation.get("target") if isinstance(operation.get("target"), dict) else {}
    sanitized["target"] = {
        "domain": str(target.get("domain") or ""),
        "authProfileId": str(target.get("authProfileId") or ""),
    }
    return sanitized


def _applied_operation_result(
    operation: Dict[str, Any],
    *,
    status: str,
    outputs: Optional[Dict[str, Any]] = None,
    error_type: str = "",
) -> Dict[str, Any]:
    result = _executor_operation_preview(operation)
    result["status"] = status
    result["willMutate"] = status != "skipped"
    sanitized_outputs = _sanitize_apply_outputs(outputs or {})
    if sanitized_outputs:
        result["outputs"] = sanitized_outputs
    if error_type:
        result["errorType"] = error_type
    return result


def _auth_provisioning_apply_enabled() -> bool:
    return str(os.getenv("AUTH_PROVISIONING_APPLY_ENABLED", AUTH_PROVISIONING_APPLY_ENABLED)).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _load_existing_operation_outputs(plan: Dict[str, Any], operations: list[Dict[str, Any]]) -> Dict[str, Any]:
    outputs: Dict[str, Any] = {}
    for operation in operations:
        state = _load_operation_state(plan, operation)
        if _operation_state_succeeded(state, operation):
            outputs.update(_state_outputs(state))
    return outputs


def _operation_state_succeeded(state: Dict[str, Any], operation: Dict[str, Any]) -> bool:
    if not state:
        return False
    return (
        state.get("status") == "succeeded"
        and state.get("operationId") == operation.get("operationId")
        and state.get("idempotencyKey") == operation.get("idempotencyKey")
    )


def _load_operation_state(plan: Dict[str, Any], operation: Dict[str, Any]) -> Dict[str, Any]:
    table_name = _provisioning_state_table_name()
    key = _operation_state_key(plan, operation)
    response = _dynamodb().get_item(
        TableName=table_name,
        Key={
            "pk": {"S": key["pk"]},
            "sk": {"S": key["sk"]},
        },
        ConsistentRead=True,
    )
    return _from_dynamodb_item(response.get("Item") or {})


def _write_operation_state(
    plan: Dict[str, Any],
    operation: Dict[str, Any],
    *,
    status: str,
    outputs: Dict[str, Any],
    error_type: str = "",
) -> None:
    table_name = _provisioning_state_table_name()
    key = _operation_state_key(plan, operation)
    item = {
        "pk": {"S": key["pk"]},
        "sk": {"S": key["sk"]},
        "recordType": {"S": "operation"},
        "domain": {"S": str(plan.get("domain") or "")},
        "authProfileId": {"S": str(plan.get("authProfileId") or "")},
        "tenantId": {"S": str(plan.get("tenantId") or "")},
        "planKey": {"S": str(plan.get("planKey") or "")},
        "configHash": {"S": str(plan.get("configHash") or "")},
        "operationId": {"S": str(operation.get("operationId") or "")},
        "idempotencyKey": {"S": str(operation.get("idempotencyKey") or "")},
        "status": {"S": status},
        "outputsJson": {"S": json.dumps(_sanitize_apply_outputs(outputs), sort_keys=True, separators=(",", ":"))},
    }
    if error_type:
        item["errorType"] = {"S": error_type}
    kwargs: Dict[str, Any] = {"TableName": table_name, "Item": item}
    if status == "in-progress":
        item["lockExpiresAt"] = {"N": str(int(time.time()) + 900)}
        kwargs["ConditionExpression"] = (
            "attribute_not_exists(pk) OR #status = :failed OR "
            "(#status = :inProgress AND lockExpiresAt < :now)"
        )
        kwargs["ExpressionAttributeNames"] = {"#status": "status"}
        kwargs["ExpressionAttributeValues"] = {
            ":failed": {"S": "failed"},
            ":inProgress": {"S": "in-progress"},
            ":now": {"N": str(int(time.time()))},
        }
    try:
        _dynamodb().put_item(**kwargs)
    except Exception as exc:
        if exc.__class__.__name__ == "ConditionalCheckFailedException":
            raise AuthServiceError("Cognito provisioning operation is already in progress") from exc
        raise


def _profile_with_effective_auth_state(domain: str, profile: Dict[str, Any]) -> Dict[str, Any]:
    try:
        plan = _cognito_plan(domain, profile)
        state = _load_effective_auth_state(plan)
    except Exception as exc:
        log("WARNING", "Unable to load effective auth state", domain=domain, authProfileId=_profile_id(profile), errorType=type(exc).__name__)
        return profile
    if state.get("status") != "active":
        return profile
    if state.get("configHash") != plan.get("configHash"):
        return profile
    runtime_auth = state.get("runtimeAuth") if isinstance(state.get("runtimeAuth"), dict) else {}
    client_id = str(runtime_auth.get("clientId") or "").strip()
    issuer = str(runtime_auth.get("issuer") or "").strip()
    hosted_ui_domain = str(runtime_auth.get("hostedUiDomain") or "").strip()
    if not client_id or not issuer or not hosted_ui_domain:
        return profile
    merged = dict(profile)
    merged.update({
        "status": "active",
        "issuer": issuer,
        "hostedUiDomain": hosted_ui_domain,
        "clientId": client_id,
        "audiences": [client_id],
        "jwksUrl": _jwks_url(issuer),
        "userPoolId": str(runtime_auth.get("userPoolId") or "").strip(),
    })
    return merged


def _load_effective_auth_state(plan: Dict[str, Any]) -> Dict[str, Any]:
    table_name = str(os.getenv("AUTH_PROVISIONING_STATE_TABLE_NAME", AUTH_PROVISIONING_STATE_TABLE_NAME)).strip()
    if not table_name or boto3 is None:
        return {}
    key = _auth_state_key(plan)
    response = _dynamodb().get_item(
        TableName=table_name,
        Key={"pk": {"S": key["pk"]}, "sk": {"S": key["sk"]}},
        ConsistentRead=True,
    )
    item = _from_dynamodb_item(response.get("Item") or {})
    runtime_auth = str(item.get("runtimeAuthJson") or "").strip()
    if runtime_auth:
        try:
            parsed = json.loads(runtime_auth)
            item["runtimeAuth"] = parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            item["runtimeAuth"] = {}
    return item


def _write_effective_auth_state(plan: Dict[str, Any], operation_outputs: Dict[str, Any]) -> None:
    table_name = _provisioning_state_table_name()
    key = _auth_state_key(plan)
    activation = operation_outputs.get("activation") if isinstance(operation_outputs.get("activation"), dict) else {}
    runtime_auth = {
        "status": "active",
        "issuer": str((activation or {}).get("issuer") or operation_outputs.get("issuer") or ""),
        "hostedUiDomain": str((activation or {}).get("hostedUiDomain") or operation_outputs.get("hostedUiDomain") or ""),
        "clientId": str((activation or {}).get("clientId") or operation_outputs.get("clientId") or operation_outputs.get("userPoolClientId") or ""),
        "userPoolId": str(operation_outputs.get("userPoolId") or ""),
    }
    item = {
        "pk": {"S": key["pk"]},
        "sk": {"S": key["sk"]},
        "recordType": {"S": "auth-state"},
        "status": {"S": "active"},
        "domain": {"S": str(plan.get("domain") or "")},
        "authProfileId": {"S": str(plan.get("authProfileId") or "")},
        "tenantId": {"S": str(plan.get("tenantId") or "")},
        "planKey": {"S": str(plan.get("planKey") or "")},
        "configHash": {"S": str(plan.get("configHash") or "")},
        "runtimeAuthJson": {"S": json.dumps(runtime_auth, sort_keys=True, separators=(",", ":"))},
    }
    _dynamodb().put_item(TableName=table_name, Item=item)


def _auth_state_key(plan: Dict[str, Any]) -> Dict[str, str]:
    return {
        "pk": "AUTH#{}#{}".format(str(plan.get("domain") or ""), str(plan.get("authProfileId") or "")),
        "sk": "STATE",
    }


def _operation_state_key(plan: Dict[str, Any], operation: Dict[str, Any]) -> Dict[str, str]:
    return {
        "pk": "AUTH#{}#{}".format(
            str(plan.get("domain") or ""),
            str(plan.get("authProfileId") or ""),
        ),
        "sk": "OP#{}#{}#{}".format(
            str(plan.get("configHash") or ""),
            str(operation.get("operationId") or ""),
            str(operation.get("idempotencyKey") or ""),
        ),
    }


def _state_outputs(state: Dict[str, Any]) -> Dict[str, Any]:
    raw = str(state.get("outputsJson") or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _from_dynamodb_item(item: Dict[str, Any]) -> Dict[str, Any]:
    parsed: Dict[str, Any] = {}
    for key, value in item.items():
        if isinstance(value, dict):
            if "S" in value:
                parsed[key] = value.get("S")
            elif "N" in value:
                parsed[key] = value.get("N")
            elif "BOOL" in value:
                parsed[key] = value.get("BOOL")
    return parsed


def _preflight_social_identity_provider_credentials(plan: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    credentials: Dict[str, Dict[str, str]] = {}
    for provider in plan.get("socialIdentityProviders") or []:
        if not isinstance(provider, dict) or not provider.get("enabled", True):
            continue
        provider_id = str(provider.get("providerId") or "").strip()
        credentials[provider_id] = _resolve_social_identity_provider_credentials(provider, plan)
    return credentials


def _resolve_social_identity_provider_credentials(provider: Dict[str, Any], plan: Dict[str, Any]) -> Dict[str, str]:
    secret_refs = provider.get("secretRefs") if isinstance(provider.get("secretRefs"), dict) else {}
    merged: Dict[str, str] = {}
    provider_ref = str(secret_refs.get("provider") or "").strip()
    if provider_ref:
        merged.update(_secret_ref_object(provider_ref, plan))

    client_id_ref = str(secret_refs.get("clientId") or "").strip()
    client_secret_ref = str(secret_refs.get("clientSecret") or "").strip()
    if client_id_ref:
        merged["clientId"] = _secret_ref_string(client_id_ref, plan, preferred_key="clientId")
    if client_secret_ref:
        merged["clientSecret"] = _secret_ref_string(client_secret_ref, plan, preferred_key="clientSecret")

    client_id = str(merged.get("clientId") or merged.get("client_id") or "").strip()
    client_secret = str(merged.get("clientSecret") or merged.get("client_secret") or "").strip()
    _reject_placeholder_secret_value(client_id)
    _reject_placeholder_secret_value(client_secret)
    if not client_id or not client_secret:
        raise AuthServiceError("Social identity provider credentials are incomplete")
    return {"clientId": client_id, "clientSecret": client_secret}


def _secret_ref_object(secret_ref: str, plan: Dict[str, Any]) -> Dict[str, Any]:
    parsed = _load_secret_ref(secret_ref, plan)
    if isinstance(parsed, dict):
        return parsed
    raise AuthServiceError("Social identity provider credential secret must be a JSON object")


def _secret_ref_string(secret_ref: str, plan: Dict[str, Any], *, preferred_key: str) -> str:
    parsed = _load_secret_ref(secret_ref, plan)
    if isinstance(parsed, str):
        return parsed.strip()
    if isinstance(parsed, dict):
        value = parsed.get(preferred_key) or parsed.get(_snake_case(preferred_key))
        if isinstance(value, str):
            return value.strip()
    raise AuthServiceError("Social identity provider credential secret is invalid")


def _load_secret_ref(secret_ref: str, plan: Dict[str, Any]) -> Any:
    _validate_secret_ref_value(secret_ref, "socialIdentityProviders.secretRefs")
    _validate_secret_ref_scope(secret_ref, plan)
    if ":secret:" in str(secret_ref):
        return _load_secrets_manager_ref(secret_ref)
    ssm_value = _load_ssm_secret_ref(secret_ref)
    if ssm_value is not None:
        return ssm_value
    return _load_secrets_manager_ref(secret_ref)


def _validate_secret_ref_scope(secret_ref: str, plan: Dict[str, Any]) -> None:
    ref = str(secret_ref or "").strip()
    tenant_id = str(plan.get("tenantId") or "").strip()
    if not tenant_id:
        raise AuthServiceError("Provisioning tenant is missing")
    allowed_path_prefix = f"/zoolanding/auth/{tenant_id}/"
    allowed_ssm_arn_fragment = f":parameter/zoolanding/auth/{tenant_id}/"
    allowed_secret_arn_fragment = f":secret:/zoolanding/auth/{tenant_id}/"
    if ref.startswith(allowed_path_prefix):
        return
    if ":parameter/" in ref and allowed_ssm_arn_fragment in ref:
        return
    if ":secret:" in ref and allowed_secret_arn_fragment in ref:
        return
    raise AuthServiceError("Social identity provider credential reference is outside tenant scope")


def _reject_placeholder_secret_value(value: str) -> None:
    normalized = str(value or "").strip().lower()
    placeholders = {
        "",
        "__set_in_aws_console__",
        "__set_me__",
        "changeme",
        "change-me",
        "todo",
        "placeholder",
        "replace-me",
    }
    if normalized in placeholders or normalized.startswith("fake-"):
        raise AuthServiceError("Social identity provider credential secret is not configured")


def _load_ssm_secret_ref(secret_ref: str) -> Any:
    try:
        response = _ssm().get_parameter(Name=secret_ref, WithDecryption=True)
    except Exception as exc:
        if exc.__class__.__name__ == "ParameterNotFound":
            return None
        raise
    raw = (response.get("Parameter") or {}).get("Value")
    return _parse_secret_ref_payload(raw)


def _load_secrets_manager_ref(secret_ref: str) -> Any:
    try:
        response = _secrets_manager().get_secret_value(SecretId=secret_ref)
    except Exception as exc:
        if exc.__class__.__name__ in {"ResourceNotFoundException", "KeyError"}:
            raise AuthServiceError("Social identity provider credential secret is invalid") from exc
        raise
    raw = response.get("SecretString")
    return _parse_secret_ref_payload(raw)


def _parse_secret_ref_payload(raw: Any) -> Any:
    if not isinstance(raw, str) or not raw.strip():
        raise AuthServiceError("Social identity provider credential secret is missing")
    stripped = raw.strip()
    if stripped.startswith("{"):
        parsed = json.loads(stripped)
        if not isinstance(parsed, dict):
            raise AuthServiceError("Social identity provider credential secret is invalid")
        return parsed
    return stripped


def _sanitize_apply_outputs(outputs: Dict[str, Any]) -> Dict[str, Any]:
    allowed = {
        "activation",
        "clientId",
        "createdGroups",
        "groups",
        "hostedUiDomain",
        "hostedUiDomainPrefix",
        "identityProviders",
        "issuer",
        "userPoolClientId",
        "userPoolId",
    }
    sanitized: Dict[str, Any] = {}
    for key, value in (outputs or {}).items():
        if key not in allowed:
            continue
        if isinstance(value, dict):
            sanitized[key] = _sanitize_apply_outputs(value)
        elif isinstance(value, list):
            sanitized[key] = [str(item) for item in value if str(item).strip()]
        elif isinstance(value, (str, bool, int, float)) or value is None:
            sanitized[key] = value
    return sanitized


def _required_output(outputs: Dict[str, Any], key: str) -> str:
    value = str(outputs.get(key) or "").strip()
    if not value:
        raise AuthServiceError(f"Cognito provisioning output {key} is missing")
    return value


def _cognito_resource_name(plan: Dict[str, Any], suffix: str) -> str:
    base = "-".join((
        "zoolanding",
        _safe_name_segment(str(plan.get("domain") or "domain")),
        _safe_name_segment(str(plan.get("tenantId") or "tenant")),
        _safe_name_segment(str(plan.get("authProfileId") or "auth")),
        suffix,
    ))
    return base[:128].strip("-") or f"zoolanding-{suffix}"


def _cognito_resource_tags(plan: Dict[str, Any]) -> Dict[str, str]:
    return {
        "managedBy": "zoolandingpage",
        "domain": str(plan.get("domain") or ""),
        "tenantId": str(plan.get("tenantId") or ""),
        "authProfileId": str(plan.get("authProfileId") or ""),
        "configHash": str(plan.get("configHash") or ""),
    }


def _safe_name_segment(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9-]+", "-", str(value or "").strip().lower())
    return re.sub(r"-{2,}", "-", normalized).strip("-") or "default"


def _hosted_ui_domain_prefix(plan: Dict[str, Any]) -> str:
    hosted_ui = plan.get("hostedUi") if isinstance(plan.get("hostedUi"), dict) else {}
    domain_host = str((hosted_ui or {}).get("domainHost") or "").strip().lower()
    if not domain_host:
        raise AuthServiceError("Hosted UI domain is missing")
    suffix = f".auth.{_aws_region()}.amazoncognito.com"
    if domain_host.endswith(suffix):
        return domain_host[: -len(suffix)]
    return domain_host.split(".", 1)[0]


def _list_cognito_groups(user_pool_id: str) -> set[str]:
    groups: set[str] = set()
    kwargs: Dict[str, Any] = {"UserPoolId": user_pool_id, "Limit": 60}
    while True:
        response = _cognito_idp().list_groups(**kwargs)
        for group in response.get("Groups") or []:
            name = str(group.get("GroupName") or "").strip()
            if name:
                groups.add(name)
        token = response.get("NextToken")
        if not token:
            return groups
        kwargs["NextToken"] = token


def _find_cognito_user_pool_by_name(plan: Dict[str, Any], pool_name: str) -> str:
    matches: list[str] = []
    kwargs: Dict[str, Any] = {"MaxResults": 60}
    while True:
        response = _cognito_idp().list_user_pools(**kwargs)
        for user_pool in response.get("UserPools") or []:
            if str(user_pool.get("Name") or "") == pool_name:
                pool_id = str(user_pool.get("Id") or "").strip()
                if pool_id:
                    matches.append(pool_id)
        token = response.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token

    if len(matches) > 1:
        raise AuthServiceError("Multiple Cognito user pools match the planned name")
    if not matches:
        return ""
    _validate_cognito_user_pool_tags(plan, matches[0])
    return matches[0]


def _validate_cognito_user_pool_tags(plan: Dict[str, Any], user_pool_id: str) -> None:
    response = _cognito_idp().describe_user_pool(UserPoolId=user_pool_id)
    user_pool = response.get("UserPool") if isinstance(response, dict) else {}
    arn = str((user_pool or {}).get("Arn") or "").strip()
    if not arn:
        raise AuthServiceError("Cognito user pool cannot be reconciled without an ARN")
    tags_response = _cognito_idp().list_tags_for_resource(ResourceArn=arn)
    actual_tags = tags_response.get("Tags") if isinstance(tags_response, dict) else {}
    expected_tags = _cognito_resource_tags(plan)
    for key in ("managedBy", "domain", "tenantId", "authProfileId"):
        if str((actual_tags or {}).get(key) or "") != expected_tags[key]:
            raise AuthServiceError("Cognito user pool name is already used outside this auth profile")


def _find_cognito_user_pool_client_by_name(user_pool_id: str, client_name: str) -> str:
    matches: list[str] = []
    kwargs: Dict[str, Any] = {"UserPoolId": user_pool_id, "MaxResults": 60}
    while True:
        response = _cognito_idp().list_user_pool_clients(**kwargs)
        for client in response.get("UserPoolClients") or []:
            if str(client.get("ClientName") or "") == client_name:
                client_id = str(client.get("ClientId") or "").strip()
                if client_id:
                    matches.append(client_id)
        token = response.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token

    if len(matches) > 1:
        raise AuthServiceError("Multiple Cognito app clients match the planned name")
    return matches[0] if matches else ""


def _validate_cognito_public_client(user_pool_id: str, client_id: str) -> None:
    response = _cognito_idp().describe_user_pool_client(UserPoolId=user_pool_id, ClientId=client_id)
    user_pool_client = response.get("UserPoolClient") if isinstance(response, dict) else {}
    if str((user_pool_client or {}).get("ClientSecret") or "").strip():
        raise AuthServiceError("Existing Cognito app client is not public")


def _supported_identity_provider_names(plan: Dict[str, Any], *, include_social: bool) -> list[str]:
    providers = ["COGNITO"]
    if include_social:
        for provider in plan.get("socialIdentityProviders") or []:
            if isinstance(provider, dict) and provider.get("enabled", True):
                providers.append(_cognito_provider_name(provider))
    return providers


def _update_cognito_public_client(
    plan: Dict[str, Any],
    user_pool_id: str,
    client_id: str,
    supported_identity_providers: list[str],
) -> None:
    public_client = (plan.get("runtimeAuth") or {}).get("publicClient") if isinstance(plan.get("runtimeAuth"), dict) else {}
    _cognito_idp().update_user_pool_client(
        UserPoolId=user_pool_id,
        ClientId=client_id,
        SupportedIdentityProviders=supported_identity_providers,
        AllowedOAuthFlowsUserPoolClient=True,
        AllowedOAuthFlows=["code"],
        AllowedOAuthScopes=_string_list((public_client or {}).get("scopes")) or ["openid", "email", "profile"],
        CallbackURLs=_string_list((public_client or {}).get("callbackUrls")),
        LogoutURLs=_string_list((public_client or {}).get("logoutUrls")),
        ExplicitAuthFlows=["ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_SRP_AUTH"],
        PreventUserExistenceErrors="ENABLED",
    )


def _cognito_provider_name(provider: Dict[str, Any]) -> str:
    provider_type = str(provider.get("providerType") or "").strip().lower()
    if provider_type == "google":
        return "Google"
    if provider_type == "facebook":
        return "Facebook"
    return str(provider.get("providerId") or provider_type).strip()


def _cognito_provider_type(provider: Dict[str, Any]) -> str:
    provider_type = str(provider.get("providerType") or "").strip().lower()
    if provider_type == "google":
        return "Google"
    if provider_type == "facebook":
        return "Facebook"
    if provider_type == "oidc":
        return "OIDC"
    return provider_type.upper()


def _cognito_provider_details(provider: Dict[str, Any], credentials: Dict[str, str]) -> Dict[str, str]:
    provider_type = str(provider.get("providerType") or "").strip().lower()
    if provider_type == "facebook":
        scopes = ",".join(_string_list(provider.get("scopes")) or ["public_profile", "email"])
    else:
        scopes = " ".join(_string_list(provider.get("scopes")) or ["email", "profile", "openid"])
    details = {
        "client_id": credentials["clientId"],
        "client_secret": credentials["clientSecret"],
        "authorize_scopes": scopes,
    }
    if provider_type == "facebook":
        details["api_version"] = str(provider.get("apiVersion") or "v17.0")
    if provider_type == "oidc":
        oidc_mapping = {
            "issuer": "oidc_issuer",
            "authorizeUrl": "authorize_url",
            "tokenUrl": "token_url",
            "userInfoUrl": "attributes_url",
            "jwksUrl": "jwks_uri",
            "attributeRequestMethod": "attributes_request_method",
        }
        for source_key, target_key in oidc_mapping.items():
            value = str(provider.get(source_key) or "").strip()
            if value:
                details[target_key] = value
    return details


def _cognito_provider_attribute_mapping(provider: Dict[str, Any]) -> Dict[str, str]:
    provider_type = str(provider.get("providerType") or "").strip().lower()
    if provider_type == "facebook":
        return {"email": "email", "name": "name"}
    return {"email": "email"}


def _safe_cognito_call(method_name: str, **kwargs: Any) -> Dict[str, Any]:
    method = getattr(_cognito_idp(), method_name)
    try:
        return method(**kwargs)
    except Exception as exc:
        if exc.__class__.__name__ in {"ResourceNotFoundException", "InvalidParameterException"}:
            return {}
        raise


def _provisioning_state_table_name() -> str:
    table_name = str(os.getenv("AUTH_PROVISIONING_STATE_TABLE_NAME", AUTH_PROVISIONING_STATE_TABLE_NAME)).strip()
    if not table_name:
        raise AuthServiceError("Auth provisioning state table is not configured")
    return table_name


def _aws_region() -> str:
    return str(os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1").strip()


def _cognito_idp():
    global _COGNITO_IDP_CLIENT
    if boto3 is None:
        raise RuntimeError("boto3 is not available")
    if _COGNITO_IDP_CLIENT is None:
        _COGNITO_IDP_CLIENT = boto3.client("cognito-idp")
    return _COGNITO_IDP_CLIENT


def _dynamodb():
    global _DYNAMODB_CLIENT
    if boto3 is None:
        raise RuntimeError("boto3 is not available")
    if _DYNAMODB_CLIENT is None:
        _DYNAMODB_CLIENT = boto3.client("dynamodb")
    return _DYNAMODB_CLIENT


def _ssm():
    global _SSM_CLIENT
    if boto3 is None:
        raise RuntimeError("boto3 is not available")
    if _SSM_CLIENT is None:
        _SSM_CLIENT = boto3.client("ssm")
    return _SSM_CLIENT


def _secrets_manager():
    global _SECRETS_CLIENT
    if boto3 is None:
        raise RuntimeError("boto3 is not available")
    if _SECRETS_CLIENT is None:
        _SECRETS_CLIENT = boto3.client("secretsmanager")
    return _SECRETS_CLIENT


def _snake_case(value: str) -> str:
    return re.sub(r"(?<!^)([A-Z])", r"_\1", value).lower()


def _is_trusted_server_request(event: Dict[str, Any]) -> bool:
    caller_arn = _caller_arn(event)
    if not caller_arn:
        return False
    allowed_arns = set(_csv_env("AUTH_PROVISIONING_ALLOWED_ROLE_ARNS", AUTH_PROVISIONING_ALLOWED_ROLE_ARNS))
    allowed_names = set(_csv_env("AUTH_PROVISIONING_ALLOWED_ROLE_NAMES", AUTH_PROVISIONING_ALLOWED_ROLE_NAMES))
    if caller_arn in allowed_arns:
        return True
    caller_role_name = _role_name_from_arn(caller_arn)
    return bool(caller_role_name and caller_role_name in allowed_names)


def _caller_arn(event: Dict[str, Any]) -> str:
    request_context = event.get("requestContext") if isinstance(event.get("requestContext"), dict) else {}
    candidates = [
        _extract_nested(request_context, ["identity", "userArn"]),
        _extract_nested(request_context, ["authorizer", "iam", "userArn"]),
        _extract_nested(request_context, ["authorizer", "iam", "callerArn"]),
        _extract_nested(request_context, ["authorizer", "principalId"]),
    ]
    for candidate in candidates:
        arn = str(candidate or "").strip()
        if arn.startswith("arn:"):
            return arn
    return ""


def _role_name_from_arn(arn: str) -> str:
    match = re.search(r":assumed-role/([^/]+)/", arn)
    if match:
        return match.group(1)
    match = re.search(r":role/(.+)$", arn)
    if match:
        return match.group(1).split("/")[-1]
    return ""


def _extract_nested(mapping: Any, path: list[str]) -> Any:
    current = mapping
    for part in path:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _reject_raw_secret_material(value: Any, path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = str(key)
            if normalized_key in ALLOWED_SECRET_REFERENCE_KEYS:
                _validate_secret_ref_value(child, normalized_key)
                continue
            if normalized_key in SAFE_PUBLIC_AUTH_METADATA_KEYS:
                _reject_raw_secret_material(child, f"{path}.{normalized_key}" if path else normalized_key)
                continue
            if normalized_key not in ALLOWED_SECRET_REFERENCE_KEYS and RAW_SECRET_KEY_RE.search(normalized_key):
                raise AuthRegistryError("Auth registry must not contain raw secrets")
            _reject_raw_secret_material(child, f"{path}.{normalized_key}" if path else normalized_key)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_raw_secret_material(child, f"{path}[{index}]")
    elif isinstance(value, str):
        if "-----BEGIN " in value or re.search(r"\bAKIA[0-9A-Z]{16}\b", value):
            raise AuthRegistryError("Auth registry must not contain raw secrets")


def _validate_secret_ref_value(value: Any, label: str) -> None:
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            _validate_secret_ref_value(child_value, f"{label}.{child_key}")
        return
    if isinstance(value, list):
        for index, child_value in enumerate(value):
            _validate_secret_ref_value(child_value, f"{label}[{index}]")
        return
    if not isinstance(value, str):
        raise AuthRegistryError("Auth secret refs must be references")
    normalized = value.strip()
    if (
        not normalized
        or normalized != value
        or "\\" in normalized
        or CONTROL_OR_WHITESPACE_RE.search(normalized)
        or not (
            normalized.startswith("/")
            or normalized.startswith("arn:aws:ssm:")
            or normalized.startswith("arn:aws:secretsmanager:")
        )
    ):
        raise AuthRegistryError("Auth secret refs must be references")


def _runtime_path_from_profile(profile: Dict[str, Any], path_key: str, url_key: str, label: str) -> str:
    explicit_path = str(profile.get(path_key) or "").strip()
    if explicit_path:
        _validate_same_origin_path(explicit_path, label)
        return explicit_path

    urls = _string_list(profile.get(url_key))
    if not urls:
        raise AuthRegistryError(f"{label} must be a same-origin path")
    _validate_https_url(urls[0], label)
    parsed = urllib.parse.urlparse(urls[0])
    resolved_path = parsed.path or "/"
    if parsed.query:
        resolved_path = f"{resolved_path}?{parsed.query}"
    _validate_same_origin_path(resolved_path, label)
    return resolved_path


def _validate_https_url(value: str, label: str) -> None:
    normalized = str(value or "").strip()
    if not normalized or "\\" in normalized or CONTROL_OR_WHITESPACE_RE.search(normalized):
        raise AuthRegistryError(f"{label} must be an absolute https URL")
    parsed = urllib.parse.urlparse(normalized)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise AuthRegistryError(f"{label} must be an absolute https URL")


def _validate_same_origin_path(value: str, label: str) -> None:
    normalized = str(value or "").strip()
    if (
        not normalized.startswith("/")
        or normalized.startswith("//")
        or "\\" in normalized
        or CONTROL_OR_WHITESPACE_RE.search(normalized)
        or urllib.parse.urlparse(normalized).scheme
    ):
        raise AuthRegistryError(f"{label} must be a same-origin path")


def _jwks_url(issuer: str) -> str:
    return f"{str(issuer or '').rstrip('/')}/.well-known/jwks.json"


def _validate_provisioning_profile(profile: Dict[str, Any]) -> None:
    status = _profile_status(profile)
    if status not in AUTH_PROFILE_STATUSES:
        raise AuthRegistryError("Auth profile status is invalid")
    if not str(profile.get("tenantId") or "").strip():
        raise AuthRegistryError("Provisioning plan requires tenantId")

    issuer = str(profile.get("issuer") or "").strip()
    if issuer:
        _validate_https_url(issuer, "issuer")

    hosted_ui_domain = str(profile.get("hostedUiDomain") or "").strip()
    if hosted_ui_domain:
        _validate_https_url(hosted_ui_domain, "hostedUiDomain")

    _runtime_path_from_profile(profile, "redirectPath", "callbackUrls", "redirectPath")
    _runtime_path_from_profile(profile, "logoutPath", "logoutUrls", "logoutPath")
    _validate_same_origin_path(str(profile.get("loginPath") or "/login"), "loginPath")
    if status == "active" and not _audiences(profile):
        raise AuthRegistryError("Provisioning plan requires an audience/clientId")
    for callback_url in _string_list(profile.get("callbackUrls")):
        _validate_https_url(callback_url, "callbackUrl")
    for logout_url in _string_list(profile.get("logoutUrls")):
        _validate_https_url(logout_url, "logoutUrl")
    for optional_path in ("postLoginPath", "postLogoutPath"):
        if profile.get(optional_path):
            _validate_same_origin_path(str(profile.get(optional_path)), optional_path)

    _validate_social_identity_provider_metadata(profile)


def _plan_lifecycle(status: str) -> Dict[str, Any]:
    if status == "planned":
        return {
            "currentStatus": status,
            "runtimeAuthEnabled": False,
            "executorAction": "prepare-provisioning",
            "expectedNextStatus": "provisioning",
            "expectedFinalStatus": "active",
        }
    if status == "provisioning":
        return {
            "currentStatus": status,
            "runtimeAuthEnabled": False,
            "executorAction": "resume-provisioning",
            "expectedNextStatus": "provisioning",
            "expectedFinalStatus": "active",
        }
    if status == "active":
        return {
            "currentStatus": status,
            "runtimeAuthEnabled": True,
            "executorAction": "noop-already-active",
            "expectedNextStatus": "active",
            "expectedFinalStatus": "active",
        }
    return {
        "currentStatus": status,
        "runtimeAuthEnabled": False,
        "executorAction": "manual-review",
        "expectedNextStatus": status,
        "expectedFinalStatus": status,
    }


def _hosted_ui_details(profile: Dict[str, Any]) -> Dict[str, Any]:
    hosted_ui_domain = str(profile.get("hostedUiDomain") or "").strip()
    parsed = urllib.parse.urlparse(hosted_ui_domain)
    return {
        "domainUrl": hosted_ui_domain,
        "domainHost": parsed.netloc,
        "loginPath": str(profile.get("loginPath") or "/login").strip(),
        "redirectPath": _runtime_path_from_profile(profile, "redirectPath", "callbackUrls", "redirectPath"),
        "logoutPath": _runtime_path_from_profile(profile, "logoutPath", "logoutUrls", "logoutPath"),
    }


def _social_identity_providers(profile: Dict[str, Any]) -> list[Dict[str, Any]]:
    providers = profile.get("socialIdentityProviders")
    if isinstance(providers, list):
        normalized: list[Dict[str, Any]] = []
        for provider in providers:
            if isinstance(provider, dict):
                normalized.append(_normalize_social_identity_provider(provider))
        normalized.sort(key=lambda item: item["providerId"])
        return normalized

    legacy_refs = profile.get("socialIdpSecretRefs")
    if isinstance(legacy_refs, dict):
        normalized = []
        for provider_id in sorted(legacy_refs.keys()):
            normalized.append({
                "providerId": str(provider_id).strip().lower(),
                "providerType": str(provider_id).strip().lower(),
                "enabled": True,
                "secretRefs": {
                    "provider": str(legacy_refs[provider_id]).strip(),
                },
            })
        return normalized

    return []


def _normalize_social_identity_provider(provider: Dict[str, Any]) -> Dict[str, Any]:
    provider_id = str(
        provider.get("providerId")
        or provider.get("provider")
        or provider.get("name")
        or provider.get("id")
        or provider.get("type")
        or ""
    ).strip().lower()
    if not provider_id:
        raise AuthRegistryError("Social identity provider requires providerId")

    provider_type = str(provider.get("providerType") or provider.get("type") or provider_id).strip().lower()
    normalized: Dict[str, Any] = {
        "providerId": provider_id,
        "providerType": provider_type,
        "enabled": bool(provider.get("enabled", True)),
    }

    display_name = str(provider.get("displayName") or "").strip()
    if display_name:
        normalized["displayName"] = display_name

    scopes = _string_list(provider.get("scopes"))
    if scopes:
        normalized["scopes"] = scopes

    for key in ("issuer", "discoveryUrl", "authorizeUrl", "tokenUrl", "userInfoUrl", "jwksUrl", "attributeRequestMethod"):
        value = provider.get(key)
        if isinstance(value, str) and value.strip():
            normalized[key] = value.strip()

    secret_refs: Dict[str, Any] = {}
    if isinstance(provider.get("secretRefs"), dict):
        for ref_key, ref_value in provider["secretRefs"].items():
            secret_refs[str(ref_key)] = ref_value
    for source_key, target_key in (
        ("secretRef", "provider"),
        ("providerSecretRef", "provider"),
        ("clientIdRef", "clientId"),
        ("clientSecretRef", "clientSecret"),
    ):
        value = provider.get(source_key)
        if isinstance(value, str) and value.strip():
            secret_refs[target_key] = value.strip()
    if secret_refs:
        _validate_secret_ref_value(secret_refs, "socialIdentityProviders.secretRefs")
        normalized["secretRefs"] = secret_refs

    return normalized


def _validate_social_identity_provider_metadata(profile: Dict[str, Any]) -> None:
    for provider in _social_identity_providers(profile):
        for url_key in ("issuer", "discoveryUrl", "authorizeUrl", "tokenUrl", "userInfoUrl", "jwksUrl"):
            if provider.get(url_key):
                _validate_https_url(str(provider.get(url_key)), url_key)


def _provisioning_operations(
    *,
    domain: str,
    auth_profile_id: str,
    tenant_id: str,
    status: str,
    social_identity_providers: list[Dict[str, Any]],
    config_hash: str,
) -> list[Dict[str, Any]]:
    if status == "active":
        return []
    if status in {"suspended", "failed"}:
        return []

    operations = [
        _plan_operation(
            domain=domain,
            auth_profile_id=auth_profile_id,
            tenant_id=tenant_id,
            status=status,
            config_hash=config_hash,
            operation_id="ensure-user-pool",
            stage="identity-core",
            expected_status_after_completion="provisioning",
        ),
        _plan_operation(
            domain=domain,
            auth_profile_id=auth_profile_id,
            tenant_id=tenant_id,
            status=status,
            config_hash=config_hash,
            operation_id="ensure-hosted-ui-domain",
            stage="hosted-ui",
            expected_status_after_completion="provisioning",
            depends_on=["ensure-user-pool"],
        ),
        _plan_operation(
            domain=domain,
            auth_profile_id=auth_profile_id,
            tenant_id=tenant_id,
            status=status,
            config_hash=config_hash,
            operation_id="ensure-public-client",
            stage="public-client",
            expected_status_after_completion="provisioning",
            depends_on=["ensure-user-pool"],
        ),
        _plan_operation(
            domain=domain,
            auth_profile_id=auth_profile_id,
            tenant_id=tenant_id,
            status=status,
            config_hash=config_hash,
            operation_id="ensure-user-groups",
            stage="groups",
            expected_status_after_completion="provisioning",
            depends_on=["ensure-public-client"],
        ),
    ]
    if social_identity_providers:
        operations.append(
            _plan_operation(
                domain=domain,
                auth_profile_id=auth_profile_id,
                tenant_id=tenant_id,
                status=status,
                config_hash=config_hash,
                operation_id="ensure-social-identity-providers",
                stage="social-idps",
                expected_status_after_completion="provisioning",
                depends_on=["ensure-public-client"],
            )
        )
    operations.append(
        _plan_operation(
            domain=domain,
            auth_profile_id=auth_profile_id,
            tenant_id=tenant_id,
            status=status,
            config_hash=config_hash,
            operation_id="finalize-runtime-activation",
            stage="finalize",
            expected_status_after_completion="active",
            depends_on=[operation["operationId"] for operation in operations],
        )
    )
    return operations


def _plan_operation(
    *,
    domain: str,
    auth_profile_id: str,
    tenant_id: str,
    status: str,
    config_hash: str,
    operation_id: str,
    stage: str,
    expected_status_after_completion: str,
    depends_on: Optional[list[str]] = None,
) -> Dict[str, Any]:
    operation_key = ":".join(("cognito", domain, auth_profile_id, operation_id))
    operation = {
        "operationId": operation_id,
        "operationKey": operation_key,
        "idempotencyKey": _stable_key(
            "op",
            AUTH_PROVISIONING_PLAN_SCHEMA_VERSION,
            domain,
            auth_profile_id,
            tenant_id,
            status,
            operation_id,
            config_hash,
        ),
        "stage": stage,
        "expectedStatusAfterCompletion": expected_status_after_completion,
        "target": {
            "domain": domain,
            "authProfileId": auth_profile_id,
            "tenantId": tenant_id,
        },
    }
    if depends_on:
        operation["dependsOn"] = depends_on
    return operation


def _stable_key(*parts: str) -> str:
    raw = "|".join(str(part or "").strip() for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _request_payload(event: Dict[str, Any]) -> Dict[str, Any]:
    if _request_method(event) == "GET":
        params = event.get("queryStringParameters") or {}
        return params if isinstance(params, dict) else {}

    body = event.get("body")
    if body is None or body == "":
        return {}
    if event.get("isBase64Encoded"):
        raise ValueError("Base64 auth request bodies are not supported")
    if isinstance(body, dict):
        return body
    parsed = json.loads(body)
    if not isinstance(parsed, dict):
        raise ValueError("Body must decode into a JSON object")
    return parsed


def _request_origin(event: Dict[str, Any]) -> Optional[str]:
    headers = event.get("headers") if isinstance(event.get("headers"), dict) else {}
    for key, value in headers.items():
        if str(key).lower() == "origin":
            return str(value or "").strip() or None
    return None


def _request_method(event: Dict[str, Any]) -> str:
    return str(
        event.get("httpMethod")
        or (event.get("requestContext") or {}).get("http", {}).get("method")
        or "",
    ).upper()


def _request_path(event: Dict[str, Any]) -> str:
    return str(
        event.get("rawPath")
        or event.get("path")
        or (event.get("requestContext") or {}).get("http", {}).get("path")
        or "",
    ).rstrip("/")


def _is_options_request(event: Dict[str, Any]) -> bool:
    return _request_method(event) == "OPTIONS"


def _auth_response(status_code: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": resolve_cors_origin(_AUTH_REQUEST_ORIGIN),
            "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Zoolanding-Domain,X-Zoolanding-Auth-Profile-Id",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
            "Vary": "Origin",
        },
        "body": json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
    }


def _bearer_token(event: Dict[str, Any]) -> str:
    token = str(event.get("authorizationToken") or "").strip()
    if not token:
        headers = event.get("headers") if isinstance(event.get("headers"), dict) else {}
        for key, value in headers.items():
            if str(key).lower() == "authorization":
                token = str(value or "").strip()
                break
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if not token:
        raise AuthJwtError()
    return token


def _authorizer_domain(event: Dict[str, Any]) -> str:
    headers = event.get("headers") if isinstance(event.get("headers"), dict) else {}
    for key, value in headers.items():
        if str(key).lower() == "x-zoolanding-domain":
            return normalize_domain(value)
    return normalize_domain(event.get("domain") or event.get("domainName"))


def _authorizer_profile_id(event: Dict[str, Any]) -> str:
    headers = event.get("headers") if isinstance(event.get("headers"), dict) else {}
    for key, value in headers.items():
        if str(key).lower() == "x-zoolanding-auth-profile-id":
            return str(value or "").strip()
    return str(event.get("authProfileId") or "").strip()


def _authorizer_policy(effect: str, resource: str, principal_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
    safe_context = {key: str(value) for key, value in context.items() if value is not None}
    return {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": resource,
                }
            ],
        },
        "context": safe_context,
    }


def _csv_env(name: str, fallback: str) -> list[str]:
    raw = os.getenv(name, fallback)
    return [item.strip() for item in raw.split(",") if item.strip()]


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []
