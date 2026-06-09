import json
import os
from pathlib import Path
import re
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


CONFIG_TABLE_NAME = os.getenv("CONFIG_TABLE_NAME", "zoolanding-config-registry")
CONFIG_PAYLOADS_BUCKET_NAME = os.getenv("CONFIG_PAYLOADS_BUCKET_NAME", "zoolanding-config-payloads")
AUTH_REGISTRY_FILE_NAME = os.getenv("AUTH_REGISTRY_FILE_NAME", "auth-profile-registry.json")
AUTH_PROVISIONING_ALLOWED_ROLE_NAMES = os.getenv("AUTH_PROVISIONING_ALLOWED_ROLE_NAMES", "")
AUTH_PROVISIONING_ALLOWED_ROLE_ARNS = os.getenv("AUTH_PROVISIONING_ALLOWED_ROLE_ARNS", "")
_AUTH_REQUEST_ORIGIN = None

AUTH_PATHS = {"/auth/runtime-config", "/auth/provisioning-plan"}
TEST_PREVIEW_ORIGIN_HOST = "test.zoolandingpage.com.mx"
CONTROL_OR_WHITESPACE_RE = re.compile(r"[\s\x00-\x1f\x7f]")
RAW_SECRET_KEY_RE = re.compile(r"(secret|token|password|private[_-]?key|credential|api[_-]?key)", re.I)
RUNTIME_CONFIG_ALLOWED_KEYS = {"domain", "authProfileId"}
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

    published = metadata.get("published") if isinstance(metadata.get("published"), dict) else None
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
        if status not in {"active", "planned", "provisioning", "suspended", "failed"}:
            raise AuthRegistryError("Auth profile status is invalid")
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
    status = _profile_status(profile)
    auth_payload = _public_runtime_auth(profile, enabled=status == "active")
    return _auth_response(200, {"ok": True, "domain": domain, "auth": auth_payload})


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

    domain = normalize_domain(payload.get("domain"))
    registry = load_auth_registry_for_domain(domain)
    profile = _find_profile(registry, str(payload.get("authProfileId") or registry.get("defaultAuthProfileId") or ""))
    return _auth_response(200, {"ok": True, "domain": domain, "plan": _cognito_plan(domain, profile)})


def _public_runtime_auth(profile: Dict[str, Any], *, enabled: bool = True) -> Dict[str, Any]:
    issuer = str(profile.get("issuer") or "").strip()
    audiences = _audiences(profile)
    client_id = str(profile.get("clientId") or (audiences[0] if audiences else "")).strip()
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
    issuer = str(profile.get("issuer") or "").strip()
    return {
        "mode": "plan-only",
        "provider": "cognito",
        "domain": normalize_domain(domain),
        "profileId": _profile_id(profile),
        "tenantId": str(profile.get("tenantId") or "").strip(),
        "status": _profile_status(profile),
        "issuer": issuer,
        "jwksUrl": str(profile.get("jwksUrl") or _jwks_url(issuer)) if issuer else "",
        "hostedUiDomain": str(profile.get("hostedUiDomain") or "").strip(),
        "audiences": _audiences(profile),
        "callbackUrls": _string_list(profile.get("callbackUrls")),
        "logoutUrls": _string_list(profile.get("logoutUrls")),
        "allowedGroups": _string_list(profile.get("allowedGroups")),
        "socialIdpSecretRefs": profile.get("socialIdpSecretRefs") if isinstance(profile.get("socialIdpSecretRefs"), dict) else {},
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


def _reject_unsupported_runtime_options(payload: Dict[str, Any]) -> None:
    if not all(str(key) in RUNTIME_CONFIG_ALLOWED_KEYS for key in payload.keys()):
        raise AuthServiceError("Unsupported auth runtime option")


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
