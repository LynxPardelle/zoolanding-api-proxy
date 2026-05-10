import base64
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

from zoolanding_lambda_common import (
    bad_gateway,
    bad_request,
    default_version_prefix,
    get_request_id,
    is_local_cors_origin,
    join_s3_key,
    json_response,
    load_item,
    load_json_from_s3,
    log,
    normalize_domain,
    not_found,
    ok,
    origin_hostname,
    parse_json_body,
    server_error,
    set_request_cors_origin,
    site_pk,
)

try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover - local fallback when boto3 is unavailable
    boto3 = None


CONFIG_TABLE_NAME = os.getenv("CONFIG_TABLE_NAME", "zoolanding-config-registry")
CONFIG_PAYLOADS_BUCKET_NAME = os.getenv("CONFIG_PAYLOADS_BUCKET_NAME", "zoolanding-config-payloads")
DEFAULT_TIMEOUT_MS = int(os.getenv("DEFAULT_UPSTREAM_TIMEOUT_MS", "4000"))
DEFAULT_MAX_RESPONSE_BYTES = int(os.getenv("DEFAULT_MAX_RESPONSE_BYTES", "1048576"))
DEFAULT_USER_AGENT = os.getenv("DEFAULT_UPSTREAM_USER_AGENT", "Zoolandingpage API Proxy/1.0")
MAX_TEMPLATE_INPUT_LENGTH = int(os.getenv("MAX_TEMPLATE_INPUT_LENGTH", "256"))
URL_TEMPLATE_PLACEHOLDER_RE = re.compile(r"{([A-Za-z0-9_]+)}")
ALLOWED_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
_SECRETS_CLIENT = None


class ApiProxyError(Exception):
    status_code = 400
    public_message = "API proxy request failed"

    def __init__(self, message: Optional[str] = None):
        super().__init__(message or self.public_message)
        if message:
            self.public_message = message


class ValidationError(ApiProxyError):
    status_code = 400
    public_message = "Invalid API proxy request"


class NotFoundError(ApiProxyError):
    status_code = 404
    public_message = "Integration not found"


class UpstreamError(ApiProxyError):
    status_code = 502
    public_message = "Upstream request failed"


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    request_id = get_request_id(context)
    request_origin = _request_origin(event)
    set_request_cors_origin(request_origin)

    if _is_options_request(event):
        return json_response(200, {"ok": True})

    try:
        body = parse_json_body(event)
        kind = _resolve_proxy_kind(event)
        domain = normalize_domain(str(body.get("domain") or ""))
        if not domain:
            raise ValidationError("Missing domain")
        _enforce_origin_domain(request_origin, domain)

        target_id = _resolve_target_id(kind, body)
        input_payload = _normalize_input(body.get("input"))
        policy = _load_policy_for_domain(domain)
        integration = _find_integration(policy, kind, target_id)
        data = _execute_integration(integration, input_payload)
        return ok({"data": data})
    except ValueError:
        return bad_request("Body must be valid JSON")
    except ValidationError as exc:
        return bad_request(exc.public_message)
    except NotFoundError as exc:
        return not_found(exc.public_message)
    except UpstreamError:
        log("WARNING", "Upstream API proxy request failed", requestId=request_id)
        return bad_gateway("Upstream request failed")
    except Exception as exc:
        log("ERROR", "API proxy request failed", requestId=request_id, errorType=type(exc).__name__)
        return server_error()


def _request_origin(event: Dict[str, Any]) -> Optional[str]:
    headers = event.get("headers") if isinstance(event.get("headers"), dict) else {}
    for key, value in headers.items():
        if str(key).lower() == "origin":
            return str(value or "").strip() or None
    return None


def _is_options_request(event: Dict[str, Any]) -> bool:
    method = str(
        event.get("httpMethod")
        or (event.get("requestContext") or {}).get("http", {}).get("method")
        or "",
    ).upper()
    return method == "OPTIONS"


def _enforce_origin_domain(origin: Optional[str], domain: str) -> None:
    if not origin:
        return
    if is_local_cors_origin(origin):
        return

    origin_domain = origin_hostname(origin)
    if origin_domain == "test.zoolandingpage.com.mx":
        return
    if origin_domain == domain:
        return

    raise ValidationError("Origin is not allowed for requested domain")


def _resolve_proxy_kind(event: Dict[str, Any]) -> str:
    path = str(
        event.get("rawPath")
        or event.get("path")
        or (event.get("requestContext") or {}).get("http", {}).get("path")
        or "",
    ).rstrip("/")
    if path.endswith("/api-proxy/read"):
        return "read"
    if path.endswith("/api-proxy/action"):
        return "action"
    raise ValidationError("Unsupported API proxy path")


def _resolve_target_id(kind: str, body: Dict[str, Any]) -> str:
    key = "sourceId" if kind == "read" else "actionId"
    target_id = str(body.get(key) or "").strip()
    if not target_id:
        raise ValidationError(f"Missing {key}")
    return target_id


def _normalize_input(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict) or isinstance(value, list):
        raise ValidationError("input must be a JSON object")
    return value


def _load_policy_for_domain(domain: str) -> Dict[str, Any]:
    canonical_domain = normalize_domain(domain)
    metadata = load_item(CONFIG_TABLE_NAME, site_pk(canonical_domain))
    if not isinstance(metadata, dict):
        raise NotFoundError("Site metadata not found")

    published = metadata.get("published") if isinstance(metadata.get("published"), dict) else None
    if not published:
        raise NotFoundError("Published configuration not found")

    version_id = str(published.get("versionId") or "").strip()
    prefix = str(published.get("prefix") or default_version_prefix(canonical_domain, version_id)).strip()
    if not prefix:
        raise NotFoundError("Published configuration prefix is missing")

    policy_key = join_s3_key(prefix, canonical_domain, "server", "integrations.json")
    policy = load_json_from_s3(CONFIG_PAYLOADS_BUCKET_NAME, policy_key)
    if not isinstance(policy, dict):
        raise NotFoundError("Server integration policy not found")
    return policy


def _find_integration(policy: Dict[str, Any], kind: str, target_id: str) -> Dict[str, Any]:
    collection_key = "sources" if kind == "read" else "actions"
    integrations = policy.get(collection_key)
    if not isinstance(integrations, list):
        raise NotFoundError("Integration not found")

    for entry in integrations:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("id") or "").strip() == target_id and entry.get("enabled", True) is not False:
            return entry
    raise NotFoundError("Integration not found")


def _execute_integration(integration: Dict[str, Any], input_payload: Dict[str, Any]) -> Dict[str, Any]:
    method = str(integration.get("method") or "GET").upper().strip()
    if method not in ALLOWED_HTTP_METHODS:
        raise ValidationError(f"HTTP method {method or 'missing'} is not allowed")

    allowed_input = _allowed_input_fields(integration)
    unknown_fields = sorted(set(input_payload.keys()) - set(allowed_input))
    if unknown_fields:
        raise ValidationError(f"Input field '{unknown_fields[0]}' is not allowed")

    safe_input = {field: input_payload[field] for field in allowed_input if field in input_payload}
    url, template_fields = _resolve_integration_url(integration, safe_input, allowed_input)
    forwarded_input = {
        field: value
        for field, value in safe_input.items()
        if field not in template_fields
    }
    headers = _build_headers(integration)
    query = forwarded_input if method == "GET" else {}
    body = None if method == "GET" else forwarded_input
    response_data = _fetch_upstream(
        method=method,
        url=url,
        headers=headers,
        query=query,
        body=body,
        timeout_seconds=_timeout_seconds(integration),
        max_response_bytes=_max_response_bytes(integration),
    )
    return _filter_response(response_data, integration)


def _resolve_integration_url(
    integration: Dict[str, Any],
    safe_input: Dict[str, Any],
    allowed_input: list[str],
) -> tuple[str, set[str]]:
    url_template = str(integration.get("urlTemplate") or "").strip()
    if url_template:
        return _resolve_url_template(url_template, safe_input, allowed_input)

    return _validate_upstream_url(str(integration.get("url") or "")), set()


def _resolve_url_template(
    url_template: str,
    safe_input: Dict[str, Any],
    allowed_input: list[str],
) -> tuple[str, set[str]]:
    placeholder_names = URL_TEMPLATE_PLACEHOLDER_RE.findall(url_template)
    if not placeholder_names:
        return _validate_upstream_url(url_template), set()

    allowed = set(allowed_input)
    template_fields = set()
    resolved_url = url_template
    for name in placeholder_names:
        if name not in allowed:
            raise ValidationError(f"URL template field '{name}' is not allowed")
        if name not in safe_input:
            raise ValidationError(f"URL template field '{name}' is missing")

        encoded_value = _encode_template_value(name, safe_input[name])
        resolved_url = resolved_url.replace(f"{{{name}}}", encoded_value)
        template_fields.add(name)

    unresolved = URL_TEMPLATE_PLACEHOLDER_RE.findall(resolved_url)
    if unresolved:
        raise ValidationError("URL template contains unresolved fields")

    return _validate_upstream_url(resolved_url), template_fields


def _encode_template_value(name: str, value: Any) -> str:
    if value is None or isinstance(value, (dict, list, tuple, set)):
        raise ValidationError(f"URL template field '{name}' must be a scalar value")

    normalized = str(value).strip()
    if not normalized:
        raise ValidationError(f"URL template field '{name}' is required")
    if len(normalized) > MAX_TEMPLATE_INPUT_LENGTH:
        raise ValidationError(f"URL template field '{name}' is too long")

    return urllib.parse.quote(normalized, safe="")


def _validate_upstream_url(url: str) -> str:
    if not url:
        raise ValidationError("Integration URL is missing")

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        if not (os.getenv("ALLOW_INSECURE_UPSTREAM", "0") in {"1", "true", "TRUE"} and parsed.hostname in {"localhost", "127.0.0.1"}):
            raise ValidationError("Integration URL must use https")
    if parsed.username or parsed.password:
        raise ValidationError("Integration URL must not include credentials")
    if not parsed.netloc:
        raise ValidationError("Integration URL is invalid")
    return url


def _allowed_input_fields(integration: Dict[str, Any]) -> list[str]:
    direct = integration.get("allowedInputFields")
    request = integration.get("request") if isinstance(integration.get("request"), dict) else {}
    nested = request.get("allowedInputFields") if isinstance(request, dict) else None
    fields = direct if isinstance(direct, list) else nested
    if not isinstance(fields, list):
        return []
    return [str(field) for field in fields if str(field).strip()]


def _build_headers(integration: Dict[str, Any]) -> Dict[str, str]:
    headers = {
        "Accept": "application/json",
        "User-Agent": DEFAULT_USER_AGENT,
    }
    headers.update(_static_headers(integration))

    auth = integration.get("auth") if isinstance(integration.get("auth"), dict) else {}
    credential_ref = str(integration.get("credentialRef") or "").strip()
    if not auth or not credential_ref:
        return headers

    secret = _get_secret(credential_ref)
    auth_type = str(auth.get("type") or "").strip().lower()

    if auth_type == "bearer":
        secret_field = str(auth.get("secretField") or "token").strip()
        secret_value = str(secret.get(secret_field) or "").strip()
        if not secret_value:
            raise ValidationError("Configured credential secret field is missing")
        headers["Authorization"] = f"Bearer {secret_value}"
    elif auth_type == "api-key-header":
        secret_field = str(auth.get("secretField") or "token").strip()
        secret_value = str(secret.get(secret_field) or "").strip()
        if not secret_value:
            raise ValidationError("Configured credential secret field is missing")
        header_name = str(auth.get("headerName") or "").strip()
        if not header_name:
            raise ValidationError("Configured API key header name is missing")
        headers[header_name] = secret_value
    elif auth_type == "oauth2-client-credentials":
        token_url = _validate_upstream_url(str(auth.get("tokenUrl") or ""))
        client_id_field = str(auth.get("clientIdField") or "clientId").strip()
        client_secret_field = str(auth.get("clientSecretField") or "clientSecret").strip()
        client_id = str(secret.get(client_id_field) or "").strip()
        client_secret = str(secret.get(client_secret_field) or "").strip()
        if not client_id or not client_secret:
            raise ValidationError("Configured OAuth client credential fields are missing")
        token = _fetch_oauth_client_credentials_token(
            token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            timeout_seconds=_timeout_seconds(integration),
        )
        headers["Authorization"] = f"Bearer {token}"
    else:
        raise ValidationError("Configured auth type is not supported")
    return headers


def _static_headers(integration: Dict[str, Any]) -> Dict[str, str]:
    configured = integration.get("headers")
    if not isinstance(configured, dict):
        return {}

    headers: Dict[str, str] = {}
    for raw_name, raw_value in configured.items():
        name = str(raw_name or "").strip()
        value = str(raw_value or "").strip()
        if not name or not value:
            continue
        if name.lower() in {"authorization", "cookie", "set-cookie", "x-api-key"}:
            raise ValidationError("Configured static header is not allowed")
        headers[name] = value
    return headers


def _fetch_oauth_client_credentials_token(
    *,
    token_url: str,
    client_id: str,
    client_secret: str,
    timeout_seconds: float,
) -> str:
    encoded_credentials = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")
    body = urllib.parse.urlencode({"grant_type": "client_credentials"}).encode("utf-8")
    request = urllib.request.Request(
        token_url,
        data=body,
        headers={
            "Authorization": f"Basic {encoded_credentials}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - token URL is server policy-controlled.
            raw = response.read(65537)
    except urllib.error.HTTPError as exc:
        raise UpstreamError() from exc
    except urllib.error.URLError as exc:
        raise UpstreamError() from exc

    if len(raw) > 65536:
        raise UpstreamError()

    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise UpstreamError()

    access_token = str(parsed.get("access_token") or "").strip()
    token_type = str(parsed.get("token_type") or "Bearer").strip().lower()
    if not access_token or token_type != "bearer":
        raise UpstreamError()
    return access_token


def _get_secret(credential_ref: str) -> Dict[str, Any]:
    global _SECRETS_CLIENT
    if not credential_ref:
        raise ValidationError("credentialRef is missing")
    if boto3 is None:
        raise RuntimeError("boto3 is not available")
    if _SECRETS_CLIENT is None:
        _SECRETS_CLIENT = boto3.client("secretsmanager")

    response = _SECRETS_CLIENT.get_secret_value(SecretId=credential_ref)
    raw = response.get("SecretString")
    if not raw:
        raise ValidationError("SecretString is missing")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValidationError("SecretString must be a JSON object")
    return parsed


def _fetch_upstream(
    *,
    method: str,
    url: str,
    headers: Dict[str, str],
    query: Dict[str, Any],
    body: Optional[Dict[str, Any]],
    timeout_seconds: float,
    max_response_bytes: int,
) -> Dict[str, Any]:
    target_url = _url_with_query(url, query)
    encoded_body = None
    request_headers = dict(headers)
    if body is not None:
        encoded_body = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        request_headers["Content-Type"] = "application/json"

    request = urllib.request.Request(target_url, data=encoded_body, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - URL is server policy-controlled.
            raw = response.read(max_response_bytes + 1)
    except urllib.error.HTTPError as exc:
        raise UpstreamError() from exc
    except urllib.error.URLError as exc:
        raise UpstreamError() from exc

    if len(raw) > max_response_bytes:
        raise UpstreamError()

    if not raw.strip():
        return {}

    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise UpstreamError()
    return parsed


def _url_with_query(url: str, query: Dict[str, Any]) -> str:
    if not query:
        return url

    parsed = urllib.parse.urlparse(url)
    encoded = urllib.parse.urlencode(query, doseq=True)
    joined_query = "&".join(part for part in [parsed.query, encoded] if part)
    return urllib.parse.urlunparse(parsed._replace(query=joined_query))


def _timeout_seconds(integration: Dict[str, Any]) -> float:
    raw = integration.get("timeoutMs", DEFAULT_TIMEOUT_MS)
    try:
        timeout_ms = int(raw)
    except Exception:
        timeout_ms = DEFAULT_TIMEOUT_MS
    return max(100, min(timeout_ms, 15000)) / 1000


def _max_response_bytes(integration: Dict[str, Any]) -> int:
    response_policy = integration.get("response") if isinstance(integration.get("response"), dict) else {}
    raw = response_policy.get("maxBytes", DEFAULT_MAX_RESPONSE_BYTES)
    try:
        value = int(raw)
    except Exception:
        value = DEFAULT_MAX_RESPONSE_BYTES
    return max(1, min(value, DEFAULT_MAX_RESPONSE_BYTES))


def _filter_response(response_data: Dict[str, Any], integration: Dict[str, Any]) -> Dict[str, Any]:
    response_policy = integration.get("response") if isinstance(integration.get("response"), dict) else {}
    allowed_fields = response_policy.get("allowedFields")
    if not isinstance(allowed_fields, list):
        return {}

    allowed = [str(field) for field in allowed_fields if str(field).strip()]
    filtered: Dict[str, Any] = {}
    for field in allowed:
        _copy_allowed_path(response_data, filtered, [part for part in field.split(".") if part])
    if response_policy.get("singleItem") is True:
        return {"items": [filtered] if filtered else []}
    return filtered


def _copy_allowed_path(source: Any, target: Any, parts: list[str]) -> None:
    if not parts:
        return

    key = parts[0]
    if isinstance(source, dict):
        if key not in source:
            return
        value = source[key]
        if len(parts) == 1:
            if isinstance(target, dict):
                target[key] = value
            return

        if isinstance(value, list):
            if isinstance(target, dict):
                existing = target.get(key)
                if not isinstance(existing, list):
                    existing = [{} if isinstance(item, dict) else None for item in value]
                    target[key] = existing
                for index, item in enumerate(value):
                    if isinstance(item, dict) and index < len(existing):
                        if not isinstance(existing[index], dict):
                            existing[index] = {}
                        _copy_allowed_path(item, existing[index], parts[1:])
            return

        if isinstance(value, dict) and isinstance(target, dict):
            nested = target.get(key)
            if not isinstance(nested, dict):
                nested = {}
                target[key] = nested
            _copy_allowed_path(value, nested, parts[1:])
