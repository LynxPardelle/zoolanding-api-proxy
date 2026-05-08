import base64
import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:
    import boto3  # type: ignore
    from botocore.exceptions import ClientError  # type: ignore
except Exception:  # pragma: no cover - local fallback when boto3 is unavailable
    boto3 = None
    ClientError = Exception  # type: ignore


LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
DRY_RUN = os.getenv("DRY_RUN", "0").strip().lower() in {"1", "true", "yes", "on"}
_S3_CLIENT = None
_DYNAMODB_RESOURCE = None
_REQUEST_CORS_ORIGIN = None


def should_log(level: str) -> bool:
    order = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}
    return order.get(level, 20) >= order.get(LOG_LEVEL, 20)


def log(level: str, message: str, **fields: Any) -> None:
    if not should_log(level):
        return

    record = {"level": level, "message": message, **fields}
    try:
        print(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
    except Exception:
        print({"level": level, "message": message, "fields": str(fields)})


def _configured_cors_origins() -> list[str]:
    configured = os.getenv("ALLOWED_CORS_ORIGINS") or os.getenv("ALLOWED_CORS_ORIGIN") or "https://zoolandingpage.com.mx"
    return [origin.strip() for origin in configured.split(",") if origin.strip()]


def set_request_cors_origin(origin: Optional[str]) -> None:
    global _REQUEST_CORS_ORIGIN
    _REQUEST_CORS_ORIGIN = origin


def resolve_cors_origin(origin: Optional[str]) -> str:
    configured = _configured_cors_origins()
    fallback = configured[0] if configured else "https://zoolandingpage.com.mx"
    normalized = str(origin or "").strip()
    if not normalized:
        return fallback

    if normalized in configured:
        return normalized

    normalized_lower = normalized.lower()
    if normalized_lower.startswith(("http://localhost:", "http://127.0.0.1:", "http://[::1]:")):
        return normalized

    return fallback


def json_response(status_code: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": resolve_cors_origin(_REQUEST_CORS_ORIGIN),
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
            "Access-Control-Allow-Methods": "POST,OPTIONS",
            "Vary": "Origin",
        },
        "body": json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
    }


def ok(payload: Dict[str, Any]) -> Dict[str, Any]:
    return json_response(200, {"ok": True, **payload})


def bad_request(message: str, **extra: Any) -> Dict[str, Any]:
    return json_response(400, {"ok": False, "error": message, **extra})


def not_found(message: str, **extra: Any) -> Dict[str, Any]:
    return json_response(404, {"ok": False, "error": message, **extra})


def bad_gateway(message: str = "Upstream request failed", **extra: Any) -> Dict[str, Any]:
    return json_response(502, {"ok": False, "error": message, **extra})


def server_error(message: str = "Internal error", **extra: Any) -> Dict[str, Any]:
    return json_response(500, {"ok": False, "error": message, **extra})


def get_request_id(context: Any) -> str:
    request_id = getattr(context, "aws_request_id", None)
    if isinstance(request_id, str) and request_id.strip():
        return request_id.strip()
    return f"local-{uuid.uuid4().hex[:12]}"


def parse_json_body(event: Dict[str, Any]) -> Dict[str, Any]:
    body = event.get("body")
    if body is None or body == "":
        raise ValueError("Missing body")

    if event.get("isBase64Encoded"):
        if not isinstance(body, str):
            raise ValueError("Body is base64Encoded but not a string")
        body = base64.b64decode(body).decode("utf-8")

    if isinstance(body, (bytes, bytearray)):
        body = body.decode("utf-8")

    if isinstance(body, str):
        parsed = json.loads(body)
    elif isinstance(body, dict):
        parsed = body
    else:
        raise ValueError("Body must be valid JSON")

    if not isinstance(parsed, dict):
        raise ValueError("Body must decode into a JSON object")

    return parsed


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sanitize_key_segment(value: str, fallback: str = "value") -> str:
    normalized = re.sub(r"[^A-Za-z0-9._/-]+", "-", str(value or "").strip())
    normalized = re.sub(r"/{2,}", "/", normalized).strip("-./")
    return normalized or fallback


def normalize_domain(value: str) -> str:
    domain = str(value or "").strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/", 1)[0]
    domain = domain.split(":", 1)[0]
    return domain.strip("/ ")


def default_version_prefix(domain: str, version_id: str) -> str:
    normalized_domain = sanitize_key_segment(normalize_domain(domain), fallback="site")
    normalized_version = sanitize_key_segment(version_id, fallback="version")
    return f"sites/{normalized_domain}/versions/{normalized_version}"


def join_s3_key(*parts: str) -> str:
    flattened: list[str] = []
    for part in parts:
        flattened.extend(segment for segment in str(part or "").split("/") if segment)
    return "/".join(flattened)


def get_s3_client():
    global _S3_CLIENT
    if _S3_CLIENT is not None:
        return _S3_CLIENT
    if boto3 is None:
        raise RuntimeError("boto3 is not available")
    _S3_CLIENT = boto3.client("s3")
    return _S3_CLIENT


def get_dynamodb_resource():
    global _DYNAMODB_RESOURCE
    if _DYNAMODB_RESOURCE is not None:
        return _DYNAMODB_RESOURCE
    if boto3 is None:
        raise RuntimeError("boto3 is not available")
    _DYNAMODB_RESOURCE = boto3.resource("dynamodb")
    return _DYNAMODB_RESOURCE


def load_item(table_name: str, pk: str, sk: str = "METADATA") -> Optional[Dict[str, Any]]:
    response = get_dynamodb_resource().Table(table_name).get_item(Key={"pk": pk, "sk": sk})
    item = response.get("Item")
    return item if isinstance(item, dict) else None


def load_json_from_s3(bucket: str, key: str) -> Optional[Dict[str, Any]]:
    try:
        response = get_s3_client().get_object(Bucket=bucket, Key=key)
    except ClientError as exc:  # type: ignore[misc]
        code = str(getattr(exc, "response", {}).get("Error", {}).get("Code"))
        if code in {"NoSuchKey", "404", "NotFound"}:
            return None
        raise

    raw = response["Body"].read().decode("utf-8")
    return json.loads(raw) if raw.strip() else {}


def site_pk(domain: str) -> str:
    return f"SITE#{normalize_domain(domain)}"
