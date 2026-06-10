import argparse
import getpass
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any


DEFAULT_REGION = "us-east-1"
DEFAULT_TENANT_ID = "zoosite"
DEFAULT_AUTH_PROFILE_ID = "staff"
DEFAULT_SECRET_PREFIX = "/zoolanding/auth"
SUPPORTED_PROVIDERS = ("google", "facebook")
PLACEHOLDERS = {
    "",
    "__set_in_aws_console__",
    "__set_me__",
    "changeme",
    "change-me",
    "todo",
    "placeholder",
    "replace-me",
}


class LoaderError(Exception):
    pass


def secret_name(*, tenant_id: str, auth_profile_id: str, provider_id: str, prefix: str = DEFAULT_SECRET_PREFIX) -> str:
    cleaned_prefix = "/" + str(prefix or "").strip().strip("/")
    return f"{cleaned_prefix}/{tenant_id}/{auth_profile_id}/{provider_id}"


def env_name(provider_id: str, key: str) -> str:
    return f"{provider_id}_{key}".upper()


def is_placeholder(value: str) -> bool:
    normalized = str(value or "").strip().lower()
    return normalized in PLACEHOLDERS or normalized.startswith("fake-")


def validate_secret_payload(payload: dict[str, str]) -> None:
    client_id = str(payload.get("clientId") or "").strip()
    client_secret = str(payload.get("clientSecret") or "").strip()
    if is_placeholder(client_id):
        raise LoaderError("clientId is missing or placeholder")
    if is_placeholder(client_secret):
        raise LoaderError("clientSecret is missing or placeholder")


def build_secret_payload(provider_id: str, *, no_prompt: bool) -> dict[str, str]:
    client_id = os.getenv(env_name(provider_id, "client_id"))
    client_secret = os.getenv(env_name(provider_id, "client_secret"))
    if not client_id and not no_prompt:
        client_id = getpass.getpass(f"{provider_id} clientId: ")
    if not client_secret and not no_prompt:
        client_secret = getpass.getpass(f"{provider_id} clientSecret: ")
    payload = {
        "clientId": str(client_id or "").strip(),
        "clientSecret": str(client_secret or "").strip(),
    }
    validate_secret_payload(payload)
    return payload


def run_aws(args: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["aws", *args],
        input=input_text,
        capture_output=True,
        check=False,
        encoding="utf-8",
    )


def safe_error(result: subprocess.CompletedProcess[str]) -> str:
    text = (result.stderr or result.stdout or "").strip()
    if not text:
        return f"AWS CLI exited with code {result.returncode}"
    return "\n".join(line for line in text.splitlines() if "clientSecret" not in line and "SecretString" not in line)


def secret_exists(name: str, *, region: str) -> bool:
    result = run_aws(["secretsmanager", "describe-secret", "--secret-id", name, "--region", region])
    if result.returncode == 0:
        return True
    if "ResourceNotFoundException" in (result.stderr or ""):
        return False
    raise LoaderError(f"Failed to describe secret {name}: {safe_error(result)}")


def load_secret(name: str, *, region: str) -> dict[str, Any] | None:
    result = run_aws([
        "secretsmanager",
        "get-secret-value",
        "--secret-id",
        name,
        "--query",
        "SecretString",
        "--output",
        "text",
        "--region",
        region,
    ])
    if result.returncode != 0:
        if "ResourceNotFoundException" in (result.stderr or ""):
            return None
        raise LoaderError(f"Failed to read secret {name}: {safe_error(result)}")
    raw = result.stdout.strip()
    if not raw:
        raise LoaderError(f"Secret {name} is empty")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LoaderError(f"Secret {name} is not JSON") from exc
    if not isinstance(parsed, dict):
        raise LoaderError(f"Secret {name} must be a JSON object")
    return parsed


def write_secret(
    name: str,
    payload: dict[str, str],
    *,
    provider_id: str,
    tenant_id: str,
    auth_profile_id: str,
    region: str,
    dry_run: bool,
) -> str:
    validate_secret_payload(payload)
    exists = secret_exists(name, region=region)
    if dry_run:
        return "would-update" if exists else "would-create"

    with tempfile.TemporaryDirectory(prefix="zoolanding-auth-secret-") as temp_dir:
        secret_file = Path(temp_dir) / "secret.json"
        secret_file.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
        if exists:
            result = run_aws([
                "secretsmanager",
                "put-secret-value",
                "--secret-id",
                name,
                "--secret-string",
                f"file://{secret_file}",
                "--region",
                region,
            ])
            action = "updated"
        else:
            result = run_aws([
                "secretsmanager",
                "create-secret",
                "--name",
                name,
                "--secret-string",
                f"file://{secret_file}",
                "--region",
                region,
                "--tags",
                "Key=managedBy,Value=zoolandingpage",
                f"Key=tenantId,Value={tenant_id}",
                f"Key=authProfileId,Value={auth_profile_id}",
                f"Key=providerId,Value={provider_id}",
            ])
            action = "created"
    if result.returncode != 0:
        raise LoaderError(f"Failed to write secret {name}: {safe_error(result)}")
    return action


def check_secret(name: str, *, region: str) -> dict[str, Any]:
    parsed = load_secret(name, region=region)
    if parsed is None:
        return {"exists": False, "validShape": False, "placeholder": None}
    client_id = str(parsed.get("clientId") or parsed.get("client_id") or "").strip()
    client_secret = str(parsed.get("clientSecret") or parsed.get("client_secret") or "").strip()
    return {
        "exists": True,
        "validShape": bool(client_id and client_secret),
        "placeholder": is_placeholder(client_id) or is_placeholder(client_secret),
    }


def providers_from_args(value: str) -> list[str]:
    if value == "all":
        return list(SUPPORTED_PROVIDERS)
    providers = [item.strip().lower() for item in value.split(",") if item.strip()]
    unsupported = [item for item in providers if item not in SUPPORTED_PROVIDERS]
    if unsupported:
        raise LoaderError(f"Unsupported providers: {', '.join(unsupported)}")
    return providers


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Load or check Zoosite social IdP credential secrets.")
    parser.add_argument("--mode", choices=("check", "upsert"), default="check")
    parser.add_argument("--provider", default="all", help="all, google, facebook, or comma-separated providers.")
    parser.add_argument("--tenant-id", default=DEFAULT_TENANT_ID)
    parser.add_argument("--auth-profile-id", default=DEFAULT_AUTH_PROFILE_ID)
    parser.add_argument("--secret-prefix", default=DEFAULT_SECRET_PREFIX)
    parser.add_argument("--region", default=DEFAULT_REGION)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-prompt", action="store_true", help="Read only environment variables; fail if missing.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        providers = providers_from_args(args.provider)
        results = []
        for provider_id in providers:
            name = secret_name(
                tenant_id=args.tenant_id,
                auth_profile_id=args.auth_profile_id,
                provider_id=provider_id,
                prefix=args.secret_prefix,
            )
            if args.mode == "check":
                status = check_secret(name, region=args.region)
                results.append({"providerId": provider_id, "secretId": name, **status})
            else:
                payload = build_secret_payload(provider_id, no_prompt=args.no_prompt)
                action = write_secret(
                    name,
                    payload,
                    provider_id=provider_id,
                    tenant_id=args.tenant_id,
                    auth_profile_id=args.auth_profile_id,
                    region=args.region,
                    dry_run=args.dry_run,
                )
                results.append({"providerId": provider_id, "secretId": name, "action": action})
        print(json.dumps({"ok": True, "results": results}, indent=2, sort_keys=True))
        return 0
    except LoaderError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
