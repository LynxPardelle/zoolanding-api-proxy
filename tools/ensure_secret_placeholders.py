#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

PLACEHOLDER_VALUE = "__SET_IN_AWS_CONSOLE__"
MANAGED_BY = "zoolanding-api-proxy"


def build_placeholder_secret(fields: list[str]) -> dict[str, str]:
    normalized_fields = []
    seen = set()
    for field in fields:
        normalized = str(field or "").strip()
        if not normalized:
            raise ValueError("Secret fields must be non-empty strings")
        if normalized in seen:
            raise ValueError(f"Duplicate secret field: {normalized}")
        seen.add(normalized)
        normalized_fields.append(normalized)

    if not normalized_fields:
        raise ValueError("Secret must declare at least one field")

    return {field: PLACEHOLDER_VALUE for field in normalized_fields}


def build_create_secret_command(entry: dict[str, Any], *, region: str) -> list[str]:
    name = normalized_secret_name(entry)
    fields = entry.get("fields")
    if not isinstance(fields, list):
        raise ValueError(f"{name} must declare fields as a list")

    command = [
        "aws",
        "secretsmanager",
        "create-secret",
        "--region",
        region,
        "--name",
        name,
    ]

    description = str(entry.get("description") or "").strip()
    if description:
        command.extend(["--description", description])

    command.extend([
        "--secret-string",
        json.dumps(build_placeholder_secret(fields), separators=(",", ":")),
    ])

    tags = build_tags(entry.get("tags"))
    if tags:
        command.append("--tags")
        command.extend(tags)

    return command


def build_describe_secret_command(name: str, *, region: str) -> list[str]:
    return [
        "aws",
        "secretsmanager",
        "describe-secret",
        "--region",
        region,
        "--secret-id",
        name,
        "--output",
        "json",
    ]


def build_tags(raw_tags: Any) -> list[str]:
    tags = {"ManagedBy": MANAGED_BY}
    if isinstance(raw_tags, dict):
        for key, value in raw_tags.items():
            normalized_key = str(key or "").strip()
            normalized_value = str(value or "").strip()
            if normalized_key and normalized_value:
                tags[normalized_key] = normalized_value

    return [f"Key={key},Value={value}" for key, value in sorted(tags.items())]


def normalized_secret_name(entry: dict[str, Any]) -> str:
    name = str(entry.get("name") or "").strip()
    if not name:
        raise ValueError("Secret entry must declare a name")
    return name


def load_manifest(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)

    secrets = manifest.get("secrets") if isinstance(manifest, dict) else None
    if not isinstance(secrets, list):
        raise ValueError("Manifest must be a JSON object with a secrets list")

    entries = []
    for entry in secrets:
        if not isinstance(entry, dict):
            raise ValueError("Every secret entry must be a JSON object")
        entries.append(entry)
    return entries


def run_aws(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


def secret_exists(name: str, *, region: str) -> bool:
    result = run_aws(build_describe_secret_command(name, region=region))
    if result.returncode == 0:
        return True

    combined = f"{result.stdout}\n{result.stderr}"
    if "ResourceNotFoundException" in combined:
        return False

    raise RuntimeError(safe_aws_error("Failed to describe secret", name, result))


def create_secret(entry: dict[str, Any], *, region: str) -> None:
    name = normalized_secret_name(entry)
    result = run_aws(build_create_secret_command(entry, region=region))
    if result.returncode != 0:
        raise RuntimeError(safe_aws_error("Failed to create secret", name, result))


def safe_aws_error(prefix: str, name: str, result: subprocess.CompletedProcess[str]) -> str:
    message = (result.stderr or result.stdout or "").strip()
    return f"{prefix} {name}: {message}"


def ensure_secrets(entries: list[dict[str, Any]], *, region: str, prefix: str, dry_run: bool) -> int:
    created = 0
    for entry in entries:
        name = normalized_secret_name(entry)
        if not name.startswith(prefix):
            raise ValueError(f"{name} must start with allowed prefix {prefix}")

        fields = entry.get("fields")
        if not isinstance(fields, list):
            raise ValueError(f"{name} must declare fields as a list")
        build_placeholder_secret(fields)

        if dry_run:
            print(f"DRY RUN create-if-missing {name} fields={','.join(fields)}")
            continue

        if secret_exists(name, region=region):
            print(f"exists {name}")
            continue

        create_secret(entry, region=region)
        created += 1
        print(f"created {name}")

    return created


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create AWS Secrets Manager placeholders for API proxy credentialRefs.")
    parser.add_argument(
        "--manifest",
        default=str(Path("secret-placeholders") / "credential-placeholders.json"),
        help="Path to the credential placeholder manifest.",
    )
    parser.add_argument(
        "--region",
        default=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1",
        help="AWS region to use.",
    )
    parser.add_argument(
        "--prefix",
        default="zoolanding/api/",
        help="Allowed Secrets Manager name prefix.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Validate the manifest without creating secrets.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    entries = load_manifest(Path(args.manifest))
    created = ensure_secrets(entries, region=args.region, prefix=args.prefix, dry_run=args.dry_run)
    if not args.dry_run:
        print(f"complete created={created}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
