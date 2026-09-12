"""Build the minimal, isolated THN runtime-config Lambda artifact."""

from __future__ import annotations

from pathlib import Path
import shutil
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ALLOWED_FILES = (
    "thn_auth_runtime_v2.py",
    "service_binding_registry_consumer_v2.py",
)


def build(destination: Path) -> None:
    if destination.exists() and any(destination.iterdir()):
        raise RuntimeError("artifact destination is not empty")
    destination.mkdir(parents=True, exist_ok=True)
    for name in ALLOWED_FILES:
        source = PROJECT_ROOT / name
        if not source.is_file():
            raise RuntimeError(f"required artifact source is missing: {name}")
        shutil.copy2(source, destination / name)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: build_thn_auth_runtime_v2_artifact.py ARTIFACTS_DIR")
    destination = Path(sys.argv[1]).resolve()
    build(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
