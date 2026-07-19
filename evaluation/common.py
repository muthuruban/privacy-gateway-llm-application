"""Shared helpers for the evaluation harnesses: dataset loading and
environment metadata so every generated result file is traceable to the
exact code and environment that produced it."""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any

EVALUATION_DIR = Path(__file__).parent
DATASET_PATH = EVALUATION_DIR / "datasets" / "synthetic_pii_cases.json"
RESULTS_DIR = EVALUATION_DIR / "results"

_TRACKED_PACKAGES = (
    "presidio-analyzer",
    "presidio-anonymizer",
    "spacy",
    "fastapi",
    "pydantic",
    "httpx",
)


def load_dataset() -> list[dict[str, Any]]:
    data = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    return list(data["cases"])


def _git_commit() -> str:
    try:
        return subprocess.run(  # noqa: S603 - fixed argv, no user input
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        ).stdout.strip()
    except OSError:
        return "unknown"


def environment_metadata(configuration: dict[str, Any] | None = None) -> dict[str, Any]:
    """Provenance block embedded in every generated result file, so a
    number can never be quoted without its context."""
    versions = {}
    for package in _TRACKED_PACKAGES:
        try:
            versions[package] = metadata.version(package)
        except metadata.PackageNotFoundError:
            versions[package] = "not installed"
    return {
        "generated_at_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "git_commit": _git_commit(),
        "python_version": sys.version,
        "platform": platform.platform(),
        "dependency_versions": versions,
        "test_configuration": configuration or {},
    }


def write_results(name: str, payload: dict[str, Any]) -> Path:
    """Write a timestamped JSON result file under evaluation/results/
    (which is gitignored: generated numbers are environment-specific and
    must not be committed as if they were universal)."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = RESULTS_DIR / f"{name}_{stamp}.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path
