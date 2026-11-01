"""Shared helpers for tests that corrupt or edit a COPY of the sample case.

Used by the Phase 3 test files and the policy tests. (The Phase 2 test file
keeps its own private copies so it stays exactly as reviewed.)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from security.models.schemas import MANIFEST_FILENAME, EvidenceSource, ValidationResult
from security.utils.helpers import sha256_file

SAMPLE_DIR = (
    Path(__file__).resolve().parents[1]
    / "security" / "sample_evidence" / "INC-001"
)
Mutator = Callable[[dict[str, Any]], None]


def rebuild_manifest(case_dir: Path) -> None:
    """TEST-ONLY: make the manifest match the files currently on disk."""
    manifest_path = case_dir / MANIFEST_FILENAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = []
    for source in EvidenceSource:
        path = case_dir / f"{source.value}.json"
        if not path.is_file():
            continue
        entry: dict[str, Any] = {
            "name": path.name,
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
        }
        try:
            entry["record_count"] = len(
                json.loads(path.read_text(encoding="utf-8"))["records"])
        except (ValueError, KeyError, TypeError):
            pass
        entries.append(entry)
    manifest["files"] = entries
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def edit(case_dir: Path, name: str, mutate: Mutator, rebuild: bool = True) -> None:
    """Load a JSON evidence file, mutate it, save it, optionally rehash."""
    path = case_dir / name
    data = json.loads(path.read_text(encoding="utf-8"))
    mutate(data)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    if rebuild:
        rebuild_manifest(case_dir)


def error_codes(result: ValidationResult) -> set[str]:
    return {issue.code for issue in result.errors}


def warning_codes(result: ValidationResult) -> set[str]:
    return {issue.code for issue in result.warnings}


def snapshot(folder: Path) -> dict[str, tuple[bytes, int]]:
    """Bytes and mtime of every file: used to prove nothing was modified."""
    return {
        p.name: (p.read_bytes(), p.stat().st_mtime_ns)
        for p in sorted(folder.iterdir()) if p.is_file()
    }
