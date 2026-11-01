"""Read one evidence file safely and report every integrity problem.

The file is read ONCE as bytes. The SHA-256 is computed from those same bytes
that are then parsed, so the hash we compare against the manifest always
describes exactly the content we validated. Nothing is ever written.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from security.models.schemas import IssueSeverity, ValidationIssue

_UTF8_BOM = b"\xef\xbb\xbf"


@dataclass
class LoadedFile:
    """Result of reading one JSON file.

    ``data`` is the parsed top-level JSON object, or ``None`` when the file
    could not be used (see ``issues`` for why). ``sha256`` is set whenever
    the bytes could be read, even if parsing failed, so the manifest check
    can still run.
    """

    name: str
    sha256: Optional[str] = None
    size_bytes: Optional[int] = None
    data: Optional[dict[str, Any]] = None
    issues: list[ValidationIssue] = field(default_factory=list)

    def _error(self, code: str, message: str) -> None:
        self.issues.append(
            ValidationIssue(code, IssueSeverity.ERROR, message, file=self.name)
        )


def _reject_constant(name: str) -> None:
    raise ValueError(f"non-standard JSON constant {name!r} is not allowed")


def load_evidence_file(path: Path) -> LoadedFile:
    """Read and parse ``path``; never raises for bad evidence."""
    loaded = LoadedFile(name=path.name)

    try:
        raw = path.read_bytes()
    except OSError as exc:
        loaded._error(
            "FILE_UNREADABLE",
            f"{path.name}: cannot read file ({exc.strerror or exc}). "
            "Check that it is a regular file with read permission.",
        )
        return loaded

    loaded.sha256 = hashlib.sha256(raw).hexdigest()
    loaded.size_bytes = len(raw)

    if not raw.strip():
        loaded._error(
            "FILE_EMPTY",
            f"{path.name}: file is empty ({len(raw)} bytes). "
            "The collector must write a JSON object with an envelope.",
        )
        return loaded

    if raw.startswith(_UTF8_BOM):
        loaded._error(
            "JSON_BOM",
            f"{path.name}: file starts with a UTF-8 byte-order mark (BOM). "
            "Save it as UTF-8 without BOM.",
        )
        return loaded

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        loaded._error(
            "FILE_NOT_UTF8",
            f"{path.name}: not valid UTF-8 (invalid byte at offset {exc.start}).",
        )
        return loaded

    duplicate_keys: list[str] = []

    def collect_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: set[str] = set()
        for key, _ in pairs:
            if key in seen and key not in duplicate_keys:
                duplicate_keys.append(key)
            seen.add(key)
        return dict(pairs)

    try:
        data = json.loads(
            text, object_pairs_hook=collect_pairs, parse_constant=_reject_constant
        )
    except json.JSONDecodeError as exc:
        loaded._error(
            "JSON_INVALID",
            f"{path.name}: invalid JSON at line {exc.lineno}, column "
            f"{exc.colno}: {exc.msg}.",
        )
        return loaded
    except (ValueError, RecursionError) as exc:
        loaded._error("JSON_INVALID", f"{path.name}: invalid JSON: {exc}.")
        return loaded

    for key in duplicate_keys:
        loaded._error(
            "JSON_DUPLICATE_KEY",
            f"{path.name}: JSON object contains the key {key!r} more than once; "
            "only one value would survive parsing, so the evidence is ambiguous.",
        )

    if not isinstance(data, dict):
        loaded._error(
            "JSON_NOT_OBJECT",
            f"{path.name}: top level must be a JSON object with the evidence "
            f"envelope, got {type(data).__name__}.",
        )
        return loaded

    loaded.data = data
    return loaded
