"""Small, dependency-free helpers shared by every module.

Keep this file tiny. If a helper is only used by one module, it belongs in
that module instead.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_FRACTION = re.compile(r"\.(\d+)(?=[+-]\d{2}:\d{2}$)")


def load_json(path: Path) -> Any:
    """Load a UTF-8 JSON file.

    Raises:
        FileNotFoundError: the file does not exist.
        json.JSONDecodeError: the file is not valid JSON.
    """
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def sha256_file(path: Path, chunk_size: int = 65536) -> str:
    """Return the lowercase hex SHA-256 digest of a file."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO 8601 timestamp into a timezone-aware UTC datetime.

    The evidence contract requires UTC with a trailing ``Z``
    (e.g. ``2026-10-08T07:34:01Z``). Offsets such as ``+03:00`` are accepted
    and converted to UTC. Timestamps WITHOUT a timezone are rejected because
    they make cross-source timeline ordering unreliable.

    Raises:
        ValueError: value is not a string, not ISO 8601, or has no timezone.
    """
    if not isinstance(value, str):
        raise ValueError(f"timestamp must be a string, got {type(value).__name__}")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"  # Python < 3.11 cannot parse a bare 'Z'
    # Python < 3.11 only parses 3 or 6 fractional digits, while Windows
    # writes up to 7. Normalize to 6 (microseconds) so behaviour is the same
    # on every supported Python version.
    text = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"invalid ISO 8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError(
            f"timestamp has no timezone (expected UTC 'Z'): {value!r}"
        )
    return parsed.astimezone(timezone.utc)


def format_timestamp(value: datetime) -> str:
    """Format a datetime as an ISO 8601 UTC string ending in ``Z``."""
    if value.tzinfo is None:
        raise ValueError("cannot format a naive datetime; attach a timezone first")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
