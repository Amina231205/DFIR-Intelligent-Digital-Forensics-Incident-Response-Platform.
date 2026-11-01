"""Manifest checks: chain-of-custody integrity for an evidence folder.

The manifest lists every evidence file with its SHA-256. This module only
COMPARES; it never rewrites, regenerates or "fixes" a manifest. A mismatch
means the evidence changed after collection, and that must stay visible.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from security.models.schemas import (
    MANIFEST_FILENAME,
    OPTIONAL_SOURCES,
    EvidenceSource,
    IssueSeverity,
    ValidationIssue,
)
from security.validation.checks import (
    check_field,
    check_schema_version,
    type_problem,
)
from security.validation.loader import LoadedFile

HASH_ALGORITHM = "SHA-256"
_SHA256_FORMAT = re.compile(r"^[0-9a-fA-F]{64}$")
_KNOWN_NAMES = {f"{source.value}.json": source for source in EvidenceSource}

# The contract shows the manifest as an example (section 5) without marking
# fields required. Minimum we rely on: identity + algorithm + file list.
_REQUIRED_TOP = ("schema_version", "case_id", "device", "hash_algorithm", "files")


def _issue(code: str, message: str, field: Optional[str] = None,
           severity: IssueSeverity = IssueSeverity.ERROR) -> ValidationIssue:
    return ValidationIssue(code, severity, message, MANIFEST_FILENAME,
                           None, field)


def check_manifest(
    manifest: dict[str, Any],
    evidence: dict[str, LoadedFile],
) -> list[ValidationIssue]:
    """Validate the manifest and verify hashes of the evidence files.

    Args:
        manifest: parsed manifest.json (a JSON object).
        evidence: files that exist in the folder, keyed by file name.
    """
    issues: list[ValidationIssue] = []
    file = MANIFEST_FILENAME

    for name in _REQUIRED_TOP:
        if name not in manifest:
            issues.append(_issue(
                "MANIFEST_FIELD_MISSING",
                f"{file}: required field '{name}' is missing.", name))
    for name, type_name in (("schema_version", "str"), ("case_id", "str"),
                            ("device", "str"), ("hash_algorithm", "str"),
                            ("created_at", "ts"), ("collector", "object")):
        if name in manifest:
            issues += check_field(file, "manifest", name, manifest[name],
                                  type_name, name in _REQUIRED_TOP)
    if isinstance(manifest.get("schema_version"), str):
        issues += check_schema_version(file, manifest["schema_version"])
    algorithm = manifest.get("hash_algorithm")
    if isinstance(algorithm, str) and algorithm != HASH_ALGORITHM:
        issues.append(_issue(
            "MANIFEST_HASH_ALGORITHM",
            f"{file}: hash_algorithm is {algorithm!r}; the contract requires "
            f"{HASH_ALGORITHM!r}.", "hash_algorithm"))

    entries = manifest.get("files")
    if entries is None:
        return issues
    if not isinstance(entries, list):
        issues.append(_issue(
            "MANIFEST_FILES_NOT_LIST",
            f"{file}: 'files' must be a list, got {type(entries).__name__}.",
            "files"))
        return issues

    listed: set[str] = set()
    for index, entry in enumerate(entries):
        issues += _check_entry(index, entry, evidence, listed)

    # Inventory completeness: every evidence file on disk must be covered.
    for name in evidence:
        if name not in listed:
            issues.append(_issue(
                "MANIFEST_FILE_UNLISTED",
                f"{file}: {name} exists in the folder but is not listed, so "
                "its integrity cannot be verified.", "files"))
    return issues


def _check_entry(
    index: int,
    entry: Any,
    evidence: dict[str, LoadedFile],
    listed: set[str],
) -> list[ValidationIssue]:
    file = MANIFEST_FILENAME
    where = f"files[{index}]"
    if not isinstance(entry, dict):
        return [_issue("MANIFEST_ENTRY_INVALID",
                       f"{file} {where}: entry must be a JSON object, got "
                       f"{type(entry).__name__}.", "files")]

    name = entry.get("name")
    if not isinstance(name, str) or not name.strip():
        return [_issue("MANIFEST_ENTRY_INVALID",
                       f"{file} {where}: 'name' must be a non-empty string.",
                       "files")]
    # Only bare file names: a manifest must never make us read other paths.
    if name in (".", "..") or "/" in name or "\\" in name:
        return [_issue(
            "MANIFEST_BAD_FILE_NAME",
            f"{file} {where}: name {name!r} is a path, not a file name. "
            "Entries must be plain names such as 'processes.json'; the entry "
            "was not followed.", "files")]
    if name in listed:
        return [_issue("MANIFEST_DUPLICATE_ENTRY",
                       f"{file}: {name} is listed more than once.", "files")]
    listed.add(name)

    if name not in _KNOWN_NAMES:
        return [_issue(
            "MANIFEST_UNKNOWN_FILE",
            f"{file}: {name} is not an evidence file defined by the contract; "
            "its hash was not verified and the file is ignored.", "files",
            IssueSeverity.WARNING)]

    issues: list[ValidationIssue] = []
    expected = entry.get("sha256")
    if not isinstance(expected, str) or not _SHA256_FORMAT.match(expected):
        issues.append(_issue(
            "MANIFEST_ENTRY_INVALID",
            f"{file} {name}: 'sha256' must be 64 hex characters, got "
            f"{expected!r}.", "files"))
        expected = None
    counts: dict[str, Optional[int]] = {}
    for key in ("size_bytes", "record_count"):
        value = entry.get(key)
        if value is not None and type_problem(value, "int"):
            issues.append(_issue(
                "MANIFEST_ENTRY_INVALID",
                f"{file} {name}: '{key}' must be an integer, got {value!r}.",
                "files"))
            value = None  # do not compare against a bad value
        counts[key] = value

    loaded = evidence.get(name)
    if loaded is None:
        # A missing REQUIRED file is already reported by the validator.
        if _KNOWN_NAMES[name] in OPTIONAL_SOURCES:
            issues.append(_issue(
                "MANIFEST_FILE_MISSING",
                f"{file}: lists {name} but the file is not in the folder "
                "(deleted or never delivered).", "files"))
        return issues
    if loaded.sha256 is None or expected is None:
        return issues  # unreadable file already reported; bad entry reported

    if loaded.sha256 != expected.lower():
        issues.append(ValidationIssue(
            "MANIFEST_HASH_MISMATCH", IssueSeverity.ERROR,
            f"{name}: SHA-256 does not match the manifest. Manifest says "
            f"{expected.lower()}, file is {loaded.sha256}. The file changed "
            "after collection (or the manifest is wrong). Do not analyze it "
            "until the collector re-exports the case; the validator never "
            "repairs manifests.", file=name, field="sha256"))
        return issues

    if counts["size_bytes"] is not None and counts["size_bytes"] != loaded.size_bytes:
        issues.append(_issue(
            "MANIFEST_SIZE_MISMATCH",
            f"{file}: {name} is {loaded.size_bytes} bytes but the manifest "
            f"says {counts['size_bytes']}.", "files"))
    records = loaded.data.get("records") if loaded.data else None
    count = counts["record_count"]
    if count is not None and isinstance(records, list) and count != len(records):
        issues.append(_issue(
            "MANIFEST_RECORD_COUNT",
            f"{file}: {name} has {len(records)} records but the manifest "
            f"says {count}.", "files"))
    return issues
