"""Evidence validation (Module 1) - the public entry point.

    from security.validation import validate_case
    result = validate_case("security/sample_evidence/INC-001")
    if not result.valid:
        for issue in result.errors:
            print(issue.code, issue.message)

The validator is read-only and independent of the database, FastAPI and every
later analysis phase. It never raises for bad evidence: every problem becomes
a ``ValidationIssue`` in the returned ``ValidationResult``.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Optional, Union

from security.models.schemas import (
    MANIFEST_FILENAME,
    OPTIONAL_SOURCES,
    REQUIRED_SOURCES,
    EvidenceSource,
    IssueSeverity,
    ValidationIssue,
    ValidationResult,
)
from security.validation.checks import check_envelope, check_records
from security.validation.loader import LoadedFile, load_evidence_file
from security.validation.manifest import check_manifest


class EvidenceNotValidError(Exception):
    """Raised by consumers (e.g. normalization) that refuse invalid evidence.

    The full ``ValidationResult`` is available as ``.result``.
    """

    def __init__(self, result: ValidationResult) -> None:
        self.result = result
        first = result.errors[0].message if result.errors else "unknown error"
        super().__init__(
            f"Evidence in {result.folder} failed validation "
            f"({len(result.errors)} errors). First error: {first}"
        )


def validate_case(folder: Union[str, Path]) -> ValidationResult:
    """Validate one evidence folder and return every issue found."""
    return validate_and_load(folder)[0]


def validate_and_load(
    folder: Union[str, Path],
) -> tuple[ValidationResult, dict[str, LoadedFile]]:
    """Validate a folder AND return the files that were parsed doing so.

    Later stages must analyze exactly the bytes that were validated. Reading
    the files a second time would leave a window in which they could change
    after their SHA-256 was verified, so consumers use ``LoadedFile.data``
    from this call instead of re-reading from disk.
    """
    folder = Path(folder)
    result = ValidationResult(folder=str(folder))

    if not folder.is_dir():
        result.add(ValidationIssue(
            "CASE_DIR_NOT_FOUND", IssueSeverity.ERROR,
            f"Evidence folder not found or not a directory: {folder}"))
        return result, {}

    loaded: dict[str, LoadedFile] = {}
    for source in (*REQUIRED_SOURCES, *OPTIONAL_SOURCES):
        _validate_source_file(folder, source, loaded, result)

    manifest_data = _validate_manifest(folder, loaded, result)
    _check_consistency(loaded, manifest_data, result)
    _check_record_ids_across_files(loaded, result)
    return result, loaded


def _validate_source_file(
    folder: Path,
    source: EvidenceSource,
    loaded: dict[str, LoadedFile],
    result: ValidationResult,
) -> None:
    name = f"{source.value}.json"
    path = folder / name
    if not path.exists():
        if source in REQUIRED_SOURCES:
            result.add(ValidationIssue(
                "REQUIRED_FILE_MISSING", IssueSeverity.ERROR,
                f"Required evidence file {name} is missing from {folder.name}/.",
                file=name))
        else:
            result.add(ValidationIssue(
                "OPTIONAL_FILE_MISSING", IssueSeverity.WARNING,
                f"Optional evidence file {name} is not present; analysis can "
                "continue without it.", file=name))
        return

    file = load_evidence_file(path)
    loaded[name] = file
    result.checked_files.append(name)
    for issue in file.issues:
        result.add(issue)
    if file.data is not None:
        for issue in (*check_envelope(name, file.data, source),
                      *check_records(name, file.data, source)):
            result.add(issue)


def _validate_manifest(
    folder: Path,
    loaded: dict[str, LoadedFile],
    result: ValidationResult,
) -> Optional[dict]:
    """Load and check manifest.json; return its data if it was usable."""
    path = folder / MANIFEST_FILENAME
    if not path.exists():
        result.add(ValidationIssue(
            "MANIFEST_MISSING", IssueSeverity.ERROR,
            f"{MANIFEST_FILENAME} is missing, so the integrity of the "
            "evidence cannot be verified. It must come from the collector's "
            "preservation step; the validator will not create one.",
            file=MANIFEST_FILENAME))
        return None

    manifest = load_evidence_file(path)
    result.checked_files.append(MANIFEST_FILENAME)
    for issue in manifest.issues:
        result.add(issue)
    if manifest.data is None:
        return None
    for issue in check_manifest(manifest.data, loaded):
        result.add(issue)
    return manifest.data


def _text(value: object) -> Optional[str]:
    return value if isinstance(value, str) and value.strip() else None


def _check_consistency(
    loaded: dict[str, LoadedFile],
    manifest: Optional[dict],
    result: ValidationResult,
) -> None:
    """case_id and device must be identical in every file and the manifest.

    The reference value is the one most files agree on, so the report points
    at the odd one out. On a tie the manifest wins (it is listed first).
    """
    for field_name, code in (("case_id", "CASE_ID_MISMATCH"),
                             ("device", "DEVICE_MISMATCH")):
        values: list[tuple[str, str]] = []
        if manifest is not None and _text(manifest.get(field_name)):
            values.append((MANIFEST_FILENAME, manifest[field_name]))
        for name, file in loaded.items():
            if file.data is not None and _text(file.data.get(field_name)):
                values.append((name, file.data[field_name]))
        if not values:
            continue
        ref_value = Counter(v for _, v in values).most_common(1)[0][0]
        ref_file = next(n for n, v in values if v == ref_value)
        setattr(result, field_name, ref_value)
        for name, value in values:
            if value != ref_value:
                result.add(ValidationIssue(
                    code, IssueSeverity.ERROR,
                    f"{name}: {field_name} is {value!r} but {ref_file} (and "
                    f"most other files) say {ref_value!r}. All files in a "
                    f"case must use the same {field_name}.",
                    file=name, field=field_name))

    _check_hostname(loaded, result)


def _check_hostname(loaded: dict[str, LoadedFile], result: ValidationResult) -> None:
    """system.json hostname should match the case device (warning only).

    The contract does not say whether 'device' must equal the hostname, so a
    difference is reported as a warning rather than an error.
    """
    system = loaded.get("system.json")
    if system is None or system.data is None or result.device is None:
        return
    records = system.data.get("records")
    if not (isinstance(records, list) and records and isinstance(records[0], dict)):
        return
    hostname = _text(records[0].get("hostname"))
    if hostname and hostname.casefold() != result.device.casefold():
        result.add(ValidationIssue(
            "HOSTNAME_DEVICE_MISMATCH", IssueSeverity.WARNING,
            f"system.json: hostname {hostname!r} differs from the case device "
            f"{result.device!r}. Confirm both identify the same machine.",
            file="system.json", field="hostname"))


def _check_record_ids_across_files(
    loaded: dict[str, LoadedFile], result: ValidationResult
) -> None:
    """record_id must be unique across the whole case, not just per file."""
    seen: dict[str, str] = {}
    for name, file in loaded.items():
        records = file.data.get("records") if file.data else None
        if not isinstance(records, list):
            continue
        for record in records:
            rid = record.get("record_id") if isinstance(record, dict) else None
            if not isinstance(rid, str):
                continue
            first = seen.setdefault(rid, name)
            if first != name:
                result.add(ValidationIssue(
                    "RECORD_ID_DUPLICATE", IssueSeverity.ERROR,
                    f"record_id {rid!r} is used in both {first} and {name}. "
                    "IDs must be unique across the whole case.",
                    file=name, record_id=rid, field="record_id"))
