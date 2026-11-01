"""Phase 2 tests: the evidence validator.

Every corruption happens on a temporary COPY of the sample case (``case``
fixture). The original ``sample_evidence/INC-001`` is never modified.

Most tests rebuild the manifest after editing a file, so that only the
intended problem is reported (a changed file would otherwise ALSO trigger a
manifest hash mismatch). Tests about the manifest itself skip the rebuild.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Callable

import pytest

from security.models.schemas import (
    ENVELOPE_FIELDS,
    FIELD_ALLOWED_VALUES,
    FIELD_TYPES,
    MANIFEST_FILENAME,
    REQUIRED_RECORD_FIELDS,
    REQUIRED_SOURCES,
    EvidenceSource,
    ValidationResult,
)
from security.utils.helpers import parse_timestamp, sha256_file
from security.validation import validate_case
from security.validation.__main__ import main as cli_main

SAMPLE_DIR = (
    Path(__file__).resolve().parents[1]
    / "security" / "sample_evidence" / "INC-001"
)
Mutator = Callable[[dict[str, Any]], None]


# ------------------------------------------------------------------ helpers
@pytest.fixture
def case(tmp_path: Path) -> Path:
    """A fresh, disposable copy of the sample case."""
    destination = tmp_path / "INC-001"
    shutil.copytree(SAMPLE_DIR, destination)
    return destination


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
            pass  # deliberately broken file: no record count
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


def write_raw(case_dir: Path, name: str, content: bytes, rebuild: bool = True) -> None:
    (case_dir / name).write_bytes(content)
    if rebuild:
        rebuild_manifest(case_dir)


def error_codes(result: ValidationResult) -> set[str]:
    return {issue.code for issue in result.errors}


def warning_codes(result: ValidationResult) -> set[str]:
    return {issue.code for issue in result.warnings}


def snapshot(folder: Path) -> dict[str, tuple[bytes, int]]:
    return {
        p.name: (p.read_bytes(), p.stat().st_mtime_ns)
        for p in sorted(folder.iterdir()) if p.is_file()
    }


# -------------------------------------------------------------- valid case
class TestValidSample:
    def test_sample_case_is_valid(self):
        result = validate_case(SAMPLE_DIR)
        assert result.valid is True
        assert result.errors == []
        assert result.warnings == []
        assert result.case_id == "INC-001"
        assert result.device == "WIN-PC-01"

    def test_all_files_are_reported_as_checked(self):
        result = validate_case(SAMPLE_DIR)
        expected = [f"{s.value}.json" for s in EvidenceSource] + [MANIFEST_FILENAME]
        assert sorted(result.checked_files) == sorted(expected)

    def test_result_serializes_to_json(self):
        payload = json.loads(json.dumps(validate_case(SAMPLE_DIR).to_dict()))
        assert payload["valid"] is True
        assert set(payload) >= {"valid", "errors", "warnings", "checked_files"}

    def test_validation_does_not_modify_the_sample(self):
        before = snapshot(SAMPLE_DIR)
        validate_case(SAMPLE_DIR)
        assert snapshot(SAMPLE_DIR) == before

    def test_unknown_extra_fields_are_ignored(self, case):
        edit(case, "processes.json",
             lambda d: d["records"][0].update(collector_extra=123))
        assert validate_case(case).valid


# ------------------------------------------------------------ files present
class TestRequiredAndOptionalFiles:
    @pytest.mark.parametrize("source", REQUIRED_SOURCES)
    def test_missing_required_file_is_reported_by_name(self, case, source):
        name = f"{source.value}.json"
        (case / name).unlink()
        rebuild_manifest(case)
        result = validate_case(case)
        assert not result.valid
        assert error_codes(result) == {"REQUIRED_FILE_MISSING"}
        assert name in result.errors[0].message
        assert result.errors[0].file == name
        assert name not in result.checked_files

    def test_every_missing_required_file_is_listed(self, case):
        for name in ("events.json", "network.json"):
            (case / name).unlink()
        rebuild_manifest(case)
        result = validate_case(case)
        assert [i.file for i in result.errors] == ["network.json", "events.json"]

    def test_missing_optional_file_is_only_a_warning(self, case):
        (case / "files.json").unlink()
        rebuild_manifest(case)
        result = validate_case(case)
        assert result.valid
        assert result.errors == []
        assert warning_codes(result) == {"OPTIONAL_FILE_MISSING"}
        assert "files.json" in result.warnings[0].message

    def test_optional_file_listed_in_manifest_but_deleted_is_an_error(self, case):
        (case / "files.json").unlink()  # manifest still lists it
        result = validate_case(case)
        assert error_codes(result) == {"MANIFEST_FILE_MISSING"}

    def test_folder_not_found(self, tmp_path):
        result = validate_case(tmp_path / "does-not-exist")
        assert not result.valid
        assert error_codes(result) == {"CASE_DIR_NOT_FOUND"}

    def test_path_is_a_file_not_a_folder(self, case):
        result = validate_case(case / "system.json")
        assert error_codes(result) == {"CASE_DIR_NOT_FOUND"}

    def test_unreadable_evidence_path_is_reported(self, case):
        (case / "processes.json").unlink()
        (case / "processes.json").mkdir()  # exists, but is not a readable file
        assert error_codes(validate_case(case)) == {"FILE_UNREADABLE"}


# ----------------------------------------------------------- JSON integrity
class TestJsonIntegrity:
    @pytest.mark.parametrize("content", [b"", b"   \n\t "])
    def test_empty_file(self, case, content):
        write_raw(case, "network.json", content)
        result = validate_case(case)
        assert error_codes(result) == {"FILE_EMPTY"}
        assert result.errors[0].file == "network.json"

    def test_truncated_json_reports_line_and_column(self, case):
        text = (case / "users.json").read_text(encoding="utf-8")
        write_raw(case, "users.json", text[:200].encode("utf-8"))
        result = validate_case(case)
        assert error_codes(result) == {"JSON_INVALID"}
        assert "users.json" in result.errors[0].message
        assert "line" in result.errors[0].message

    @pytest.mark.parametrize("content", [b"[]", b'"text"', b"null", b"42"])
    def test_top_level_must_be_an_object(self, case, content):
        write_raw(case, "events.json", content)
        assert error_codes(validate_case(case)) == {"JSON_NOT_OBJECT"}

    def test_utf8_bom_is_rejected_with_clear_message(self, case):
        raw = (case / "system.json").read_bytes()
        write_raw(case, "system.json", b"\xef\xbb\xbf" + raw)
        result = validate_case(case)
        assert error_codes(result) == {"JSON_BOM"}
        assert "BOM" in result.errors[0].message

    def test_non_utf8_bytes(self, case):
        write_raw(case, "system.json", b'{"x": "\xff\xfe"}')
        assert error_codes(validate_case(case)) == {"FILE_NOT_UTF8"}

    def test_duplicate_json_keys_are_not_silently_accepted(self, case):
        path = case / "network.json"
        text = path.read_text(encoding="utf-8")
        needle = '"device": "WIN-PC-01",'
        assert needle in text
        write_raw(case, "network.json",
                  text.replace(needle, needle + "\n  " + needle, 1).encode())
        result = validate_case(case)
        assert error_codes(result) == {"JSON_DUPLICATE_KEY"}
        assert "'device'" in result.errors[0].message

    def test_nan_is_rejected(self, case):
        text = (case / "processes.json").read_text(encoding="utf-8")
        write_raw(case, "processes.json", text.replace('"pid": 5304', '"pid": NaN').encode())
        assert error_codes(validate_case(case)) == {"JSON_INVALID"}

    def test_malformed_files_do_not_stop_other_files_being_checked(self, case):
        write_raw(case, "network.json", b"{ not json", rebuild=False)
        edit(case, "users.json", lambda d: d["records"][0].pop("username"),
             rebuild=False)
        codes = error_codes(validate_case(case))
        assert {"JSON_INVALID", "FIELD_MISSING", "MANIFEST_HASH_MISMATCH"} <= codes


# ----------------------------------------------------------------- envelope
class TestEnvelope:
    @pytest.mark.parametrize("field", ENVELOPE_FIELDS)
    def test_missing_envelope_field(self, case, field):
        edit(case, "processes.json", lambda d: d.pop(field))
        result = validate_case(case)
        assert error_codes(result) == {"ENVELOPE_FIELD_MISSING"}
        assert result.errors[0].field == field
        assert f"'{field}'" in result.errors[0].message

    def test_source_must_match_file_name(self, case):
        edit(case, "processes.json", lambda d: d.update(source="network"))
        assert error_codes(validate_case(case)) == {"SOURCE_MISMATCH"}

    def test_collector_must_be_an_object(self, case):
        edit(case, "processes.json", lambda d: d.update(collector="tool"))
        assert error_codes(validate_case(case)) == {"FIELD_TYPE"}

    def test_records_must_be_a_list(self, case):
        edit(case, "processes.json", lambda d: d.update(records={}))
        assert error_codes(validate_case(case)) == {"RECORDS_NOT_LIST"}

    def test_each_record_must_be_an_object(self, case):
        edit(case, "processes.json", lambda d: d["records"].append(5))
        result = validate_case(case)
        assert error_codes(result) == {"RECORD_NOT_OBJECT"}
        assert "records[9]" in result.errors[0].message

    def test_empty_records_list_is_a_warning(self, case):
        edit(case, "powershell.json", lambda d: d.update(records=[]))
        result = validate_case(case)
        assert result.valid
        assert warning_codes(result) == {"RECORDS_EMPTY"}

    @pytest.mark.parametrize("records_edit", ["empty", "two"])
    def test_system_json_must_have_exactly_one_record(self, case, records_edit):
        def mutate(d):
            d["records"] = [] if records_edit == "empty" else (
                d["records"] + [{**d["records"][0], "record_id": "SYS-0002"}])
        edit(case, "system.json", mutate)
        assert error_codes(validate_case(case)) == {"SYSTEM_RECORD_COUNT"}

    @pytest.mark.parametrize("version, errors, warnings", [
        ("2.0", {"SCHEMA_VERSION_UNSUPPORTED"}, set()),
        ("1.9", set(), {"SCHEMA_MINOR_NEWER"}),
        ("one", {"SCHEMA_VERSION_INVALID"}, set()),
        ("1", {"SCHEMA_VERSION_INVALID"}, set()),
        (1.0, {"FIELD_TYPE"}, set()),
    ])
    def test_schema_version_rules(self, case, version, errors, warnings):
        edit(case, "processes.json", lambda d: d.update(schema_version=version))
        result = validate_case(case)
        assert error_codes(result) == errors
        assert warning_codes(result) == warnings


# ------------------------------------------------------------ record fields
REQUIRED_PAIRS = [
    (source, name)
    for source in EvidenceSource
    for name in REQUIRED_RECORD_FIELDS[source]
]


class TestRecordFields:
    @pytest.mark.parametrize("source, field", REQUIRED_PAIRS,
                             ids=[f"{s.value}.{f}" for s, f in REQUIRED_PAIRS])
    def test_missing_required_field(self, case, source, field):
        edit(case, f"{source.value}.json", lambda d: d["records"][0].pop(field))
        result = validate_case(case)
        expected = "RECORD_ID_MISSING" if field == "record_id" else "FIELD_MISSING"
        assert error_codes(result) == {expected}
        assert result.errors[0].field == field
        assert result.errors[0].file == f"{source.value}.json"
        assert f"'{field}'" in result.errors[0].message

    def test_error_identifies_file_record_and_field(self, case):
        edit(case, "processes.json", lambda d: d["records"][0].update(pid="abc"))
        issue = validate_case(case).errors[0]
        assert (issue.file, issue.record_id, issue.field) == (
            "processes.json", "PROC-0001", "pid")
        assert "PROC-0001" in issue.message and "'pid'" in issue.message

    def test_required_field_may_not_be_null(self, case):
        edit(case, "processes.json", lambda d: d["records"][0].update(pid=None))
        assert error_codes(validate_case(case)) == {"FIELD_NULL"}

    def test_optional_field_may_be_null(self, case):
        edit(case, "processes.json",
             lambda d: d["records"][0].update(parent_name=None, sha256=None))
        assert validate_case(case).valid

    def test_required_empty_string_is_an_error(self, case):
        edit(case, "processes.json", lambda d: d["records"][0].update(user=""))
        assert error_codes(validate_case(case)) == {"FIELD_EMPTY"}

    def test_optional_empty_string_is_a_warning(self, case):
        edit(case, "processes.json",
             lambda d: d["records"][0].update(parent_name="  "))
        result = validate_case(case)
        assert result.valid
        assert warning_codes(result) == {"FIELD_EMPTY"}

    @pytest.mark.parametrize("source, field, value", [
        (EvidenceSource.PROCESSES, "pid", "abc"),
        (EvidenceSource.PROCESSES, "pid", True),
        (EvidenceSource.PROCESSES, "pid", 1.5),
        (EvidenceSource.USERS, "enabled", "yes"),
        (EvidenceSource.USERS, "is_admin", 1),
        (EvidenceSource.USERS, "groups", "Users"),
        (EvidenceSource.USERS, "groups", [1, 2]),
        (EvidenceSource.EVENTS, "data", "text"),
        (EvidenceSource.EVENTS, "event_id", "4624"),
        (EvidenceSource.NETWORK, "local_port", "80"),
        (EvidenceSource.NETWORK, "remote_address", "999.1.1.1"),
        (EvidenceSource.NETWORK, "remote_address", "example.com"),
        (EvidenceSource.FILES, "size_bytes", "big"),
        (EvidenceSource.FILES, "sha256", "XYZ"),
        (EvidenceSource.FILES, "sha256", "A" * 64),
        (EvidenceSource.POWERSHELL, "command", 123),
        (EvidenceSource.SYSTEM, "ip_addresses", "10.0.0.1"),
    ])
    def test_wrong_types(self, case, source, field, value):
        edit(case, f"{source.value}.json", lambda d: d["records"][0].update({field: value}))
        result = validate_case(case)
        assert error_codes(result) == {"FIELD_TYPE"}
        assert result.errors[0].field == field

    @pytest.mark.parametrize("source, field, value", [
        (EvidenceSource.NETWORK, "protocol", "ICMP"),
        (EvidenceSource.NETWORK, "direction", "sideways"),
        (EvidenceSource.USERS, "account_type", "cloud"),
        (EvidenceSource.PROCESSES, "origin", "guess"),
        (EvidenceSource.POWERSHELL, "origin", "memory"),
    ])
    def test_values_outside_the_contract_vocabulary(self, case, source, field, value):
        edit(case, f"{source.value}.json", lambda d: d["records"][0].update({field: value}))
        result = validate_case(case)
        assert error_codes(result) == {"FIELD_VALUE"}
        assert "allowed values" in result.errors[0].message


# ---------------------------------------------------------------- record IDs
class TestRecordIds:
    def test_duplicate_id_in_one_file(self, case):
        edit(case, "processes.json",
             lambda d: d["records"][1].update(record_id="PROC-0001"))
        result = validate_case(case)
        assert error_codes(result) == {"RECORD_ID_DUPLICATE"}
        message = result.errors[0].message
        assert "PROC-0001" in message and "records[0]" in message and "records[1]" in message

    def test_duplicate_ids_are_each_reported(self, case):
        def mutate(d):
            d["records"][1]["record_id"] = "NET-0001"   # duplicates records[0]
            d["records"][3]["record_id"] = "NET-0003"   # duplicates records[2]
        edit(case, "network.json", mutate)
        result = validate_case(case)
        assert error_codes(result) == {"RECORD_ID_DUPLICATE"}
        assert [i.record_id for i in result.errors] == ["NET-0001", "NET-0003"]

    @pytest.mark.parametrize("bad_id", ["PROC-1", "proc-0001", "PROC0001", "PROC-00A1"])
    def test_wrong_id_format(self, case, bad_id):
        edit(case, "processes.json",
             lambda d: d["records"][0].update(record_id=bad_id))
        assert error_codes(validate_case(case)) == {"RECORD_ID_FORMAT"}

    def test_id_with_another_sources_prefix(self, case):
        edit(case, "processes.json",
             lambda d: d["records"][0].update(record_id="NET-0099"))
        assert error_codes(validate_case(case)) == {"RECORD_ID_FORMAT"}

    def test_same_id_used_in_two_files(self, case):
        edit(case, "powershell.json",
             lambda d: d["records"][0].update(record_id="PROC-0001"))
        codes = error_codes(validate_case(case))
        assert "RECORD_ID_DUPLICATE" in codes

    def test_longer_numbers_are_allowed(self, case):
        edit(case, "processes.json",
             lambda d: d["records"][0].update(record_id="PROC-000001"))
        assert validate_case(case).valid


# ---------------------------------------------------------------- timestamps
BAD_TIMESTAMPS = [
    "2026-10-08T07:34:01",          # no timezone
    "2026-10-08T10:34:01+03:00",    # offset instead of Z
    "2026-10-08T07:34:01z",         # lowercase z
    "2026-10-08 07:34:01Z",         # space instead of T
    "2026-10-08",                   # date only
    "yesterday",
    "2026-13-40T07:34:01Z",         # impossible date
    "2026-10-08T25:00:00Z",         # impossible time
    1696750441,                     # epoch number
    ["2026-10-08T07:34:01Z"],       # wrong JSON type
]
TIMESTAMP_FIELDS: list[tuple[str, Callable[[dict, Any], None]]] = [
    ("processes.json", lambda d, v: d["records"][0].update(timestamp=v)),
    ("events.json", lambda d, v: d["records"][0].update(timestamp=v)),
    ("system.json", lambda d, v: d["records"][0].update(boot_time=v)),
    ("users.json", lambda d, v: d["records"][0].update(created_at=v)),
    ("users.json", lambda d, v: d["records"][2].update(last_logon=v)),   # optional
    ("files.json", lambda d, v: d["records"][0].update(modified_at=v)),  # optional
    ("processes.json", lambda d, v: d.update(collected_at=v)),           # envelope
]


class TestTimestamps:
    @pytest.mark.parametrize("bad", BAD_TIMESTAMPS, ids=repr)
    @pytest.mark.parametrize("name, setter", TIMESTAMP_FIELDS,
                             ids=[f"{n}-{i}" for i, (n, _) in enumerate(TIMESTAMP_FIELDS)])
    def test_invalid_timestamps_are_rejected(self, case, name, setter, bad):
        edit(case, name, lambda d: setter(d, bad))
        result = validate_case(case)
        assert error_codes(result) == {"TIMESTAMP_INVALID"}
        assert "ending in 'Z'" in result.errors[0].message

    @pytest.mark.parametrize("good", [
        "2026-10-08T07:34:01Z",
        "2026-10-08T07:34:01.5Z",
        "2026-10-08T07:34:01.123Z",
        "2026-10-08T07:34:01.1234567Z",   # Windows writes 7 digits
    ])
    def test_valid_utc_timestamps_are_accepted(self, case, good):
        edit(case, "processes.json", lambda d: d["records"][0].update(timestamp=good))
        assert validate_case(case).valid

    def test_missing_required_timestamp(self, case):
        edit(case, "network.json", lambda d: d["records"][2].pop("timestamp"))
        result = validate_case(case)
        assert error_codes(result) == {"FIELD_MISSING"}
        assert result.errors[0].record_id == "NET-0003"

    def test_optional_timestamp_may_be_null(self, case):
        edit(case, "users.json", lambda d: d["records"][2].update(last_logon=None))
        assert validate_case(case).valid


# ---------------------------------------------------- case/device consistency
class TestConsistency:
    def test_case_id_mismatch_names_the_odd_file(self, case):
        edit(case, "network.json", lambda d: d.update(case_id="INC-999"))
        result = validate_case(case)
        assert error_codes(result) == {"CASE_ID_MISMATCH"}
        assert result.errors[0].file == "network.json"
        assert "INC-999" in result.errors[0].message
        assert result.case_id == "INC-001"   # the majority value is the reference

    def test_device_mismatch_names_the_odd_file(self, case):
        edit(case, "users.json", lambda d: d.update(device="OTHER-PC"))
        result = validate_case(case)
        assert error_codes(result) == {"DEVICE_MISMATCH"}
        assert result.errors[0].file == "users.json"
        assert result.device == "WIN-PC-01"

    def test_manifest_can_be_the_odd_one_out(self, case):
        path = case / MANIFEST_FILENAME
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["case_id"] = "INC-777"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        result = validate_case(case)
        assert error_codes(result) == {"CASE_ID_MISMATCH"}
        assert [i.file for i in result.errors] == [MANIFEST_FILENAME]

    def test_hostname_differing_from_device_is_a_warning(self, case):
        edit(case, "system.json", lambda d: d["records"][0].update(hostname="OTHER-PC"))
        result = validate_case(case)
        assert result.valid
        assert warning_codes(result) == {"HOSTNAME_DEVICE_MISMATCH"}

    def test_hostname_letter_case_is_not_flagged(self, case):
        edit(case, "system.json", lambda d: d["records"][0].update(hostname="win-pc-01"))
        assert validate_case(case).warnings == []


# ------------------------------------------------------------------ manifest
class TestManifest:
    def test_missing_manifest(self, case):
        (case / MANIFEST_FILENAME).unlink()
        result = validate_case(case)
        assert not result.valid
        assert error_codes(result) == {"MANIFEST_MISSING"}
        assert not (case / MANIFEST_FILENAME).exists()   # never auto-created

    def test_modified_evidence_causes_hash_mismatch(self, case):
        edit(case, "processes.json",
             lambda d: d["records"][5].update(command_line="powershell.exe -NoProfile"),
             rebuild=False)
        manifest_before = (case / MANIFEST_FILENAME).read_bytes()
        result = validate_case(case)

        assert not result.valid
        assert error_codes(result) == {"MANIFEST_HASH_MISMATCH"}
        issue = result.errors[0]
        assert issue.file == "processes.json"
        assert sha256_file(case / "processes.json") in issue.message
        # The failed manifest is left exactly as it was: no auto-repair.
        assert (case / MANIFEST_FILENAME).read_bytes() == manifest_before

    def test_whitespace_only_change_is_still_detected(self, case):
        path = case / "system.json"
        path.write_bytes(path.read_bytes() + b"\n")
        assert error_codes(validate_case(case)) == {"MANIFEST_HASH_MISMATCH"}

    def test_manifest_must_be_valid_json(self, case):
        write_raw(case, MANIFEST_FILENAME, b"{ broken", rebuild=False)
        result = validate_case(case)
        assert error_codes(result) == {"JSON_INVALID"}
        assert result.errors[0].file == MANIFEST_FILENAME

    def test_empty_manifest(self, case):
        write_raw(case, MANIFEST_FILENAME, b"", rebuild=False)
        assert error_codes(validate_case(case)) == {"FILE_EMPTY"}

    @pytest.mark.parametrize("field", [
        "schema_version", "case_id", "device", "hash_algorithm", "files"])
    def test_manifest_required_fields(self, case, field):
        edit(case, MANIFEST_FILENAME, lambda d: d.pop(field), rebuild=False)
        result = validate_case(case)
        assert "MANIFEST_FIELD_MISSING" in error_codes(result)
        assert result.errors[0].file == MANIFEST_FILENAME

    def test_only_sha256_is_accepted_as_algorithm(self, case):
        edit(case, MANIFEST_FILENAME, lambda d: d.update(hash_algorithm="MD5"),
             rebuild=False)
        assert error_codes(validate_case(case)) == {"MANIFEST_HASH_ALGORITHM"}

    def test_files_must_be_a_list(self, case):
        edit(case, MANIFEST_FILENAME, lambda d: d.update(files={}), rebuild=False)
        assert error_codes(validate_case(case)) == {"MANIFEST_FILES_NOT_LIST"}

    @pytest.mark.parametrize("entry", [
        5,
        {"sha256": "0" * 64},                         # no name
        {"name": "system.json", "sha256": "short"},   # bad hash
    ])
    def test_malformed_manifest_entries(self, case, entry):
        def mutate(d):
            d["files"] = [e for e in d["files"] if e["name"] != "system.json"] + [entry]
        edit(case, MANIFEST_FILENAME, mutate, rebuild=False)
        assert "MANIFEST_ENTRY_INVALID" in error_codes(validate_case(case))

    def test_duplicate_manifest_entries(self, case):
        edit(case, MANIFEST_FILENAME,
             lambda d: d["files"].append(dict(d["files"][0])), rebuild=False)
        assert error_codes(validate_case(case)) == {"MANIFEST_DUPLICATE_ENTRY"}

    @pytest.mark.parametrize("name", [
        "../secret.json", "sub/processes.json", "..\\secret.json", "/etc/passwd", ".."])
    def test_manifest_paths_are_never_followed(self, case, name):
        edit(case, MANIFEST_FILENAME,
             lambda d: d["files"].append({"name": name, "sha256": "0" * 64}),
             rebuild=False)
        result = validate_case(case)
        assert error_codes(result) == {"MANIFEST_BAD_FILE_NAME"}

    def test_unknown_manifest_entry_is_a_warning(self, case):
        edit(case, MANIFEST_FILENAME,
             lambda d: d["files"].append({"name": "notes.txt", "sha256": "0" * 64}),
             rebuild=False)
        result = validate_case(case)
        assert result.valid
        assert warning_codes(result) == {"MANIFEST_UNKNOWN_FILE"}

    def test_evidence_file_missing_from_manifest(self, case):
        edit(case, MANIFEST_FILENAME,
             lambda d: d.update(files=[e for e in d["files"] if e["name"] != "network.json"]),
             rebuild=False)
        result = validate_case(case)
        assert error_codes(result) == {"MANIFEST_FILE_UNLISTED"}
        assert "network.json" in result.errors[0].message

    def test_manifest_size_mismatch(self, case):
        edit(case, MANIFEST_FILENAME,
             lambda d: d["files"][0].update(size_bytes=1), rebuild=False)
        assert error_codes(validate_case(case)) == {"MANIFEST_SIZE_MISMATCH"}

    def test_manifest_record_count_mismatch(self, case):
        edit(case, MANIFEST_FILENAME,
             lambda d: d["files"][1].update(record_count=99), rebuild=False)
        assert error_codes(validate_case(case)) == {"MANIFEST_RECORD_COUNT"}

    def test_uppercase_hash_in_manifest_is_accepted(self, case):
        edit(case, MANIFEST_FILENAME,
             lambda d: d["files"][0].update(sha256=d["files"][0]["sha256"].upper()),
             rebuild=False)
        assert validate_case(case).valid


# --------------------------------------------------------- result and safety
class TestResultAndSafety:
    def test_all_problems_are_reported_together(self, case):
        write_raw(case, "network.json", b"", rebuild=False)
        edit(case, "users.json", lambda d: d["records"][0].pop("username"), rebuild=False)
        (case / "events.json").unlink()
        codes = error_codes(validate_case(case))
        assert {"FILE_EMPTY", "FIELD_MISSING", "REQUIRED_FILE_MISSING",
                "MANIFEST_HASH_MISMATCH"} <= codes

    def test_warnings_never_make_a_case_invalid(self, case):
        (case / "files.json").unlink()
        rebuild_manifest(case)
        edit(case, "processes.json",
             lambda d: d["records"][0].update(parent_name=""))
        result = validate_case(case)
        assert len(result.warnings) == 2
        assert result.valid

    def test_validation_never_changes_a_failing_case(self, case):
        edit(case, "processes.json", lambda d: d["records"][0].update(pid="x"),
             rebuild=False)
        write_raw(case, "network.json", b"garbage", rebuild=False)
        (case / "users.json").unlink()
        before = snapshot(case)
        validate_case(case)
        assert snapshot(case) == before   # no repair, no new files, same mtimes

    def test_issue_dicts_are_json_safe(self, case):
        edit(case, "processes.json", lambda d: d["records"][0].update(pid="x"))
        payload = json.loads(json.dumps(validate_case(case).to_dict()))
        assert payload["valid"] is False
        assert payload["errors"][0]["severity"] == "error"
        assert payload["errors"][0]["record_id"] == "PROC-0001"


# ----------------------------------------------------------------------- CLI
class TestCli:
    def test_valid_case_exit_code_zero(self, capsys):
        assert cli_main([str(SAMPLE_DIR)]) == 0
        assert "VALID" in capsys.readouterr().out

    def test_invalid_case_exit_code_one_and_lists_errors(self, case, capsys):
        edit(case, "processes.json", lambda d: d["records"][0].update(pid="x"))
        assert cli_main([str(case)]) == 1
        output = capsys.readouterr().out
        assert "INVALID" in output and "[FIELD_TYPE]" in output

    def test_json_output(self, case, capsys):
        (case / "files.json").unlink()
        rebuild_manifest(case)
        assert cli_main([str(case), "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["valid"] is True
        assert payload["warnings"][0]["code"] == "OPTIONAL_FILE_MISSING"

    def test_missing_folder_exit_code_one(self, tmp_path, capsys):
        assert cli_main([str(tmp_path / "nope")]) == 1
        assert "CASE_DIR_NOT_FOUND" in capsys.readouterr().out


# ------------------------------------------------- constants stay consistent
class TestContractConstants:
    def test_every_required_field_has_a_type(self):
        for source in EvidenceSource:
            assert set(REQUIRED_RECORD_FIELDS[source]) <= set(FIELD_TYPES[source])

    def test_allowed_values_refer_to_known_fields(self):
        for source, fields in FIELD_ALLOWED_VALUES.items():
            assert set(fields) <= set(FIELD_TYPES[source])

    def test_every_type_name_is_known(self):
        known = {"str", "int", "bool", "object", "list_str", "ts", "ipv4", "sha256"}
        for fields in FIELD_TYPES.values():
            assert set(fields.values()) <= known


class TestTimestampParserFractions:
    """parse_timestamp must give the same answer on every Python version."""

    @pytest.mark.parametrize("text, micro", [
        ("2026-10-08T07:34:01.5Z", 500000),
        ("2026-10-08T07:34:01.123Z", 123000),
        ("2026-10-08T07:34:01.1234567Z", 123456),
        ("2026-10-08T07:34:01Z", 0),
    ])
    def test_fractional_seconds(self, text, micro):
        assert parse_timestamp(text).microsecond == micro
