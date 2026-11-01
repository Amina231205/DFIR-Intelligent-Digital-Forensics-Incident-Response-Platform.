"""Phase 3 tests: evidence normalization.

Corruption/editing always happens on a temporary COPY of the sample case
(``case`` fixture from conftest.py); the original is never modified.
Single-record mapping rules are tested by calling the mappers directly with
small inline records, which keeps those tests independent of the sample files.
"""

from __future__ import annotations

import copy
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from helpers import SAMPLE_DIR, edit, rebuild_manifest, snapshot

from security.models.schemas import (
    EventType,
    EvidenceSource,
    NormalizationResult,
    NormalizedEvent,
)
from security.normalization import event_sort_key, normalize_case, normalize_validated
from security.normalization.__main__ import main as cli_main
from security.normalization.mappers import (
    MappingContext,
    clean,
    map_event_record,
    map_file_record,
    map_network_record,
    map_powershell_record,
    map_process_record,
)
from security.utils.helpers import load_json
from security.validation import EvidenceNotValidError, validate_and_load, validate_case

EVENT_SOURCES = ("events", "processes", "network", "powershell", "files")


# ------------------------------------------------------------------ helpers
@pytest.fixture(scope="module")
def sample() -> NormalizationResult:
    return normalize_case(SAMPLE_DIR)


def by_evidence(result: NormalizationResult) -> dict[str, NormalizedEvent]:
    return {event.evidence_id: event for event in result.events}


def ctx() -> MappingContext:
    return MappingContext(case_id="INC-T", device="PC-T")


def evl(event_id: int, data: dict[str, Any], channel: str = "Security",
        record_id: str = "EVL-0001") -> dict[str, Any]:
    return {"record_id": record_id, "timestamp": "2026-10-08T07:00:00Z",
            "event_id": event_id, "channel": channel,
            "provider": "Microsoft-Windows-Security-Auditing",
            "record_number": 1, "data": data}


def ts(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


# ------------------------------------------------------------- sample case
class TestSampleCase:
    def test_event_count_and_types(self, sample):
        assert len(sample.events) == 32
        assert Counter(e.event_type.value for e in sample.events) == {
            "logon_failed": 7, "logon_success": 3, "account_created": 1,
            "group_member_added": 1, "process_created": 9,
            "network_connection": 5, "powershell_executed": 3,
            "file_created": 3,
        }

    def test_case_and_device(self, sample):
        assert (sample.case_id, sample.device) == ("INC-001", "WIN-PC-01")
        assert all(e.case_id == "INC-001" and e.device == "WIN-PC-01"
                   for e in sample.events)

    def test_source_counts(self, sample):
        assert sample.source_counts == {
            "events": 12, "processes": 9, "network": 5, "powershell": 3,
            "files": 3}

    def test_no_warnings_on_clean_sample(self, sample):
        assert sample.warnings == []

    def test_validation_result_travels_with_output(self, sample):
        assert sample.validation is not None and sample.validation.valid

    def test_event_ids_are_sequential_and_unique(self, sample):
        assert [e.event_id for e in sample.events] == [
            f"E-{n:05d}" for n in range(1, 33)]

    def test_events_are_chronological(self, sample):
        times = [e.timestamp for e in sample.events]
        assert times == sorted(times)
        assert sample.events[0].evidence_id == "EVL-0001"     # 06:54:58 failed logon
        assert sample.events[-1].evidence_id == "EVL-0012"    # 07:35:31 group change

    def test_sort_key_is_a_strict_total_order(self, sample):
        keys = [event_sort_key(e) for e in sample.events]
        assert keys == sorted(keys) and len(set(keys)) == len(keys)

    def test_timestamps_are_timezone_aware_utc(self, sample):
        assert all(e.timestamp.utcoffset().total_seconds() == 0 for e in sample.events)

    def test_event_types_and_sources_are_vocabulary_members(self, sample):
        assert all(isinstance(e.event_type, EventType) for e in sample.events)
        assert {e.source.value for e in sample.events} == set(EVENT_SOURCES)

    def test_json_serializable_with_z_timestamps(self, sample):
        payload = json.loads(json.dumps(sample.to_dict()))
        assert payload["events"][0]["timestamp"] == "2026-10-08T06:54:58Z"
        assert payload["events"][0]["event_type"] == "logon_failed"
        assert payload["validation"]["valid"] is True

    def test_details_shape_is_stable_per_event_type(self, sample):
        shapes: dict[str, set[frozenset]] = defaultdict(set)
        for event in sample.events:
            shapes[event.event_type.value].add(frozenset(event.details))
        assert all(len(variants) == 1 for variants in shapes.values())

    def test_every_event_has_user_context_key(self, sample):
        assert all("user_context" in e.details for e in sample.events)


# ------------------------------------------------------------ traceability
class TestTraceability:
    def test_one_event_per_source_record_and_ids_preserved(self, sample):
        raw_ids = {
            record["record_id"]
            for name in EVENT_SOURCES
            for record in load_json(SAMPLE_DIR / f"{name}.json")["records"]
        }
        event_ids = [e.evidence_id for e in sample.events]
        assert len(event_ids) == len(set(event_ids))          # no record twice
        assert set(event_ids) == raw_ids                      # none lost or invented

    def test_event_points_back_to_its_source_file(self, sample):
        for event in sample.events:
            records = load_json(SAMPLE_DIR / event.evidence_file)["records"]
            assert event.evidence_id in {r["record_id"] for r in records}

    def test_event_fields_match_the_raw_record(self, sample):
        raw = {r["record_id"]: r for r in
               load_json(SAMPLE_DIR / "processes.json")["records"]}
        event = by_evidence(sample)["PROC-0006"]
        record = raw["PROC-0006"]
        assert event.timestamp == ts(record["timestamp"])
        assert event.user == record["user"]
        assert event.details["pid"] == record["pid"]
        assert event.details["command_line"] == record["command_line"]
        assert event.details["sha256"] == record["sha256"]


# -------------------------------------------- users/system are not events
class TestUsersAndSystemAreNotEvents:
    def test_no_event_comes_from_users_or_system(self, sample):
        assert not any(e.source in (EvidenceSource.USERS, EvidenceSource.SYSTEM)
                       for e in sample.events)
        assert not any(e.evidence_id.startswith(("USR-", "SYS-"))
                       for e in sample.events)

    def test_host_context_is_the_system_record(self, sample):
        assert sample.host == load_json(SAMPLE_DIR / "system.json")["records"][0]
        assert sample.host["hostname"] == "WIN-PC-01"

    def test_users_are_kept_as_enrichment_records(self, sample):
        assert sample.users == load_json(SAMPLE_DIR / "users.json")["records"]

    def test_new_account_creation_time_does_not_add_an_event(self, sample):
        # svc_helpdesk's created_at (07:35:22) appears once, from Event 4720 only.
        created = [e for e in sample.events if e.event_type is EventType.ACCOUNT_CREATED]
        assert [e.evidence_id for e in created] == ["EVL-0011"]


# ----------------------------------------------------- events.json mapping
class TestEventLogMapping:
    def test_failed_logon_over_rdp(self, sample):
        event = by_evidence(sample)["EVL-0004"]
        assert event.event_type is EventType.LOGON_FAILED
        assert event.user == "ahmed"
        details = event.details
        assert details["windows_event_id"] == 4625
        assert details["logon_type"] == 10
        assert details["logon_type_name"] == "RemoteInteractive"
        assert details["source_ip"] == "198.51.100.23"
        assert details["failure_reason"] == "wrong password"
        assert details["status"] == "0xC000006D"

    def test_dash_ip_becomes_null(self, sample):
        local_failure = by_evidence(sample)["EVL-0001"]
        assert local_failure.details["source_ip"] is None
        assert local_failure.details["logon_type_name"] == "Interactive"

    def test_successful_logon_has_no_failure_keys(self, sample):
        event = by_evidence(sample)["EVL-0010"]
        assert event.event_type is EventType.LOGON_SUCCESS
        assert event.details["source_ip"] == "198.51.100.23"
        assert "failure_reason" not in event.details
        assert by_evidence(sample)["EVL-0003"].details["logon_type_name"] == "Service"

    def test_account_created_uses_the_actor_as_user(self, sample):
        event = by_evidence(sample)["EVL-0011"]
        assert event.event_type is EventType.ACCOUNT_CREATED
        assert event.user == "ahmed"                       # who did it
        assert event.details["target_user"] == "svc_helpdesk"   # who was created
        assert event.details["target_sid"].endswith("-1004")

    def test_group_member_added(self, sample):
        event = by_evidence(sample)["EVL-0012"]
        assert event.event_type is EventType.GROUP_MEMBER_ADDED
        assert event.user == "ahmed"
        assert event.details["group"] == "Administrators"
        assert event.details["member"] == "WIN-PC-01\\svc_helpdesk"
        assert event.details["member_name"] == "svc_helpdesk"

    @pytest.mark.parametrize("sub_status, status, expected", [
        ("0xC0000064", "0xC000006D", "user name does not exist"),
        ("0xc000006a", "0xC000006D", "wrong password"),          # lowercase hex
        ("0x0", "0xC0000234", "account locked out"),             # falls back to Status
        ("0xDEADBEEF", "0xDEADBEEF", None),                      # unknown code
    ])
    def test_failure_reason_lookup(self, sub_status, status, expected):
        record = evl(4625, {"TargetUserName": "u", "LogonType": "3",
                            "Status": status, "SubStatus": sub_status})
        assert map_event_record(record, ctx()).details["failure_reason"] == expected

    def test_member_without_domain_prefix(self):
        record = evl(4732, {"MemberName": "svc_x", "TargetUserName": "Administrators",
                            "SubjectUserName": "root"})
        assert map_event_record(record, ctx()).details["member_name"] == "svc_x"

    def test_channel_comparison_ignores_case(self):
        event = map_event_record(evl(4625, {"TargetUserName": "u"}, channel="SECURITY"), ctx())
        assert event.event_type is EventType.LOGON_FAILED

    def test_unknown_logon_type_number_keeps_value_without_name(self):
        event = map_event_record(evl(4624, {"TargetUserName": "u", "LogonType": "99"}), ctx())
        assert event.details["logon_type"] == 99
        assert event.details["logon_type_name"] is None


class TestUnknownEvents:
    def test_unsupported_windows_event_becomes_other_and_keeps_data(self):
        raw = {"NewProcessName": "x.exe", "Nested": {"a": [1, 2]}}
        context = ctx()
        event = map_event_record(evl(4688, raw), context)
        assert event.event_type is EventType.OTHER
        assert event.user is None
        assert event.details["windows_event_id"] == 4688
        assert event.details["data"] == raw
        assert context.warnings == []

    def test_other_event_data_is_a_copy(self):
        raw = {"Nested": {"a": [1]}}
        event = map_event_record(evl(1102, raw), ctx())
        event.details["data"]["Nested"]["a"].append(2)
        assert raw == {"Nested": {"a": [1]}}

    def test_supported_id_in_another_channel_is_not_misclassified(self):
        event = map_event_record(evl(4624, {"TargetUserName": "u"}, channel="Application"), ctx())
        assert event.event_type is EventType.OTHER

    def test_other_events_flow_through_the_whole_pipeline(self, case):
        edit(case, "events.json", lambda d: d["records"].append(
            evl(4688, {"x": "y"}, record_id="EVL-0013")
            | {"timestamp": "2026-10-08T07:40:00Z"}))
        result = normalize_case(case)
        assert len(result.events) == 33
        assert by_evidence(result)["EVL-0013"].event_type is EventType.OTHER
        assert result.events[-1].evidence_id == "EVL-0013"


class TestEventDataQualityWarnings:
    def test_missing_user_name_warns_but_keeps_the_event(self, case):
        edit(case, "events.json",
             lambda d: d["records"][3]["data"].pop("TargetUserName"))
        result = normalize_case(case)
        event = by_evidence(result)["EVL-0004"]
        assert event.user is None
        assert len(result.events) == 32
        assert [(w.code, w.evidence_id) for w in result.warnings] == [
            ("EVENT_DATA_MISSING_FIELD", "EVL-0004")]
        assert "TargetUserName" in result.warnings[0].message

    def test_dash_user_name_counts_as_missing(self):
        context = ctx()
        event = map_event_record(evl(4625, {"TargetUserName": "-"}), context)
        assert event.user is None
        assert [w.code for w in context.warnings] == ["EVENT_DATA_MISSING_FIELD"]

    def test_non_numeric_logon_type_warns(self):
        context = ctx()
        event = map_event_record(
            evl(4624, {"TargetUserName": "u", "LogonType": "abc"}), context)
        assert event.details["logon_type"] is None
        assert [w.code for w in context.warnings] == ["EVENT_DATA_INVALID"]

    def test_account_created_without_actor_warns(self):
        context = ctx()
        event = map_event_record(
            evl(4720, {"TargetUserName": "new", "SubjectUserName": "-"}), context)
        assert event.user is None and event.details["target_user"] == "new"
        assert [w.code for w in context.warnings] == ["EVENT_DATA_MISSING_FIELD"]

    def test_clean_helper(self):
        assert [clean(v) for v in (None, "", "  ", "-", " x ", 5)] == [
            None, None, None, None, "x", "5"]


# ------------------------------------------- processes / network / ps / files
def process_record(**overrides) -> dict[str, Any]:
    base = {"record_id": "PROC-0001", "timestamp": "2026-10-08T07:00:00Z",
            "pid": 10, "ppid": 4, "name": "a.exe", "command_line": "a.exe /x",
            "user": "ahmed"}
    return base | overrides


class TestOtherSources:
    def test_process_mapping(self, sample):
        event = by_evidence(sample)["PROC-0006"]
        assert event.event_type is EventType.PROCESS_CREATED
        assert event.source is EvidenceSource.PROCESSES
        assert event.details["name"] == "powershell.exe"
        assert event.details["parent_name"] == "wscript.exe"
        assert "-EncodedCommand" in event.details["command_line"]
        assert event.details["origin"] == "event_log"

    def test_null_command_line_is_preserved_as_null(self):
        event = map_process_record(process_record(command_line=None), ctx())
        assert event.details["command_line"] is None

    def test_null_command_line_end_to_end(self, case):
        edit(case, "processes.json",
             lambda d: d["records"][0].update(command_line=None))
        result = normalize_case(case)          # validation accepts it
        assert by_evidence(result)["PROC-0001"].details["command_line"] is None
        assert len(result.events) == 32

    def test_absent_and_blank_optional_fields_become_null(self):
        event = map_process_record(process_record(parent_name="  "), ctx())
        assert event.details["parent_name"] is None
        assert event.details["executable_path"] is None
        assert event.details["sha256"] is None

    def test_network_mapping_has_no_derived_external_flag(self, sample):
        event = by_evidence(sample)["NET-0004"]
        assert event.event_type is EventType.NETWORK_CONNECTION
        assert event.user is None
        assert event.details["remote_address"] == "203.0.113.77"
        assert event.details["remote_hostname"] == "files-sync.example.net"
        assert event.details["pid"] == 6012
        assert not any("external" in key for key in event.details)

    def test_network_user_is_used_when_the_collector_provides_one(self):
        record = {"record_id": "NET-0001", "timestamp": "2026-10-08T07:00:00Z",
                  "protocol": "TCP", "local_address": "10.0.0.1", "local_port": 1,
                  "remote_address": "10.0.0.2", "remote_port": 2,
                  "direction": "outbound", "pid": 1, "process_name": "x.exe",
                  "user": "sara"}
        event = map_network_record(record, ctx())
        assert event.user == "sara"
        assert event.details["state"] is None

    def test_powershell_mapping(self, sample):
        event = by_evidence(sample)["PS-0002"]
        assert event.event_type is EventType.POWERSHELL_EXECUTED
        assert event.user == "ahmed"
        assert "Invoke-WebRequest" in event.details["command"]
        assert "-EncodedCommand" in event.details["host_application"]
        assert event.details["script_path"] is None
        assert event.details["windows_event_id"] == 4104
        assert event.details["pid"] == 6012

    def test_powershell_minimal_record(self):
        record = {"record_id": "PS-0001", "timestamp": "2026-10-08T07:00:00Z",
                  "user": "u", "pid": 1, "command": "Get-Date"}
        event = map_powershell_record(record, ctx())
        assert event.details["windows_event_id"] is None
        assert event.details["host_application"] is None

    def test_file_mapping(self, sample):
        event = by_evidence(sample)["FILE-0003"]
        assert event.event_type is EventType.FILE_CREATED
        assert event.timestamp == ts("2026-10-08T07:34:09Z")
        assert event.user == "ahmed"
        assert event.details["path"] == "C:\\Users\\Public\\update_svc.ps1"
        assert event.details["size_bytes"] == 164

    def test_file_without_owner(self):
        record = {"record_id": "FILE-0001", "timestamp": "2026-10-08T07:00:00Z",
                  "path": "C:\\a.txt", "name": "a.txt", "size_bytes": 1,
                  "sha256": "0" * 64}
        event = map_file_record(record, ctx())
        assert event.user is None and event.details["owner"] is None


# -------------------------------------------------------------- enrichment
class TestUserEnrichment:
    def test_actor_context_from_users_json(self, sample):
        context = by_evidence(sample)["PROC-0006"].details["user_context"]
        assert context["evidence_id"] == "USR-0003"
        assert context["is_admin"] is True
        assert context["account_type"] == "local"
        assert context["groups"] == ["Administrators", "Users"]

    def test_non_admin_service_account(self, sample):
        context = by_evidence(sample)["PROC-0003"].details["user_context"]
        assert context["evidence_id"] == "USR-0005"
        assert context["is_admin"] is False

    def test_target_account_context_for_account_events(self, sample):
        for rid in ("EVL-0011", "EVL-0012"):
            target = by_evidence(sample)[rid].details["target_user_context"]
            assert target["evidence_id"] == "USR-0006"
            assert target["username"] == "svc_helpdesk"
            assert target["is_admin"] is True

    def test_target_context_only_on_account_events(self, sample):
        for event in sample.events:
            has = "target_user_context" in event.details
            assert has == (event.event_type in
                           (EventType.ACCOUNT_CREATED, EventType.GROUP_MEMBER_ADDED))

    def test_event_without_user_gets_null_context(self, sample):
        assert by_evidence(sample)["NET-0004"].details["user_context"] is None

    def test_unknown_user_gets_null_context(self, case):
        edit(case, "processes.json", lambda d: d["records"][0].update(user="ghost"))
        event = by_evidence(normalize_case(case))["PROC-0001"]
        assert event.user == "ghost" and event.details["user_context"] is None

    def test_matching_ignores_case_but_keeps_original_spelling(self, case):
        edit(case, "processes.json", lambda d: d["records"][0].update(user="AHMED"))
        event = by_evidence(normalize_case(case))["PROC-0001"]
        assert event.user == "AHMED"
        assert event.details["user_context"]["username"] == "ahmed"

    def test_target_not_in_users_json_gets_null_target_context(self, case):
        def drop_new_account(data):
            data["records"] = [r for r in data["records"]
                               if r["username"] != "svc_helpdesk"]
        edit(case, "users.json", drop_new_account)
        event = by_evidence(normalize_case(case))["EVL-0011"]
        assert event.details["target_user_context"] is None
        assert event.details["user_context"]["evidence_id"] == "USR-0003"

    def test_duplicate_usernames_warn_and_first_record_wins(self, case):
        def add_duplicate(data):
            data["records"].append({**data["records"][2], "record_id": "USR-0007",
                                    "username": "AHMED", "is_admin": False})
        edit(case, "users.json", add_duplicate)
        result = normalize_case(case)
        assert [(w.code, w.evidence_id) for w in result.warnings] == [
            ("USERS_DUPLICATE_USERNAME", "USR-0007")]
        assert by_evidence(result)["PROC-0006"].details["user_context"][
            "evidence_id"] == "USR-0003"

    def test_contexts_are_independent_copies(self, sample):
        events = [e for e in sample.events if e.user == "ahmed"]
        first, second = events[0].details["user_context"], events[1].details["user_context"]
        assert first == second and first is not second
        assert first["groups"] is not second["groups"]


# ---------------------------------------------------------------- ordering
def make_event(source: EvidenceSource, evidence_id: str, when: str) -> NormalizedEvent:
    return NormalizedEvent(
        event_id="", case_id="C", timestamp=ts(when), event_type=EventType.OTHER,
        source=source, device="D", user=None, evidence_id=evidence_id)


class TestOrdering:
    def test_time_comes_first(self):
        early = make_event(EvidenceSource.FILES, "FILE-0001", "2026-10-08T07:00:00Z")
        late = make_event(EvidenceSource.EVENTS, "EVL-0001", "2026-10-08T07:00:01Z")
        assert sorted([late, early], key=event_sort_key) == [early, late]

    def test_subsecond_precision_is_respected(self):
        a = make_event(EvidenceSource.EVENTS, "EVL-0002", "2026-10-08T07:00:00.250000Z")
        b = make_event(EvidenceSource.EVENTS, "EVL-0001", "2026-10-08T07:00:00.750000Z")
        assert sorted([b, a], key=event_sort_key) == [a, b]

    def test_same_time_orders_by_source(self):
        when = "2026-10-08T07:00:00Z"
        events = [make_event(s, f"{p}-0001", when) for s, p in [
            (EvidenceSource.FILES, "FILE"), (EvidenceSource.POWERSHELL, "PS"),
            (EvidenceSource.NETWORK, "NET"), (EvidenceSource.PROCESSES, "PROC"),
            (EvidenceSource.EVENTS, "EVL")]]
        ordered = sorted(events, key=event_sort_key)
        assert [e.source.value for e in ordered] == [
            "events", "processes", "network", "powershell", "files"]

    def test_same_source_orders_by_record_number_not_text(self):
        when = "2026-10-08T07:00:00Z"
        ids = ["PROC-0010", "PROC-0002", "PROC-000003", "PROC-0001"]
        events = [make_event(EvidenceSource.PROCESSES, i, when) for i in ids]
        ordered = [e.evidence_id for e in sorted(events, key=event_sort_key)]
        assert ordered == ["PROC-0001", "PROC-0002", "PROC-000003", "PROC-0010"]

    def test_ties_across_sources_in_a_real_case(self, case):
        same = "2026-10-08T09:00:00Z"
        edit(case, "network.json", lambda d: d["records"][0].update(timestamp=same))
        edit(case, "processes.json", lambda d: d["records"][0].update(timestamp=same))
        edit(case, "files.json", lambda d: d["records"][0].update(timestamp=same))
        tail = [e.evidence_id for e in normalize_case(case).events[-3:]]
        assert tail == ["PROC-0001", "NET-0001", "FILE-0001"]


# ------------------------------------------------------------- determinism
class TestDeterminism:
    def test_two_runs_are_identical(self):
        first = normalize_case(SAMPLE_DIR).to_dict()
        second = normalize_case(SAMPLE_DIR).to_dict()
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)

    def test_record_order_inside_files_does_not_matter(self, case, sample):
        for name in (*EVENT_SOURCES, "users"):
            edit(case, f"{name}.json", lambda d: d["records"].reverse(), rebuild=False)
        rebuild_manifest(case)
        shuffled = normalize_case(case)
        assert [e.to_dict() for e in shuffled.events] == [
            e.to_dict() for e in sample.events]
        assert shuffled.warnings == sample.warnings
        assert shuffled.host == sample.host

    def test_warning_order_is_deterministic(self, case):
        def break_two(data):
            data["records"][3]["data"].pop("TargetUserName")
            data["records"][9]["data"].pop("TargetUserName")
        edit(case, "events.json", break_two)
        forward = [w.evidence_id for w in normalize_case(case).warnings]
        edit(case, "events.json", lambda d: d["records"].reverse())
        assert [w.evidence_id for w in normalize_case(case).warnings] == forward


# ---------------------------------------------------- validation gate
class TestOnlyValidatedEvidenceIsAccepted:
    def test_missing_required_file(self, case):
        (case / "network.json").unlink()
        rebuild_manifest(case)
        with pytest.raises(EvidenceNotValidError) as caught:
            normalize_case(case)
        assert {i.code for i in caught.value.result.errors} == {"REQUIRED_FILE_MISSING"}

    def test_tampered_file_fails_the_manifest_hash(self, case):
        edit(case, "processes.json",
             lambda d: d["records"][0].update(name="evil.exe"), rebuild=False)
        with pytest.raises(EvidenceNotValidError) as caught:
            normalize_case(case)
        assert {i.code for i in caught.value.result.errors} == {"MANIFEST_HASH_MISMATCH"}

    def test_invalid_timestamp(self, case):
        edit(case, "events.json",
             lambda d: d["records"][0].update(timestamp="2026-10-08T07:00:00+03:00"))
        with pytest.raises(EvidenceNotValidError) as caught:
            normalize_case(case)
        assert "TIMESTAMP_INVALID" in {i.code for i in caught.value.result.errors}

    def test_missing_manifest(self, case):
        (case / "manifest.json").unlink()
        with pytest.raises(EvidenceNotValidError):
            normalize_case(case)

    def test_missing_folder(self, tmp_path):
        with pytest.raises(EvidenceNotValidError) as caught:
            normalize_case(tmp_path / "nope")
        assert caught.value.result.errors[0].code == "CASE_DIR_NOT_FOUND"

    def test_exception_message_names_the_folder_and_first_error(self, case):
        (case / "events.json").unlink()
        with pytest.raises(EvidenceNotValidError, match="events.json") as caught:
            normalize_case(case)
        assert str(case) in str(caught.value)

    def test_each_file_is_read_exactly_once(self, monkeypatch):
        """Analyzed bytes == validated bytes: no second read after the hash check."""
        reads: list[str] = []
        original = Path.read_bytes

        def counting(self: Path) -> bytes:
            reads.append(self.name)
            return original(self)

        monkeypatch.setattr(Path, "read_bytes", counting)
        normalize_case(SAMPLE_DIR)
        assert sorted(reads) == sorted(
            [f"{s}.json" for s in (*EVENT_SOURCES, "users", "system")] + ["manifest.json"])

    def test_validate_and_load_agrees_with_validate_case(self):
        result, loaded = validate_and_load(SAMPLE_DIR)
        assert result.to_dict() == validate_case(SAMPLE_DIR).to_dict()
        assert set(loaded) == {f"{s.value}.json" for s in EvidenceSource}
        assert all(file.data is not None for file in loaded.values())


# ------------------------------------------------- optional and empty files
class TestOptionalAndEmptySources:
    def test_missing_files_json_is_fine(self, case):
        (case / "files.json").unlink()
        rebuild_manifest(case)
        result = normalize_case(case)
        assert len(result.events) == 29
        assert "files" not in result.source_counts
        assert not any(e.event_type is EventType.FILE_CREATED for e in result.events)
        assert [w.code for w in result.validation.warnings] == ["OPTIONAL_FILE_MISSING"]

    def test_empty_records_list_yields_zero_events(self, case):
        edit(case, "powershell.json", lambda d: d.update(records=[]))
        result = normalize_case(case)
        assert result.source_counts["powershell"] == 0
        assert not any(e.source is EvidenceSource.POWERSHELL for e in result.events)
        assert [w.code for w in result.validation.warnings] == ["RECORDS_EMPTY"]

    def test_normalize_validated_works_with_minimal_evidence(self):
        envelope = copy.deepcopy(load_json(SAMPLE_DIR / "processes.json"))
        result = normalize_validated({EvidenceSource.PROCESSES: envelope})
        assert len(result.events) == 9
        assert result.host == {} and result.users == []
        assert all(e.details["user_context"] is None for e in result.events)
        assert result.validation is None


# --------------------------------------------------- read-only guarantees
class TestReadOnly:
    def test_normalizing_does_not_touch_the_sample(self):
        before = snapshot(SAMPLE_DIR)
        normalize_case(SAMPLE_DIR)
        assert snapshot(SAMPLE_DIR) == before

    def test_no_files_are_created_or_changed_in_a_working_copy(self, case):
        before = snapshot(case)
        normalize_case(case)
        assert snapshot(case) == before

    def test_input_data_is_not_mutated(self):
        evidence = {source: copy.deepcopy(load_json(SAMPLE_DIR / f"{source.value}.json"))
                    for source in EvidenceSource}
        pristine = copy.deepcopy(evidence)
        normalize_validated(evidence)
        assert evidence == pristine

    def test_output_is_independent_of_the_input(self):
        evidence = {source: copy.deepcopy(load_json(SAMPLE_DIR / f"{source.value}.json"))
                    for source in EvidenceSource}
        pristine = copy.deepcopy(evidence)
        result = normalize_validated(evidence)
        result.host["hostname"] = "CHANGED"
        result.users[0]["username"] = "CHANGED"
        result.events[0].details["source_ip"] = "CHANGED"
        assert evidence == pristine


# -------------------------------------------------------------------- CLI
class TestCli:
    def test_valid_case(self, capsys):
        assert cli_main([str(SAMPLE_DIR)]) == 0
        output = capsys.readouterr().out
        assert "Events  : 32" in output
        assert "logon_failed" in output and "E-00001" in output

    def test_limit_zero_lists_every_event(self, capsys):
        assert cli_main([str(SAMPLE_DIR), "--limit", "0"]) == 0
        assert "E-00032" in capsys.readouterr().out

    def test_json_output(self, capsys):
        assert cli_main([str(SAMPLE_DIR), "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert len(payload["events"]) == 32
        assert payload["events"][0]["event_id"] == "E-00001"

    def test_invalid_evidence_prints_validation_report_and_fails(self, case, capsys):
        (case / "events.json").unlink()
        assert cli_main([str(case)]) == 1
        output = capsys.readouterr().out
        assert "nothing was normalized" in output
        assert "REQUIRED_FILE_MISSING" in output

    def test_warnings_are_listed(self, case, capsys):
        edit(case, "events.json",
             lambda d: d["records"][3]["data"].pop("TargetUserName"))
        assert cli_main([str(case)]) == 0
        assert "EVENT_DATA_MISSING_FIELD" in capsys.readouterr().out
