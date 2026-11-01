"""Phase 4 tests: timeline reconstruction.

Timelines are built from the sample case (via normalization) or from small
hand-made ``NormalizedEvent`` lists when the point is ordering/tie behaviour.
Anything that edits evidence works on a temporary copy (``case`` fixture).
"""

from __future__ import annotations

import copy
import json
import random
from datetime import datetime, timedelta, timezone

import pytest
from helpers import SAMPLE_DIR, edit, snapshot

from security.models.schemas import (
    EventType,
    EvidenceSource,
    NormalizationResult,
    NormalizedEvent,
    Timeline,
)
from security.normalization import normalize_case
from security.timeline import (
    build_case_timeline,
    build_timeline,
    build_timeline_from_result,
    describe_event,
    filter_timeline,
    format_gap,
    format_timeline,
)
from security.timeline.__main__ import main as cli_main
from security.utils.helpers import load_json
from security.validation import EvidenceNotValidError

EVENT_FILES = ("events", "processes", "network", "powershell", "files")


# ------------------------------------------------------------------ helpers
@pytest.fixture(scope="module")
def result() -> NormalizationResult:
    return normalize_case(SAMPLE_DIR)


@pytest.fixture(scope="module")
def timeline(result) -> Timeline:
    return build_timeline_from_result(result)


def ts(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def event(event_id: str, when: str, source: EvidenceSource = EvidenceSource.EVENTS,
          evidence_id: str = "EVL-0001", event_type: EventType = EventType.OTHER,
          user: str | None = None, device: str = "PC-1", case_id: str = "C-1",
          details: dict | None = None) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id, case_id=case_id, timestamp=ts(when),
        event_type=event_type, source=source, device=device, user=user,
        evidence_id=evidence_id, details=details or {})


def ids(tl: Timeline) -> list[str]:
    return [e.event_id for e in tl.entries]


# ------------------------------------------------------- chronological order
class TestChronologicalOrder:
    def test_sample_has_one_entry_per_event(self, timeline, result):
        assert timeline.event_count == len(timeline.entries) == len(result.events) == 32

    def test_entries_are_chronological(self, timeline):
        times = [e.timestamp for e in timeline.entries]
        assert times == sorted(times)

    def test_sequence_is_one_based_and_contiguous(self, timeline):
        assert [e.sequence for e in timeline.entries] == list(range(1, 33))

    def test_event_ids_follow_phase3_numbering(self, timeline):
        assert ids(timeline) == [f"E-{n:05d}" for n in range(1, 33)]

    def test_start_end_and_duration(self, timeline):
        assert timeline.start == ts("2026-10-08T06:54:58Z")
        assert timeline.end == ts("2026-10-08T07:35:31Z")
        assert timeline.duration_seconds == (timeline.end - timeline.start).total_seconds() == 2433

    def test_what_happened_next_gaps(self, timeline):
        first, second = timeline.entries[0], timeline.entries[1]
        assert first.gap_from_previous_seconds is None
        assert first.offset_from_start_seconds == 0.0
        assert second.gap_from_previous_seconds == 14.0           # 06:54:58 -> 06:55:12
        for before, after in zip(timeline.entries, timeline.entries[1:]):
            gap = after.gap_from_previous_seconds
            assert gap >= 0
            assert after.offset_from_start_seconds == pytest.approx(
                before.offset_from_start_seconds + gap)
        assert timeline.entries[-1].offset_from_start_seconds == timeline.duration_seconds

    def test_unsorted_input_gives_the_same_timeline(self, result):
        reversed_events = list(reversed(result.events))
        assert (build_timeline(reversed_events).to_dict()
                == build_timeline_from_result(result).to_dict())

    def test_every_shuffle_gives_the_same_timeline(self, result):
        expected = build_timeline_from_result(result).to_dict()
        for seed in range(5):
            events = list(result.events)
            random.Random(seed).shuffle(events)
            assert build_timeline(events).to_dict() == expected

    def test_subsecond_ordering(self):
        late = event("E-2", "2026-10-08T07:00:00.750000Z", evidence_id="EVL-0002")
        early = event("E-1", "2026-10-08T07:00:00.250000Z", evidence_id="EVL-0001")
        tl = build_timeline([late, early])
        assert ids(tl) == ["E-1", "E-2"]
        assert tl.entries[1].gap_from_previous_seconds == 0.5

    def test_timestamps_spanning_days_and_timezones(self):
        cairo = timezone(timedelta(hours=3))
        a = event("E-1", "2026-10-08T23:59:59Z", evidence_id="EVL-0001")
        b = NormalizedEvent(
            event_id="E-2", case_id="C-1",
            timestamp=datetime(2026, 10, 9, 3, 0, 1, tzinfo=cairo),   # 00:00:01Z
            event_type=EventType.OTHER, source=EvidenceSource.EVENTS,
            device="PC-1", user=None, evidence_id="EVL-0002")
        tl = build_timeline([b, a])
        assert ids(tl) == ["E-1", "E-2"]
        assert tl.entries[1].gap_from_previous_seconds == 2.0


# --------------------------------------------------------- identical times
class TestIdenticalTimestamps:
    WHEN = "2026-10-08T07:00:00Z"

    def _tied(self) -> list[NormalizedEvent]:
        return [
            event("E-5", self.WHEN, EvidenceSource.FILES, "FILE-0001"),
            event("E-4", self.WHEN, EvidenceSource.POWERSHELL, "PS-0001"),
            event("E-3", self.WHEN, EvidenceSource.NETWORK, "NET-0001"),
            event("E-2", self.WHEN, EvidenceSource.PROCESSES, "PROC-0001"),
            event("E-1", self.WHEN, EvidenceSource.EVENTS, "EVL-0001"),
        ]

    def test_ties_resolve_by_source_order(self):
        assert [e.source.value for e in build_timeline(self._tied()).entries] == [
            "events", "processes", "network", "powershell", "files"]

    def test_ties_inside_one_source_resolve_by_numeric_record_number(self):
        events = [event(f"E-{i}", self.WHEN, EvidenceSource.PROCESSES, rid)
                  for i, rid in enumerate(["PROC-0010", "PROC-0002", "PROC-0001"], 1)]
        assert [e.evidence_id for e in build_timeline(events).entries] == [
            "PROC-0001", "PROC-0002", "PROC-0010"]

    def test_tie_resolution_ignores_input_order(self):
        tied = self._tied()
        expected = build_timeline(tied).to_dict()
        for seed in range(10):
            shuffled = list(tied)
            random.Random(seed).shuffle(shuffled)
            assert build_timeline(shuffled).to_dict() == expected

    def test_tied_events_have_zero_gap_and_offset(self):
        entries = build_timeline(self._tied()).entries
        assert [e.gap_from_previous_seconds for e in entries] == [None, 0.0, 0.0, 0.0, 0.0]
        assert {e.offset_from_start_seconds for e in entries} == {0.0}

    def test_sample_ties_keep_phase3_order(self, timeline):
        # 07:15:03Z has a process (PROC-0003) and a PowerShell record (PS-0001)
        same = [e for e in timeline.entries
                if e.timestamp == ts("2026-10-08T07:15:03Z")]
        assert [e.evidence_id for e in same] == ["PROC-0003", "PS-0001"]
        assert same[1].gap_from_previous_seconds == 0.0

    def test_duplicate_event_id_is_rejected(self):
        with pytest.raises(ValueError, match="duplicate event_id 'E-1'"):
            build_timeline([event("E-1", self.WHEN, evidence_id="EVL-0001"),
                            event("E-1", self.WHEN, evidence_id="EVL-0002")])


# ---------------------------------------------------------- empty timelines
class TestEmptyTimeline:
    def test_empty_timeline_shape(self):
        tl = build_timeline([], case_id="INC-9")
        assert tl.entries == [] and tl.event_count == 0
        assert (tl.case_id, tl.start, tl.end, tl.duration_seconds) == ("INC-9", None, None, 0.0)
        assert tl.counts_by_type == {} and tl.counts_by_source == {}
        assert tl.users == [] and tl.devices == []

    def test_empty_timeline_without_case_id(self):
        assert build_timeline([]).case_id is None

    def test_empty_timeline_serializes(self):
        payload = json.loads(json.dumps(build_timeline([], case_id="INC-9").to_dict()))
        assert payload["entries"] == [] and payload["start"] is None

    def test_empty_timeline_lookups_and_filters(self):
        tl = build_timeline([], case_id="INC-9")
        assert tl.get_by_event_id("E-00001") is None
        assert tl.get_by_evidence_id("EVL-0001") is None
        filtered = filter_timeline(tl, users="ahmed", start="2026-10-08T00:00:00Z")
        assert filtered.entries == [] and filtered.case_id == "INC-9"

    def test_empty_timeline_renders(self):
        assert "No events in this timeline." in format_timeline(
            build_timeline([], case_id="INC-9"))

    def test_case_with_no_events_end_to_end(self, case):
        for name in EVENT_FILES:
            edit(case, f"{name}.json", lambda d: d.update(records=[]))
        tl = build_case_timeline(case)         # valid evidence, nothing to show
        assert tl.event_count == 0 and tl.case_id == "INC-001"

    def test_selection_that_matches_nothing_is_empty_not_an_error(self, timeline):
        tl = filter_timeline(timeline, users="nobody")
        assert tl.event_count == 0 and tl.start is None and tl.entries == []


# ---------------------------------------------- field preservation / lossless
class TestPreservation:
    def test_every_event_round_trips_exactly(self, timeline, result):
        assert [e.to_event() for e in timeline.entries] == result.events

    def test_named_fields_are_preserved(self, timeline, result):
        for entry, event_ in zip(timeline.entries, result.events):
            assert entry.event_id == event_.event_id
            assert entry.evidence_id == event_.evidence_id
            assert entry.timestamp == event_.timestamp
            assert entry.source is event_.source
            assert entry.event_type is event_.event_type
            assert entry.user == event_.user
            assert entry.device == event_.device
            assert entry.case_id == event_.case_id
            assert entry.details == event_.details

    def test_details_are_independent_copies(self, result):
        tl = build_timeline_from_result(result)
        tl.entries[0].details["source_ip"] = "CHANGED"
        assert result.events[0].details["source_ip"] is None

    def test_timeline_statistics(self, timeline):
        assert timeline.counts_by_type == {
            "account_created": 1, "file_created": 3, "group_member_added": 1,
            "logon_failed": 7, "logon_success": 3, "network_connection": 5,
            "powershell_executed": 3, "process_created": 9}
        assert timeline.counts_by_source == {
            "events": 12, "files": 3, "network": 5, "powershell": 3, "processes": 9}
        assert timeline.users == ["ahmed", "svc_backup"]
        assert timeline.devices == ["WIN-PC-01"]
        assert timeline.case_id == "INC-001"

    def test_json_output_is_flat_and_complete(self, timeline):
        payload = json.loads(json.dumps(timeline.to_dict()))
        row = payload["entries"][21]               # E-00022, PROC-0006
        assert row["timestamp"] == "2026-10-08T07:34:01Z"
        assert row["event_type"] == "process_created"
        assert row["source"] == "processes" and row["evidence_file"] == "processes.json"
        assert row["details"]["parent_name"] == "wscript.exe"
        assert set(row) == {
            "sequence", "event_id", "case_id", "timestamp", "event_type", "source",
            "device", "user", "evidence_id", "evidence_file", "summary",
            "gap_from_previous_seconds", "offset_from_start_seconds", "details"}


# ------------------------------------------------------ evidence traceability
class TestTraceability:
    def test_every_entry_points_to_a_real_raw_record(self, timeline):
        for entry in timeline.entries:
            records = load_json(SAMPLE_DIR / entry.evidence_file)["records"]
            assert entry.evidence_id in {r["record_id"] for r in records}

    def test_all_raw_records_appear_exactly_once(self, timeline):
        raw = {r["record_id"] for n in EVENT_FILES
               for r in load_json(SAMPLE_DIR / f"{n}.json")["records"]}
        listed = [e.evidence_id for e in timeline.entries]
        assert len(listed) == len(set(listed)) and set(listed) == raw

    def test_lookup_by_evidence_id(self, timeline):
        entry = timeline.get_by_evidence_id("PROC-0006")
        assert entry.event_id == "E-00022"
        assert entry.evidence_file == "processes.json"
        assert entry.details["pid"] == 6012

    def test_lookup_by_event_id(self, timeline):
        assert timeline.get_by_event_id("E-00030").evidence_id == "EVL-0011"

    def test_unknown_lookups_return_none(self, timeline):
        assert timeline.get_by_event_id("E-99999") is None
        assert timeline.get_by_evidence_id("PROC-9999") is None

    def test_users_and_system_never_appear(self, timeline):
        assert not any(e.evidence_id.startswith(("USR-", "SYS-")) for e in timeline.entries)

    def test_ids_stay_stable_through_filtering(self, timeline):
        view = filter_timeline(timeline, event_types="logon_failed")
        for entry in view.entries:
            original = timeline.get_by_event_id(entry.event_id)
            assert original.evidence_id == entry.evidence_id
            assert original.to_event() == entry.to_event()


# ---------------------------------------------------------------- summaries
class TestSummaries:
    @pytest.mark.parametrize("evidence_id, expected", [
        ("EVL-0001", "Failed logon (Interactive) for ahmed: wrong password"),
        ("EVL-0004", "Failed logon (RemoteInteractive) for ahmed from 198.51.100.23: "
                     "wrong password"),
        ("EVL-0010", "Successful logon (RemoteInteractive) for ahmed from 198.51.100.23"),
        ("EVL-0011", "Account 'svc_helpdesk' created by ahmed"),
        ("EVL-0012", "'svc_helpdesk' added to group 'Administrators' by ahmed"),
        ("PROC-0006", "Process created: powershell.exe (PID 6012) by ahmed, parent wscript.exe"),
        ("NET-0003", "Inbound TCP 198.51.100.23:51842 -> 10.20.0.15:3389 (svchost.exe)"),
        ("NET-0004", "Outbound TCP 10.20.0.15:49822 -> 203.0.113.77:443 "
                     "(powershell.exe, files-sync.example.net)"),
        ("PS-0002", "PowerShell script block by ahmed (PID 6012)"),
        ("PS-0003", "PowerShell script block by ahmed (PID 6188), "
                    "script C:\\Users\\Public\\update_svc.ps1"),
        ("FILE-0003", "File created: C:\\Users\\Public\\update_svc.ps1 (164 bytes), owner ahmed"),
    ])
    def test_sample_summaries(self, timeline, evidence_id, expected):
        assert timeline.get_by_evidence_id(evidence_id).summary == expected

    def test_summaries_are_neutral_statements_of_fact(self, timeline):
        forbidden = ("suspicious", "malicious", "attack", "brute", "compromise", "threat")
        for entry in timeline.entries:
            assert not any(word in entry.summary.lower() for word in forbidden)

    def test_sample_summaries_are_ascii_safe_for_any_console(self, timeline):
        assert all(e.summary.isascii() for e in timeline.entries)
        assert format_timeline(timeline).isascii()

    @pytest.mark.parametrize("event_type, details, user, expected", [
        (EventType.LOGON_FAILED, {}, None, "Failed logon for unknown user"),
        (EventType.LOGON_SUCCESS, {"logon_type": 7}, "u", "Successful logon (type 7) for u"),
        (EventType.ACCOUNT_CREATED, {}, None, "Account unknown account created by unknown user"),
        (EventType.GROUP_MEMBER_ADDED, {}, None,
         "unknown account added to group unknown group by unknown user"),
        (EventType.PROCESS_CREATED, {"name": "a.exe", "pid": 1}, None,
         "Process created: a.exe (PID 1)"),
        (EventType.POWERSHELL_EXECUTED, {"pid": 2, "origin": "psreadline_history"}, "u",
         "PowerShell command history entry by u (PID 2)"),
        (EventType.FILE_CREATED, {"path": "C:\\a.txt"}, None, "File created: C:\\a.txt"),
        (EventType.OTHER, {"windows_event_id": 4688, "channel": "Security"}, None,
         "Windows event 4688 in Security log"),
        (EventType.NETWORK_CONNECTION,
         {"protocol": "UDP", "direction": "outbound", "local_address": "1.1.1.1",
          "local_port": 1, "remote_address": "2.2.2.2", "remote_port": 2}, None,
         "Outbound UDP 1.1.1.1:1 -> 2.2.2.2:2"),
    ])
    def test_missing_values_never_raise(self, event_type, details, user, expected):
        assert describe_event(event("E-1", "2026-10-08T07:00:00Z", event_type=event_type,
                                    user=user, details=details)) == expected


# ---------------------------------------------------------------- filtering
class TestFiltering:
    def test_no_criteria_returns_an_equal_copy(self, timeline):
        copy_ = filter_timeline(timeline)
        assert copy_ is not timeline and copy_.to_dict() == timeline.to_dict()

    @pytest.mark.parametrize("value", ["logon_failed", EventType.LOGON_FAILED,
                                       ["logon_failed"], (EventType.LOGON_FAILED,)])
    def test_by_event_type_accepts_str_enum_and_collections(self, timeline, value):
        view = filter_timeline(timeline, event_types=value)
        assert view.event_count == 7
        assert {e.event_type for e in view.entries} == {EventType.LOGON_FAILED}

    def test_multiple_types_are_or(self, timeline):
        view = filter_timeline(timeline, event_types=["account_created", "group_member_added"])
        assert [e.evidence_id for e in view.entries] == ["EVL-0011", "EVL-0012"]

    @pytest.mark.parametrize("source, count", [
        ("processes", 9), (EvidenceSource.NETWORK, 5), (["events", "files"], 15)])
    def test_by_source(self, timeline, source, count):
        assert filter_timeline(timeline, sources=source).event_count == count

    @pytest.mark.parametrize("users, count", [
        ("ahmed", 23), ("AHMED", 23), (["ahmed", "svc_backup"], 27), ("svc_backup", 4)])
    def test_by_user_is_case_insensitive(self, timeline, users, count):
        assert filter_timeline(timeline, users=users).event_count == count

    def test_user_counts_agree_with_the_raw_evidence(self, timeline):
        """Count users straight from the raw files, independent of the timeline."""
        raw_users = []
        for record in load_json(SAMPLE_DIR / "events.json")["records"]:
            data = record["data"]
            raw_users.append(data["SubjectUserName"] if record["event_id"] in (4720, 4732)
                             else data["TargetUserName"])
        for name in ("processes", "powershell"):
            raw_users += [r["user"] for r in load_json(SAMPLE_DIR / f"{name}.json")["records"]]
        raw_users += [r["owner"] for r in load_json(SAMPLE_DIR / "files.json")["records"]]
        for name in ("ahmed", "svc_backup"):
            assert filter_timeline(timeline, users=name).event_count == raw_users.count(name)

    def test_unknown_user_matches_nothing(self, timeline):
        assert filter_timeline(timeline, users="ghost").event_count == 0

    def test_entries_without_a_user_never_match_a_user_filter(self, timeline):
        view = filter_timeline(timeline, users=["ahmed", "svc_backup"])
        assert view.event_count == 27                 # 32 minus the 5 network rows (no user)
        assert all(e.user for e in view.entries)

    @pytest.mark.parametrize("device, count", [
        ("WIN-PC-01", 32), ("win-pc-01", 32), (["OTHER", "WIN-PC-01"], 32), ("OTHER", 0)])
    def test_by_device(self, timeline, device, count):
        assert filter_timeline(timeline, devices=device).event_count == count

    def test_time_range_is_inclusive_at_both_ends(self, timeline):
        view = filter_timeline(timeline, start="2026-10-08T07:31:02Z",
                               end="2026-10-08T07:32:08Z")
        assert ids(view) == [f"E-{n:05d}" for n in range(11, 17)]

    def test_start_only_and_end_only(self, timeline):
        assert filter_timeline(timeline, start="2026-10-08T07:35:00Z").event_count == 4
        assert filter_timeline(timeline, end="2026-10-08T06:55:12Z").event_count == 2

    def test_range_accepts_datetimes_and_other_timezones(self, timeline):
        utc = filter_timeline(timeline, start="2026-10-08T07:31:02Z", end="2026-10-08T07:32:08Z")
        cairo = timezone(timedelta(hours=3))
        local = filter_timeline(
            timeline, start=datetime(2026, 10, 8, 10, 31, 2, tzinfo=cairo),
            end="2026-10-08T10:32:08+03:00")
        assert ids(local) == ids(utc)

    def test_criteria_combine_with_and(self, timeline):
        view = filter_timeline(
            timeline, event_types="logon_failed", users="ahmed",
            sources="events", devices="WIN-PC-01",
            start="2026-10-08T07:00:00Z", end="2026-10-08T08:00:00Z")
        assert view.event_count == 6                  # the 06:54 typo is outside the range
        assert filter_timeline(timeline, event_types="logon_failed",
                               sources="processes").event_count == 0

    def test_chained_filters_equal_one_combined_filter(self, timeline):
        chained = filter_timeline(
            filter_timeline(timeline, users="ahmed"), event_types="process_created",
            start="2026-10-08T07:33:00Z")
        combined = filter_timeline(timeline, users="ahmed", event_types="process_created",
                                   start="2026-10-08T07:33:00Z")
        assert chained.to_dict() == combined.to_dict()

    def test_filtered_timeline_is_self_consistent(self, timeline):
        view = filter_timeline(timeline, start="2026-10-08T07:34:00Z", users="ahmed")
        assert [e.sequence for e in view.entries] == list(range(1, view.event_count + 1))
        assert view.entries[0].gap_from_previous_seconds is None
        assert view.entries[0].offset_from_start_seconds == 0.0
        assert view.start == view.entries[0].timestamp
        assert view.end == view.entries[-1].timestamp
        assert view.event_count == sum(view.counts_by_type.values())
        assert view.users == ["ahmed"]
        assert view.case_id == timeline.case_id

    def test_order_is_preserved(self, timeline):
        view = filter_timeline(timeline, sources=["files", "events"])
        assert [e.timestamp for e in view.entries] == sorted(e.timestamp for e in view.entries)

    def test_filter_does_not_change_the_original(self, timeline):
        before = copy.deepcopy(timeline.to_dict())
        view = filter_timeline(timeline, users="ahmed")
        view.entries[0].details["x"] = 1
        assert timeline.to_dict() == before

    @pytest.mark.parametrize("kwargs, message", [
        ({"event_types": "nonsense"}, "unknown event type 'nonsense'"),
        ({"sources": "nonsense"}, "unknown source 'nonsense'"),
        ({"start": "2026-10-08T07:00:00"}, "no timezone"),
        ({"end": "yesterday"}, "invalid ISO 8601"),
        ({"start": datetime(2026, 10, 8, 7, 0, 0)}, "timezone-aware"),
        ({"start": "2026-10-08T08:00:00Z", "end": "2026-10-08T07:00:00Z"}, "start is after end"),
        ({"users": []}, "users is empty"),
        ({"event_types": []}, "event_types is empty"),
        ({"devices": ()}, "devices is empty"),
    ])
    def test_invalid_filters_fail_loudly(self, timeline, kwargs, message):
        with pytest.raises(ValueError, match=message):
            filter_timeline(timeline, **kwargs)

    def test_error_lists_valid_event_types(self, timeline):
        with pytest.raises(ValueError, match="valid values: logon_success, logon_failed"):
            filter_timeline(timeline, event_types="nonsense")


# -------------------------------------------------------------- input rules
class TestBuildInputRules:
    def test_event_without_id_is_rejected(self):
        with pytest.raises(ValueError, match="no event_id"):
            build_timeline([event("", "2026-10-08T07:00:00Z")])

    def test_mixed_cases_are_rejected(self):
        with pytest.raises(ValueError, match="one case"):
            build_timeline([event("E-1", "2026-10-08T07:00:00Z", case_id="A"),
                            event("E-2", "2026-10-08T07:00:01Z", case_id="B",
                                  evidence_id="EVL-0002")])

    def test_explicit_case_id_must_match_the_events(self):
        with pytest.raises(ValueError, match="one case"):
            build_timeline([event("E-1", "2026-10-08T07:00:00Z", case_id="A")], case_id="B")

    def test_case_id_is_taken_from_the_events(self):
        assert build_timeline([event("E-1", "2026-10-08T07:00:00Z")]).case_id == "C-1"

    def test_multiple_devices_are_supported(self):
        tl = build_timeline([event("E-1", "2026-10-08T07:00:00Z", device="B-PC"),
                             event("E-2", "2026-10-08T07:00:01Z", device="a-pc",
                                   evidence_id="EVL-0002")])
        assert tl.devices == ["a-pc", "B-PC"]
        assert "[B-PC]" in format_timeline(tl)


# ---------------------------------------------------- determinism / read-only
class TestDeterminismAndReadOnly:
    def test_two_builds_are_identical(self):
        first = build_case_timeline(SAMPLE_DIR).to_dict()
        second = build_case_timeline(SAMPLE_DIR).to_dict()
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)

    def test_building_does_not_touch_the_evidence(self):
        before = snapshot(SAMPLE_DIR)
        build_case_timeline(SAMPLE_DIR)
        assert snapshot(SAMPLE_DIR) == before

    def test_building_does_not_modify_or_reorder_the_input_events(self, result):
        events = list(reversed(result.events))
        pristine = copy.deepcopy(events)
        build_timeline(events)
        assert events == pristine                      # same objects, same order, same data

    def test_normalization_result_is_unchanged_by_timeline_building(self):
        fresh = normalize_case(SAMPLE_DIR)
        before = fresh.to_dict()
        build_timeline_from_result(fresh)
        assert fresh.to_dict() == before

    def test_invalid_evidence_never_produces_a_timeline(self, case):
        (case / "network.json").unlink()
        with pytest.raises(EvidenceNotValidError):
            build_case_timeline(case)

    def test_tampered_evidence_never_produces_a_timeline(self, case):
        edit(case, "processes.json", lambda d: d["records"][0].update(name="x.exe"),
             rebuild=False)
        with pytest.raises(EvidenceNotValidError):
            build_case_timeline(case)

    def test_edited_evidence_changes_the_timeline_deterministically(self, case):
        edit(case, "network.json", lambda d: d["records"][0].update(
            timestamp="2026-10-08T05:00:00Z"))
        tl = build_case_timeline(case)
        assert tl.entries[0].evidence_id == "NET-0001"
        assert tl.start == ts("2026-10-08T05:00:00Z")


# -------------------------------------------------------------- text output
class TestTextOutput:
    @pytest.mark.parametrize("seconds, text", [
        (None, "-"), (0, "+0s"), (13, "+13s"), (0.5, "+0.5s"), (59.9, "+59.9s"),
        (60, "+1m00s"), (65, "+1m05s"), (3725, "+1h02m"), (90061, "+1d01h")])
    def test_format_gap(self, seconds, text):
        assert format_gap(seconds) == text

    def test_text_report_contents(self, timeline):
        text = format_timeline(timeline)
        assert "Case ID  : INC-001" in text and "Events   : 32" in text
        assert "(40m33s)" in text
        assert text.count("\nE-") == 0 and text.count("  E-000") == 32

    def test_limit_truncates_with_a_note(self, timeline):
        text = format_timeline(timeline, limit=5)
        assert text.count("  E-000") == 5 and "27 more" in text


# ---------------------------------------------------------------------- CLI
class TestCli:
    def test_full_timeline(self, capsys):
        assert cli_main([str(SAMPLE_DIR)]) == 0
        output = capsys.readouterr().out
        assert "Events   : 32" in output and "E-00032" in output

    def test_filters_from_the_command_line(self, capsys):
        assert cli_main([str(SAMPLE_DIR), "--type", "logon_failed", "--user", "ahmed",
                         "--start", "2026-10-08T07:31:00Z",
                         "--end", "2026-10-08T07:33:00Z"]) == 0
        output = capsys.readouterr().out
        assert "Events   : 6" in output and "E-00011" in output and "E-00001 " not in output

    def test_repeated_flags_are_or(self, capsys):
        assert cli_main([str(SAMPLE_DIR), "--type", "account_created",
                         "--type", "group_member_added"]) == 0
        assert "Events   : 2" in capsys.readouterr().out

    def test_json_output(self, capsys):
        assert cli_main([str(SAMPLE_DIR), "--source", "files", "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["event_count"] == 3
        assert [e["evidence_id"] for e in payload["entries"]] == [
            "FILE-0001", "FILE-0002", "FILE-0003"]

    def test_limit(self, capsys):
        assert cli_main([str(SAMPLE_DIR), "--limit", "3"]) == 0
        assert "29 more" in capsys.readouterr().out

    def test_empty_selection_is_not_an_error(self, capsys):
        assert cli_main([str(SAMPLE_DIR), "--user", "ghost"]) == 0
        assert "No events in this timeline." in capsys.readouterr().out

    def test_invalid_evidence_prints_report_and_exits_1(self, case, capsys):
        (case / "events.json").unlink()
        assert cli_main([str(case)]) == 1
        output = capsys.readouterr().out
        assert "no timeline was built" in output and "REQUIRED_FILE_MISSING" in output

    @pytest.mark.parametrize("args", [
        ["--type", "nonsense"], ["--start", "2026-10-08T07:00:00"],
        ["--start", "2026-10-08T08:00:00Z", "--end", "2026-10-08T07:00:00Z"]])
    def test_bad_filters_exit_2(self, args, capsys):
        assert cli_main([str(SAMPLE_DIR), *args]) == 2
        assert "invalid filter" in capsys.readouterr().err
