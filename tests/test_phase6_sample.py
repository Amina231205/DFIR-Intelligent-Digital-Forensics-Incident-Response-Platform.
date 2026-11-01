"""Phase 6 tests: IOC extraction on the sample case INC-001 (ground truth).

The sample holds one intrusion chain plus benign activity. The expected IOCs
below were derived from the raw evidence by hand; the traceability tests check
every extracted value against the raw JSON files independently of the code.
"""

from __future__ import annotations

import copy
import json
import random
from datetime import datetime, timezone

import pytest
from detection_helpers import NOW
from helpers import SAMPLE_DIR, edit, snapshot

from security.detection import DetectionConfig, run_detection
from security.ioc import IocConfig, extract_case_iocs, extract_iocs
from security.ioc.__main__ import main as cli_main
from security.ioc.parsers import text_variants
from security.ioc.report import format_iocs
from security.models.schemas import IOCType
from security.timeline import build_case_timeline, build_timeline
from security.utils.helpers import load_json
from security.validation import EvidenceNotValidError

RAW_FILES = ("events", "processes", "network", "powershell", "files", "users")
DEMO_CONFIG = SAMPLE_DIR.parents[2] / "examples" / "detection_synthetic_demo.json"


@pytest.fixture(scope="module")
def timeline():
    return build_case_timeline(SAMPLE_DIR)


@pytest.fixture(scope="module")
def detection(timeline):
    return run_detection(timeline, now=NOW)


@pytest.fixture(scope="module")
def result(timeline, detection):
    return extract_iocs(timeline, detection)


@pytest.fixture(scope="module")
def raw_hashes():
    return {r["record_id"]: r["sha256"]
            for r in load_json(SAMPLE_DIR / "files.json")["records"]}


def ioc(result, value):
    return next(i for i in result.iocs if i.value == value)


# ------------------------------------------------------------------ ground truth
class TestGroundTruth:
    def test_the_expected_indicators(self, result, raw_hashes):
        assert [(i.ioc_id, i.type.value, i.value, i.related_findings, len(i.occurrences))
                for i in result.iocs] == [
            ("IOC-001", "ip", "198.51.100.23", ["F-001", "F-004"], 7),
            ("IOC-002", "username", "ahmed", ["F-001", "F-002", "F-003", "F-004"], 16),
            ("IOC-003", "hash", raw_hashes["FILE-0002"], ["F-004"], 1),
            ("IOC-004", "filename", "invoice_update.vbs", ["F-004"], 2),
            ("IOC-005", "domain", "files-sync.example.net", ["F-002", "F-003", "F-004"], 5),
            ("IOC-006", "url", "https://files-sync.example.net/stage/update_svc.ps1",
             ["F-002", "F-004"], 3),
            ("IOC-007", "filename", "update_svc.ps1", ["F-002", "F-003", "F-004"], 7),
            ("IOC-008", "hash", raw_hashes["FILE-0003"], ["F-002", "F-003", "F-004"], 1),
            ("IOC-009", "ip", "203.0.113.77", ["F-002", "F-003"], 2),
            ("IOC-010", "username", "svc_helpdesk", ["F-004"], 2)]

    def test_counts(self, result):
        assert result.counts_by_type == {
            "domain": 1, "filename": 2, "hash": 2, "ip": 2, "url": 1, "username": 2}
        assert result.data_gaps == [] and result.case_id == "INC-001"

    def test_findings_now_reference_their_iocs(self, result):
        assert {f.finding_id: f.iocs for f in result.findings} == {
            "F-001": ["IOC-001", "IOC-002"],
            "F-002": ["IOC-002", "IOC-005", "IOC-006", "IOC-007", "IOC-008", "IOC-009"],
            "F-003": ["IOC-002", "IOC-005", "IOC-007", "IOC-008", "IOC-009"],
            "F-004": ["IOC-001", "IOC-002", "IOC-003", "IOC-004", "IOC-005", "IOC-006",
                      "IOC-007", "IOC-008", "IOC-010"]}

    def test_ioc_and_finding_links_agree_both_ways(self, result):
        by_id = {i.ioc_id: i for i in result.iocs}
        for f in result.findings:
            for ioc_id in f.iocs:
                assert f.finding_id in by_id[ioc_id].related_findings
        for i in result.iocs:
            for finding_id in i.related_findings:
                assert i.ioc_id in next(f for f in result.findings
                                        if f.finding_id == finding_id).iocs

    def test_benign_and_system_artifacts_are_not_iocs(self, result):
        extracted = {i.value.casefold() for i in result.iocs}
        for benign in ("192.0.2.44", "mail.example.org", "10.20.0.15", "svc_backup",
                       "sara", "disk-report.ps1", "disk-report.csv", "chrome.exe",
                       "powershell.exe", "wscript.exe", "explorer.exe", "net.exe", "wininit.exe"):
            assert benign.casefold() not in extracted, benign
        assert not [i for i in result.iocs if i.type is IOCType.PROCESS]

    def test_system_binary_hashes_are_not_iocs(self, result):
        process_hashes = {r["sha256"] for r in
                          load_json(SAMPLE_DIR / "processes.json")["records"]}
        assert not process_hashes & {i.value for i in result.iocs}

    def test_the_c2_ip_is_extracted_even_though_it_is_not_external_by_default(self, result):
        ip = ioc(result, "203.0.113.77")
        assert ip.attributes == {"ip_class": "documentation", "external": False}
        assert {o["evidence_id"] for o in ip.occurrences} == {"NET-0004", "NET-0005"}
        assert {o["port"] for o in ip.occurrences} == {443, 8443}

    def test_attributes(self, result):
        assert ioc(result, "198.51.100.23").attributes["ip_class"] == "documentation"
        assert ioc(result, "files-sync.example.net").attributes == {
            "reserved_for_documentation": True}
        url = ioc(result, "https://files-sync.example.net/stage/update_svc.ps1")
        assert url.attributes == {"scheme": "https", "host": "files-sync.example.net",
                                  "host_type": "domain", "credentials_removed": False}
        assert ioc(result, "update_svc.ps1").attributes == {
            "extension": "ps1", "paths": ["C:\\Users\\Public\\update_svc.ps1"]}
        assert ioc(result, "invoice_update.vbs").attributes["paths"] == [
            "C:\\Users\\ahmed\\Downloads\\invoice_update.vbs"]
        assert ioc(result, "svc_helpdesk").attributes["roles"] == [
            "account added to group 'Administrators'", "account that was created"]

    def test_hash_iocs_are_the_files_hashes_linked_by_path(self, result, raw_hashes):
        vbs = ioc(result, raw_hashes["FILE-0002"])
        assert vbs.attributes == {"algorithm": "sha256", "file_paths": [
            "C:\\Users\\ahmed\\Downloads\\invoice_update.vbs"]}
        assert [o["evidence_file"] for o in vbs.occurrences] == ["files.json"]
        assert vbs.related_findings == ["F-004"]       # inherited from the path's finding

    def test_the_file_record_is_the_first_sighting_of_the_dropped_files(self, result):
        vbs = ioc(result, "invoice_update.vbs")
        assert (vbs.source, vbs.evidence_id) == ("files.json", "FILE-0002")
        assert vbs.first_seen == datetime(2026, 10, 8, 7, 33, 30, tzinfo=timezone.utc)
        assert vbs.last_seen == datetime(2026, 10, 8, 7, 33, 52, tzinfo=timezone.utc)

    def test_the_url_is_found_in_plain_and_decoded_text(self, result):
        fields = {(o["evidence_id"], o["field"]) for o in ioc(
            result, "https://files-sync.example.net/stage/update_svc.ps1").occurrences}
        assert ("PS-0002", "command") in fields
        assert ("PROC-0006", "command_line (decoded)") in fields

    def test_no_secrets_or_payloads_are_copied(self, result):
        text = json.dumps(result.to_dict())
        for record in load_json(SAMPLE_DIR / "processes.json")["records"]:
            command = record["command_line"] or ""
            if "-EncodedCommand" in command:
                assert command.split("-EncodedCommand ")[1] not in text
        # the collector's redaction marker may appear inside copied Phase 5 findings,
        # but no extracted indicator may contain it
        assert "[REDACTED]" not in json.dumps(result.to_dict()["iocs"])
        assert not [i for i in result.iocs if "redacted" in i.value.casefold()]


# --------------------------------------------------------------- traceability
def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


@pytest.fixture(scope="module")
def raw():
    records = {}
    for name in RAW_FILES:
        for record in load_json(SAMPLE_DIR / f"{name}.json")["records"]:
            texts = list(_strings(record))
            decoded = [t for text in texts for _, t in text_variants(text, "x")[1:]]
            records[record["record_id"]] = (f"{name}.json", "\n".join(texts + decoded))
    return records


class TestTraceability:
    def test_every_occurrence_names_a_real_raw_record_and_file(self, result, raw):
        for i in result.iocs:
            for occurrence in i.occurrences:
                assert occurrence["evidence_id"] in raw, (i.value, occurrence)
                assert raw[occurrence["evidence_id"]][0] == occurrence["evidence_file"]

    def test_every_indicator_value_really_appears_in_its_raw_record(self, result, raw):
        for i in result.iocs:
            for occurrence in i.occurrences:
                needle = occurrence.get("path") or i.value
                haystack = raw[occurrence["evidence_id"]][1].casefold()
                assert needle.casefold() in haystack, (i.ioc_id, i.value, occurrence)

    def test_primary_source_matches_the_first_occurrence(self, result):
        for i in result.iocs:
            first = i.occurrences[0]
            assert (i.source, i.evidence_id) == (first["evidence_file"], first["evidence_id"])
            assert i.timestamp == i.first_seen

    def test_occurrence_events_exist_in_the_timeline(self, result, timeline):
        for i in result.iocs:
            for occurrence in i.occurrences:
                entry = timeline.get_by_event_id(occurrence["event_id"])
                assert entry.evidence_id == occurrence["evidence_id"]
                assert entry.evidence_file == occurrence["evidence_file"]

    def test_occurrences_are_chronological_and_inside_the_first_last_range(self, result):
        for i in result.iocs:
            stamps = [o["timestamp"] for o in i.occurrences]
            assert stamps == sorted(stamps)
            assert i.first_seen <= i.last_seen

    def test_every_event_behind_an_occurrence_is_cited_or_linked_by_path(
            self, result, detection):
        cited = set()
        for f in detection.findings:
            cited |= set(f.supporting_events)
            cited |= {r["event_id"] for r in f.context.get("correlated_records", [])}
        for i in result.iocs:
            for occurrence in i.occurrences:
                if occurrence["event_id"] not in cited:
                    assert occurrence["evidence_file"] == "files.json"      # path-linked only


# ------------------------------------------------- determinism / read-only / policy
class TestBehaviour:
    def test_two_runs_are_identical(self, timeline, detection):
        first = extract_iocs(timeline, detection).to_dict()
        second = extract_iocs(timeline, detection).to_dict()
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)

    def test_event_order_does_not_matter(self, timeline, result):
        events = [e.to_event() for e in timeline.entries]
        for seed in range(3):
            shuffled = list(events)
            random.Random(seed).shuffle(shuffled)
            shuffled_timeline = build_timeline(shuffled, case_id="INC-001")
            again = extract_iocs(shuffled_timeline, run_detection(shuffled_timeline, now=NOW))
            assert again.to_dict() == result.to_dict()

    def test_nothing_is_modified(self):
        tl = build_case_timeline(SAMPLE_DIR)
        det = run_detection(tl, now=NOW)
        before_tl, before_det = copy.deepcopy(tl.to_dict()), copy.deepcopy(det.to_dict())
        before_files = snapshot(SAMPLE_DIR)
        extract_iocs(tl, det)
        assert tl.to_dict() == before_tl and det.to_dict() == before_det
        assert snapshot(SAMPLE_DIR) == before_files
        assert all(f.iocs == [] for f in det.findings)

    def test_the_iocs_do_not_depend_on_the_detection_external_policy(self, result, timeline):
        demo = DetectionConfig.from_dict(json.loads(DEMO_CONFIG.read_text(encoding="utf-8")))
        other = extract_iocs(timeline, run_detection(timeline, config=demo, now=NOW))
        assert [(i.type, i.value, i.related_findings) for i in other.iocs] == [
            (i.type, i.value, i.related_findings) for i in result.iocs]

    def test_the_external_attribute_can_opt_in_to_documentation_ranges(self, timeline,
                                                                       detection):
        config = IocConfig.from_dict({"ip_policy": {"external_classes": ["public",
                                                                         "documentation"]}})
        ips = [i for i in extract_iocs(timeline, detection, config).iocs
               if i.type is IOCType.IP]
        assert [i.attributes["external"] for i in ips] == [True, True]

    def test_public_only_ip_classes_drop_the_documentation_addresses(self, timeline, detection):
        reduced = extract_iocs(timeline, detection, IocConfig(ip_classes=("public",)))
        assert "ip" not in reduced.counts_by_type
        assert reduced.counts_by_type["username"] == 2 and reduced.counts_by_type["hash"] == 2

    def test_without_file_linking_there_are_no_hashes(self, timeline, detection):
        reduced = extract_iocs(timeline, detection, IocConfig(link_file_records=False))
        assert "hash" not in reduced.counts_by_type
        assert len(ioc(reduced, "update_svc.ps1").occurrences) == 6        # one fewer

    def test_without_decoding_the_url_is_still_found_in_plain_text(self, timeline, detection):
        plain = extract_iocs(timeline, detection, IocConfig(decode_encoded_commands=False))
        url = ioc(plain, "https://files-sync.example.net/stage/update_svc.ps1")
        assert url.occurrences and not any("(decoded)" in o["field"] for o in url.occurrences)

    def test_extra_iocs_in_an_edited_copy_are_found(self, case):
        edit(case, "network.json", lambda d: d["records"][3].update(
            remote_hostname="Other-C2.Example.org"))
        result = extract_case_iocs(case, now=NOW)
        assert "other-c2.example.org" in {i.value for i in result.iocs}

    def test_invalid_hostnames_in_evidence_become_data_gaps(self, case):
        edit(case, "network.json", lambda d: d["records"][3].update(remote_hostname="bad_host"))
        result = extract_case_iocs(case, now=NOW)
        assert result.data_gaps == [
            "NET-0004: remote_hostname 'bad_host' is not a valid domain name; not extracted"]
        assert "bad_host" not in {i.value for i in result.iocs}

    def test_invalid_evidence_is_refused(self, case):
        (case / "network.json").unlink()
        with pytest.raises(EvidenceNotValidError):
            extract_case_iocs(case)

    def test_tampered_evidence_is_refused(self, case):
        edit(case, "files.json", lambda d: d["records"][0].update(name="x.exe"), rebuild=False)
        with pytest.raises(EvidenceNotValidError):
            extract_case_iocs(case)


class TestReport:
    def test_report_is_ascii_and_complete(self, result):
        text = format_iocs(result)
        assert text.isascii() and "IOCs    : 10" in text
        assert "IOC-009  ip        203.0.113.77" in text
        assert "class=documentation, external by policy=no" in text
        assert "findings: F-002, F-003" in text
        assert "Findings -> IOCs:" in text and "F-004: IOC-001, IOC-002" in text

    def test_report_without_iocs_points_to_the_scope_rule(self, timeline):
        empty = extract_iocs(timeline, run_detection(timeline, rule_ids=["DET-001"], now=NOW),
                             IocConfig(ip_classes=("public",), ignored_usernames=("ahmed",)))
        assert "No IOCs." in format_iocs(empty)

    def test_non_ascii_text_is_escaped(self):
        from security.detection.report import ascii_safe
        assert ascii_safe("caf\u00e9") == "caf\\xe9"


# ------------------------------------------------------------------------- CLI
class TestCli:
    def test_default_run(self, capsys):
        assert cli_main([str(SAMPLE_DIR)]) == 0
        out = capsys.readouterr().out
        assert "IOCs    : 10" in out and out.isascii() and "update_svc.ps1" in out

    def test_json_is_reproducible_with_now(self, capsys):
        args = [str(SAMPLE_DIR), "--json", "--now", "2026-10-09T12:00:00Z"]
        assert cli_main(args) == 0
        first = capsys.readouterr().out
        assert cli_main(args) == 0
        assert capsys.readouterr().out == first
        payload = json.loads(first)
        assert len(payload["iocs"]) == 10 and payload["findings"][3]["iocs"][0] == "IOC-001"

    def test_ioc_config_file(self, tmp_path, capsys):
        path = tmp_path / "ioc.json"
        path.write_text(json.dumps({"ip_classes": ["public"]}), encoding="utf-8")
        assert cli_main([str(SAMPLE_DIR), "--ioc-config", str(path), "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert "ip" not in payload["counts_by_type"]
        assert payload["config"]["ip_classes"] == ["public"]

    def test_detection_config_file_is_used_for_the_findings(self, tmp_path, capsys):
        path = tmp_path / "det.json"
        path.write_text(json.dumps({"brute_force": {"threshold": 7}}), encoding="utf-8")
        assert cli_main([str(SAMPLE_DIR), "--config", str(path), "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert [f["rule_id"] for f in payload["findings"]] == ["DET-002", "DET-002", "DET-003"]

    @pytest.mark.parametrize("flag, content, message", [
        ("--ioc-config", "{ not json", "cannot read IOC configuration"),
        ("--ioc-config", '{"ip_clases": []}', "unknown IOC option"),
        ("--ioc-config", '{"max_scan_chars": 0}', "positive integer"),
        ("--ioc-config", "[]", "JSON object"),
        ("--config", '{"brute_force": {"threshold": 0}}', "positive integer"),
        ("--config", '{"nope": {}}', "unknown configuration section")])
    def test_invalid_configuration_exits_2(self, tmp_path, capsys, flag, content, message):
        path = tmp_path / "c.json"
        path.write_text(content, encoding="utf-8")
        assert cli_main([str(SAMPLE_DIR), flag, str(path)]) == 2
        assert message in capsys.readouterr().err

    def test_missing_config_file_exits_2(self, tmp_path, capsys):
        assert cli_main([str(SAMPLE_DIR), "--ioc-config", str(tmp_path / "nope.json")]) == 2
        assert "cannot read IOC configuration" in capsys.readouterr().err

    @pytest.mark.parametrize("value", ["yesterday", "2026-10-09T12:00:00"])
    def test_invalid_now_exits_2(self, capsys, value):
        assert cli_main([str(SAMPLE_DIR), "--now", value]) == 2
        assert "invalid --now" in capsys.readouterr().err

    def test_invalid_evidence_exits_1_with_the_validation_report(self, case, capsys):
        (case / "events.json").unlink()
        assert cli_main([str(case)]) == 1
        out = capsys.readouterr().out
        assert "IOC extraction was not run" in out and "REQUIRED_FILE_MISSING" in out

    def test_the_cli_does_not_modify_the_evidence(self, case, capsys):
        before = snapshot(case)
        cli_main([str(case)])
        assert snapshot(case) == before
