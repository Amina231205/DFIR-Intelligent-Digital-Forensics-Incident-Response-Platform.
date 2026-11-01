"""Phase 5 tests: the detection engine on the sample case, plus engine behaviour.

The sample case INC-001 is the ground truth: one brute-force burst followed by
a successful logon, a hidden/encoded PowerShell chain that downloads a script
and connects out, and a new administrator account created by that chain; plus
benign controls that must NOT be flagged.
"""

from __future__ import annotations

import copy
import json
import random
from datetime import datetime, timezone

import pytest
from detection_helpers import NOW, Factory
from helpers import SAMPLE_DIR, edit, snapshot

from security.detection import (
    DetectionConfig, IpClass, Rule, RuleContext, RuleOutput, default_rules, detect_case,
    format_detection, run_detection)
from security.detection.__main__ import main as cli_main
from security.detection.base import build_finding
from security.detection.report import ascii_safe
from security.models.schemas import Confidence, DetectionResult, Severity
from security.timeline import build_case_timeline, build_timeline
from security.utils.helpers import load_json
from security.validation import EvidenceNotValidError

RAW_FILES = ("events", "processes", "network", "powershell", "files", "users")
DEMO_CONFIG_FILE = SAMPLE_DIR.parents[2] / "examples" / "detection_synthetic_demo.json"


@pytest.fixture(scope="module")
def timeline():
    return build_case_timeline(SAMPLE_DIR)


@pytest.fixture(scope="module")
def result(timeline) -> DetectionResult:
    return run_detection(timeline, now=NOW)


@pytest.fixture(scope="module")
def demo_result(timeline) -> DetectionResult:
    """Sample case under the EXPLICIT synthetic-demo opt-in (documentation = external)."""
    config = DetectionConfig.from_dict(json.loads(DEMO_CONFIG_FILE.read_text(encoding="utf-8")))
    return run_detection(timeline, config=config, now=NOW)


def finding(result, finding_id):
    return next(f for f in result.findings if f.finding_id == finding_id)


# ------------------------------------------------- sample case ground truth
class TestSampleCase:
    def test_findings_and_order(self, result):
        assert [(f.finding_id, f.rule_id) for f in result.findings] == [
            ("F-001", "DET-001"), ("F-002", "DET-002"),
            ("F-003", "DET-002"), ("F-004", "DET-003")]

    def test_brute_force_finding(self, result):
        f = finding(result, "F-001")
        assert (f.severity, f.confidence) == (Severity.HIGH, Confidence.MEDIUM)
        assert f.user == "ahmed" and f.device == "WIN-PC-01"
        assert f.supporting_events == [f"E-{n:05d}" for n in (11, 12, 13, 14, 15, 16, 18)]
        assert f.evidence_sources == [f"EVL-{n:04d}" for n in range(4, 11)]
        assert f.evidence_files == ["events.json"]
        assert f.context["grouping"]["source_ip"] == "198.51.100.23"
        assert f.context["failure_count"] == 6
        assert f.context["followed_by_successful_logon"] == "yes"
        assert f.context["seconds_to_successful_logon"] == 32
        assert f.context["source_ip_class"] == "documentation"
        assert f.context["failure_reasons"] == {"wrong password": 6}

    def test_encoded_powershell_chain_finding(self, result):
        f = finding(result, "F-002")
        assert (f.severity, f.confidence) == (Severity.HIGH, Confidence.HIGH)
        assert f.context["process"]["pid"] == 6012
        assert f.context["process"]["parent_name"] == "wscript.exe"
        assert {m["indicator"] for m in f.matched_indicators} == {
            "encoded_command", "hidden_window", "execution_policy_bypass",
            "download_cradle", "unusual_parent", "user_writable_script_path"}
        assert f.supporting_events == ["E-00022", "E-00023"]
        assert f.evidence_sources == ["PROC-0006", "PS-0002", "USR-0003"]
        assert f.evidence_files == ["powershell.json", "processes.json", "users.json"]

    def test_documentation_ip_is_not_an_external_connection_by_default(self, result):
        for fid in ("F-002", "F-003"):
            f = finding(result, fid)
            assert "external_connection" not in {m["indicator"] for m in f.matched_indicators}
            assert not any("outbound connection" in x for x in f.severity_factors)
            assert "NET-0004" not in f.evidence_sources and "NET-0005" not in f.evidence_sources
        # the connection is still CORRELATED (same PID, device, window); it just is not external
        linked = [r["evidence_id"] for r in finding(result, "F-002").context["correlated_records"]
                  if r["link"] == "network_connection"]
        assert linked == ["NET-0004"]

    def test_second_powershell_process_is_its_own_finding(self, result):
        f = finding(result, "F-003")
        assert f.context["process"]["pid"] == 6188
        assert {m["indicator"] for m in f.matched_indicators} == {
            "execution_policy_bypass", "user_writable_script_path"}
        assert f.supporting_events == ["E-00026", "E-00027"]
        assert (f.severity, f.confidence) == (Severity.HIGH, Confidence.MEDIUM)
        assert not set(f.supporting_events) & set(finding(result, "F-002").supporting_events)

    def test_account_creation_finding_keeps_actor_and_target_apart(self, result):
        f = finding(result, "F-004")
        assert (f.severity, f.confidence) == (Severity.HIGH, Confidence.HIGH)
        assert f.user == "ahmed"                                    # actor
        assert f.context["actor"] == "ahmed"
        assert f.context["target_account"] == "svc_helpdesk"        # created account
        assert f.context["privileged_basis"] == ["group_membership_event", "users_snapshot"]
        assert f.context["linked_findings"] == {
            "powershell": ["F-002", "F-003"], "brute_force": ["F-001"]}
        assert {e["evidence_id"] for e in f.context["creating_evidence"]} == {
            "PROC-0008", "PS-0003"}
        assert f.context["snapshot_created_at_consistent"] is True
        assert "USR-0006" in f.evidence_sources

    def test_benign_activity_is_not_flagged(self, result):
        used = {rid for f in result.findings for rid in f.evidence_sources}
        controls = {
            "EVL-0001": "single failed logon (typo)", "EVL-0002": "normal logon",
            "EVL-0003": "service logon", "PROC-0001": "explorer", "PROC-0002": "chrome",
            "PROC-0003": "scheduled PowerShell", "PS-0001": "scheduled script block",
            "NET-0001": "chrome to an external site", "NET-0002": "inbound RDP",
            "NET-0003": "inbound RDP", "FILE-0001": "report csv"}
        assert not used & set(controls), sorted(used & set(controls))

    def test_rule_summaries_distinguish_negatives_from_gaps(self, result):
        by_rule = {r.rule_id: r for r in result.rules}
        assert (by_rule["DET-001"].events_considered, by_rule["DET-001"].findings) == (7, 1)
        assert len(by_rule["DET-001"].data_gaps) == 1
        assert "E-00001" in by_rule["DET-001"].data_gaps[0]        # the lone typo is reported
        assert (by_rule["DET-002"].events_considered, by_rule["DET-002"].findings) == (8, 2)
        assert by_rule["DET-002"].data_gaps == []
        assert (by_rule["DET-003"].events_considered, by_rule["DET-003"].findings) == (1, 1)
        assert result.duplicates_removed == 0

    def test_result_header(self, result, timeline):
        assert result.case_id == "INC-001" and result.event_count == 32
        assert result.generated_at == NOW
        assert all(f.detected_at == NOW for f in result.findings)

    def test_findings_never_claim_confirmed_attacks(self, result):
        for f in result.findings:
            text = " ".join([f.title, f.description, f.reason]).lower()
            assert "confirmed" not in text and "malware" not in text
        assert "not proof" in finding(result, "F-002").description

    def test_later_phase_fields_stay_empty(self, result):
        for f in result.findings:
            assert f.iocs == [] and f.mitre_techniques == [] and f.recommended_next_steps == []

    def test_severity_never_exceeds_high(self, result):
        assert all(f.severity in (Severity.LOW, Severity.MEDIUM, Severity.HIGH)
                   for f in result.findings)

    def test_json_serializable(self, result):
        payload = json.loads(json.dumps(result.to_dict()))
        assert payload["findings"][0]["severity"] == "High"
        assert payload["findings"][0]["detected_at"] == "2026-10-09T12:00:00Z"
        assert payload["config"]["brute_force"]["threshold"] == 5
        assert payload["rules"][0]["rule_id"] == "DET-001"


class TestSampleCaseWithSyntheticDemoPolicy:
    """The explicit opt-in (documentation ranges = external) restores the earlier result."""

    def test_the_example_config_is_an_explicit_opt_in(self):
        config = DetectionConfig.from_dict(
            json.loads(DEMO_CONFIG_FILE.read_text(encoding="utf-8")))
        assert config.powershell.ip_policy.external_classes == frozenset(
            {IpClass.PUBLIC, IpClass.DOCUMENTATION})
        assert DetectionConfig().powershell.ip_policy.external_classes == frozenset(
            {IpClass.PUBLIC})

    def test_encoded_powershell_chain_finding(self, demo_result):
        f = finding(demo_result, "F-002")
        assert (f.severity, f.confidence) == (Severity.HIGH, Confidence.HIGH)
        assert f.context["process"]["pid"] == 6012
        assert f.context["process"]["parent_name"] == "wscript.exe"
        assert {m["indicator"] for m in f.matched_indicators} == {
            "encoded_command", "hidden_window", "execution_policy_bypass",
            "download_cradle", "unusual_parent", "user_writable_script_path",
            "external_connection"}
        assert f.supporting_events == ["E-00022", "E-00023", "E-00025"]
        assert f.evidence_sources == ["PROC-0006", "PS-0002", "NET-0004", "USR-0003"]
        assert f.evidence_files == ["network.json", "powershell.json",
                                    "processes.json", "users.json"]
        external = [m for m in f.matched_indicators if m["indicator"] == "external_connection"]
        assert external[0]["matched_text"] == "203.0.113.77:443 (documentation)"

    def test_second_powershell_process_is_its_own_finding(self, demo_result):
        f = finding(demo_result, "F-003")
        assert f.context["process"]["pid"] == 6188
        assert {m["indicator"] for m in f.matched_indicators} == {
            "execution_policy_bypass", "user_writable_script_path", "external_connection"}
        assert f.supporting_events == ["E-00026", "E-00027", "E-00028"]
        assert (f.severity, f.confidence) == (Severity.HIGH, Confidence.HIGH)

    def test_the_other_findings_do_not_depend_on_the_policy(self, result, demo_result):
        assert [f.rule_id for f in result.findings] == [f.rule_id for f in demo_result.findings]
        for fid in ("F-001", "F-004"):
            assert finding(result, fid).severity == finding(demo_result, fid).severity
            assert finding(result, fid).confidence == finding(demo_result, fid).confidence

    def test_cli_uses_the_default_unless_the_config_is_given(self, capsys):
        assert cli_main([str(SAMPLE_DIR), "--json", "--now", "2026-10-09T12:00:00Z"]) == 0
        default = json.loads(capsys.readouterr().out)
        assert cli_main([str(SAMPLE_DIR), "--json", "--now", "2026-10-09T12:00:00Z",
                         "--config", str(DEMO_CONFIG_FILE)]) == 0
        demo = json.loads(capsys.readouterr().out)

        def indicators(payload, index):
            return {m["indicator"] for m in payload["findings"][index]["matched_indicators"]}
        assert "external_connection" not in indicators(default, 1)
        assert "external_connection" in indicators(demo, 1)
        assert default["config"]["powershell"]["ip_policy"]["external_classes"] == ["public"]
        assert demo["config"]["powershell"]["ip_policy"]["external_classes"] == [
            "documentation", "public"]


# ----------------------------------------------------------- traceability
@pytest.fixture(scope="module")
def raw_ids():
    ids = {}
    for name in RAW_FILES:
        for record in load_json(SAMPLE_DIR / f"{name}.json")["records"]:
            ids[record["record_id"]] = f"{name}.json"
    return ids


class TestTraceability:
    def test_every_cited_record_exists_in_the_raw_evidence(self, result, raw_ids):
        for f in result.findings:
            assert set(f.evidence_sources) <= set(raw_ids), f.finding_id

    def test_evidence_files_match_the_cited_records(self, result, raw_ids):
        for f in result.findings:
            assert set(f.evidence_files) == {raw_ids[r] for r in f.evidence_sources}

    def test_supporting_events_exist_in_the_timeline_and_point_to_the_cited_records(
            self, result, timeline):
        for f in result.findings:
            entries = [timeline.get_by_event_id(i) for i in f.supporting_events]
            assert all(entries), f.finding_id
            assert [e.evidence_id for e in entries] == [
                r for r in f.evidence_sources if not r.startswith("USR-")]

    def test_time_range_is_the_span_of_the_supporting_events(self, result, timeline):
        for f in result.findings:
            stamps = [timeline.get_by_event_id(i).timestamp for i in f.supporting_events]
            assert (f.first_seen, f.last_seen) == (min(stamps), max(stamps))

    def test_every_matched_indicator_is_backed_by_a_cited_record(self, result, raw_ids):
        for f in result.findings:
            for match in f.matched_indicators:
                if "evidence_id" in match:
                    assert match["evidence_id"] in f.evidence_sources
                    assert match["evidence_file"] == raw_ids[match["evidence_id"]]
                if "event_id" in match:
                    assert match["event_id"] in f.supporting_events

    def test_events_in_findings_are_in_chronological_order(self, result, timeline):
        for f in result.findings:
            order = [timeline.get_by_event_id(i).sequence for i in f.supporting_events]
            assert order == sorted(order)

    def test_matched_text_comes_from_the_raw_record(self, result):
        commands = {r["record_id"]: r["command_line"] for r in
                    load_json(SAMPLE_DIR / "processes.json")["records"]}
        f = finding(result, "F-002")
        hidden = next(m for m in f.matched_indicators if m["indicator"] == "hidden_window"
                      and m["evidence_id"] == "PROC-0006")
        assert hidden["matched_text"] in commands["PROC-0006"]


# ------------------------------------------- determinism, duplicates, read-only
class TestDeterminism:
    def test_same_inputs_same_output(self, timeline):
        first = run_detection(timeline, now=NOW).to_dict()
        second = run_detection(timeline, now=NOW).to_dict()
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)

    def test_only_the_clock_fields_differ_between_two_times(self, timeline):
        a = run_detection(timeline, now=NOW).to_dict()
        b = run_detection(timeline, now=datetime(2030, 1, 1, tzinfo=timezone.utc)).to_dict()
        assert a != b
        for payload in (a, b):
            payload.pop("generated_at")
            for finding_ in payload["findings"]:
                finding_.pop("detected_at")
        assert a == b

    def test_input_event_order_does_not_matter(self, timeline, result):
        events = [e.to_event() for e in timeline.entries]
        for seed in range(5):
            shuffled = list(events)
            random.Random(seed).shuffle(shuffled)
            again = run_detection(build_timeline(shuffled, case_id="INC-001"), now=NOW)
            assert again.to_dict() == result.to_dict()

    def test_without_now_the_clock_is_used_but_findings_are_unchanged(self, timeline, result):
        live = run_detection(timeline)
        assert live.generated_at.tzinfo is not None
        assert [f.supporting_events for f in live.findings] == [
            f.supporting_events for f in result.findings]


class TestDuplicatesAndModularity:
    class Twice(Rule):
        """Emits the same finding twice, plus one with the same events under another rule."""

        rule_id, name = "DET-900", "Test Duplicate Rule"

        def evaluate(self, context: RuleContext) -> RuleOutput:
            event = context.events[0]

            def make():
                return build_finding(
                    self, context, severity=Severity.LOW, confidence=Confidence.LOW,
                    device=event.device, user=event.user, description="d", reason="r",
                    supporting=[event], matched_indicators=[], finding_context={},
                    severity_factors=[], confidence_factors=[])

            return RuleOutput([make(), make()], events_considered=1)

    class Other(Twice):
        rule_id, name = "DET-901", "Test Other Rule"

    def timeline(self):
        f = Factory()
        f.logon(0)
        return f.timeline()

    def test_identical_findings_of_one_rule_are_removed_and_counted(self):
        result = run_detection(self.timeline(), rules=[self.Twice()], now=NOW)
        assert [f.finding_id for f in result.findings] == ["F-001"]
        assert result.duplicates_removed == 1
        assert result.rules[0].findings == 1

    def test_same_evidence_under_different_rules_is_not_a_duplicate(self):
        result = run_detection(self.timeline(), rules=[self.Twice(), self.Other()], now=NOW)
        assert [(f.finding_id, f.rule_id) for f in result.findings] == [
            ("F-001", "DET-900"), ("F-002", "DET-901")]
        assert result.duplicates_removed == 2

    def test_a_new_rule_plugs_in_next_to_the_built_in_ones(self, timeline):
        rules = [*default_rules(), self.Twice()]
        result = run_detection(timeline, rules=rules, now=NOW)
        assert [f.rule_id for f in result.findings] == [
            "DET-001", "DET-002", "DET-002", "DET-003", "DET-900"]
        assert result.findings[-1].finding_id == "F-005"

    def test_a_rule_may_not_return_another_rules_findings(self):
        class Liar(self.Twice):
            def evaluate(self, context):
                output = super().evaluate(context)
                for item in output.findings:
                    item.rule_id = "DET-001"
                return output
        with pytest.raises(ValueError, match="returned a finding for DET-001"):
            run_detection(self.timeline(), rules=[Liar()], now=NOW)

    def test_default_run_has_no_duplicates(self, result):
        assert result.duplicates_removed == 0
        signatures = [(f.rule_id, tuple(sorted(f.supporting_events))) for f in result.findings]
        assert len(signatures) == len(set(signatures))


class TestReadOnly:
    def test_timeline_is_unchanged_by_detection(self):
        tl = build_case_timeline(SAMPLE_DIR)
        before = copy.deepcopy(tl.to_dict())
        run_detection(tl, now=NOW)
        assert tl.to_dict() == before

    def test_evidence_files_are_unchanged(self):
        before = snapshot(SAMPLE_DIR)
        detect_case(SAMPLE_DIR, now=NOW)
        assert snapshot(SAMPLE_DIR) == before

    def test_results_do_not_share_state_with_the_timeline(self, timeline):
        result = run_detection(timeline, now=NOW)
        before = copy.deepcopy(timeline.to_dict())
        result.findings[0].context["x"] = 1
        result.findings[1].matched_indicators.clear()
        assert timeline.to_dict() == before
        assert run_detection(timeline, now=NOW).findings[1].matched_indicators

    def test_config_is_not_modified(self):
        config = DetectionConfig()
        before = config.to_dict()
        detect_case(SAMPLE_DIR, config=config, now=NOW)
        assert config.to_dict() == before

    def test_running_twice_on_one_timeline_gives_identical_results(self, timeline):
        assert (run_detection(timeline, now=NOW).to_dict()
                == run_detection(timeline, now=NOW).to_dict())


# ------------------------------------------------ configuration end to end
class TestConfigurationEndToEnd:
    def test_higher_threshold_removes_the_brute_force_finding_and_renumbers(self, timeline):
        config = DetectionConfig.from_dict({"brute_force": {"threshold": 7}})
        result = run_detection(timeline, config=config, now=NOW)
        assert [(f.finding_id, f.rule_id) for f in result.findings] == [
            ("F-001", "DET-002"), ("F-002", "DET-002"), ("F-003", "DET-003")]
        account = finding(result, "F-003")
        assert account.context["linked_findings"] == {
            "powershell": ["F-001", "F-002"], "brute_force": []}
        assert account.context["context_indicators_matched"] == [
            "process_chain_linked_to_powershell_finding"]

    def test_stricter_powershell_minimum_drops_the_weaker_process(self, timeline):
        config = DetectionConfig.from_dict({"powershell": {"min_indicators": 4}})
        result = run_detection(timeline, config=config, now=NOW)
        assert [f.rule_id for f in result.findings] == ["DET-001", "DET-002", "DET-003"]
        assert finding(result, "F-003").context["linked_findings"]["powershell"] == ["F-002"]

    def test_public_only_policy_makes_the_documentation_ranges_internal(self, timeline):
        config = DetectionConfig.from_dict(
            {"powershell": {"ip_policy": {"external_classes": ["public"]}}})
        result = run_detection(timeline, config=config, now=NOW)
        by_pid = {f.context["process"]["pid"]: f for f in result.findings
                  if f.rule_id == "DET-002"}
        for f in by_pid.values():                    # no connection counts as external now
            assert "external_connection" not in {m["indicator"] for m in f.matched_indicators}
        # pid 6188 keeps exactly its 2 remaining indicators, which still meets the minimum
        assert {m["indicator"] for m in by_pid[6188].matched_indicators} == {
            "execution_policy_bypass", "user_writable_script_path"}
        assert by_pid[6188].confidence is Confidence.MEDIUM          # 2 indicators, 2 files
        assert len(by_pid[6012].context["correlated_records"]) == 2   # still correlated

    def test_configuration_used_is_recorded_in_the_result(self, timeline):
        config = DetectionConfig.from_dict({"brute_force": {"window_seconds": 60}})
        assert run_detection(timeline, config=config, now=NOW).config[
            "brute_force"]["window_seconds"] == 60

    def test_sourceless_events_option_does_not_invent_a_burst(self, timeline):
        config = DetectionConfig.from_dict({"brute_force": {"include_events_without_source": True}})
        result = run_detection(timeline, config=config, now=NOW)
        assert [f.rule_id for f in result.findings].count("DET-001") == 1
        assert result.rules[0].data_gaps == []


# ----------------------------------------------------- engine input rules
class TestEngineInputValidation:
    def test_empty_timeline_is_a_valid_clean_run(self):
        result = run_detection(build_timeline([], case_id="INC-9"), now=NOW)
        assert result.findings == [] and result.case_id == "INC-9" and result.event_count == 0
        assert [r.events_considered for r in result.rules] == [0, 0, 0]
        assert all(r.data_gaps == [] for r in result.rules)

    def test_timeline_with_no_matching_events_is_a_clean_negative(self):
        f = Factory()
        f.logon(0)
        f.process(1, 10, name="notepad.exe", command_line="notepad.exe")
        result = f.run()
        assert result.findings == [] and all(r.data_gaps == [] for r in result.rules)

    @pytest.mark.parametrize("bad", [None, [], "timeline", {"entries": []}])
    def test_timeline_must_be_a_timeline(self, bad):
        with pytest.raises(TypeError, match="Timeline"):
            run_detection(bad)

    def test_config_must_be_a_detection_config(self, timeline):
        with pytest.raises(TypeError, match="DetectionConfig"):
            run_detection(timeline, config={"brute_force": {}})

    @pytest.mark.parametrize("bad", [datetime(2026, 10, 9, 12, 0), "2026-10-09", 5])
    def test_now_must_be_timezone_aware(self, timeline, bad):
        with pytest.raises(ValueError, match="timezone-aware"):
            run_detection(timeline, now=bad)

    def test_unknown_rule_id(self, timeline):
        with pytest.raises(ValueError, match="unknown rule id"):
            run_detection(timeline, rule_ids=["DET-999"], now=NOW)

    def test_duplicate_rule_ids(self, timeline):
        rules = default_rules()
        with pytest.raises(ValueError, match="duplicate rule id"):
            run_detection(timeline, rules=[rules[0], rules[0]], now=NOW)

    def test_rules_must_be_rule_instances(self, timeline):
        with pytest.raises(TypeError, match="Rule instances"):
            run_detection(timeline, rules=["DET-001"], now=NOW)

    def test_rule_ids_select_a_subset_and_keep_ids_consistent(self, timeline):
        result = run_detection(timeline, rule_ids=["DET-001"], now=NOW)
        assert [(f.finding_id, f.rule_id) for f in result.findings] == [("F-001", "DET-001")]
        assert [r.rule_id for r in result.rules] == ["DET-001"]

    def test_detect_case_refuses_invalid_evidence(self, case):
        (case / "events.json").unlink()
        with pytest.raises(EvidenceNotValidError):
            detect_case(case, now=NOW)

    def test_detect_case_refuses_tampered_evidence(self, case):
        edit(case, "processes.json", lambda d: d["records"][0].update(name="x.exe"),
             rebuild=False)
        with pytest.raises(EvidenceNotValidError):
            detect_case(case, now=NOW)

    def test_detect_case_on_a_valid_edited_copy(self, case):
        def drop_rdp_failures(data):
            data["records"] = [
                r for r in data["records"]
                if not (r["event_id"] == 4625 and r["data"]["LogonType"] == "10")]

        edit(case, "events.json", drop_rdp_failures)
        result = detect_case(case, now=NOW)
        assert all(f.rule_id != "DET-001" for f in result.findings)


# ------------------------------------------------------------------ report
class TestReport:
    def test_report_is_ascii_only_with_ascii_arrows(self, result):
        text = format_detection(result)
        assert text.isascii() and "->" in text and "\u2192" not in text

    def test_report_lists_every_finding_with_its_evidence(self, result):
        text = format_detection(result)
        for f in result.findings:
            assert f"{f.finding_id}  {f.title}  [{f.rule_id}]" in text
        assert "Severity   : High    Confidence: Medium" in text
        assert "EVL-0004, EVL-0005" in text and "PROC-0006" in text
        assert "Severity because:" in text and "Confidence because:" in text

    def test_report_shows_data_gaps_separately(self, result):
        text = format_detection(result)
        assert "Data gaps (things a rule could not evaluate; not negative results):" in text
        assert "E-00001" in text

    def test_report_without_findings_warns_that_gaps_are_not_clean(self):
        f = Factory()
        f.burst(0, 6, ip=None)
        text = format_detection(f.run())
        assert "No findings." in text and "has not ruled it out" in text
        assert "no source address" in text

    def test_non_ascii_evidence_text_is_escaped(self):
        f = Factory()
        f.process(0, 500, command_line="powershell.exe -w hidden -ep bypass", user="ahm\u00e9d")
        text = format_detection(f.run())
        assert text.isascii() and "ahm\\xe9d" in text
        assert ascii_safe("caf\u00e9 \u2192") == "caf\\xe9 \\u2192"

    def test_report_is_pure_presentation(self, result):
        before = copy.deepcopy(result.to_dict())
        format_detection(result)
        assert result.to_dict() == before

    def test_empty_result_report(self):
        text = format_detection(run_detection(build_timeline([], case_id="X"), now=NOW))
        assert "Findings : 0" in text and "No findings." in text


# --------------------------------------------------------------------- CLI
class TestCli:
    def test_default_run(self, capsys):
        assert cli_main([str(SAMPLE_DIR)]) == 0
        output = capsys.readouterr().out
        assert "Findings : 4" in output and "F-004  Suspicious Account Creation" in output
        assert output.isascii()

    def test_json_output_is_reproducible_with_now(self, capsys):
        args = [str(SAMPLE_DIR), "--json", "--now", "2026-10-09T12:00:00Z"]
        assert cli_main(args) == 0
        first = capsys.readouterr().out
        assert cli_main(args) == 0
        assert capsys.readouterr().out == first
        payload = json.loads(first)
        assert payload["generated_at"] == "2026-10-09T12:00:00Z"
        assert len(payload["findings"]) == 4

    def test_rule_filter(self, capsys):
        assert cli_main([str(SAMPLE_DIR), "--rule", "DET-001", "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert [f["rule_id"] for f in payload["findings"]] == ["DET-001"]

    def test_config_file_changes_the_result(self, tmp_path, capsys):
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"brute_force": {"threshold": 7}}), encoding="utf-8")
        assert cli_main([str(SAMPLE_DIR), "--config", str(path), "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert [f["rule_id"] for f in payload["findings"]] == ["DET-002", "DET-002", "DET-003"]
        assert payload["config"]["brute_force"]["threshold"] == 7

    @pytest.mark.parametrize("content, message", [
        ("{ not json", "cannot read configuration"),
        ('{"brute_force": {"treshold": 3}}', "unknown option"),
        ('{"nope": {}}', "unknown configuration section"),
        ('{"brute_force": {"threshold": 0}}', "positive integer"),
        ("[]", "JSON object"),
    ])
    def test_invalid_config_files_exit_2(self, tmp_path, capsys, content, message):
        path = tmp_path / "config.json"
        path.write_text(content, encoding="utf-8")
        assert cli_main([str(SAMPLE_DIR), "--config", str(path)]) == 2
        assert message in capsys.readouterr().err

    def test_missing_config_file_exits_2(self, tmp_path, capsys):
        assert cli_main([str(SAMPLE_DIR), "--config", str(tmp_path / "nope.json")]) == 2
        assert "cannot read configuration" in capsys.readouterr().err

    def test_unknown_rule_exits_2(self, capsys):
        assert cli_main([str(SAMPLE_DIR), "--rule", "DET-999"]) == 2
        assert "unknown rule id" in capsys.readouterr().err

    @pytest.mark.parametrize("value", ["yesterday", "2026-10-09T12:00:00"])
    def test_invalid_now_exits_2(self, capsys, value):
        assert cli_main([str(SAMPLE_DIR), "--now", value]) == 2
        assert "invalid --now" in capsys.readouterr().err

    def test_invalid_evidence_exits_1_with_the_validation_report(self, case, capsys):
        (case / "events.json").unlink()
        assert cli_main([str(case)]) == 1
        output = capsys.readouterr().out
        assert "detection was not run" in output and "REQUIRED_FILE_MISSING" in output

    def test_cli_does_not_modify_the_evidence(self, case, capsys):
        before = snapshot(case)
        cli_main([str(case)])
        assert snapshot(case) == before
