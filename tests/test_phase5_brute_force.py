"""Phase 5 tests: DET-001 brute-force logon detection."""

from __future__ import annotations

from datetime import timedelta

import pytest
from detection_helpers import NOW, Factory, at, findings_of, summary_of

from security.detection import BruteForceConfig, DetectionConfig
from security.detection.brute_force import Burst, find_bursts
from security.models.schemas import Confidence, Severity


def times(*seconds):
    return [at(s) for s in seconds]


def bf(result):
    return findings_of(result, "DET-001")


def config(**kwargs) -> DetectionConfig:
    return DetectionConfig(brute_force=BruteForceConfig(**kwargs))


# ------------------------------------------------------------- the algorithm
class TestFindBursts:
    def test_no_events(self):
        assert find_bursts([], 5, 120) == []

    def test_below_threshold(self):
        assert find_bursts(times(0, 10, 20, 30), 5, 120) == []

    def test_exactly_threshold_inside_the_window(self):
        assert find_bursts(times(0, 30, 60, 90, 120), 5, 120) == [Burst(0, 4, 5)]

    def test_window_boundary_is_inclusive(self):
        assert find_bursts(times(0, 30, 60, 90, 120), 5, 120) != []
        assert find_bursts(times(0, 30, 60, 90, 121), 5, 120) == []

    def test_window_boundary_to_the_microsecond(self):
        just_inside = [at(0), at(30), at(60), at(90), at(0) + timedelta(seconds=120)]
        just_outside = just_inside[:4] + [at(0) + timedelta(seconds=120, microseconds=1)]
        assert find_bursts(just_inside, 5, 120) != []
        assert find_bursts(just_outside, 5, 120) == []

    def test_threshold_boundary(self):
        assert find_bursts(times(0, 1, 2, 3), 4, 60) == [Burst(0, 3, 4)]
        assert find_bursts(times(0, 1, 2, 3), 5, 60) == []

    def test_slow_drip_never_reaches_the_threshold(self):
        assert find_bursts(times(*range(0, 600, 60)), 5, 120) == []   # max 3 per window

    def test_overlapping_windows_merge_into_one_burst(self):
        bursts = find_bursts(times(*range(0, 300, 30)), 5, 120)     # 10 events
        assert bursts == [Burst(0, 9, 5)]

    def test_dense_attack_is_one_burst(self):
        assert find_bursts(times(*range(20)), 5, 120) == [Burst(0, 19, 20)]

    def test_separate_bursts_stay_separate(self):
        bursts = find_bursts(times(0, 10, 20, 30, 40, 1000, 1010, 1020, 1030, 1040), 5, 120)
        assert bursts == [Burst(0, 4, 5), Burst(5, 9, 5)]

    def test_noise_before_a_burst_is_not_included(self):
        assert find_bursts(times(0, 500, 510, 520, 530, 540), 5, 60) == [Burst(1, 5, 5)]

    def test_threshold_of_one_gives_one_burst_per_isolated_event(self):
        assert find_bursts(times(0, 1000), 1, 120) == [Burst(0, 0, 1), Burst(1, 1, 1)]

    def test_each_event_belongs_to_at_most_one_burst(self):
        bursts = find_bursts(times(*range(0, 1000, 17)), 3, 60)
        covered = [i for b in bursts for i in range(b.start, b.end + 1)]
        assert len(covered) == len(set(covered))


# ------------------------------------------------------------- positive case
class TestPositive:
    def test_threshold_met_produces_one_complete_finding(self):
        f = Factory()
        events = f.burst(0, 5, spacing=10)
        result = f.run()
        [finding] = bf(result)
        assert finding.finding_id == "F-001" and finding.rule_id == "DET-001"
        assert finding.title == finding.rule_name == "Possible Brute-Force Logon Attempts"
        assert (finding.severity, finding.confidence) == (Severity.MEDIUM, Confidence.MEDIUM)
        assert (finding.user, finding.device) == ("ahmed", "PC-1")
        assert (finding.first_seen, finding.last_seen) == (at(0), at(40))
        assert finding.detected_at == NOW
        assert finding.supporting_events == [e.event_id for e in events]
        assert finding.evidence_sources == [e.evidence_id for e in events]
        assert finding.evidence_files == ["events.json"]
        assert finding.context["grouping"] == {
            "device": "PC-1", "target_account": "ahmed", "source_ip": "198.51.100.23"}
        assert finding.context["failure_count"] == 5
        assert finding.context["threshold"] == 5 and finding.context["window_seconds"] == 120
        indicator = finding.matched_indicators[0]
        assert indicator["indicator"] == "repeated_failed_logons"
        assert (indicator["observed_failures"], indicator["threshold"]) == (5, 5)
        assert "5 failed logons" in finding.reason and "198.51.100.23" in finding.description
        assert finding.recommended_next_steps == []      # investigation is a later phase
        assert finding.iocs == [] and finding.mitre_techniques == []
        assert finding.severity_factors and finding.confidence_factors

    def test_four_failures_are_a_negative_result(self):
        f = Factory()
        f.burst(0, 4)
        result = f.run()
        assert bf(result) == []
        summary = summary_of(result, "DET-001")
        assert (summary.events_considered, summary.findings, summary.data_gaps) == (4, 0, [])

    def test_a_single_failed_logon_is_never_brute_force(self):
        f = Factory()
        f.failed_logon(0)
        assert bf(f.run()) == []

    def test_twice_the_threshold_raises_confidence(self):
        f = Factory()
        f.burst(0, 10, spacing=5)
        [finding] = bf(f.run())
        assert finding.confidence is Confidence.HIGH
        g = Factory()
        g.burst(0, 9, spacing=5)
        assert bf(g.run())[0].confidence is Confidence.MEDIUM

    def test_long_attack_is_one_finding_not_one_per_window(self):
        f = Factory()
        f.burst(0, 30, spacing=10)
        [finding] = bf(f.run())
        assert finding.context["failure_count"] == 30

    def test_two_separate_bursts_give_two_chronological_findings(self):
        f = Factory()
        late = f.burst(1000, 5)
        early = f.burst(0, 5)
        first, second = bf(f.run())
        assert (first.finding_id, second.finding_id) == ("F-001", "F-002")
        assert first.supporting_events == [e.event_id for e in early]
        assert second.supporting_events == [e.event_id for e in late]
        assert not set(first.supporting_events) & set(second.supporting_events)

    def test_other_event_types_are_ignored(self):
        f = Factory()
        f.logon(0)
        f.process(1, 10)
        f.connection(2, 10)
        result = f.run()
        assert bf(result) == [] and summary_of(result, "DET-001").events_considered == 0


class TestBoundariesAndConfiguration:
    def test_window_boundary_through_the_rule(self):
        inside = Factory()
        inside.burst(0, 5, spacing=30)                      # span exactly 120 s
        assert len(bf(inside.run())) == 1
        outside = Factory()
        outside.burst(0, 5, spacing=30.25)                  # span 121 s
        assert bf(outside.run()) == []

    def test_threshold_and_window_are_configurable(self):
        f = Factory()
        f.burst(0, 3, spacing=5)                            # 3 failures over 10 s
        assert bf(f.run(config(threshold=3, window_seconds=10)))
        assert not bf(f.run(config(threshold=3, window_seconds=9)))
        assert not bf(f.run(config(threshold=4, window_seconds=10)))
        assert bf(f.run()) == []                            # default threshold is 5

    def test_configuration_is_reported_in_the_finding_and_result(self):
        f = Factory()
        f.burst(0, 3, spacing=1)
        result = f.run(config(threshold=3, window_seconds=30))
        assert result.config["brute_force"]["threshold"] == 3
        assert bf(result)[0].context["window_seconds"] == 30


# --------------------------------------------------------------- grouping
class TestGrouping:
    def test_different_accounts_are_not_combined(self):
        f = Factory()
        f.burst(0, 3, user="alice")
        f.burst(30, 3, user="bob")
        assert bf(f.run()) == []

    def test_each_account_over_the_threshold_gets_its_own_finding(self):
        f = Factory()
        f.burst(0, 5, user="alice")
        f.burst(0, 5, user="bob")
        findings = bf(f.run())
        assert sorted(x.user for x in findings) == ["alice", "bob"]

    def test_different_sources_are_not_combined(self):
        f = Factory()
        f.burst(0, 3, ip="198.51.100.1")
        f.burst(30, 3, ip="198.51.100.2")
        assert bf(f.run()) == []

    def test_same_account_two_sources_each_over_threshold(self):
        f = Factory()
        f.burst(0, 5, ip="198.51.100.1")
        f.burst(0, 5, ip="198.51.100.2")
        assert {x.context["grouping"]["source_ip"] for x in bf(f.run())} == {
            "198.51.100.1", "198.51.100.2"}

    def test_different_devices_are_not_combined(self):
        f = Factory()
        f.burst(0, 3, device="PC-A")
        f.burst(30, 3, device="PC-B")
        assert bf(f.run()) == []

    def test_a_device_over_the_threshold_is_attributed_correctly(self):
        f = Factory()
        f.burst(0, 5, device="PC-A")
        f.burst(0, 2, device="PC-B")
        [finding] = bf(f.run())
        assert finding.device == "PC-A"

    def test_account_comparison_ignores_case(self):
        f = Factory()
        f.burst(0, 3, user="ahmed")
        f.burst(30, 2, user="AHMED")
        [finding] = bf(f.run())
        assert finding.context["failure_count"] == 5 and finding.user == "ahmed"

    def test_findings_are_ordered_chronologically_across_groups(self):
        f = Factory()
        f.burst(500, 5, user="zoe")
        f.burst(0, 5, user="amy")
        assert [x.user for x in bf(f.run())] == ["amy", "zoe"]


# ----------------------------------------------------- missing / odd data
class TestMissingData:
    def test_failures_without_a_source_are_a_data_gap_not_a_negative(self):
        f = Factory()
        f.burst(0, 6, ip=None)
        result = f.run()
        assert bf(result) == []
        gap = summary_of(result, "DET-001").data_gaps
        assert len(gap) == 1 and "no source address" in gap[0]
        assert "include_events_without_source" in gap[0]

    def test_events_without_source_can_be_grouped_on_request(self):
        f = Factory()
        f.burst(0, 6, ip=None)
        [finding] = bf(f.run(config(include_events_without_source=True)))
        assert finding.confidence is Confidence.LOW          # same source not established
        assert finding.context["grouping"]["source_ip"] is None
        assert finding.context["source_ip_class"] == "missing"
        assert "unknown source" in finding.description

    def test_sourceless_failures_do_not_count_toward_a_sourced_group(self):
        f = Factory()
        sourced = f.burst(0, 5)
        f.burst(5, 5, ip=None)
        result = f.run()
        [finding] = bf(result)
        assert finding.context["failure_count"] == 5
        assert finding.supporting_events == [e.event_id for e in sourced]
        assert "5 failed logon(s) have no source address" in summary_of(
            result, "DET-001").data_gaps[0]

    def test_dash_placeholder_counts_as_missing(self):
        f = Factory()
        f.burst(0, 5, ip="  ")
        assert bf(f.run()) == []

    def test_failures_without_an_account_are_a_data_gap(self):
        f = Factory()
        f.burst(0, 6, user=None)
        result = f.run()
        assert bf(result) == []
        assert "no target account" in summary_of(result, "DET-001").data_gaps[0]

    def test_invalid_source_text_is_grouped_and_reported(self):
        f = Factory()
        f.burst(0, 5, ip="not-an-ip")
        result = f.run()
        [finding] = bf(result)
        assert finding.context["source_ip_class"] == "invalid"
        assert any("not a valid IP address" in g for g in summary_of(
            result, "DET-001").data_gaps)

    @pytest.mark.parametrize("ip, expected", [
        ("8.8.8.8", "public"), ("10.0.0.5", "private"), ("127.0.0.1", "loopback"),
        ("169.254.1.1", "link_local"), ("203.0.113.9", "documentation"),
        ("224.0.0.5", "multicast"), ("::1", "loopback"), ("fe80::1", "link_local")])
    def test_source_class_is_recorded_and_never_changes_the_verdict(self, ip, expected):
        f = Factory()
        f.burst(0, 5, ip=ip)
        [finding] = bf(f.run())
        assert finding.context["source_ip_class"] == expected
        assert (finding.severity, finding.confidence) == (Severity.MEDIUM, Confidence.MEDIUM)


# ------------------------------------------------- success correlation
class TestSuccessCorrelation:
    def setup_method(self):
        self.f = Factory()
        self.failures = self.f.burst(0, 5, spacing=10)       # last failure at t=40

    def finding(self, **config_kwargs):
        [finding] = bf(self.f.run(config(**config_kwargs) if config_kwargs else None))
        return finding

    def test_success_from_the_same_source_raises_severity(self):
        success = self.f.logon(70)
        finding = self.finding()
        assert finding.context["followed_by_successful_logon"] == "yes"
        assert finding.context["successful_logon_event_id"] == success.event_id
        assert finding.context["seconds_to_successful_logon"] == 30
        assert finding.severity is Severity.HIGH
        assert success.event_id in finding.supporting_events
        assert finding.last_seen == at(70)
        assert finding.matched_indicators[1]["indicator"] == "followed_by_successful_logon"
        assert "+1" in " ".join(finding.severity_factors)

    @pytest.mark.parametrize("delay, expected", [(0, "yes"), (260, "yes"), (300, "yes"),
                                                 (301, "no"), (-1, "no")])
    def test_success_window_boundaries(self, delay, expected):
        self.f.logon(40 + delay)
        finding = self.finding()
        assert finding.context["followed_by_successful_logon"] == expected
        assert finding.severity is (Severity.HIGH if expected == "yes" else Severity.MEDIUM)

    def test_success_window_is_configurable(self):
        self.f.logon(40 + 60)
        assert self.finding(success_window_seconds=60).severity is Severity.HIGH
        assert self.finding(success_window_seconds=59).severity is Severity.MEDIUM

    def test_success_from_another_source_is_not_linked(self):
        self.f.logon(50, ip="198.51.100.99")
        finding = self.finding()
        assert finding.context["followed_by_successful_logon"] == "no"
        assert finding.severity is Severity.MEDIUM

    def test_success_for_another_account_is_not_linked(self):
        self.f.logon(50, user="bob")
        assert self.finding().context["followed_by_successful_logon"] == "no"

    def test_success_on_another_device_is_not_linked(self):
        self.f.logon(50, device="OTHER-PC")
        assert self.finding().context["followed_by_successful_logon"] == "no"

    def test_success_without_a_source_is_unverifiable_not_negative(self):
        success = self.f.logon(50, ip=None)
        finding = self.finding()
        assert finding.context["followed_by_successful_logon"] == "unverifiable"
        assert finding.severity is Severity.MEDIUM
        assert success.event_id not in finding.supporting_events
        assert "cannot be linked" in finding.description

    def test_a_matching_success_wins_over_an_unverifiable_one(self):
        self.f.logon(50, ip=None)
        self.f.logon(60)
        assert self.finding().context["followed_by_successful_logon"] == "yes"

    def test_success_matching_ignores_case(self):
        self.f.logon(50, user="AHMED")
        assert self.finding().context["followed_by_successful_logon"] == "yes"

    def test_unknown_source_group_can_never_be_confirmed(self):
        g = Factory()
        g.burst(0, 5, ip=None)
        g.logon(50, ip="198.51.100.23")
        [finding] = bf(g.run(config(include_events_without_source=True)))
        assert finding.context["followed_by_successful_logon"] == "unverifiable"

    def test_the_earliest_matching_success_is_used(self):
        first = self.f.logon(60)
        self.f.logon(90)
        assert self.finding().context["successful_logon_event_id"] == first.event_id
