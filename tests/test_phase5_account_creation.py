"""Phase 5 tests: DET-003 suspicious account creation.

``build`` lays out one synthetic incident (all times in seconds from BASE):

    0-40    five failed logons for the brute-force account      -> DET-001
    70      successful logon from the same source
    100     PowerShell pid 500 with two indicators              -> DET-002
    200     net.exe pid 600 (child of 500) "net user ... /add"  creating process
    202     account created (4720) by the actor
    210     (optional) target added to Administrators (4732)

Every option can switch one part off or break one link, so each rule
condition is tested on its own.
"""

from __future__ import annotations

import pytest
from detection_helpers import Factory, findings_of, iso, summary_of, user_context

from security.detection import AccountCreationConfig, DetectionConfig
from security.models.schemas import Confidence, Severity

CREATE = "net.exe user svc_new [REDACTED] /add"


def build(f: Factory, *, brute=True, ps_process=True, creating=True, snapshot="admin",
          group_offset=None, group="Administrators", member="svc_new", group_device=None,
          actor="ahmed", target="svc_new", creation_t=202, creating_command=CREATE,
          creating_user=None, creating_offset=2, creating_ppid=500, brute_user="ahmed",
          brute_device=None, brute_success_t=70, ps_user=None, ps_command=None,
          ps_start=100, snapshot_offset=0):
    if brute:
        f.burst(0, 5, spacing=10, user=brute_user, device=brute_device)
        f.logon(brute_success_t, user=brute_user, device=brute_device)
    if ps_process:
        f.process(ps_start, 500, user=ps_user or actor, parent="explorer.exe",
                  command_line=ps_command or "powershell.exe -w hidden -ep bypass")
    if creating:
        f.process(creation_t - creating_offset, 600, name="net.exe",
                  command_line=creating_command, user=creating_user or actor,
                  parent="powershell.exe", ppid=creating_ppid)
    context = None
    if snapshot:
        context = user_context(target, snapshot == "admin", iso(creation_t + snapshot_offset),
                               "USR-0006")
    creation = f.account(creation_t, actor=actor, target=target, target_context=context)
    if group_offset is not None:
        f.group_add(creation_t + group_offset, member=member, group=group, actor=actor,
                    device=group_device)
    return creation


def acct(result):
    return findings_of(result, "DET-003")


def config(**kwargs) -> DetectionConfig:
    return DetectionConfig(account_creation=AccountCreationConfig(**kwargs))


def gaps(result) -> str:
    return " | ".join(summary_of(result, "DET-003").data_gaps)


# ----------------------------------------------------------- the full chain
class TestFullChain:
    def setup_method(self):
        self.f = Factory()
        self.creation = build(self.f, group_offset=8)
        self.result = self.f.run()
        [self.finding] = acct(self.result)

    def test_all_three_rules_fire_in_order(self):
        assert [x.rule_id for x in self.result.findings] == [
            "DET-001", "DET-002", "DET-003"]
        assert self.finding.finding_id == "F-003"

    def test_actor_and_target_are_kept_distinct(self):
        finding = self.finding
        assert finding.user == "ahmed"                           # the actor
        assert finding.context["actor"] == "ahmed"
        assert finding.context["target_account"] == "svc_new"    # the created account
        assert finding.context["actor"] != finding.context["target_account"]
        assert "Account 'svc_new' was created" in finding.description
        assert "by 'ahmed'" in finding.description

    def test_severity_and_confidence(self):
        assert self.finding.severity is Severity.HIGH
        assert self.finding.confidence is Confidence.HIGH
        assert self.finding.severity_factors[0].startswith("base level")
        assert len(self.finding.severity_factors) == 4          # base + privileged + 2 context

    def test_privileged_target_has_two_independent_bases(self):
        assert self.finding.context["privileged_target"] == "yes"
        assert self.finding.context["privileged_basis"] == [
            "group_membership_event", "users_snapshot"]

    def test_links_name_the_earlier_findings_by_final_id(self):
        assert self.finding.context["linked_findings"] == {
            "powershell": ["F-002"], "brute_force": ["F-001"]}
        by_name = {m["indicator"]: m for m in self.finding.matched_indicators
                   if m["indicator"] != "privileged_target"}
        assert by_name["process_chain_linked_to_powershell_finding"]["finding_id"] == "F-002"
        assert by_name["actor_account_targeted_by_bruteforce"]["finding_id"] == "F-001"
        assert "account-level" in by_name[
            "actor_account_targeted_by_bruteforce"]["link_strength"]

    def test_creating_process_is_recorded(self):
        [creating] = self.finding.context["creating_evidence"]
        assert creating["evidence_file"] == "processes.json"
        assert "net.exe user svc_new" in creating["command"]

    def test_supporting_evidence_is_complete_and_cites_users_json(self):
        by_id = {e.event_id: e for e in self.f.events}
        supporting = {by_id[i].evidence_id for i in self.finding.supporting_events}
        assert self.creation.evidence_id in supporting
        assert {"PROC-0002", "PROC-0001"} <= supporting          # creating + PowerShell
        assert "USR-0006" in self.finding.evidence_sources
        assert "users.json" in self.finding.evidence_files
        assert set(self.finding.supporting_events) <= {e.event_id for e in self.f.events}

    def test_confidence_explains_each_corroboration(self):
        text = " ".join(self.finding.confidence_factors)
        assert "users.json USR-0006 created_at matches" in text
        assert "creation command naming the target account" in text


# ------------------------------------------------------------- criterion 1
class TestPrivilegedTarget:
    def test_privileged_alone_is_not_enough_by_default(self):
        f = Factory()
        build(f, brute=False, ps_process=False, creating=False, group_offset=5)
        result = f.run()
        assert acct(result) == []
        assert "no creating process identified" in gaps(result)

    def test_privileged_only_can_be_reported_when_configured(self):
        f = Factory()
        build(f, brute=False, ps_process=False, creating=False, group_offset=5)
        [finding] = acct(f.run(config(min_context_indicators=0)))
        assert finding.severity is Severity.MEDIUM            # Low + privileged
        assert finding.context["context_indicators_matched"] == []

    def test_non_privileged_target_is_a_known_negative(self):
        f = Factory()
        build(f, snapshot="user")
        result = f.run()
        assert acct(result) == []
        assert "could not be determined" not in gaps(result)   # we KNOW it is not admin

    def test_requirement_of_privilege_can_be_switched_off(self):
        f = Factory()
        build(f, snapshot="user")
        [finding] = acct(f.run(config(require_privileged_target=False)))
        assert finding.context["privileged_target"] == "no"
        assert finding.severity is Severity.HIGH              # Low + 2 context indicators

    def test_unknown_privilege_is_a_data_gap_not_a_negative(self):
        f = Factory()
        build(f, snapshot=None)
        result = f.run()
        assert acct(result) == []
        assert "privilege level could not be determined" in gaps(result)

    def test_snapshot_alone_establishes_privilege(self):
        f = Factory()
        build(f)
        [finding] = acct(f.run())
        assert finding.context["privileged_basis"] == ["users_snapshot"]

    def test_group_event_alone_establishes_privilege(self):
        f = Factory()
        build(f, snapshot=None, group_offset=5)
        [finding] = acct(f.run())
        assert finding.context["privileged_basis"] == ["group_membership_event"]
        assert finding.context["snapshot_created_at_consistent"] is None

    @pytest.mark.parametrize("offset, privileged", [(0, True), (600, True), (601, False),
                                                    (-1, False)])
    def test_group_add_window_boundaries(self, offset, privileged):
        f = Factory()
        build(f, snapshot=None, group_offset=offset)
        assert bool(acct(f.run())) is privileged

    def test_group_add_window_is_configurable(self):
        f = Factory()
        build(f, snapshot=None, group_offset=100)          # 100 s after the creation
        assert acct(f.run())                                # default window is 600 s
        assert acct(f.run(config(group_add_window_seconds=100)))
        assert not acct(f.run(config(group_add_window_seconds=99)))

    @pytest.mark.parametrize("kwargs", [
        {"group": "Users"},                        # not a privileged group
        {"member": "someone_else"},                # a different account
        {"group_device": "OTHER-PC"},              # a different device
    ], ids=["other-group", "other-member", "other-device"])
    def test_group_add_that_does_not_match_is_ignored(self, kwargs):
        f = Factory()
        build(f, snapshot=None, group_offset=5, **kwargs)
        assert acct(f.run()) == []

    def test_group_and_member_matching_ignores_case(self):
        f = Factory()
        build(f, snapshot=None, group_offset=5, group="ADMINISTRATORS", member="SVC_NEW")
        assert acct(f.run())

    def test_privileged_groups_are_configurable(self):
        f = Factory()
        build(f, snapshot=None, group_offset=5, group="Backup Operators")
        assert not acct(f.run())
        assert acct(f.run(config(privileged_groups=("Backup Operators",))))


# ------------------------------------------------------------- criterion 2
class TestProcessChainContext:
    def only_chain(self, **kwargs):
        f = Factory()
        build(f, brute=False, **kwargs)
        return f, f.run(kwargs.pop("cfg", None))

    def test_chain_alone_is_enough(self):
        f, result = self.only_chain()
        [finding] = acct(result)
        assert finding.context["context_indicators_matched"] == [
            "process_chain_linked_to_powershell_finding"]
        assert finding.severity is Severity.HIGH              # Low + privileged + chain
        assert finding.confidence is Confidence.HIGH           # creating process corroborates

    @pytest.mark.parametrize("offset, found", [(60, True), (61, False), (0, True)])
    def test_creating_process_window_boundary(self, offset, found):
        _, result = self.only_chain(creating_offset=offset)
        assert bool(acct(result)) is found
        if not found:
            assert "no creating process identified" in gaps(result)

    @pytest.mark.parametrize("kwargs, why", [
        ({"creating_user": "bob"}, "different user"),
        ({"creating_command": "net.exe user other_acct pw /add"}, "does not name the target"),
        ({"creating_command": "net.exe user svc_new"}, "no /add"),
        ({"creating_command": "net.exe localgroup Administrators svc_new /add"},
         "group change, not a creation"),
        ({"creating_command": "net.exe user svc_new2 pw /add"}, "similar but different name"),
    ])
    def test_process_that_is_not_the_creating_one_is_not_used(self, kwargs, why):
        _, result = self.only_chain(**kwargs)
        assert acct(result) == []
        assert "no creating process identified" in gaps(result)

    def test_creating_process_without_a_command_line_is_a_gap(self):
        _, result = self.only_chain(creating_command=None)
        assert acct(result) == []
        assert "no command line" in gaps(result)

    def test_unknown_parent_ends_the_chain(self):
        _, result = self.only_chain(creating_ppid=999)
        assert acct(result) == []

    def test_ancestor_must_be_part_of_a_powershell_finding(self):
        _, result = self.only_chain(ps_command="powershell.exe -NoProfile")   # no indicators
        assert findings_of(result, "DET-002") == [] and acct(result) == []

    @pytest.mark.parametrize("creation_t, linked", [(3702, True), (3703, False)])
    def test_ancestry_window_boundary(self, creation_t, linked):
        # PowerShell started at t=100; creating process starts 2 s before the event
        _, result = self.only_chain(creation_t=creation_t)
        assert bool(acct(result)) is linked

    def test_ancestry_window_is_configurable(self):
        f = Factory()
        build(f, brute=False, creation_t=3703)
        assert acct(f.run(config(ancestry_window_seconds=3700)))

    @pytest.mark.parametrize("depth, linked", [(1, False), (2, True)])
    def test_ancestry_depth_bound(self, depth, linked):
        f = Factory()
        build(f, brute=False, creating_ppid=510)
        f.process(110, 510, name="cmd.exe", command_line="cmd.exe /c x", user="ahmed",
                  parent="powershell.exe", ppid=500)
        assert bool(acct(f.run(config(max_ancestry_depth=depth)))) is linked

    def test_ancestor_started_after_the_child_is_not_a_parent(self):
        f = Factory()
        build(f, brute=False, ps_start=300)                    # starts after net.exe (200)
        assert acct(f.run()) == []

    def test_ancestor_with_a_different_user_is_not_followed(self):
        f = Factory()
        build(f, brute=False, ps_user="bob")
        assert acct(f.run()) == []


class TestBruteForceContext:
    def only_brute(self, **kwargs):
        f = Factory()
        build(f, ps_process=False, creating=False, **kwargs)
        return f, f.run()

    def test_brute_force_alone_is_enough(self):
        _, result = self.only_brute()
        [finding] = acct(result)
        assert finding.context["context_indicators_matched"] == [
            "actor_account_targeted_by_bruteforce"]
        assert finding.severity is Severity.HIGH

    def test_confidence_is_high_when_users_json_corroborates(self):
        _, result = self.only_brute()
        assert acct(result)[0].confidence is Confidence.HIGH
        assert acct(result)[0].context["snapshot_created_at_consistent"] is True

    @pytest.mark.parametrize("offset, confidence", [
        (60, Confidence.HIGH), (-60, Confidence.HIGH), (61, Confidence.LOW),
        (3600, Confidence.LOW)])
    def test_snapshot_tolerance_decides_corroboration(self, offset, confidence):
        _, result = self.only_brute(snapshot_offset=offset)
        [finding] = acct(result)
        assert finding.confidence is confidence
        assert finding.context["snapshot_created_at_consistent"] is (offset in (60, -60))

    def test_account_level_link_without_corroboration_is_low_confidence(self):
        f = Factory()
        build(f, ps_process=False, creating=False, snapshot=None, group_offset=5)
        [finding] = acct(f.run())
        assert finding.confidence is Confidence.LOW
        assert "account-level" in " ".join(finding.confidence_factors)

    @pytest.mark.parametrize("success_t, linked", [(200, True), (199, False)])
    def test_context_window_boundary(self, success_t, linked):
        # creation at t=2000: success must be at most 1800 s earlier
        _, result = self.only_brute(creation_t=2000, brute_success_t=success_t)
        assert bool(acct(result)) is linked

    def test_success_after_the_creation_is_not_context(self):
        _, result = self.only_brute(brute_success_t=300)
        assert acct(result) == []

    def test_context_window_is_configurable(self):
        f = Factory()
        build(f, ps_process=False, creating=False, creation_t=2000, brute_success_t=199)
        assert acct(f.run(config(context_window_seconds=1801)))

    def test_link_requires_the_actor_not_the_target(self):
        # bob creates an account named like the brute-forced account
        f = Factory()
        build(f, ps_process=False, creating=False, actor="bob", target="ahmed",
              brute_user="ahmed", creating_command="net.exe user ahmed pw /add")
        assert acct(f.run()) == []

    def test_other_device_is_not_linked(self):
        _, result = self.only_brute(brute_device="OTHER-PC")
        assert acct(result) == []

    def test_brute_force_without_a_successful_logon_is_not_context(self):
        f = Factory()
        f.burst(0, 5, spacing=10)
        build(f, brute=False, ps_process=False, creating=False)
        assert acct(f.run()) == []

    def test_account_name_matching_ignores_case(self):
        _, result = self.only_brute(brute_user="AHMED")
        assert acct(result)


class TestActorVersusTarget:
    def test_different_actor_and_target_stay_separate_in_every_field(self):
        f = Factory()
        build(f, actor="bob", target="ahmed", brute_user="ahmed", ps_user="bob",
              creating_command="net.exe user ahmed pw /add", group_offset=5)
        [finding] = acct(f.run())
        assert finding.user == "bob"
        assert finding.context["actor"] == "bob"
        assert finding.context["target_account"] == "ahmed"
        # the brute-forced account is the TARGET here, so it must not count as context
        assert finding.context["linked_findings"]["brute_force"] == []
        assert "actor_account_targeted_by_bruteforce" not in finding.context[
            "context_indicators_matched"]


# ---------------------------------------------------- scripts, dependencies
class TestOtherEvidence:
    def test_creation_command_in_a_script_block_corroborates(self):
        f = Factory()
        build(f, ps_process=False, creating=False, snapshot=None, group_offset=5)
        f.script(172, 777, command="net user svc_new [REDACTED] /add", user="ahmed")
        [finding] = acct(f.run())
        assert finding.confidence is Confidence.HIGH
        assert finding.context["creating_evidence"][0]["evidence_file"] == "powershell.json"

    def test_script_command_in_another_statement_is_not_a_creation(self):
        f = Factory()
        build(f, ps_process=False, creating=False, snapshot=None, group_offset=5)
        f.script(172, 777, command="net localgroup Administrators svc_new /add; net user x",
                 user="ahmed")
        [finding] = acct(f.run())
        assert finding.confidence is Confidence.LOW         # nothing corroborates

    def test_creation_patterns_are_configurable(self):
        f = Factory()
        build(f, brute=False, creating_command="addacct.exe svc_new")
        assert not acct(f.run())
        assert acct(f.run(config(creation_command_patterns=(r"addacct\.exe",))))

    def test_running_only_this_rule_reports_the_missing_context_as_gaps(self):
        f = Factory()
        build(f, group_offset=5)
        result = f.run(rule_ids=["DET-003"])
        assert acct(result) == []
        text = gaps(result)
        assert "DET-001 was not run" in text and "DET-002 was not run" in text

    def test_chain_context_still_works_without_the_brute_force_rule(self):
        f = Factory()
        build(f)
        result = f.run(rule_ids=["DET-002", "DET-003"])
        [finding] = acct(result)
        assert finding.context["context_indicators_matched"] == [
            "process_chain_linked_to_powershell_finding"]
        assert "DET-001 was not run" in gaps(result)


# --------------------------------------------------------- missing data
class TestMissingData:
    def test_missing_target_name_is_a_gap(self):
        f = Factory()
        f.account(0, target=None)
        result = f.run()
        assert acct(result) == []
        assert "no target account name" in gaps(result)

    def test_missing_actor_is_a_gap_and_blocks_actor_based_context(self):
        f = Factory()
        build(f, actor=None, creating_user="ahmed", ps_user="ahmed", group_offset=5)
        result = f.run()
        assert acct(result) == []
        assert "no acting user" in gaps(result)

    def test_unknown_actor_can_still_be_reported_when_context_is_not_required(self):
        f = Factory()
        build(f, actor=None, creating_user="ahmed", ps_user="ahmed", group_offset=5)
        [finding] = acct(f.run(config(min_context_indicators=0)))
        assert finding.user is None and finding.context["actor"] is None
        assert "unknown user" in finding.description

    def test_no_account_creation_events_is_a_clean_negative(self):
        f = Factory()
        f.logon(0)
        result = f.run()
        assert acct(result) == []
        assert summary_of(result, "DET-003").events_considered == 0
        assert summary_of(result, "DET-003").data_gaps == []


class TestMultipleCreations:
    def test_each_creation_is_evaluated_separately(self):
        f = Factory()
        build(f, brute=False, ps_process=False, creating=False, group_offset=5,
              snapshot=None, target="first_acct", member="first_acct")
        build(f, brute=False, ps_process=False, creating=False, group_offset=5,
              snapshot=None, target="second_acct", member="second_acct", creation_t=2000)
        first, second = acct(f.run(config(min_context_indicators=0)))
        assert (first.context["target_account"], second.context["target_account"]) == (
            "first_acct", "second_acct")
        assert not set(first.supporting_events) & set(second.supporting_events)
        assert (first.finding_id, second.finding_id) == ("F-001", "F-002")


class TestMalformedProcessTrees:
    def test_a_process_that_is_its_own_parent_terminates_and_links_nothing(self):
        f = Factory()
        build(f, brute=False, ps_process=False, creating_ppid=600)    # pid 600, ppid 600
        result = f.run()
        assert acct(result) == []

    def test_a_parent_child_cycle_terminates(self):
        f = Factory()
        build(f, brute=False, ps_process=False, creating_ppid=610)
        # 610's parent is the creating process 600, and both start at the same time
        f.process(200, 610, name="cmd.exe", command_line="cmd.exe", user="ahmed",
                  parent="x.exe", ppid=600)
        assert acct(f.run()) == []                          # finishes; no PowerShell finding
