"""DET-003: suspicious account creation.

Creating an account is routine administration. This rule raises a finding for
an ``account_created`` event (Windows 4720) only when its configured criteria
are met. ACTOR and TARGET are kept apart everywhere:

* actor  = the account that performed the creation (event ``user``,
  Windows ``SubjectUserName``) -> ``Finding.user``
* target = the account that was created (``details.target_user``, Windows
  ``TargetUserName``) -> ``Finding.context["target_account"]``

DEFAULT CRITERIA (``require_privileged_target`` and ``min_context_indicators``)
------------------------------------------------------------------------------
1. PRIVILEGED TARGET - the new account is privileged, shown by either
   * a ``group_member_added`` event on the same device whose member is the
     target and whose group is in ``privileged_groups``, within
     ``group_add_window_seconds`` AFTER the creation; or
   * the users.json snapshot (``target_user_context``) saying ``is_admin``.
   Answer is yes / no / unknown: "unknown" (target missing from users.json and
   no group event) is a data gap, never silently "no".
2. at least ``min_context_indicators`` (default 1) of two SURROUNDING-ACTIVITY
   indicators, each requiring an exact link:
   * process_chain_linked_to_powershell_finding: the process that ran the
     creation command (same device, same actor, started at most
     ``creating_process_window_seconds`` before the event, command line naming
     the target and matching ``creation_command_patterns``) has an ancestor
     (``ppid`` -> ``pid`` links, bounded by ``ancestry_window_seconds`` and
     ``max_ancestry_depth``) that is part of a DET-002 finding.
   * actor_account_targeted_by_bruteforce: a DET-001 finding on the same
     device, for an account with the actor's name, was followed by a successful
     logon that happened before the creation, at most ``context_window_seconds``
     earlier. This link is ACCOUNT-LEVEL: the normalized events carry no
     logon-session id, so it cannot prove the creation ran in that session.

Both indicators need earlier rules' findings, so DET-001 and DET-002 must run
first (the default order). If the needed data or rule is absent, the indicator
is reported as a data gap, not as a negative result.
"""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any, Optional

from security.detection.base import (
    Rule, RuleContext, RuleOutput, build_finding, raise_severity, snippet,
    users_compatible)
from security.detection.config import AccountCreationConfig
from security.models.schemas import (
    Confidence, EventType, Finding, NormalizedEvent, Severity)
from security.utils.helpers import format_timestamp, parse_timestamp

CONTEXT_INDICATORS = (
    "process_chain_linked_to_powershell_finding",
    "actor_account_targeted_by_bruteforce",
)


def _same(first: Optional[str], second: Optional[str]) -> bool:
    return bool(first and second and first.casefold() == second.casefold())


class AccountCreationRule(Rule):
    rule_id = "DET-003"
    name = "Suspicious Account Creation"

    def __init__(self, config: Optional[AccountCreationConfig] = None) -> None:
        self.config = config or AccountCreationConfig()
        self._patterns = [re.compile(p) for p in self.config.creation_command_patterns]

    def evaluate(self, context: RuleContext) -> RuleOutput:
        events = context.events
        creations = [e for e in events if e.event_type is EventType.ACCOUNT_CREATED]
        gaps: set[str] = set()
        findings: list[Finding] = []
        for creation in creations:
            finding = self._evaluate_creation(context, creation, gaps)
            if finding is not None:
                findings.append(finding)
        findings.sort(key=lambda f: (f.first_seen, f.supporting_events))
        return RuleOutput(findings, len(creations), sorted(gaps))

    # ------------------------------------------------------------------
    def _evaluate_creation(self, context: RuleContext, creation: NormalizedEvent,
                           gaps: set[str]) -> Optional[Finding]:
        cfg = self.config
        actor = creation.user
        target = creation.details.get("target_user")
        ref = creation.evidence_id
        if not target:
            gaps.add(f"{ref}: account creation event has no target account name; "
                     "it was not evaluated")
            return None
        if not actor:
            gaps.add(f"{ref}: account creation event has no acting user, so the "
                     "creating process and account context cannot be linked")

        privileged, basis, group_events, snapshot = self._privileged(
            context, creation, target, gaps)
        creating, creating_scripts = self._creating_evidence(
            context, creation, actor, target, gaps)
        chain_links = self._process_chain(context, creation, creating, gaps)
        brute_links = self._bruteforce_link(context, creation, actor, gaps)

        indicators_matched = [name for name, links in zip(
            CONTEXT_INDICATORS, (chain_links, brute_links)) if links]
        privileged_ok = privileged == "yes" or not cfg.require_privileged_target
        if not privileged_ok or len(indicators_matched) < cfg.min_context_indicators:
            return None
        return self._build(context, creation, actor, target, privileged, basis,
                           group_events, snapshot, creating, creating_scripts,
                           chain_links, brute_links, indicators_matched)

    # -------------------------------------------------- criterion 1
    def _privileged(self, context: RuleContext, creation: NormalizedEvent, target: str,
                    gaps: set[str]):
        cfg = self.config
        window = timedelta(seconds=cfg.group_add_window_seconds)
        group_events = [
            e for e in context.events
            if e.event_type is EventType.GROUP_MEMBER_ADDED
            and e.device.casefold() == creation.device.casefold()
            and _same(e.details.get("member_name"), target)
            and (e.details.get("group") or "").casefold() in cfg.privileged_groups
            and timedelta(0) <= e.timestamp - creation.timestamp <= window]
        snapshot = creation.details.get("target_user_context")
        basis: list[str] = []
        if group_events:
            basis.append("group_membership_event")
        if snapshot and snapshot.get("is_admin") is True:
            basis.append("users_snapshot")
        if basis:
            return "yes", basis, group_events, snapshot
        if snapshot is not None:
            return "no", [], group_events, snapshot
        gaps.add(f"{creation.evidence_id}: target account '{target}' is not in users.json "
                 "and no privileged-group membership event followed, so its privilege "
                 "level could not be determined")
        return "unknown", [], group_events, snapshot

    # -------------------------------------------------- creating process / script
    def _creating_evidence(self, context: RuleContext, creation: NormalizedEvent,
                           actor: Optional[str], target: str, gaps: set[str]):
        cfg = self.config
        if not actor:
            return [], []
        window = timedelta(seconds=cfg.creating_process_window_seconds)
        target_re = re.compile(rf"(?<![\w.-]){re.escape(target)}(?![\w.-])", re.IGNORECASE)

        def in_window(event: NormalizedEvent) -> bool:
            return (event.device.casefold() == creation.device.casefold()
                    and _same(event.user, actor)
                    and timedelta(0) <= creation.timestamp - event.timestamp <= window)

        def matches(text: Any) -> bool:
            return (isinstance(text, str) and bool(target_re.search(text))
                    and any(p.search(text) for p in self._patterns))

        processes, scripts, no_command = [], [], []
        for event in context.events:
            if event.event_type is EventType.PROCESS_CREATED and in_window(event):
                command = event.details.get("command_line")
                if not (isinstance(command, str) and command.strip()):
                    no_command.append(event.evidence_id)
                elif matches(command):
                    processes.append(event)
            elif event.event_type is EventType.POWERSHELL_EXECUTED and in_window(event):
                if matches(event.details.get("command")):
                    scripts.append(event)
        if no_command and not processes:
            gaps.add(f"{creation.evidence_id}: process record(s) {', '.join(no_command)} "
                     "in the creating window have no command line and could not be "
                     "checked as the creating process")
        return processes, scripts

    # -------------------------------------------------- context indicator 1
    def _process_chain(self, context: RuleContext, creation: NormalizedEvent,
                       creating: list[NormalizedEvent], gaps: set[str]):
        cfg = self.config
        if "DET-002" not in context.rules_run:
            gaps.add(f"{creation.evidence_id}: DET-002 was not run, so the process-chain "
                     "context could not be evaluated")
            return []
        if not creating:
            gaps.add(f"{creation.evidence_id}: no creating process identified (same "
                     "device and actor, command line naming the target, within "
                     f"{cfg.creating_process_window_seconds} s before the event), so the "
                     "process-chain context could not be evaluated")
            return []
        processes = [e for e in context.events if e.event_type is EventType.PROCESS_CREATED]
        window = timedelta(seconds=cfg.ancestry_window_seconds)
        checked: dict[str, NormalizedEvent] = {e.event_id: e for e in creating}
        for start in creating:
            current = start
            for _ in range(cfg.max_ancestry_depth):
                parents = [
                    q for q in processes
                    if q.device.casefold() == current.device.casefold()
                    and q.details.get("pid") == current.details.get("ppid")
                    and q.event_id != current.event_id
                    and q.timestamp <= current.timestamp
                    and current.timestamp - q.timestamp <= window
                    and users_compatible(q.user, current.user)]
                if not parents or current.details.get("ppid") is None:
                    break
                current = parents[-1]          # most recent start of that PID
                checked[current.event_id] = current
        links = []
        for finding in context.prior_findings:
            if (finding.rule_id == "DET-002"
                    and finding.device.casefold() == creation.device.casefold()):
                hit = sorted(set(finding.supporting_events) & set(checked))
                if hit:
                    links.append({"finding": finding, "linked_process_events":
                                  [checked[i] for i in hit], "chain": list(checked.values())})
        return links

    # -------------------------------------------------- context indicator 2
    def _bruteforce_link(self, context: RuleContext, creation: NormalizedEvent,
                         actor: Optional[str], gaps: set[str]):
        cfg = self.config
        if "DET-001" not in context.rules_run:
            gaps.add(f"{creation.evidence_id}: DET-001 was not run, so the brute-force "
                     "context could not be evaluated")
            return []
        if not actor:
            return []
        by_id = {e.event_id: e for e in context.events}
        links = []
        for finding in context.prior_findings:
            if (finding.rule_id != "DET-001"
                    or finding.device.casefold() != creation.device.casefold()
                    or not _same(finding.user, actor)):
                continue
            success = by_id.get(finding.context.get("successful_logon_event_id") or "")
            if success is None:
                continue
            gap = creation.timestamp - success.timestamp
            if timedelta(0) <= gap <= timedelta(seconds=cfg.context_window_seconds):
                links.append({"finding": finding, "success": success,
                              "seconds_before_creation": round(gap.total_seconds(), 6)})
        return links

    # -------------------------------------------------- finding assembly
    def _build(self, context: RuleContext, creation: NormalizedEvent,
               actor: Optional[str], target: str, privileged: str, basis: list[str],
               group_events: list[NormalizedEvent], snapshot: Optional[dict],
               creating: list[NormalizedEvent], creating_scripts: list[NormalizedEvent],
               chain_links: list[dict], brute_links: list[dict],
               indicators_matched: list[str]) -> Finding:
        cfg = self.config
        indicators: list[dict[str, Any]] = []
        for event in group_events:
            indicators.append({
                "indicator": "privileged_target", "basis": "group_membership_event",
                "description": "new account was added to a privileged group after creation",
                "group": event.details.get("group"), "event_id": event.event_id,
                "evidence_id": event.evidence_id, "evidence_file": event.evidence_file,
                "seconds_after_creation": round(
                    (event.timestamp - creation.timestamp).total_seconds(), 6)})
        if "users_snapshot" in basis and snapshot:
            indicators.append({
                "indicator": "privileged_target", "basis": "users_snapshot",
                "description": "users.json lists the new account as an administrator",
                "evidence_id": snapshot.get("evidence_id"), "evidence_file": "users.json",
                "is_admin": True, "groups": snapshot.get("groups")})
        supporting: list[NormalizedEvent] = [creation, *group_events, *creating,
                                             *creating_scripts]
        for link in chain_links:
            finding: Finding = link["finding"]
            supporting += link["chain"]
            indicators.append({
                "indicator": "process_chain_linked_to_powershell_finding",
                "description": "the process that created the account descends from a "
                               "process in a PowerShell finding",
                "finding_id": finding.finding_id, "rule_id": finding.rule_id,
                "linked_process_event_ids": [e.event_id for e in link["linked_process_events"]],
                "linked_process_evidence_ids": [
                    e.evidence_id for e in link["linked_process_events"]],
                "link_basis": "ppid -> pid, same device, bounded time window"})
        for link in brute_links:
            supporting.append(link["success"])
            indicators.append({
                "indicator": "actor_account_targeted_by_bruteforce",
                "description": "the acting account had a brute-force finding followed by "
                               "a successful logon before the creation",
                "finding_id": link["finding"].finding_id, "rule_id": "DET-001",
                "successful_logon_event_id": link["success"].event_id,
                "seconds_before_creation": link["seconds_before_creation"],
                "link_strength": "account-level (no logon-session id is available)"})

        # severity: Low + 1 for a privileged target + 1 per context indicator, cap High
        steps = (1 if privileged == "yes" else 0) + len(indicators_matched)
        severity = raise_severity(Severity.LOW, steps)
        severity_factors = ["base level for an account creation: Low"]
        if privileged == "yes":
            severity_factors.append("+1: the new account is privileged ("
                                    + " and ".join(basis).replace("_", " ") + ")")
        severity_factors += [f"+1: {name}" for name in indicators_matched]

        # confidence: how well the stated conditions are corroborated
        extra: list[tuple[str, str]] = []
        corroboration: list[str] = []
        snapshot_consistent: Optional[bool] = None
        if snapshot is not None:
            extra.append((snapshot["evidence_id"], "users.json"))
            try:
                delta = abs((parse_timestamp(snapshot["created_at"])
                             - creation.timestamp).total_seconds())
                snapshot_consistent = delta <= cfg.snapshot_tolerance_seconds
            except (KeyError, ValueError):
                snapshot_consistent = False
            if snapshot_consistent:
                corroboration.append(
                    f"users.json {snapshot['evidence_id']} created_at matches the event "
                    f"(within {cfg.snapshot_tolerance_seconds} s)")
        if creating or creating_scripts:
            corroboration.append("a process/script record shows the creation command "
                                 "naming the target account")
        if corroboration:
            confidence = Confidence.HIGH
            confidence_factors = ["direct 4720 event: Medium"] + [
                f"raised to High: independent corroboration - {c}" for c in corroboration]
        elif indicators_matched == ["actor_account_targeted_by_bruteforce"]:
            confidence = Confidence.LOW
            confidence_factors = [
                "lowered to Low: the only context is the account-level brute-force link "
                "and nothing independent corroborates the creation"]
        else:
            confidence = Confidence.MEDIUM
            confidence_factors = ["direct 4720 event, no independent corroboration: Medium"]

        ctx: dict[str, Any] = {
            "actor": actor,
            "target_account": target,
            "target_domain": creation.details.get("target_domain"),
            "target_sid": creation.details.get("target_sid"),
            "device": creation.device,
            "creation_event_id": creation.event_id,
            "privileged_target": privileged,
            "privileged_basis": basis,
            "creating_evidence": [
                {"event_id": e.event_id, "evidence_id": e.evidence_id,
                 "evidence_file": e.evidence_file,
                 "command": snippet(e.details.get("command_line")
                                    or e.details.get("command") or "", 100)}
                for e in sorted([*creating, *creating_scripts], key=lambda e: e.event_id)],
            "linked_findings": {
                "powershell": sorted(link["finding"].finding_id for link in chain_links),
                "brute_force": sorted(link["finding"].finding_id for link in brute_links)},
            "context_indicators_matched": indicators_matched,
            "min_context_indicators": cfg.min_context_indicators,
            "require_privileged_target": cfg.require_privileged_target,
            "snapshot_created_at_consistent": snapshot_consistent,
            "target_enabled": (snapshot or {}).get("enabled"),
        }
        description = (
            f"Account '{target}' was created on {creation.device} at "
            f"{format_timestamp(creation.timestamp)} by '{actor or 'an unknown user'}'. "
            f"Privileged target: {privileged}. Context indicators matched: "
            f"{', '.join(indicators_matched) or 'none'}.")
        reason = (
            f"Account creation by '{actor or 'unknown'}' of '{target}': privileged target = "
            f"{privileged}; {len(indicators_matched)} context indicator(s) matched "
            f"(minimum {cfg.min_context_indicators}): "
            f"{', '.join(indicators_matched) or 'none'}.")
        return build_finding(
            self, context, severity=severity, confidence=confidence,
            device=creation.device, user=actor, description=description, reason=reason,
            supporting=supporting, matched_indicators=indicators, finding_context=ctx,
            severity_factors=severity_factors, confidence_factors=confidence_factors,
            extra_evidence=extra)
