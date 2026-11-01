"""Synthetic findings, IOCs and contexts for the Phase 7 mapping tests.

The shapes mirror what the real DET-001/002/003 rules produce
(``matched_indicators`` entries, ``context`` keys, ``correlated_records``), so
mapping rules can be tested one condition at a time without running the
earlier phases. Nothing here is real data.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from security.models.schemas import IOC, Confidence, DetectionResult, Finding, IocResult, Severity

NOW = datetime(2026, 10, 9, 12, 0, 0, tzinfo=timezone.utc)
SEEN = datetime(2026, 10, 8, 7, 30, 0, tzinfo=timezone.utc)


def indicator(
    name: str,
    event_id: str = "E-00001",
    evidence_id: str = "PROC-0001",
    field: str = "command_line",
    evidence_file: str = "processes.json",
    **extra: Any,
) -> dict[str, Any]:
    return {
        "indicator": name,
        "description": "d",
        "matched_text": "x",
        "field": field,
        "event_id": event_id,
        "evidence_id": evidence_id,
        "evidence_file": evidence_file,
        **extra,
    }


def finding(
    finding_id: str = "F-001",
    rule_id: str = "DET-002",
    confidence: str = "High",
    indicators: tuple = (),
    context: Optional[dict] = None,
    events: tuple = ("E-00001",),
    records: tuple = ("PROC-0001",),
    user: str = "ahmed",
    device: str = "PC-1",
    iocs: tuple = (),
) -> Finding:
    return Finding(
        finding_id=finding_id,
        rule_id=rule_id,
        title="t",
        severity=Severity.MEDIUM,
        confidence=Confidence(confidence),
        device=device,
        user=user,
        description="d",
        reason="r",
        detected_at=NOW,
        first_seen=SEEN,
        last_seen=SEEN,
        supporting_events=list(events),
        evidence_sources=list(records),
        iocs=list(iocs),
        matched_indicators=list(indicators),
        context={} if context is None else context,
    )


def detection(*findings: Finding, case_id: str = "C-1") -> DetectionResult:
    return DetectionResult(
        case_id=case_id, generated_at=NOW, event_count=0, config={}, findings=list(findings)
    )


def ioc(
    ioc_id: str,
    ioc_type: str,
    value: str,
    related: tuple,
    files: tuple = ("processes.json",),
    roles: Optional[list] = None,
    event_id: str = "E-00001",
) -> IOC:
    attributes = {"roles": roles} if roles is not None else {}
    return IOC(
        ioc_id=ioc_id,
        type=ioc_type,
        value=value,
        source=files[0],
        evidence_id="PROC-0001",
        timestamp=SEEN,
        context="c",
        related_findings=list(related),
        first_seen=SEEN,
        last_seen=SEEN,
        attributes=attributes,
        occurrences=[
            {
                "event_id": event_id,
                "evidence_id": "PROC-0001",
                "evidence_file": f,
                "field": "x",
                "timestamp": "t",
                "context": "c",
            }
            for f in files
        ],
    )


def ioc_result(iocs: list, findings: list, case_id: str = "C-1") -> IocResult:
    return IocResult(case_id=case_id, iocs=list(iocs), findings=list(findings))


# ---- contexts shaped like the real rules' output --------------------------------
def bf_context(
    count: int = 6,
    threshold: int = 5,
    reasons: Any = "default",
    source_ip: str = "198.51.100.23",
    account: str = "ahmed",
    success_event: Optional[str] = None,
) -> dict[str, Any]:
    context: dict[str, Any] = {
        "grouping": {"device": "PC-1", "target_account": account, "source_ip": source_ip},
        "threshold": threshold,
        "window_seconds": 120,
        "failure_count": count,
        "successful_logon_event_id": success_event,
    }
    if reasons == "default":
        reasons = {"wrong password": count}
    if reasons is not None:
        context["failure_reasons"] = reasons
    return context


def ps_context(
    pid: int = 500,
    process_event: Optional[str] = "E-00001",
    script_records: int = 1,
    correlated: Optional[list] = "default",
) -> dict[str, Any]:
    if correlated == "default":
        correlated = (
            [{"link": "powershell_record", "event_id": "E-00002", "evidence_id": "PS-0001"}]
            if script_records
            else []
        )
    return {
        "process": {"pid": pid, "process_event_id": process_event, "parent_name": "explorer.exe"},
        "powershell_records_in_context": script_records,
        "correlated_records": correlated,
    }


def acct_context(
    actor: Optional[str] = "ahmed",
    target: str = "svc_new",
    target_domain: Any = "PC-1",
    context_indicators: Any = "default",
    creating: Any = "default",
    creation_event: Optional[str] = "E-00010",
) -> dict[str, Any]:
    if context_indicators == "default":
        context_indicators = ["process_chain_linked_to_powershell_finding"]
    if creating == "default":
        creating = [{"event_id": "E-00009", "evidence_id": "PROC-0009"}]
    context: dict[str, Any] = {
        "actor": actor,
        "target_account": target,
        "target_domain": target_domain,
        "device": "PC-1",
        "creation_event_id": creation_event,
        "privileged_target": "yes",
    }
    if context_indicators is not None:
        context["context_indicators_matched"] = context_indicators
    if creating is not None:
        context["creating_evidence"] = creating
    return context
