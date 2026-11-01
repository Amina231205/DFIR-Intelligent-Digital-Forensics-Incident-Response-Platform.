"""Plain-text rendering of an IocResult (ASCII only, safe on any console)."""

from __future__ import annotations

from security.detection.report import ascii_safe
from security.models.schemas import IOC, IocResult, IOCType


def _attribute_line(ioc: IOC) -> str:
    a = ioc.attributes
    if ioc.type is IOCType.IP:
        external = {True: "yes", False: "no", None: "unknown"}[a.get("external")]
        return f"class={a.get('ip_class')}, external by policy={external}"
    if ioc.type is IOCType.DOMAIN:
        return "reserved for documentation (RFC 2606)" if a.get("reserved_for_documentation") \
            else "domain name"
    if ioc.type is IOCType.URL:
        note = ", credentials removed" if a.get("credentials_removed") else ""
        return f"host={a.get('host')} ({a.get('host_type')}){note}"
    if ioc.type is IOCType.FILENAME:
        return "path: " + "; ".join(a.get("paths", []))
    if ioc.type is IOCType.HASH:
        paths = "; ".join(a.get("file_paths", [])) or "no path"
        return f"{a.get('algorithm')} of {paths}"
    if ioc.type is IOCType.PROCESS:
        return a.get("basis", "")
    return "roles: " + "; ".join(a.get("roles", []))


def format_iocs(result: IocResult) -> str:
    """Render IOCs, the findings they relate to, and data gaps as ASCII text."""
    counts = ", ".join(f"{name}={count}" for name, count in sorted(result.counts_by_type.items()))
    lines = [f"Case ID : {result.case_id or '-'}",
             f"IOCs    : {len(result.iocs)}" + (f" ({counts})" if counts else "")]
    for ioc in result.iocs:
        first = ioc.occurrences[0] if ioc.occurrences else {}
        lines += [
            "",
            f"{ioc.ioc_id}  {ioc.type.value:<9} {ioc.value}",
            f"    {_attribute_line(ioc)}",
            f"    findings: {', '.join(ioc.related_findings) or '-'}   "
            f"occurrences: {len(ioc.occurrences)}",
            f"    first: {ioc.source} {ioc.evidence_id} ({first.get('field', '-')}): {ioc.context}",
        ]
    if not result.iocs:
        lines += ["", "No IOCs. (Only evidence cited by findings is examined; check the "
                      "data gaps below.)"]
    linked = [f for f in result.findings if f.iocs]
    if linked:
        lines += ["", "Findings -> IOCs:"]
        lines += [f"  {f.finding_id}: {', '.join(f.iocs)}" for f in linked]
    if result.data_gaps:
        lines += ["", "Data gaps (values that could not be extracted; not negative results):"]
        lines += [f"  - {gap}" for gap in result.data_gaps]
    return ascii_safe("\n".join(lines))
