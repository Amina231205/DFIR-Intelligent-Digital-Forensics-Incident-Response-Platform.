"""Plain-text rendering of a timeline (ASCII only, safe on any console)."""

from __future__ import annotations

from typing import Optional

from security.models.schemas import Timeline
from security.utils.helpers import format_timestamp


def format_gap(seconds: Optional[float]) -> str:
    """Compact gap since the previous event: -, +13s, +1m05s, +1h02m, +1d01h."""
    if seconds is None:
        return "-"
    if seconds < 60:
        return f"+{seconds:g}s"
    total = int(round(seconds))
    days, rest = divmod(total, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    if days:
        return f"+{days}d{hours:02d}h"
    if hours:
        return f"+{hours}h{minutes:02d}m"
    return f"+{minutes}m{secs:02d}s"


def format_timeline(timeline: Timeline, limit: int = 0) -> str:
    """Render header, counts and one line per entry (``limit`` 0 = all)."""
    lines = [
        f"Case ID  : {timeline.case_id or '-'}",
        f"Devices  : {', '.join(timeline.devices) or '-'}",
        f"Users    : {', '.join(timeline.users) or '-'}",
        f"Range    : {format_timestamp(timeline.start) if timeline.start else '-'}"
        f"  to  {format_timestamp(timeline.end) if timeline.end else '-'}"
        f"  ({format_gap(timeline.duration_seconds).lstrip('+') if timeline.start else '-'})",
        f"Events   : {timeline.event_count}",
    ]
    if timeline.counts_by_type:
        lines.append("By type  : " + ", ".join(
            f"{name}={count}" for name, count in timeline.counts_by_type.items()))
    if not timeline.entries:
        return "\n".join([*lines, "", "No events in this timeline."])

    shown = timeline.entries if limit == 0 else timeline.entries[:limit]
    width = max(3, len(str(timeline.event_count)))
    multi_device = len(timeline.devices) > 1
    lines += ["", (f"{'seq':>{width}}  {'event':<7}  {'timestamp (UTC)':<20}  "
                   f"{'gap':>8}  {'type':<19}  {'evidence':<10}  {'user':<12}  summary")]
    for e in shown:
        device = f"[{e.device}] " if multi_device else ""
        lines.append(
            f"{e.sequence:>{width}}  {e.event_id}  {format_timestamp(e.timestamp)}  "
            f"{format_gap(e.gap_from_previous_seconds):>8}  {e.event_type.value:<19}  "
            f"{e.evidence_id:<10}  {e.user or '-':<12}  {device}{e.summary}")
    if len(shown) < len(timeline.entries):
        lines.append(f"... {len(timeline.entries) - len(shown)} more "
                     "(use --limit 0 to show all)")
    return "\n".join(lines)
