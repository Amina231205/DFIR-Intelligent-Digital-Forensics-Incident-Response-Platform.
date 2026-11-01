"""Framework-free SQLite storage service for Sentinel DFIR.

All writes are transactional and parameterized. The optional authorization hook
is an integration seam, not authentication: production callers must supply a
policy that checks the current principal before allowing access.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Callable, Optional, Union

from security.models.schemas import InvestigationResult, to_plain


class StorageError(RuntimeError):
    """Base exception for storage failures."""


class StorageValidationError(StorageError, ValueError):
    """Invalid case identifier or payload."""


class CaseNotFoundError(StorageError, LookupError):
    """Requested case does not exist."""


AuthorizationHook = Callable[[str, str], bool]
_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


_SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    device TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS timeline_events (
    case_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_timestamp TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (case_id, event_id),
    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS findings (
    case_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (case_id, finding_id),
    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS iocs (
    case_id TEXT NOT NULL,
    ioc_id TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (case_id, ioc_id),
    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS mitre_mappings (
    case_id TEXT NOT NULL,
    mapping_id TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (case_id, mapping_id),
    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS finding_iocs (
    case_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    ioc_id TEXT NOT NULL,
    PRIMARY KEY (case_id, finding_id, ioc_id),
    FOREIGN KEY (case_id, finding_id) REFERENCES findings(case_id, finding_id) ON DELETE CASCADE,
    FOREIGN KEY (case_id, ioc_id) REFERENCES iocs(case_id, ioc_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS finding_mappings (
    case_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    mapping_id TEXT NOT NULL,
    PRIMARY KEY (case_id, finding_id, mapping_id),
    FOREIGN KEY (case_id, finding_id) REFERENCES findings(case_id, finding_id) ON DELETE CASCADE,
    FOREIGN KEY (case_id, mapping_id) REFERENCES mitre_mappings(case_id, mapping_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_timeline_case_time ON timeline_events(case_id, event_timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_case_severity ON findings(case_id, severity);
CREATE INDEX IF NOT EXISTS idx_iocs_case_value ON iocs(case_id, value);
"""


def _case_id(value: Any) -> str:
    if not isinstance(value, str) or not _CASE_ID.fullmatch(value):
        raise StorageValidationError(
            "case_id must be 1-128 characters, start with a letter/number, "
            "and contain only letters, numbers, dot, underscore, or hyphen"
        )
    return value


def _connect(db_path: Union[str, Path]) -> sqlite3.Connection:
    path = Path(db_path)
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    conn.executescript(_SCHEMA)
    return conn


def _authorize(hook: Optional[AuthorizationHook], action: str, case_id: str) -> None:
    if hook is not None and hook(action, case_id) is not True:
        raise PermissionError(f"Not authorized to {action} case {case_id!r}")


def _canonical_payload(result: InvestigationResult) -> tuple[dict[str, Any], str]:
    payload = to_plain(result)
    if not isinstance(payload, dict):
        raise StorageValidationError("InvestigationResult did not serialize to an object")
    # Analysis wall-clock values are intentionally excluded from the idempotency
    # fingerprint. Evidence timestamps remain part of the fingerprint.
    fingerprint_payload = json.loads(json.dumps(payload, sort_keys=True, ensure_ascii=False))
    fingerprint_payload.pop("generated_at", None)
    for finding in fingerprint_payload.get("findings", []):
        if isinstance(finding, dict):
            finding.pop("detected_at", None)
    canonical = json.dumps(
        fingerprint_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return payload, digest


def save_investigation(
    db_path: Union[str, Path],
    result: InvestigationResult,
    *,
    authorize: Optional[AuthorizationHook] = None,
) -> dict[str, str]:
    """Persist an investigation atomically; return status created/replaced/unchanged."""
    if not isinstance(result, InvestigationResult):
        raise StorageValidationError("result must be an InvestigationResult")
    case_id = _case_id(result.incident_id)
    if not result.device:
        raise StorageValidationError("device must not be empty")
    _authorize(authorize, "write", case_id)
    payload, digest = _canonical_payload(result)
    payload_json = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    conn = _connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            "SELECT content_hash FROM cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        if existing and existing["content_hash"] == digest:
            conn.commit()
            return {"status": "unchanged", "case_id": case_id, "content_hash": digest}
        status = "created" if existing is None else "replaced"
        if existing:
            conn.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
        conn.execute(
            "INSERT INTO cases(case_id, device, generated_at, content_hash, payload_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (case_id, result.device, str(payload.get("generated_at", "")), digest, payload_json),
        )
        for event in payload.get("timeline", []):
            conn.execute(
                "INSERT INTO timeline_events(case_id,event_id,event_timestamp,evidence_id,payload_json) "
                "VALUES(?,?,?,?,?)",
                (case_id, event["event_id"], str(event["timestamp"]), event["evidence_id"],
                 json.dumps(event, sort_keys=True, ensure_ascii=False)),
            )
        for finding in payload.get("findings", []):
            fid = finding["finding_id"]
            conn.execute(
                "INSERT INTO findings(case_id,finding_id,severity,rule_id,payload_json) VALUES(?,?,?,?,?)",
                (case_id, fid, str(finding["severity"]), finding["rule_id"],
                 json.dumps(finding, sort_keys=True, ensure_ascii=False)),
            )
        for ioc in payload.get("iocs", []):
            conn.execute(
                "INSERT INTO iocs(case_id,ioc_id,ioc_type,value,payload_json) VALUES(?,?,?,?,?)",
                (case_id, ioc["ioc_id"], str(ioc["type"]), ioc["value"],
                 json.dumps(ioc, sort_keys=True, ensure_ascii=False)),
            )
        for index, mapping in enumerate(payload.get("mitre_mappings", [])):
            mid = mapping.get("mapping_id") or f"{mapping.get('technique_id','technique')}-{index}"
            conn.execute(
                "INSERT INTO mitre_mappings(case_id,mapping_id,technique_id,payload_json) VALUES(?,?,?,?)",
                (case_id, mid, mapping["technique_id"],
                 json.dumps(mapping, sort_keys=True, ensure_ascii=False)),
            )
        for finding in payload.get("findings", []):
            fid = finding["finding_id"]
            for ioc_id in sorted(set(finding.get("iocs", []))):
                if conn.execute(
                    "SELECT 1 FROM iocs WHERE case_id=? AND ioc_id=?", (case_id, ioc_id)
                ).fetchone():
                    conn.execute(
                        "INSERT OR IGNORE INTO finding_iocs(case_id,finding_id,ioc_id) VALUES(?,?,?)",
                        (case_id, fid, ioc_id),
                    )
            for mapping_id in sorted(set(finding.get("mitre_techniques", []))):
                matching = conn.execute(
                    "SELECT mapping_id FROM mitre_mappings WHERE case_id=? AND technique_id=?",
                    (case_id, mapping_id),
                ).fetchall()
                for row in matching:
                    conn.execute(
                        "INSERT OR IGNORE INTO finding_mappings(case_id,finding_id,mapping_id) VALUES(?,?,?)",
                        (case_id, fid, row["mapping_id"]),
                    )
        conn.commit()
        return {"status": status, "case_id": case_id, "content_hash": digest}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_investigation(
    db_path: Union[str, Path],
    case_id: str,
    *,
    authorize: Optional[AuthorizationHook] = None,
) -> dict[str, Any]:
    """Return the saved JSON payload as a dictionary."""
    case_id = _case_id(case_id)
    _authorize(authorize, "read", case_id)
    conn = _connect(db_path)
    try:
        row = conn.execute("SELECT payload_json FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if row is None:
            raise CaseNotFoundError(f"Case {case_id!r} was not found")
        return json.loads(row["payload_json"])
    finally:
        conn.close()


def list_cases(
    db_path: Union[str, Path],
    *,
    authorize: Optional[AuthorizationHook] = None,
) -> list[dict[str, Any]]:
    """List stored case summaries, newest generated timestamp first."""
    _authorize(authorize, "list", "*")
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT case_id, device, generated_at, content_hash FROM cases "
            "ORDER BY generated_at DESC, case_id ASC"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def delete_case(
    db_path: Union[str, Path],
    case_id: str,
    *,
    authorize: Optional[AuthorizationHook] = None,
) -> bool:
    """Delete a case and its relational rows atomically."""
    case_id = _case_id(case_id)
    _authorize(authorize, "delete", case_id)
    conn = _connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute("DELETE FROM cases WHERE case_id=?", (case_id,))
        conn.commit()
        return cur.rowcount > 0
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
