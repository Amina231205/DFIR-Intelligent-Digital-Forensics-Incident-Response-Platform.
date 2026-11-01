"""Condition language used by ATT&CK mapping rules.

Mapping rules (``mappings.json``) are DATA. They describe, in a small closed
vocabulary, which evidence a finding must carry before a technique is mapped.
This module is the only code that interprets them; nothing in a rule file is
ever executed (no ``eval``, no format-string attribute access).

Three-valued logic: every condition evaluates to ``True``, ``False`` or
``None``. ``False`` is a NEGATIVE result (the evidence was examined and the
condition does not hold). ``None`` means UNKNOWN: the data needed to decide is
missing (e.g. a context key absent, or IOC input not provided). ``all`` is
False if any part is False, else None if any part is unknown, else True;
``any`` is True if any part is True, else None if any part is unknown, else
False; ``not`` keeps None.

Leaf checks (``{"check": NAME, ...}``):

indicator_present          indicator [, where{key: value}]  a matched indicator exists
indicator_in_decoded_text  [indicator]                      a match came from decoded text
context_equals             path, value                      finding.context[path] == value
context_not_null           path                             present and not null/blank
context_missing            path                             absent, null or blank
context_list_nonempty      path                             a non-empty list (absent -> unknown)
context_number_at_least    path, value                      number >= value
context_at_least_multiple  path, of, factor                 number >= factor * other number
context_share_at_least     path, key, min_share             counts[key] / sum(counts) >= min_share
context_equals_finding_field  path, field [, casefold]      context value == a finding field
ioc_related                type [, evidence_file, role_contains]   a related IOC exists
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Optional

from security.models.schemas import IOC, Finding

Tri = Optional[bool]
_MISSING = object()
_PLACEHOLDER = re.compile(r"\{([^{}]*)\}")
FINDING_FIELDS = ("finding_id", "rule_id", "title", "device", "user")
EVIDENCE_KINDS = ("finding", "indicator", "context_value", "context_records")


@dataclass
class Subject:
    """What a condition is evaluated on: one finding and its related IOCs.

    ``iocs`` is None when no IOC result was provided (unknown), and a list
    (possibly empty) of the IOCs related to the finding otherwise.
    """

    finding: Finding
    iocs: Optional[list[IOC]]


# ---------------------------------------------------------------- lookups
def lookup(context: Any, path: str) -> Any:
    """Dotted lookup in a nested dict; ``_MISSING`` when any step is absent."""
    current = context
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return _MISSING
    return current


def _blank(value: Any) -> bool:
    return value is _MISSING or value is None or (isinstance(value, str) and not value.strip())


def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def matching_indicators(finding: Finding, name: Optional[str],
                        where: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
    """Matched indicators of ``finding`` named ``name`` whose fields equal ``where``."""
    return [m for m in finding.matched_indicators
            if isinstance(m, dict)
            and (name is None or m.get("indicator") == name)
            and all(m.get(k) == v for k, v in (where or {}).items())]


# ------------------------------------------------------------- leaf checks
def _indicator_present(s: Subject, p: dict[str, Any]) -> tuple[Tri, str]:
    where = p.get("where") or {}
    found = bool(matching_indicators(s.finding, p["indicator"], where))
    extra = f" with {where}" if where else ""
    return found, f"indicator '{p['indicator']}'{extra} {'was' if found else 'was not'} matched"


def _indicator_in_decoded_text(s: Subject, p: dict[str, Any]) -> tuple[Tri, str]:
    found = any(str(m.get("field", "")).endswith("(decoded)")
                for m in matching_indicators(s.finding, p.get("indicator")))
    return found, ("a match came from decoded text" if found
                   else "no match came from decoded text")


def _context_equals(s: Subject, p: dict[str, Any]) -> tuple[Tri, str]:
    value = lookup(s.finding.context, p["path"])
    if value is _MISSING:
        return None, f"context.{p['path']} is missing"
    ok = value == p["value"]
    return ok, f"context.{p['path']} is {value!r}, expected {p['value']!r}"


def _context_not_null(s: Subject, p: dict[str, Any]) -> tuple[Tri, str]:
    ok = not _blank(lookup(s.finding.context, p["path"]))
    return ok, f"context.{p['path']} is {'present' if ok else 'missing or null'}"


def _context_missing(s: Subject, p: dict[str, Any]) -> tuple[Tri, str]:
    missing = _blank(lookup(s.finding.context, p["path"]))
    return missing, f"context.{p['path']} is {'missing or null' if missing else 'present'}"


def _context_list_nonempty(s: Subject, p: dict[str, Any]) -> tuple[Tri, str]:
    value = lookup(s.finding.context, p["path"])
    if value is _MISSING:
        return None, f"context.{p['path']} is missing"
    ok = isinstance(value, list) and len(value) > 0
    return ok, f"context.{p['path']} {'has entries' if ok else 'is empty or not a list'}"


def _context_number_at_least(s: Subject, p: dict[str, Any]) -> tuple[Tri, str]:
    value = lookup(s.finding.context, p["path"])
    if value is _MISSING:
        return None, f"context.{p['path']} is missing"
    number = _number(value)
    ok = number is not None and number >= p["value"]
    return ok, f"context.{p['path']} is {value!r}, needs at least {p['value']}"


def _context_at_least_multiple(s: Subject, p: dict[str, Any]) -> tuple[Tri, str]:
    value = lookup(s.finding.context, p["path"])
    other = lookup(s.finding.context, p["of"])
    if value is _MISSING or other is _MISSING:
        return None, f"context.{p['path']} or context.{p['of']} is missing"
    number, base = _number(value), _number(other)
    ok = number is not None and base is not None and number >= p["factor"] * base
    return ok, (f"context.{p['path']} is {value!r}, needs at least {p['factor']} x "
                f"context.{p['of']} ({other!r})")


def _context_share_at_least(s: Subject, p: dict[str, Any]) -> tuple[Tri, str]:
    counts = lookup(s.finding.context, p["path"])
    if counts is _MISSING:
        return None, f"context.{p['path']} is missing"
    if not isinstance(counts, dict):
        return False, f"context.{p['path']} is not a mapping of counts"
    numbers = [_number(v) for v in counts.values()]
    total = sum(n for n in numbers if n is not None)
    share = (_number(counts.get(p["key"])) or 0.0) / total if total > 0 else 0.0
    ok = share >= p["min_share"]
    return ok, (f"share of {p['key']!r} in context.{p['path']} is {share:.0%}, "
                f"needs at least {p['min_share']:.0%}")


def _context_equals_finding_field(s: Subject, p: dict[str, Any]) -> tuple[Tri, str]:
    value = lookup(s.finding.context, p["path"])
    if _blank(value):
        return None, f"context.{p['path']} is missing"
    other = getattr(s.finding, p["field"])
    left, right = str(value), "" if other is None else str(other)
    if p.get("casefold"):
        left, right = left.casefold(), right.casefold()
    ok = left == right
    return ok, f"context.{p['path']} is {value!r}; finding.{p['field']} is {other!r}"


def _ioc_related(s: Subject, p: dict[str, Any]) -> tuple[Tri, str]:
    if s.iocs is None:
        return None, "IOC input was not provided"
    wanted = {"types": [p["type"]]}
    wanted.update({k: p[k] for k in ("evidence_file", "role_contains") if k in p})
    ok = bool(select_iocs(wanted, s))
    return ok, f"a related '{p['type']}' IOC {'exists' if ok else 'was not found'}"


# name -> (required params, optional params, function)
CHECKS: dict[str, tuple[frozenset, frozenset, Callable[[Subject, dict], tuple[Tri, str]]]] = {
    "indicator_present": (frozenset({"indicator"}), frozenset({"where"}), _indicator_present),
    "indicator_in_decoded_text": (frozenset(), frozenset({"indicator"}),
                                  _indicator_in_decoded_text),
    "context_equals": (frozenset({"path", "value"}), frozenset(), _context_equals),
    "context_not_null": (frozenset({"path"}), frozenset(), _context_not_null),
    "context_missing": (frozenset({"path"}), frozenset(), _context_missing),
    "context_list_nonempty": (frozenset({"path"}), frozenset(), _context_list_nonempty),
    "context_number_at_least": (frozenset({"path", "value"}), frozenset(),
                                _context_number_at_least),
    "context_at_least_multiple": (frozenset({"path", "of", "factor"}), frozenset(),
                                  _context_at_least_multiple),
    "context_share_at_least": (frozenset({"path", "key", "min_share"}), frozenset(),
                               _context_share_at_least),
    "context_equals_finding_field": (frozenset({"path", "field"}), frozenset({"casefold"}),
                                     _context_equals_finding_field),
    "ioc_related": (frozenset({"type"}), frozenset({"evidence_file", "role_contains"}),
                    _ioc_related),
}


# -------------------------------------------------------------- evaluation
def evaluate(node: dict[str, Any], subject: Subject) -> tuple[Tri, str]:
    """Evaluate a validated condition tree; returns (True/False/None, explanation)."""
    if "check" in node:
        params = {k: v for k, v in node.items() if k != "check"}
        return CHECKS[node["check"]][2](subject, params)
    if "not" in node:
        value, text = evaluate(node["not"], subject)
        return (None if value is None else not value), f"not ({text})"
    results = [evaluate(child, subject) for child in node.get("all", node.get("any", []))]
    if "all" in node:
        if any(v is False for v, _ in results):
            return False, "; ".join(t for v, t in results if v is False)
        if any(v is None for v, _ in results):
            return None, "; ".join(t for v, t in results if v is None)
        return True, "all conditions met"
    if any(v is True for v, _ in results):
        return True, next(t for v, t in results if v is True)
    if any(v is None for v, _ in results):
        return None, "; ".join(t for v, t in results if v is None)
    return False, "none of the alternatives held: " + "; ".join(t for _, t in results)


# -------------------------------------------------- evidence and IOC choice
def collect_event_ids(specs: list[dict[str, Any]], subject: Subject) -> list[str]:
    """Event ids named by a rule's ``evidence`` specs (unique, in order)."""
    finding, ids = subject.finding, []
    for spec in specs:
        kind = spec["events_from"]
        if kind == "finding":
            excluded = {lookup(finding.context, path) for path in spec.get("except_context", [])}
            ids += [e for e in finding.supporting_events if e not in excluded]
        elif kind == "indicator":
            ids += [m["event_id"] for m in matching_indicators(
                finding, spec["indicator"], spec.get("where")) if m.get("event_id")]
        elif kind == "context_value":
            value = lookup(finding.context, spec["path"])
            if isinstance(value, str) and value.strip():
                ids.append(value)
        elif kind == "context_records":
            records = lookup(finding.context, spec["path"])
            for record in records if isinstance(records, list) else []:
                if (isinstance(record, dict) and record.get(spec["key"])
                        and all(record.get(k) == v for k, v in spec.get("where", {}).items())):
                    ids.append(record[spec["key"]])
    return list(dict.fromkeys(ids))


def select_iocs(spec: dict[str, Any], subject: Subject) -> list[IOC]:
    """IOCs related to the finding that match ``types`` / ``role_contains`` / ``evidence_file``."""
    types = set(spec.get("types", []))
    if subject.iocs is None or not types:        # an empty list of types selects nothing
        return []
    chosen = []
    for ioc in subject.iocs:
        if ioc.type.value not in types:
            continue
        role = spec.get("role_contains")
        if role and not any(role in str(r) for r in ioc.attributes.get("roles", [])):
            continue
        evidence_file = spec.get("evidence_file")
        if evidence_file and not any(o.get("evidence_file") == evidence_file
                                     for o in ioc.occurrences):
            continue
        chosen.append(ioc)
    return chosen


# ------------------------------------------------------------- rationale
def _render_value(value: Any) -> str:
    if _blank(value):                      # same notion of "missing" as the conditions
        return "unknown"
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items()) or "unknown"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) or "none"
    return str(value)


def render_rationale(template: str, subject: Subject) -> str:
    """Fill ``{finding.<field>}``, ``{ctx.<dotted.path>}`` and ``{indicators}``.

    Only these placeholder forms are replaced, by plain lookup: no attribute
    access, no formatting mini-language. Missing values read as "unknown".
    """
    finding = subject.finding

    def replace(match: re.Match) -> str:
        name = match.group(1)
        if name == "indicators":
            names = sorted({m.get("indicator") for m in matching_indicators(finding, None)
                            if m.get("indicator")})
            return ", ".join(names) or "none"
        if name.startswith("finding."):
            return _render_value(getattr(finding, name[len("finding."):], None))
        return _render_value(lookup(finding.context, name[len("ctx."):]))
    return _PLACEHOLDER.sub(replace, template)


# ------------------------------------------------------------- validation
def _check_keys(where: str, node: dict, required: frozenset, optional: frozenset) -> None:
    missing = sorted(required - set(node))
    unknown = sorted(set(node) - required - optional)
    if missing:
        raise ValueError(f"{where}: missing parameter(s) {missing}")
    if unknown:
        raise ValueError(f"{where}: unknown parameter(s) {unknown}")


def _need_str(where: str, node: dict, key: str) -> None:
    if not isinstance(node.get(key), str) or not node[key].strip():
        raise ValueError(f"{where}: '{key}' must be a non-empty string")


def validate_condition(node: Any, where: str) -> None:
    """Raise ValueError unless ``node`` is a well-formed condition tree."""
    if not isinstance(node, dict):
        raise ValueError(f"{where}: a condition must be an object")
    kinds = [k for k in ("check", "all", "any", "not") if k in node]
    if len(kinds) != 1:
        raise ValueError(f"{where}: a condition needs exactly one of check/all/any/not")
    kind = kinds[0]
    if kind in ("all", "any"):
        if set(node) != {kind} or not isinstance(node[kind], list) or not node[kind]:
            raise ValueError(f"{where}: '{kind}' must be a non-empty list and nothing else")
        for index, child in enumerate(node[kind]):
            validate_condition(child, f"{where}.{kind}[{index}]")
        return
    if kind == "not":
        if set(node) != {"not"}:
            raise ValueError(f"{where}: 'not' takes only one condition")
        validate_condition(node["not"], f"{where}.not")
        return
    name = node["check"]
    if name not in CHECKS:
        raise ValueError(f"{where}: unknown check {name!r}; valid: {', '.join(sorted(CHECKS))}")
    required, optional, _ = CHECKS[name]
    params = {k: v for k, v in node.items() if k != "check"}
    _check_keys(f"{where} ({name})", params, required, optional)
    for key in ("indicator", "path", "of", "key", "field", "type", "evidence_file",
                "role_contains"):
        if key in params:
            _need_str(f"{where} ({name})", params, key)
    if "where" in params and not isinstance(params["where"], dict):
        raise ValueError(f"{where} ({name}): 'where' must be an object")
    for key in ("value", "factor", "min_share"):
        if key in params and name != "context_equals" and _number(params[key]) is None:
            raise ValueError(f"{where} ({name}): '{key}' must be a number")
    if name == "context_share_at_least" and not 0 < params["min_share"] <= 1:
        raise ValueError(f"{where} ({name}): 'min_share' must be in (0, 1]")
    if name == "context_equals_finding_field" and params["field"] not in FINDING_FIELDS:
        raise ValueError(f"{where} ({name}): 'field' must be one of {', '.join(FINDING_FIELDS)}")
    if "casefold" in params and not isinstance(params["casefold"], bool):
        raise ValueError(f"{where} ({name}): 'casefold' must be true or false")


def validate_evidence(specs: Any, where: str) -> None:
    if not isinstance(specs, list) or not specs:
        raise ValueError(f"{where}: 'evidence' must be a non-empty list")
    for index, spec in enumerate(specs):
        at = f"{where}.evidence[{index}]"
        if not isinstance(spec, dict) or spec.get("events_from") not in EVIDENCE_KINDS:
            raise ValueError(f"{at}: 'events_from' must be one of {', '.join(EVIDENCE_KINDS)}")
        kind = spec["events_from"]
        required = {"finding": set(), "indicator": {"indicator"}, "context_value": {"path"},
                    "context_records": {"path", "key"}}[kind]
        optional = {"where"} if kind in ("indicator", "context_records") else (
            {"except_context"} if kind == "finding" else set())
        _check_keys(at, {k: v for k, v in spec.items() if k != "events_from"},
                    frozenset(required), frozenset(optional))
        if "where" in spec and not isinstance(spec["where"], dict):
            raise ValueError(f"{at}: 'where' must be an object")
        if "except_context" in spec and not (
                isinstance(spec["except_context"], list)
                and all(isinstance(x, str) and x for x in spec["except_context"])):
            raise ValueError(f"{at}: 'except_context' must be a list of context paths")


def validate_ioc_spec(spec: Any, where: str) -> None:
    if not isinstance(spec, dict) or "types" not in spec:
        raise ValueError(f"{where}: 'iocs' must be an object with a 'types' list")
    unknown = sorted(set(spec) - {"types", "role_contains", "evidence_file"})
    if unknown:
        raise ValueError(f"{where}: unknown ioc option(s) {unknown}")
    if not isinstance(spec["types"], list) or not all(isinstance(t, str) for t in spec["types"]):
        raise ValueError(f"{where}: 'iocs.types' must be a list of strings")


def validate_template(template: Any, where: str) -> None:
    if not isinstance(template, str) or not template.strip():
        raise ValueError(f"{where}: 'rationale' must be a non-empty string")
    for name in _PLACEHOLDER.findall(template):
        ok = (name == "indicators"
              or (name.startswith("finding.") and name[len("finding."):] in FINDING_FIELDS)
              or (name.startswith("ctx.") and len(name) > len("ctx.")))
        if not ok:
            raise ValueError(
                f"{where}: unsupported placeholder {{{name}}}; use {{indicators}}, "
                f"{{finding.<{'|'.join(FINDING_FIELDS)}>}} or {{ctx.<path>}}")
    stripped = _PLACEHOLDER.sub("", template)
    if "{" in stripped or "}" in stripped:
        raise ValueError(f"{where}: unbalanced braces in 'rationale'")
