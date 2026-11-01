"""Detection configuration.

Every threshold, window, indicator list and policy a rule uses lives here, in
frozen (immutable) dataclasses with the documented defaults. Values are
validated when the object is built, so a wrong setting raises ``ValueError``
immediately instead of silently weakening a rule.

    config = DetectionConfig(brute_force=BruteForceConfig(threshold=3))
    config = DetectionConfig.from_dict({"brute_force": {"threshold": 3}})  # JSON-friendly
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, fields
from enum import Enum
from typing import Any, Mapping

from security.detection.ip_policy import IpPolicy

# Indicator identifiers of the PowerShell rule (used in findings and config).
POWERSHELL_INDICATORS: tuple[str, ...] = (
    "encoded_command",
    "hidden_window",
    "execution_policy_bypass",
    "download_cradle",
    "invoke_expression",
    "unusual_parent",
    "user_writable_script_path",
    "external_connection",
)


# ------------------------------------------------------------------ helpers
def _positive_int(section: str, name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(
            f"{section}.{name} must be a positive integer, got {value!r}")
    return value


def _non_negative_int(section: str, name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(
            f"{section}.{name} must be an integer >= 0, got {value!r}")
    return value


def _boolean(section: str, name: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{section}.{name} must be true or false, got {value!r}")
    return value


def _strings(section: str, name: str, value: Any, *, lower: bool = True,
             allow_empty: bool = False) -> tuple[str, ...]:
    if isinstance(value, str) or not hasattr(value, "__iter__"):
        raise ValueError(f"{section}.{name} must be a list of strings, got {value!r}")
    items = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(
                f"{section}.{name} must contain only non-empty strings, got {item!r}")
        items.append(item.strip().casefold() if lower else item.strip())
    if not items and not allow_empty:
        raise ValueError(f"{section}.{name} must not be empty")
    return tuple(items)


def _patterns(section: str, name: str, value: Any) -> tuple[str, ...]:
    patterns = _strings(section, name, value, lower=False)
    for pattern in patterns:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(
                f"{section}.{name}: invalid regular expression {pattern!r} ({exc})"
            ) from None
    return patterns


def _set(obj: Any, name: str, value: Any) -> None:
    object.__setattr__(obj, name, value)


# ------------------------------------------------------------------ DET-001
@dataclass(frozen=True)
class BruteForceConfig:
    """Brute-force logon rule (DET-001).

    threshold: failures that must occur inside one window (inclusive, >= 1).
    window_seconds: maximum span between the first and last failure counted
        together (inclusive).
    success_window_seconds: how long after the last failure a successful
        logon is still considered "followed by success".
    include_events_without_source: also group failures that carry no source
        address (as source "unknown"). Off by default because "same source"
        cannot be established for them.
    """

    threshold: int = 5
    window_seconds: int = 120
    success_window_seconds: int = 300
    include_events_without_source: bool = False

    def __post_init__(self) -> None:
        s = "brute_force"
        _positive_int(s, "threshold", self.threshold)
        _positive_int(s, "window_seconds", self.window_seconds)
        _positive_int(s, "success_window_seconds", self.success_window_seconds)
        _boolean(s, "include_events_without_source", self.include_events_without_source)


# ------------------------------------------------------------------ DET-002
@dataclass(frozen=True)
class PowerShellConfig:
    """Suspicious PowerShell rule (DET-002); see docs/DETECTION.md.

    min_indicators: distinct indicators needed before a finding is raised.
    enabled_indicators: subset of ``POWERSHELL_INDICATORS`` to evaluate.
    correlation_window_seconds: how long after a PowerShell process starts
        (or after its first PowerShell record, when no process record exists)
        its own script-block and network records may be attached to it.
    ip_policy: which address classes count as external. Default: public
        addresses only; documentation ranges are NOT external unless
        ``IpPolicy.synthetic_demo()`` (or the matching configuration) is
        chosen explicitly.
    """

    min_indicators: int = 2
    enabled_indicators: tuple = POWERSHELL_INDICATORS
    correlation_window_seconds: int = 900
    powershell_process_names: tuple = ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
    unusual_parents: tuple = (
        "wscript.exe", "cscript.exe", "mshta.exe", "winword.exe", "excel.exe",
        "powerpnt.exe", "outlook.exe", "wmiprvse.exe")
    execution_policy_values: tuple = ("bypass", "unrestricted")
    hidden_window_values: tuple = ("hidden", "1")
    download_patterns: tuple = (
        r"(?<![\w-])Invoke-WebRequest(?![\w-])",
        r"(?<![\w-])Invoke-RestMethod(?![\w-])",
        r"(?<![\w-])(?:iwr|irm)(?![\w-])",
        r"Net\.WebClient",
        r"(?<![\w-])Download(?:String|File|Data)(?![\w-])",
        r"(?<![\w-])Start-BitsTransfer(?![\w-])",
    )
    invoke_expression_patterns: tuple = (
        r"(?<![\w-])Invoke-Expression(?![\w-])",
        r"(?<![\w-])iex(?![\w-])",
    )
    writable_path_fragments: tuple = (
        "\\users\\public\\", "\\appdata\\", "\\temp\\", "\\programdata\\", "\\downloads\\")
    ip_policy: IpPolicy = field(default_factory=IpPolicy)

    def __post_init__(self) -> None:
        s = "powershell"
        _positive_int(s, "min_indicators", self.min_indicators)
        _positive_int(s, "correlation_window_seconds", self.correlation_window_seconds)
        enabled = _strings(s, "enabled_indicators", self.enabled_indicators)
        unknown = [i for i in enabled if i not in POWERSHELL_INDICATORS]
        if unknown:
            raise ValueError(
                f"powershell.enabled_indicators: unknown indicator(s) {unknown}; "
                f"valid: {', '.join(POWERSHELL_INDICATORS)}")
        # keep the canonical order so output never depends on config order
        _set(self, "enabled_indicators",
             tuple(i for i in POWERSHELL_INDICATORS if i in enabled))
        if self.min_indicators > len(self.enabled_indicators):
            raise ValueError(
                f"powershell.min_indicators ({self.min_indicators}) exceeds the "
                f"number of enabled indicators ({len(self.enabled_indicators)}); "
                "the rule could never fire")
        for name in ("powershell_process_names", "unusual_parents",
                     "execution_policy_values", "hidden_window_values"):
            _set(self, name, _strings(s, name, getattr(self, name),
                                      allow_empty=(name == "unusual_parents")))
        _set(self, "writable_path_fragments", tuple(
            f.replace("/", "\\") for f in _strings(
                s, "writable_path_fragments", self.writable_path_fragments,
                allow_empty=True)))
        for name in ("download_patterns", "invoke_expression_patterns"):
            _set(self, name, _patterns(s, name, getattr(self, name)))
        if not isinstance(self.ip_policy, IpPolicy):
            raise ValueError("powershell.ip_policy must be an IpPolicy")


# ------------------------------------------------------------------ DET-003
@dataclass(frozen=True)
class AccountCreationConfig:
    """Suspicious account creation rule (DET-003); see docs/DETECTION.md.

    privileged_groups: groups whose membership makes the new account
        "privileged" (case-insensitive).
    group_add_window_seconds: a group-membership event for the new account
        counts when it happens within this many seconds AFTER the creation.
    creating_process_window_seconds: the process/script that ran the account
        creation command must start within this many seconds BEFORE the event.
    ancestry_window_seconds / max_ancestry_depth: bounds when walking from
        the creating process to its parent processes (pid -> ppid links).
    context_window_seconds: a successful logon of the acting account (from a
        brute-force finding) counts as context when it happened at most this
        many seconds before the account was created.
    snapshot_tolerance_seconds: users.json ``created_at`` must be within this
        many seconds of the creation event to count as corroboration.
    require_privileged_target / min_context_indicators: the firing condition.
    """

    privileged_groups: tuple = ("administrators",)
    group_add_window_seconds: int = 600
    creating_process_window_seconds: int = 60
    ancestry_window_seconds: int = 3600
    max_ancestry_depth: int = 4
    context_window_seconds: int = 1800
    snapshot_tolerance_seconds: int = 60
    creation_command_patterns: tuple = (
        r"(?i)(?<![\w-])net1?(?:\.exe)?\s+user\b[^;&|\r\n]*?/add\b",
        r"(?i)(?<![\w-])(?:New|Add)-LocalUser(?![\w-])",
        r"(?i)(?<![\w-])New-ADUser(?![\w-])",
    )
    require_privileged_target: bool = True
    min_context_indicators: int = 1

    def __post_init__(self) -> None:
        s = "account_creation"
        _set(self, "privileged_groups",
             _strings(s, "privileged_groups", self.privileged_groups))
        for name in ("group_add_window_seconds", "creating_process_window_seconds",
                     "ancestry_window_seconds", "max_ancestry_depth",
                     "context_window_seconds", "snapshot_tolerance_seconds"):
            _positive_int(s, name, getattr(self, name))
        _set(self, "creation_command_patterns", _patterns(
            s, "creation_command_patterns", self.creation_command_patterns))
        _boolean(s, "require_privileged_target", self.require_privileged_target)
        _non_negative_int(s, "min_context_indicators", self.min_context_indicators)
        if self.min_context_indicators > 2:
            raise ValueError(
                "account_creation.min_context_indicators can be at most 2 "
                "(only two context indicators exist)")


# ------------------------------------------------------------- all together
_SECTIONS: dict[str, type] = {
    "brute_force": BruteForceConfig,
    "powershell": PowerShellConfig,
    "account_creation": AccountCreationConfig,
}


@dataclass(frozen=True)
class DetectionConfig:
    brute_force: BruteForceConfig = field(default_factory=BruteForceConfig)
    powershell: PowerShellConfig = field(default_factory=PowerShellConfig)
    account_creation: AccountCreationConfig = field(default_factory=AccountCreationConfig)

    def __post_init__(self) -> None:
        for name, cls in _SECTIONS.items():
            if not isinstance(getattr(self, name), cls):
                raise ValueError(f"{name} must be a {cls.__name__}")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DetectionConfig":
        """Build a config from plain data (e.g. parsed JSON).

        Only the options you give are changed; everything else keeps its
        default. Unknown sections or options raise ``ValueError`` (a typo must
        never be silently ignored).
        """
        if not isinstance(data, Mapping):
            raise ValueError("configuration must be a JSON object")
        unknown = sorted(set(data) - set(_SECTIONS))
        if unknown:
            raise ValueError(f"unknown configuration section(s) {unknown}; "
                             f"valid sections: {', '.join(_SECTIONS)}")
        built: dict[str, Any] = {}
        for name, section_cls in _SECTIONS.items():
            if name not in data:
                continue
            options = data[name]
            if not isinstance(options, Mapping):
                raise ValueError(f"section '{name}' must be a JSON object")
            valid = {f.name for f in fields(section_cls)}
            bad = sorted(set(options) - valid)
            if bad:
                raise ValueError(
                    f"unknown option(s) {bad} in section '{name}'; "
                    f"valid options: {', '.join(sorted(valid))}")
            kwargs = dict(options)
            if "ip_policy" in kwargs:
                policy = kwargs["ip_policy"]
                if not isinstance(policy, Mapping) or set(policy) - {"external_classes"}:
                    raise ValueError(
                        "powershell.ip_policy must be an object with only "
                        "'external_classes'")
                kwargs["ip_policy"] = IpPolicy.from_classes(
                    policy.get("external_classes", ()))
            built[name] = section_cls(**kwargs)
        return cls(**built)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (what DetectionResult.config stores)."""
        return {name: _plain(getattr(self, name)) for name in _SECTIONS}


def _plain(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (frozenset, set)):
        return sorted(_plain(v) for v in value)
    if isinstance(value, (tuple, list)):
        return [_plain(v) for v in value]
    if hasattr(value, "__dataclass_fields__"):
        return {f.name: _plain(getattr(value, f.name)) for f in fields(value)}
    return value
