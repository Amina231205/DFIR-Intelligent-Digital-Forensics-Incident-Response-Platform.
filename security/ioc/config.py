"""IOC extraction configuration.

Frozen (immutable) and validated on creation, like the detection config: a
wrong setting raises ``ValueError`` immediately instead of silently changing
what is extracted.

    config = IocConfig(ip_classes=("public",))
    config = IocConfig.from_dict({"suspicious_extensions": ["ps1", "exe"]})
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from enum import Enum
from typing import Any, Mapping

from security.detection.config import PowerShellConfig
from security.detection.ip_policy import IpClass, IpPolicy

# Which classified IP addresses become IOCs by default. Loopback, link-local,
# multicast and unspecified addresses are left out because they are rarely
# indicators; they can still be enabled explicitly (e.g. to investigate a
# tunnel on 127.0.0.1). Only "missing" and "invalid" can never be IOCs.
DEFAULT_IP_CLASSES = ("public", "private", "documentation", "reserved")
_IP_CLASSES_ALLOWED = tuple(c.value for c in IpClass
                            if c not in (IpClass.MISSING, IpClass.INVALID))


def _bad(name: str, message: str) -> ValueError:
    return ValueError(f"ioc.{name} {message}")


def _strings(name: str, value: Any, *, allow_empty: bool = False) -> tuple[str, ...]:
    if isinstance(value, str) or not hasattr(value, "__iter__"):
        raise _bad(name, f"must be a list of strings, got {value!r}")
    items = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise _bad(name, f"must contain only non-empty strings, got {item!r}")
        items.append(item.strip().casefold())
    if not items and not allow_empty:
        raise _bad(name, "must not be empty")
    return tuple(items)


def _set(obj: Any, name: str, value: Any) -> None:
    object.__setattr__(obj, name, value)


@dataclass(frozen=True)
class IocConfig:
    """Settings for IOC extraction; defaults are documented in docs/IOC.md.

    ip_classes: classified IP addresses that become IOCs.
    ip_policy: only used for the ``external`` attribute of IP IOCs (same
        policy as detection: public addresses only by default).
    url_schemes: URL schemes that are extracted.
    suspicious_extensions: file extensions (without the dot) that make a file
        path a filename IOC, unless it lies in a protected system folder.
    writable_path_fragments / system_path_prefixes: how paths are classified
        (see ``is_system_path``).
    known_system_processes: process names not reported as IOCs when their
        path is unknown. A known name outside the system folders IS reported.
    ignored_usernames: accounts never reported (machine accounts ending in
        ``$`` are always ignored).
    decode_encoded_commands: also scan the decoded form of Base64
        ``-EncodedCommand`` arguments (one level).
    link_file_records: add file records (files.json) whose path equals the
        path of an extracted filename IOC, with their hash.
    max_scan_chars: only the first N characters of each text are scanned.
    """

    ip_classes: tuple = DEFAULT_IP_CLASSES
    ip_policy: IpPolicy = field(default_factory=IpPolicy)
    url_schemes: tuple = ("http", "https", "ftp")
    suspicious_extensions: tuple = (
        "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "hta", "bat", "cmd", "exe",
        "dll", "scr", "com", "lnk", "msi", "jar", "sys", "cpl", "reg", "iso", "img",
        "zip", "rar", "7z", "docm", "xlsm", "pptm", "dotm")
    writable_path_fragments: tuple = (
        *PowerShellConfig().writable_path_fragments, "\\windows\\tasks\\")
    system_path_prefixes: tuple = ("\\windows\\", "\\program files\\",
                                   "\\program files (x86)\\")
    known_system_processes: tuple = (
        "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
        "svchost.exe", "winlogon.exe", "explorer.exe", "cmd.exe", "powershell.exe",
        "pwsh.exe", "powershell_ise.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "net.exe", "net1.exe", "rundll32.exe", "regsvr32.exe", "conhost.exe",
        "taskhostw.exe", "taskhost.exe", "taskeng.exe", "userinit.exe", "dllhost.exe",
        "wmiprvse.exe", "spoolsv.exe", "runtimebroker.exe", "sihost.exe", "ctfmon.exe",
        "dwm.exe", "fontdrvhost.exe", "audiodg.exe", "searchindexer.exe")
    ignored_usernames: tuple = ("system", "local service", "network service",
                                "anonymous logon", "-")
    decode_encoded_commands: bool = True
    link_file_records: bool = True
    max_scan_chars: int = 200_000

    def __post_init__(self) -> None:
        classes = _strings("ip_classes", self.ip_classes)
        unknown = [c for c in classes if c not in _IP_CLASSES_ALLOWED]
        if unknown:
            raise _bad("ip_classes", f"has unknown or unusable class(es) {unknown}; "
                                     f"valid: {', '.join(_IP_CLASSES_ALLOWED)}")
        _set(self, "ip_classes", classes)
        if not isinstance(self.ip_policy, IpPolicy):
            raise _bad("ip_policy", "must be an IpPolicy")
        _set(self, "url_schemes", _strings("url_schemes", self.url_schemes))
        _set(self, "suspicious_extensions", tuple(
            e.lstrip(".") for e in _strings("suspicious_extensions",
                                            self.suspicious_extensions)))
        _set(self, "writable_path_fragments", tuple(
            f.replace("/", "\\") for f in _strings(
                "writable_path_fragments", self.writable_path_fragments, allow_empty=True)))
        _set(self, "system_path_prefixes", tuple(
            f.replace("/", "\\") for f in _strings(
                "system_path_prefixes", self.system_path_prefixes, allow_empty=True)))
        for name in ("known_system_processes", "ignored_usernames"):
            _set(self, name, _strings(name, getattr(self, name), allow_empty=True))
        for name in ("decode_encoded_commands", "link_file_records"):
            if not isinstance(getattr(self, name), bool):
                raise _bad(name, f"must be true or false, got {getattr(self, name)!r}")
        if (isinstance(self.max_scan_chars, bool) or not isinstance(self.max_scan_chars, int)
                or self.max_scan_chars < 1):
            raise _bad("max_scan_chars",
                       f"must be a positive integer, got {self.max_scan_chars!r}")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "IocConfig":
        """Build from plain data (parsed JSON). Unknown options raise ValueError."""
        if not isinstance(data, Mapping):
            raise ValueError("IOC configuration must be a JSON object")
        valid = {f.name for f in fields(cls)}
        unknown = sorted(set(data) - valid)
        if unknown:
            raise ValueError(f"unknown IOC option(s) {unknown}; "
                             f"valid options: {', '.join(sorted(valid))}")
        kwargs = dict(data)
        if "ip_policy" in kwargs:
            policy = kwargs["ip_policy"]
            if not isinstance(policy, Mapping) or set(policy) - {"external_classes"}:
                raise ValueError(
                    "ioc.ip_policy must be an object with only 'external_classes'")
            kwargs["ip_policy"] = IpPolicy.from_classes(policy.get("external_classes", ()))
        return cls(**kwargs)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (what IocResult.config stores)."""
        return {f.name: _plain(getattr(self, f.name)) for f in fields(self)}


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
