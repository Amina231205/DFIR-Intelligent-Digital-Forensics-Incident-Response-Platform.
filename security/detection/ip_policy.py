"""IP address classification and the "external" policy.

Classification uses the standard-library ``ipaddress`` module, but NOT
``is_private`` / ``is_global`` alone, because they are misleading for this
project: Python calls the documentation ranges (203.0.113.0/24 ...) "private"
and reports multicast addresses as "global". Classes are therefore assigned
by an explicit, ordered list of checks (first match wins):

    1. MISSING        None, "", "-"                      (data absent, not "bad")
    2. INVALID        anything that is not an IP address (text, wrong type)
    3. UNSPECIFIED    0.0.0.0, ::
    4. LOOPBACK       127.0.0.0/8, ::1
    5. LINK_LOCAL     169.254.0.0/16, fe80::/10
    6. MULTICAST      224.0.0.0/4, ff00::/8
    7. DOCUMENTATION  192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32
    8. PRIVATE        10/8, 172.16/12, 192.168/16, fc00::/7   (RFC 1918 / ULA)
    9. PUBLIC         globally routable (``is_global``)
   10. RESERVED       everything else (CGNAT 100.64/10, broadcast, 240/4, ...)

IPv4-mapped IPv6 addresses (``::ffff:a.b.c.d``) are classified as the IPv4
address they wrap.

"External" means "outside the local/private network". It is NOT a verdict:
a public address is not assumed to be malicious. ``IpPolicy`` decides which
classes count as external. The DEFAULT is PUBLIC only: genuinely public,
globally routable addresses. DOCUMENTATION ranges are classified as
``documentation`` and are never external by default.

Synthetic demonstrations (the sample case uses documentation ranges as
stand-ins for internet hosts) must opt in explicitly, for example with
``IpPolicy.synthetic_demo()`` or ``external_classes: ["public",
"documentation"]`` in the configuration. That choice is never made silently.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Optional


class IpClass(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    MULTICAST = "multicast"
    UNSPECIFIED = "unspecified"
    DOCUMENTATION = "documentation"
    RESERVED = "reserved"
    INVALID = "invalid"
    MISSING = "missing"


_DOCUMENTATION = tuple(ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))
_PRIVATE = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))


def classify_ip(value: Any) -> IpClass:
    """Classify one address-like value (see the module docstring for rules)."""
    if value is None:
        return IpClass.MISSING
    if not isinstance(value, str):
        return IpClass.INVALID
    text = value.strip()
    if text in ("", "-"):
        return IpClass.MISSING
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return IpClass.INVALID
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped

    if address.is_unspecified:
        return IpClass.UNSPECIFIED
    if address.is_loopback:
        return IpClass.LOOPBACK
    if address.is_link_local:
        return IpClass.LINK_LOCAL
    if address.is_multicast:
        return IpClass.MULTICAST
    if any(address in network for network in _DOCUMENTATION
           if network.version == address.version):
        return IpClass.DOCUMENTATION
    if any(address in network for network in _PRIVATE
           if network.version == address.version):
        return IpClass.PRIVATE
    if address.is_global:
        return IpClass.PUBLIC
    return IpClass.RESERVED


@dataclass(frozen=True)
class IpPolicy:
    """Which address classes count as "external".

    Raises:
        ValueError: ``external_classes`` contains MISSING or INVALID (those
            are unknown, never external) or a value that is not an IpClass.
    """

    external_classes: frozenset = frozenset({IpClass.PUBLIC})

    def __post_init__(self) -> None:
        try:
            classes = frozenset(IpClass(c) for c in self.external_classes)
        except ValueError as exc:
            valid = ", ".join(c.value for c in IpClass)
            raise ValueError(f"unknown IP class in external_classes ({exc}); "
                             f"valid classes: {valid}") from None
        if classes & {IpClass.MISSING, IpClass.INVALID}:
            raise ValueError(
                "external_classes may not contain 'missing' or 'invalid': an "
                "unknown address is never treated as external")
        object.__setattr__(self, "external_classes", classes)

    def is_external(self, value: Any) -> Optional[bool]:
        """True/False for a classifiable address, None when it is unknown.

        None (missing or invalid address) means "cannot tell", which callers
        must treat differently from "internal".
        """
        ip_class = classify_ip(value)
        if ip_class in (IpClass.MISSING, IpClass.INVALID):
            return None
        return ip_class in self.external_classes

    @classmethod
    def from_classes(cls, classes: Iterable[Any]) -> "IpPolicy":
        return cls(external_classes=frozenset(classes))

    @classmethod
    def synthetic_demo(cls) -> "IpPolicy":
        """EXPLICIT opt-in for synthetic data: public AND documentation ranges.

        Use only for demonstrations whose "internet" hosts are documentation
        addresses (e.g. the INC-001 sample). It is never the default.
        """
        return cls(external_classes=frozenset({IpClass.PUBLIC, IpClass.DOCUMENTATION}))
