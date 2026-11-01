"""Parsing and validation helpers for IOC extraction (standard library only).

Every function here is pure: it takes text/values and returns normalized,
VALIDATED results or ``None``. Regular expressions only find CANDIDATES; each
candidate is then checked with a real parser (``ipaddress``, ``urllib.parse``,
``ntpath``) or explicit rules before it can become an indicator.

What is deliberately NOT extracted from free text (too many false positives):
bare domain names (``System.Net.WebClient`` looks like a domain), IPv6
addresses, and bare file names without a directory.
"""

from __future__ import annotations

import ipaddress
import ntpath
import re
from dataclasses import dataclass
from typing import Iterable, Optional
from urllib.parse import urlsplit, urlunsplit

from security.detection.ip_policy import IpClass, classify_ip
from security.detection.powershell import decode_encoded_command, flag_values, tokenize

# ----------------------------------------------------------------------- IPs
# Candidate: four dotted groups, not glued to a word (so "v1.2.3.4" and
# "1.2.3.4.5" are skipped) and not followed by ".<digit>".
_IPV4_CANDIDATE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")


def canonical_ip(value: object) -> Optional[str]:
    """Canonical text of a valid IPv4/IPv6 address, or None.

    Uses the same validation as the detection IP policy: ``999.1.1.1``,
    ``010.0.0.1`` (leading zeros), ``-`` and non-strings are all rejected.
    IPv4-mapped IPv6 becomes the plain IPv4 address.
    """
    if classify_ip(value) in (IpClass.MISSING, IpClass.INVALID):
        return None
    address = ipaddress.ip_address(str(value).strip())
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def find_ipv4_in_text(text: str) -> list[str]:
    """Valid IPv4 addresses found in free text (unique, in order of appearance)."""
    found: list[str] = []
    for match in _IPV4_CANDIDATE.finditer(text):
        address = canonical_ip(match.group(0))
        if address and address not in found:
            found.append(address)
    return found


# ------------------------------------------------------------------- domains
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_RESERVED_DOMAINS = ("example.com", "example.net", "example.org")        # RFC 2606
_RESERVED_TLDS = ("test", "example", "invalid", "localhost")


def normalize_domain(value: object) -> Optional[str]:
    """Lowercase ASCII (punycode) domain name, or None if it is not valid.

    Rules: at most 253 characters; at least two labels of 1-63 letters, digits
    or hyphens (no leading/trailing hyphen, no underscore); the last label is
    alphabetic (or ``xn--`` punycode) and at least 2 characters, so
    ``1.2.3.4`` and ``host.123`` are rejected; IP addresses are not domains.
    One trailing dot is accepted and removed; non-ASCII names are converted
    with IDNA.
    """
    if not isinstance(value, str):
        return None
    text = value.strip().rstrip(".")
    if not text or len(text) > 253:
        return None
    if not text.isascii():
        try:
            text = text.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    host = text.lower()
    labels = host.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        return None
    tld = labels[-1]
    if not (tld.startswith("xn--") or (tld.isalpha() and len(tld) >= 2)):
        return None
    if canonical_ip(host):
        return None
    return host


def is_reserved_domain(host: str) -> bool:
    """True for names reserved for documentation/testing (RFC 2606)."""
    return (host in _RESERVED_DOMAINS
            or any(host.endswith("." + name) for name in _RESERVED_DOMAINS)
            or host.rsplit(".", 1)[-1] in _RESERVED_TLDS)


# ---------------------------------------------------------------------- URLs
_URL_CANDIDATE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s\"'<>`^|{}\\]+")
_TRAILING_PUNCTUATION = ".,;:!?)]}>'\""
_URL_FORBIDDEN = re.compile(r"[\s\"<>`^|{}\\\x00-\x1f]")      # never part of a URL we accept


@dataclass(frozen=True)
class ParsedUrl:
    value: str               # normalized, credentials removed
    scheme: str
    host: str                # normalized domain or canonical IP
    host_type: str           # "domain" or "ip"
    credentials_removed: bool


def parse_url(raw: str, schemes: Iterable[str] = ("http", "https", "ftp")
              ) -> Optional[ParsedUrl]:
    """Validate and normalize one URL candidate.

    The scheme and host are lowercased, a user:password part is REMOVED (never
    stored), trailing sentence punctuation is dropped, and the host must be a
    valid domain or IP address. Returns None for anything else.
    """
    text = raw.rstrip(_TRAILING_PUNCTUATION)
    if _URL_FORBIDDEN.search(text):
        return None
    try:
        parts = urlsplit(text)
        host, port = parts.hostname, parts.port
    except ValueError:                                 # bad port, bad bracket, ...
        return None
    scheme = parts.scheme.lower()
    if scheme not in set(schemes) or not host:
        return None
    address = canonical_ip(host)
    if address:
        host_value, host_type = address, "ip"
    else:
        domain = normalize_domain(host)
        if domain is None:
            return None
        host_value, host_type = domain, "domain"
    shown = f"[{host_value}]" if ":" in host_value else host_value
    netloc = shown + (f":{port}" if port is not None else "")
    value = urlunsplit((scheme, netloc, parts.path, parts.query, parts.fragment))
    credentials = parts.username is not None or parts.password is not None
    return ParsedUrl(value, scheme, host_value, host_type, credentials)


def find_urls_in_text(text: str, schemes: Iterable[str] = ("http", "https", "ftp")
                      ) -> list[ParsedUrl]:
    """Valid URLs found in free text (unique by value, in order of appearance)."""
    found: list[ParsedUrl] = []
    seen: set[str] = set()
    for match in _URL_CANDIDATE.finditer(text):
        parsed = parse_url(match.group(0), schemes)
        if parsed and parsed.value not in seen:
            seen.add(parsed.value)
            found.append(parsed)
    return found


# -------------------------------------------------------------------- hashes
_HASH_ALGORITHMS = {32: "md5", 40: "sha1", 64: "sha256"}


def parse_hash(value: object) -> Optional[tuple[str, str]]:
    """(algorithm, lowercase hex) for a valid MD5/SHA-1/SHA-256, else None.

    The algorithm comes from the length (32/40/64 hex digits). A value made of
    one repeated character (``000...``) is a placeholder, not a real digest.
    """
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    algorithm = _HASH_ALGORITHMS.get(len(text))
    if algorithm is None or not re.fullmatch(r"[0-9a-f]+", text):
        return None
    if len(set(text)) == 1:
        return None
    return algorithm, text


# --------------------------------------------------------------------- paths
_PATH_CANDIDATE = re.compile(
    r"(?:(?<!\w)[A-Za-z]:[\\/]|\\\\[^\\\s\"'<>|]+\\)[^\s\"'<>|;,*?]*")
_PATH_START = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\[^\\]+\\)")
_PATH_TRAILING = ".,;)]}'\"`"
_INVALID_NAME_CHARS = set('<>:"/\\|?*')


def normalize_path_key(path: str) -> str:
    """Comparison key for a Windows path: backslashes, normalized, case-folded.

    ``..`` segments are resolved so a path such as
    ``C:\\Users\\Public\\..\\..\\Windows\\x.exe`` cannot hide where it points.
    """
    return ntpath.normpath(path.replace("/", "\\")).casefold()


def filename_of(path: str) -> str:
    """The file name part of a Windows path (``a.ps1`` for ``C:\\x\\a.ps1``)."""
    return ntpath.basename(path.replace("/", "\\"))


def extension_of(path: str) -> str:
    """Lowercase extension without the dot ('' if none)."""
    return ntpath.splitext(filename_of(path))[1].lstrip(".").casefold()


def is_valid_file_path(path: str) -> bool:
    """A drive-letter or UNC path whose last part is a plain name with an extension."""
    if not _PATH_START.match(path):
        return False
    name = filename_of(path)
    extension = ntpath.splitext(name)[1]
    return (bool(name) and len(extension) >= 2 and len(extension) <= 9
            and not (_INVALID_NAME_CHARS & set(name)))


def is_writable_path(path: str, fragments: Iterable[str]) -> bool:
    key = normalize_path_key(path)
    return any(fragment in key for fragment in fragments)


def is_system_path(path: str, prefixes: Iterable[str], writable_fragments: Iterable[str]
                   ) -> bool:
    """True for paths under protected Windows folders (C:\\Windows, Program Files).

    The check is anchored at the start of the path (after the drive letter), so
    ``C:\\Users\\x\\AppData\\Roaming\\Microsoft\\Windows\\...`` is NOT system.
    A path that also matches a user-writable fragment (``\\temp\\``) is never
    treated as system, so ``C:\\Windows\\Temp\\x.exe`` stays visible.
    """
    key = normalize_path_key(path)
    if is_writable_path(path, writable_fragments):
        return False
    return len(key) > 2 and key[1] == ":" and any(
        key[2:].startswith(prefix) for prefix in prefixes)


def find_paths_in_text(text: str) -> list[str]:
    """Windows file paths with an extension found in free text.

    Finds unquoted paths (no spaces) with a regex, and quoted paths WITH
    spaces through tokenization. A path that is only a truncated prefix of a
    longer one is dropped. Returned unique, in order of appearance.
    """
    candidates: list[str] = []

    def add(raw: str) -> None:
        path = raw.strip().rstrip(_PATH_TRAILING)
        if is_valid_file_path(path) and path not in candidates:
            candidates.append(path)

    for token in tokenize(text):
        value = token.split(":", 1)[1] if token.startswith("-") and ":" in token else token
        if " " in value and _PATH_START.match(value):
            add(value)
    for match in _PATH_CANDIDATE.finditer(text):
        add(match.group(0))
    keys = {path: normalize_path_key(path) for path in candidates}
    return [p for p in candidates
            if not any(keys[o] != keys[p] and keys[o].startswith(keys[p]) for o in candidates)]


# -------------------------------------------------------- encoded commands
def _is_encoded_flag(name: str) -> bool:
    """-EncodedCommand, any prefix (-e, -enc ...) or -ec (same rule as DET-002)."""
    return bool(name) and ("encodedcommand".startswith(name) or name == "ec")


def text_variants(text: str, label: str, decode: bool = True) -> list[tuple[str, str]]:
    """The text plus, for each Base64 -EncodedCommand argument, its decoded form.

    Returns (field label, text) pairs; decoded text is labelled
    ``"<label> (decoded)"``. One level only; nothing is executed.
    """
    variants = [(label, text)]
    if not decode:
        return variants
    for _flag, value in flag_values(tokenize(text), _is_encoded_flag):
        if re.fullmatch(r"[A-Za-z0-9+/=]{8,}", value):
            decoded = decode_encoded_command(value)
            if decoded:
                variants.append((f"{label} (decoded)", decoded))
    return variants
