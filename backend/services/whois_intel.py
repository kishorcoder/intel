"""Keyless WHOIS (RFC 3912, plain TCP port 43) crawler — used as a fallback
for domains whose registry doesn't (yet) support RDAP, or whose RDAP referral
chain is broken. WHOIS itself needs no key/auth: ICANN requires registries
and registrars to run an open port-43 server, and IANA's own WHOIS
(whois.iana.org) is the standard, universally-supported way to discover which
server is authoritative for a given TLD — no hardcoded per-TLD server list
needed.
"""

import ipaddress
import re
import socket
from datetime import datetime

IANA_WHOIS_SERVER = "whois.iana.org"
_SOCKET_TIMEOUT = 8.0

_REFERRAL_RE = re.compile(r"^\s*(?:whois|refer)\s*:\s*(\S+)", re.MULTILINE | re.IGNORECASE)


def _is_public_host(host: str) -> bool:
    """The referral server we connect to next (registry -> registrar) comes
    from parsing the previous server's response text, not from our own
    trusted config — a malicious/compromised WHOIS server could hand back a
    referral pointing at an internal address (127.0.0.1, cloud metadata IPs,
    RFC1918 ranges, ...) to make us probe our own network on its behalf.
    Resolve and check before ever opening that socket."""
    try:
        infos = socket.getaddrinfo(host, 43, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False
    for family, _type, _proto, _canon, sockaddr in infos:
        addr = ipaddress.ip_address(sockaddr[0])
        if not addr.is_global:
            return False
    return True

_DATE_FIELD_PATTERNS: dict[str, list[str]] = {
    "registered_at": [
        r"Creation Date:\s*(.+)",
        r"Registered on:\s*(.+)",
        r"Registration Date:\s*(.+)",
        r"Domain Registration Date:\s*(.+)",
        r"^created:\s*(.+)",
        r"Domain Create Date:\s*(.+)",
    ],
    "expires_at": [
        r"Registry Expiry Date:\s*(.+)",
        r"Registrar Registration Expiration Date:\s*(.+)",
        r"Expiry Date:\s*(.+)",
        r"Expiration Date:\s*(.+)",
        r"^paid-till:\s*(.+)",
        r"Domain Expiration Date:\s*(.+)",
        r"Registry Expiry:\s*(.+)",
    ],
    "last_changed_at": [
        r"Updated Date:\s*(.+)",
        r"Last Updated On:\s*(.+)",
        r"Domain Last Updated Date:\s*(.+)",
        r"^changed:\s*(.+)",
        r"Last Modified:\s*(.+)",
    ],
}


def _whois_query(server: str, query: str) -> str:
    if not _is_public_host(server):
        raise OSError(f"refusing to query non-public WHOIS host: {server}")
    with socket.create_connection((server, 43), timeout=_SOCKET_TIMEOUT) as sock:
        sock.sendall((query + "\r\n").encode("utf-8", errors="ignore"))
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="ignore")


def fetch_whois(registrable_domain: str) -> str | None:
    """Resolve the authoritative WHOIS server for the domain's TLD via IANA,
    query it, and — since gTLD registries (.com/.net/...) usually return a
    thin record pointing at the registrar's own server — follow that referral
    once for the full record. Returns the raw text, or None if unreachable."""
    tld = registrable_domain.rsplit(".", 1)[-1]
    try:
        iana_resp = _whois_query(IANA_WHOIS_SERVER, tld)
        match = _REFERRAL_RE.search(iana_resp)
        if not match:
            return None
        server = match.group(1)

        raw = _whois_query(server, registrable_domain)
        registrar_match = re.search(r"^\s*Registrar WHOIS Server:\s*(\S+)", raw, re.MULTILINE | re.IGNORECASE)
        if registrar_match and registrar_match.group(1).lower() != server.lower():
            try:
                fuller = _whois_query(registrar_match.group(1), registrable_domain)
                if fuller.strip():
                    raw = fuller
            except OSError:
                pass
        return raw
    except (OSError, socket.timeout):
        return None


def _parse_whois_date(value: str) -> datetime | None:
    value = value.strip()
    for candidate in (value, value.replace("Z", "+00:00")):
        try:
            return datetime.fromisoformat(candidate)
        except ValueError:
            continue
    for fmt in ("%Y-%m-%d", "%d-%b-%Y", "%d.%m.%Y", "%Y.%m.%d", "%d/%m/%Y"):
        try:
            return datetime.strptime(value.split("T")[0].strip(), fmt)
        except ValueError:
            continue
    return None


def parse_whois_dates(raw: str) -> dict[str, datetime]:
    """Best-effort extraction across the handful of field-name conventions
    real registries use — not exhaustive (WHOIS output format is unstandardized
    across ~1500 TLDs), but covers the common gTLD/ccTLD cases."""
    result: dict[str, datetime] = {}
    for key, patterns in _DATE_FIELD_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, raw, re.MULTILINE | re.IGNORECASE)
            if match:
                parsed = _parse_whois_date(match.group(1))
                if parsed:
                    result[key] = parsed
                    break
    return result
