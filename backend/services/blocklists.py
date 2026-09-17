import csv
import ipaddress
import io
import os
import time
from urllib.parse import urlparse

import httpx

CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data_cache")
os.makedirs(CACHE_DIR, exist_ok=True)

# FireHOL blocklist-ipsets (github.com/firehol/blocklist-ipsets) — no key, aggregates real open
# threat feeds (Spamhaus DROP/EDROP, DShield, blocklist.de, Emerging Threats, abuse.ch Feodo
# botnet C2, Tor exits, VPN/anonymizer proxies) into plain IP/CIDR text lists, updated daily.
FIREHOL_BASE = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master"
# X4BNet/lists_vpn (github.com/X4BNet/lists_vpn) — no key, a dedicated, actively-maintained
# list of commercial VPN provider IP ranges. Kept separate from firehol_anonymous (generic
# open proxies/anonymizers) so "VPN" and "Proxy" are two genuinely distinct, real signals
# rather than one flag doing double duty.
X4BNET_VPN_URL = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/ipv4.txt"
IP_LISTS = {
    "firehol_level1": f"{FIREHOL_BASE}/firehol_level1.netset",
    "firehol_level2": f"{FIREHOL_BASE}/firehol_level2.netset",
    "firehol_level3": f"{FIREHOL_BASE}/firehol_level3.netset",
    "firehol_anonymous": f"{FIREHOL_BASE}/firehol_anonymous.netset",
    "tor_exits": f"{FIREHOL_BASE}/tor_exits.ipset",
    "feodo_c2": f"{FIREHOL_BASE}/feodo.ipset",
    "vpn_ranges": X4BNET_VPN_URL,
}

# Human-readable name + what-it-means, shown per-source in the security-checks panel
# instead of just a bare aggregate score. (name, description-when-flagged)
IP_LIST_INFO = {
    "firehol_level1": ("FireHOL Level 1", "Listed — Spamhaus DROP/EDROP (fully hijacked netblocks)"),
    "firehol_level2": ("FireHOL Level 2", "Listed — DShield top attacking netblocks"),
    "firehol_level3": ("FireHOL Level 3", "Listed — blocklist.de / Emerging Threats abuse feed"),
    "firehol_anonymous": ("FireHOL Anonymous", "Listed — known open/anonymizing proxy service"),
    "tor_exits": ("Tor Project Exit List", "Listed — published Tor exit node"),
    "feodo_c2": ("abuse.ch Feodo Tracker", "Listed — known Feodo/Emotet botnet C2 infrastructure"),
    "vpn_ranges": ("X4BNet VPN Ranges", "Listed — commercial VPN provider IP range"),
}

# abuse.ch URLhaus "recent" CSV dump — confirmed at plan-implementation time to be openly
# downloadable with NO Auth-Key (unlike URLhaus's live query API, which does require one).
# Live feed of currently-active malware-distribution URLs. PhishTank's anonymous dump endpoint
# was tried first and found to be broken/decommissioned (returns a 404 placeholder), so this
# replaces it as the keyless malicious-URL source.
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

IP_REFRESH_SECONDS = 6 * 3600
URLHAUS_REFRESH_SECONDS = 3 * 3600


class _ListStore:
    """Parsed IP list: exact /32 addresses in a set (O(1) lookup), real CIDR ranges in a list
    (linear scan — far fewer entries than the exact-IP set in practice, so still fast)."""

    def __init__(self):
        self.exact: set[str] = set()
        self.networks: list = []

    def load(self, text: str):
        exact = set()
        networks = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
            except ValueError:
                continue
            if net.num_addresses == 1:
                exact.add(str(net.network_address))
            else:
                networks.append(net)
        self.exact = exact
        self.networks = networks

    def contains(self, ip_str: str) -> bool:
        if ip_str in self.exact:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return any(ip_obj in net for net in self.networks)

    def __len__(self):
        return len(self.exact) + len(self.networks)


class BlocklistRegistry:
    def __init__(self):
        self.lists: dict[str, _ListStore] = {name: _ListStore() for name in IP_LISTS}
        self.malicious_urls: set[str] = set()
        self.malicious_domains: dict[str, str] = {}  # domain -> threat type
        self._loaded = False

    def refresh_all(self, force: bool = False):
        for name, url in IP_LISTS.items():
            self._refresh_ip_list(name, url, force=force)
        self._refresh_urlhaus(force=force)
        self._loaded = True

    def _cache_paths(self, name: str):
        return (
            os.path.join(CACHE_DIR, f"{name}.txt"),
            os.path.join(CACHE_DIR, f"{name}.meta"),
        )

    def _is_stale(self, meta_path: str, max_age: int) -> bool:
        if not os.path.exists(meta_path):
            return True
        try:
            with open(meta_path) as f:
                fetched_at = float(f.read().strip())
        except (ValueError, OSError):
            return True
        return (time.time() - fetched_at) > max_age

    def _refresh_ip_list(self, name: str, url: str, force: bool):
        data_path, meta_path = self._cache_paths(name)
        if not force and not self._is_stale(meta_path, IP_REFRESH_SECONDS):
            if os.path.exists(data_path):
                self.lists[name].load(open(data_path).read())
                return
        try:
            resp = httpx.get(url, timeout=30, follow_redirects=True)
            resp.raise_for_status()
            text = resp.text
            with open(data_path, "w") as f:
                f.write(text)
            with open(meta_path, "w") as f:
                f.write(str(time.time()))
            self.lists[name].load(text)
        except (httpx.HTTPError, OSError):
            # Network unavailable / list temporarily down — fall back to whatever is cached
            # on disk from a previous successful refresh, else leave the list empty.
            if os.path.exists(data_path):
                self.lists[name].load(open(data_path).read())

    def _refresh_urlhaus(self, force: bool):
        data_path, meta_path = self._cache_paths("urlhaus")
        if not force and not self._is_stale(meta_path, URLHAUS_REFRESH_SECONDS):
            if os.path.exists(data_path):
                self._load_urlhaus(open(data_path).read())
                return
        try:
            resp = httpx.get(URLHAUS_CSV_URL, timeout=30, follow_redirects=True,
                              headers={"User-Agent": "intel-threatlookup/1.0"})
            resp.raise_for_status()
            text = resp.text
            with open(data_path, "w") as f:
                f.write(text)
            with open(meta_path, "w") as f:
                f.write(str(time.time()))
            self._load_urlhaus(text)
        except (httpx.HTTPError, OSError):
            if os.path.exists(data_path):
                self._load_urlhaus(open(data_path).read())

    def _load_urlhaus(self, text: str):
        lines = [line for line in text.splitlines() if line and not line.startswith("#")]
        urls = set()
        domains: dict[str, str] = {}
        for row in csv.reader(lines):
            if len(row) < 6:
                continue
            _id, _dateadded, url, _status, _last_online, threat = row[:6]
            if not url:
                continue
            urls.add(url)
            try:
                host = urlparse(url).hostname
                if host:
                    domains[host.lower()] = threat
            except ValueError:
                continue
        self.malicious_urls = urls
        self.malicious_domains = domains

    def check_ip(self, ip: str) -> dict:
        hits = [name for name, store in self.lists.items() if store.contains(ip)]
        is_tor = "tor_exits" in hits
        is_anon = "firehol_anonymous" in hits
        is_vpn = "vpn_ranges" in hits
        return {
            "lists_checked": len(self.lists),
            "lists_flagged": len(hits),
            "hits": hits,
            "is_tor": is_tor,
            "is_anon_proxy": is_anon,
            "is_vpn": is_vpn,
        }

    def check_url(self, url: str, domain: str | None) -> dict:
        exact = url in self.malicious_urls
        threat_type = self.malicious_domains.get(domain.lower()) if domain else None
        return {"exact_match": exact, "domain_match": threat_type is not None, "threat_type": threat_type}

    @property
    def stats(self) -> dict:
        return {name: len(store) for name, store in self.lists.items()} | {
            "urlhaus_urls": len(self.malicious_urls),
        }


def build_ip_security_checks(hits: list[str]) -> list[dict]:
    """One entry per real IP blocklist, always present (clean or flagged) — the
    per-source breakdown behind the aggregate malicious score."""
    checks = []
    for key, (name, flagged_detail) in IP_LIST_INFO.items():
        flagged = key in hits
        checks.append({"name": name, "flagged": flagged, "detail": flagged_detail if flagged else "Not listed"})
    return checks


registry = BlocklistRegistry()
