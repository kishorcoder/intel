"""Shared hostname -> registrable-domain reduction (e.g. "www.blog.example.co.uk"
-> "example.co.uk"), used by both url_intel (RDAP/WHOIS need the bare domain,
not a full hostname) and ip_intel (reverse-DNS PTR records come back as a full
hostname too). Kept in its own module rather than in either of those two —
they already import from each other, so this would create a circular import
if it lived in either one.
"""

import tldextract

# suffix_list_urls=() pins this to the bundled public-suffix-list snapshot —
# no live network fetch, so extraction stays fast and works offline.
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=())


def registrable_domain(hostname: str) -> str | None:
    ext = _tld_extractor(hostname)
    return ext.top_domain_under_public_suffix or None
