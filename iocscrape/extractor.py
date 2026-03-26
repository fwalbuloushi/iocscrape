import ipaddress
import re
from typing import Dict, Optional, Set

from .constants import IOC_TYPES_ORDER
from .deobfuscate import normalize_domain, normalize_url, normalize_hash, strip_trailing_punct


# ======= #
# Regexes #
# ======= #

URL_RE = re.compile(r"\bhttps?://[^\s<>\"]+", re.IGNORECASE)

DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b",
    re.IGNORECASE,
)

EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}\b", re.IGNORECASE)

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b", re.IGNORECASE)

MD5_RE = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
SHA1_RE = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


# ============ #
# URL helpers  #
# ============ #

def url_host(url: str) -> Optional[str]:
    m = re.match(r"^https?://([^/]+)", url, flags=re.IGNORECASE)
    if not m:
        return None
    host = m.group(1)
    host = host.split("@")[-1]
    host = host.split(":")[0]
    return host.lower().strip(".")


def is_ip_literal(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ============= #
# IOC Extractor #
# ============= #

def extract_iocs(text: str) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {k: set() for k in IOC_TYPES_ORDER}

    for m in URL_RE.finditer(text):
        out["url"].add(normalize_url(m.group(0)))

    for m in EMAIL_RE.finditer(text):
        out["email"].add(strip_trailing_punct(m.group(0)).lower())

    for m in SHA256_RE.finditer(text):
        out["sha256"].add(normalize_hash(m.group(0)))
    for m in SHA1_RE.finditer(text):
        out["sha1"].add(normalize_hash(m.group(0)))
    for m in MD5_RE.finditer(text):
        out["md5"].add(normalize_hash(m.group(0)))

    for m in CVE_RE.finditer(text):
        out["cve"].add(m.group(0).upper())

    for m in IPV4_RE.finditer(text):
        out["ipv4"].add(strip_trailing_punct(m.group(0)))
    for m in IPV6_RE.finditer(text):
        out["ipv6"].add(strip_trailing_punct(m.group(0)))

    # Replace URLs with their hostname only before running the domain regex.
    # This prevents URL path components (e.g. "malicious.exe" from
    # "https://evil.com/malicious.exe") from being extracted as domains.
    domain_text = URL_RE.sub(lambda m: url_host(m.group(0)) or "", text)
    for m in DOMAIN_RE.finditer(domain_text):
        out["domain"].add(normalize_domain(m.group(0)))

    return out
