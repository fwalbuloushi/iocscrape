import ipaddress
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from .constants import FILENAME_LIKE_EXTS, STATIC_ASSET_EXTS, IOC_TYPES_ORDER
from .extractor import url_host, is_ip_literal
from .psl import psl_invalid_reason
from .warninglist import WarninglistIndex


@dataclass(frozen=True)
class LowConfidenceItem:
    ioc_type: str
    value: str
    reason: str


def ip_low_conf_reason(ip_str: str) -> Optional[str]:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return "invalid ip"

    if ip_obj.is_private:
        return "private ip"
    if ip_obj.is_loopback:
        return "loopback ip"
    if ip_obj.is_link_local:
        return "link-local ip"
    if ip_obj.is_multicast:
        return "multicast ip"
    if ip_obj.is_reserved:
        return "reserved ip"
    if ip_obj.is_unspecified:
        return "unspecified ip"

    if isinstance(ip_obj, ipaddress.IPv6Address) and getattr(ip_obj, "is_site_local", False):
        return "site-local ip (ipv6)"

    return None


def compute_low_confidence(
    iocs: Dict[str, Set[str]], wl: WarninglistIndex
) -> List[LowConfidenceItem]:
    low: List[LowConfidenceItem] = []

    # Domains
    for d in sorted(iocs["domain"]):
        parts = d.rsplit(".", 1)
        if len(parts) == 2 and parts[1].lower() in FILENAME_LIKE_EXTS:
            low.append(LowConfidenceItem("domain", d, "looks like filename (extension)"))

        hit = wl.match_domain(d)
        if hit:
            low.append(LowConfidenceItem("domain", d, f"Warninglist: {hit}"))

        pr = psl_invalid_reason(d)
        if pr:
            low.append(LowConfidenceItem("domain", d, pr))

    # Emails
    for e in sorted(iocs["email"]):
        if "@" in e:
            domain_part = e.split("@", 1)[1]
            hit = wl.match_domain(domain_part)
            if hit:
                low.append(LowConfidenceItem("email", e, f"Warninglist: {hit}"))
                continue
            pr = psl_invalid_reason(domain_part)
            if pr:
                low.append(LowConfidenceItem("email", e, f"Invalid domain: {pr}"))

    # URLs
    for u in sorted(iocs["url"]):
        host = url_host(u)
        if host and (not is_ip_literal(host)):
            pr = psl_invalid_reason(host)
            if pr:
                low.append(LowConfidenceItem("url", u, pr))

        path_part = u.split("?", 1)[0].lower()
        pext = path_part.rsplit(".", 1)[-1] if "." in path_part else ""
        if pext in STATIC_ASSET_EXTS:
            low.append(LowConfidenceItem("url", u, "static asset url (likely noise)"))

        hit = wl.match_url(u)
        if hit:
            low.append(LowConfidenceItem("url", u, f"Warninglist: {hit}"))

    # IPs
    for t in ("ipv4", "ipv6"):
        for ip_str in sorted(iocs[t]):
            r = ip_low_conf_reason(ip_str)
            if r:
                low.append(LowConfidenceItem(t, ip_str, r))
                continue
            hit = wl.match_ip(ip_str)
            if hit:
                low.append(LowConfidenceItem(t, ip_str, f"Warninglist: {hit}"))

    # De-duplicate per (type, value) — keep first reason
    seen = set()
    deduped: List[LowConfidenceItem] = []
    for item in low:
        key = (item.ioc_type, item.value)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    return deduped
