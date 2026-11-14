import ipaddress
import os
from typing import Dict, Iterable, List, Optional, Tuple

from .constants import CACHE_WARNINGLISTS_DIR, BUNDLED_WARNINGLISTS_DIR, CONTEXT_WARNINGLISTS
from ._utils import load_json_file
from .deobfuscate import normalize_domain, normalize_url
from .extractor import url_host, is_ip_literal
from .psl import registrable_domain


CidrList = List[Tuple[ipaddress._BaseNetwork, str]]


class WarninglistIndex:
    """
    Minimal warninglist matcher:
    - exact string matches (domains/hosts/urls)
    - CIDR matches for IPs

    Lists in CONTEXT_WARNINGLISTS are kept in a separate index. They describe
    infrastructure (hosting, VPN, dynamic DNS...) and only annotate IOCs.
    """

    def __init__(self) -> None:
        self._exact_map: Dict[str, str] = {}
        self._cidr: CidrList = []
        self._ctx_exact: Dict[str, str] = {}
        self._ctx_cidr: CidrList = []
        self.loaded = False

    @staticmethod
    def _iter_warninglist_files(base_dir: str) -> Iterable[str]:
        lists_dir = os.path.join(base_dir, "lists")
        if not os.path.isdir(lists_dir):
            return []
        out = []
        for root, _, files in os.walk(lists_dir):
            for fn in files:
                if fn.lower().endswith(".json"):
                    out.append(os.path.join(root, fn))
        return out

    @staticmethod
    def _pick_warninglists_base_dir() -> Optional[str]:
        if os.path.isdir(os.path.join(CACHE_WARNINGLISTS_DIR, "lists")):
            return CACHE_WARNINGLISTS_DIR
        if os.path.isdir(os.path.join(BUNDLED_WARNINGLISTS_DIR, "lists")):
            return BUNDLED_WARNINGLISTS_DIR
        return None

    def load(self) -> None:
        base = self._pick_warninglists_base_dir()
        if not base:
            return

        for path in self._iter_warninglist_files(base):
            doc = load_json_file(path)
            if not isinstance(doc, dict):
                continue

            name = str(doc.get("name") or doc.get("description") or os.path.basename(path))
            items = doc.get("list")

            if not isinstance(items, list) or not items:
                continue

            list_id = os.path.basename(os.path.dirname(path))
            if list_id in CONTEXT_WARNINGLISTS:
                exact_map, cidr = self._ctx_exact, self._ctx_cidr
            else:
                exact_map, cidr = self._exact_map, self._cidr

            for raw in items:
                if not isinstance(raw, str):
                    continue
                v = raw.strip()
                if not v:
                    continue

                v_norm = v.lower().strip().lstrip(".")

                try:
                    if "/" in v_norm:
                        net = ipaddress.ip_network(v_norm, strict=False)
                        cidr.append((net, name))
                        continue
                    ipaddress.ip_address(v_norm)
                    exact_map.setdefault(v_norm, name)
                    continue
                except ValueError:
                    pass

                exact_map.setdefault(v_norm, name)

        for c in (self._cidr, self._ctx_cidr):
            c.sort(key=lambda x: (x[0].version, x[0].prefixlen, str(x[0])))
        self.loaded = bool(self._exact_map or self._cidr or self._ctx_exact or self._ctx_cidr)

    @staticmethod
    def _lookup_ip(ip_str: str, exact_map: Dict[str, str], cidr: CidrList) -> Optional[str]:
        s = ip_str.strip().lower()
        if s in exact_map:
            return exact_map[s]
        try:
            ip_obj = ipaddress.ip_address(s)
        except ValueError:
            return None
        for net, name in cidr:
            if ip_obj.version != net.version:
                continue
            if ip_obj in net:
                return name
        return None

    def match_domain(self, domain: str) -> Optional[str]:
        d = normalize_domain(domain)

        # 1. Check exact match
        if d in self._exact_map:
            return self._exact_map[d]

        # 2. Check parent domains (suffix match), but never above the
        #    registrable domain (e.g. co.uk, duckdns.org, github.io)
        reg = registrable_domain(d)
        parts = d.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if "." not in parent:
                break
            if reg and len(parent) < len(reg):
                break
            if parent in self._exact_map:
                return self._exact_map[parent]

        return None

    def match_url_exact(self, url: str) -> Optional[str]:
        return self._exact_map.get(normalize_url(url).strip().lower())

    def match_url(self, url: str) -> Optional[str]:
        hit = self.match_url_exact(url)
        if hit:
            return hit

        u = normalize_url(url).strip()
        h = url_host(u)
        if not h:
            return None
        if is_ip_literal(h):
            return self.match_ip(h)
        return self.match_domain(h)

    def match_hash(self, h: str) -> Optional[str]:
        return self._exact_map.get(h.strip().lower())

    def match_ip(self, ip_str: str) -> Optional[str]:
        return self._lookup_ip(ip_str, self._exact_map, self._cidr)

    # ------------- #
    # Context lists #
    # ------------- #

    def service_domain(self, domain: str) -> Optional[str]:
        """Exact match on a context list, e.g. 'duckdns.org' itself (the service, not a customer)."""
        return self._ctx_exact.get(normalize_domain(domain))

    def context_domain(self, domain: str) -> Optional[str]:
        """Context match for a domain or any parent, including public suffixes like duckdns.org."""
        d = normalize_domain(domain)
        parts = d.split(".")
        for i in range(len(parts)):
            parent = ".".join(parts[i:])
            if "." not in parent:
                break
            if parent in self._ctx_exact:
                return self._ctx_exact[parent]
        return None

    def context_ip(self, ip_str: str) -> Optional[str]:
        return self._lookup_ip(ip_str, self._ctx_exact, self._ctx_cidr)


def load_warninglists() -> WarninglistIndex:
    wl = WarninglistIndex()
    wl.load()
    return wl
