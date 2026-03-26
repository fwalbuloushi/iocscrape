import ipaddress
import os
from typing import Dict, Iterable, List, Optional, Tuple

from .constants import CACHE_WARNINGLISTS_DIR, BUNDLED_WARNINGLISTS_DIR
from ._utils import load_json_file
from .deobfuscate import normalize_domain, normalize_url
from .extractor import url_host, is_ip_literal


class WarninglistIndex:
    """
    Minimal warninglist matcher:
    - exact string matches (domains/hosts/urls)
    - CIDR matches for IPs
    """

    def __init__(self) -> None:
        self._exact_map: Dict[str, str] = {}
        self._cidr: List[Tuple[ipaddress._BaseNetwork, str]] = []

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

            for raw in items:
                if not isinstance(raw, str):
                    continue
                v = raw.strip()
                if not v:
                    continue

                v_norm = v.lower().strip()

                try:
                    if "/" in v_norm:
                        net = ipaddress.ip_network(v_norm, strict=False)
                        self._cidr.append((net, name))
                        continue
                    ipaddress.ip_address(v_norm)
                    self._exact_map.setdefault(v_norm, name)
                    continue
                except ValueError:
                    pass

                self._exact_map.setdefault(v_norm, name)

        self._cidr.sort(key=lambda x: (x[0].version, x[0].prefixlen, str(x[0])))

    def match_domain(self, domain: str) -> Optional[str]:
        d = normalize_domain(domain)

        # 1. Check exact match
        if d in self._exact_map:
            return self._exact_map[d]

        # 2. Check parent domains (suffix match) — skip bare TLDs
        parts = d.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if "." not in parent:
                continue
            if parent in self._exact_map:
                return self._exact_map[parent]

        return None

    def match_url(self, url: str) -> Optional[str]:
        u = normalize_url(url).strip()
        u_low = u.lower()
        if u_low in self._exact_map:
            return self._exact_map[u_low]

        h = url_host(u)
        if not h:
            return None
        if is_ip_literal(h):
            return self.match_ip(h)
        return self.match_domain(h)

    def match_ip(self, ip_str: str) -> Optional[str]:
        s = ip_str.strip().lower()
        if s in self._exact_map:
            return self._exact_map[s]
        try:
            ip_obj = ipaddress.ip_address(s)
        except ValueError:
            return None
        for net, name in self._cidr:
            if ip_obj.version != net.version:
                continue
            if ip_obj in net:
                return name
        return None


def load_warninglists() -> WarninglistIndex:
    wl = WarninglistIndex()
    wl.load()
    return wl
