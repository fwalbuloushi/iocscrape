import os
from typing import Optional

from publicsuffix2 import get_sld

from .constants import CACHE_PSL_FILE, BUNDLED_PSL_FILE
from .deobfuscate import normalize_domain
from .extractor import is_ip_literal


def psl_file_path() -> Optional[str]:
    if os.path.isfile(CACHE_PSL_FILE):
        return CACHE_PSL_FILE
    if os.path.isfile(BUNDLED_PSL_FILE):
        return BUNDLED_PSL_FILE
    return None


def psl_invalid_reason(domain: str) -> Optional[str]:
    d = normalize_domain(domain)

    if is_ip_literal(d):
        return None

    psl_path = psl_file_path()
    if not psl_path:
        return None

    if not d or "." not in d:
        return "invalid public suffix (PSL)"

    try:
        sld = get_sld(d, strict=True, psl_file=psl_path)
    except Exception:
        sld = None

    if not sld:
        return "invalid public suffix (PSL)"

    return None
