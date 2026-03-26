import io
import json
import os
import time
import urllib.request
import zipfile

from .constants import (
    APP_NAME, APP_VERSION,
    CACHE_DIR, CACHE_META_FILE, CACHE_PSL_FILE, CACHE_WARNINGLISTS_DIR,
    MISP_WARNINGLISTS_ZIP, PSL_URL,
)
from ._utils import ensure_dir


def update_psl_to_cache(timeout: int = 15) -> None:
    ensure_dir(CACHE_DIR)
    req = urllib.request.Request(
        PSL_URL,
        headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}", "Accept-Encoding": "identity"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    if len(data) < 1000:
        raise RuntimeError("PSL update failed: unexpected content downloaded.")
    with open(CACHE_PSL_FILE, "wb") as f:
        f.write(data)


def update_warninglists_to_cache(timeout: int = 15) -> None:
    ensure_dir(CACHE_WARNINGLISTS_DIR)
    req = urllib.request.Request(
        MISP_WARNINGLISTS_ZIP,
        headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}", "Accept-Encoding": "identity"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()

    extracted = 0
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for m in z.namelist():
            if not m.endswith(".json"):
                continue
            if "/lists/" not in m:
                continue
            rel = m.split("/lists/", 1)[1]
            out_path = os.path.join(CACHE_WARNINGLISTS_DIR, "lists", rel)
            ensure_dir(os.path.dirname(out_path))
            with z.open(m) as src, open(out_path, "wb") as dst:
                dst.write(src.read())
            extracted += 1

    if extracted == 0:
        raise RuntimeError("Warninglists update failed: no lists/**/*.json extracted.")


def write_cache_meta() -> None:
    ensure_dir(CACHE_DIR)
    try:
        with open(CACHE_META_FILE, "r", encoding="utf-8") as f:
            meta = json.load(f)
    except Exception:
        meta = {}
    meta["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    meta["warninglists_zip"] = MISP_WARNINGLISTS_ZIP
    meta["psl_url"] = PSL_URL
    with open(CACHE_META_FILE, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
