import json
import time
from typing import Dict, List, Set

from .constants import APP_NAME, APP_VERSION, PROJECT_URL, IOC_TYPES_ORDER
from .low_confidence import LowConfidenceItem


def _now_date_time_local():
    return time.strftime("%Y-%m-%d"), time.strftime("%H:%M:%S")


def write_txt(
    out_path: str,
    source: str,
    iocs: Dict[str, Set[str]],
    low_conf: List[LowConfidenceItem],
    user_agent: str,
) -> None:
    date_s, time_s = _now_date_time_local()
    title = f"{APP_NAME} Run Log"
    underline = "=" * len(title)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"{title}\n{underline}\n\n")
        f.write(f"[#] {'Target:':<12} {source}\n")
        f.write(f"[#] {'Date:':<12} {date_s}\n")
        f.write(f"[#] {'Time:':<12} {time_s}\n")
        f.write(f"[#] {'User-Agent:':<12} {user_agent}\n")
        f.write(f"[#] {'Output File:':<12} {out_path}\n\n")

        f.write("-------\n")
        f.write("Results\n")
        f.write("-------\n\n")

        for t in IOC_TYPES_ORDER:
            vals = sorted(iocs.get(t, set()))
            if not vals:
                continue
            f.write(f"[#] {t.upper()} ({len(vals)})\n")
            for v in vals:
                f.write(f"{v}\n")
            f.write("\n")

        f.write("-----------------------\n")
        f.write("Low-Confidence (Review)\n")
        f.write("-----------------------\n\n")

        if not low_conf:
            f.write("(none)\n")
            return

        grouped: Dict[str, List[LowConfidenceItem]] = {}
        for item in low_conf:
            grouped.setdefault(item.ioc_type, []).append(item)

        for t in sorted(grouped.keys()):
            f.write(f"[#] {t.upper()} ({len(grouped[t])})\n")
            for item in grouped[t]:
                f.write(f"{item.value} >> {item.reason}\n")
            f.write("\n")


def write_json(
    out_path: str,
    source: str,
    iocs: Dict[str, Set[str]],
    low_conf: List[LowConfidenceItem],
) -> None:
    payload = {
        "source": source,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "counts": {t: len(iocs.get(t, set())) for t in IOC_TYPES_ORDER},
        "iocs": {t: sorted(iocs.get(t, set())) for t in IOC_TYPES_ORDER},
        "low_confidence": [
            {"type": x.ioc_type, "value": x.value, "reason": x.reason}
            for x in low_conf
        ],
        "notice": "This tool may produce false positives. Review output before ingestion.",
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
