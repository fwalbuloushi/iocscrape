import argparse
import os
import sys
import tempfile
from typing import List, Optional

from colorama import Fore, Style, init as colorama_init

from .constants import (
    APP_NAME, APP_VERSION, PROJECT_URL, APP_DESC,
    DEFAULT_TIMEOUT_SEC, DEFAULT_MAX_BYTES, DEFAULT_REDIRECT_LIMIT,
    CACHE_DIR, IOC_TYPES_ORDER,
)
from .datasets import update_psl_to_cache, update_warninglists_to_cache, write_cache_meta
from .deobfuscate import deobfuscate_text
from .extractor import extract_iocs
from .fetcher import fetch_url_bytes, decode_bytes, read_file_text, extract_article_text_from_html, looks_like_html
from .low_confidence import LowConfidenceItem, compute_low_confidence
from .warninglist import load_warninglists
from .writers import write_txt, write_json


# =========== #
# CLI styling #
# =========== #

def c_info(s: str) -> str:
    return f"{Style.BRIGHT}{Fore.CYAN}{s}{Style.RESET_ALL}"

def c_ok(s: str) -> str:
    return f"{Style.BRIGHT}{Fore.GREEN}{s}{Style.RESET_ALL}"

def _cli_line(msg: str) -> None:
    print(c_info("[#]"), msg)


# === #
# CLI #
# === #

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog=APP_NAME,
        description=f"{APP_NAME} v{APP_VERSION}: {APP_DESC}",
    )

    p.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    g = p.add_mutually_exclusive_group(required=False)
    g.add_argument("--url", help="URL to fetch and extract IOCs from")
    g.add_argument("--file", help="Local file path to extract IOCs from (txt, html, pdf, docx, xlsx)")

    p.add_argument("--out", help="Output file path (mandatory unless using --update alone)")
    p.add_argument("--format", default="txt", choices=["txt", "json"], help="Output format (default: txt)")
    p.add_argument("--update", action="store_true", help=f"Update datasets (MISP warninglists + PSL) in cache ({CACHE_DIR})")

    args = p.parse_args(argv)

    if not args.update:
        if not (args.url or args.file):
            p.error("one of --url or --file is required")
        if not args.out:
            p.error("--out is required")
    else:
        if (args.url or args.file) and not args.out:
            p.error("--out is required when using --update with --url/--file")

    return args


def main(argv: Optional[List[str]] = None) -> None:
    colorama_init(autoreset=True)
    args = parse_args(argv)

    if args.update:
        try:
            _cli_line(f"Updating datasets into: {CACHE_DIR}")
            update_warninglists_to_cache()
            update_psl_to_cache()
            write_cache_meta()
            _cli_line("Update complete.\n")
        except Exception as e:
            print(f"[ERROR] Update failed: {e}", file=sys.stderr)
            sys.exit(1)

        if not (args.url or args.file):
            return

    source = args.url if args.url else args.file
    user_agent = f"{APP_NAME}/{APP_VERSION} (+{PROJECT_URL})"

    _cli_line(f"{APP_NAME} v{APP_VERSION}")
    _cli_line(PROJECT_URL)
    _cli_line(APP_DESC)
    _cli_line(f"Target: {source}\n")

    try:
        if args.url:
            raw_bytes, final_url, headers = fetch_url_bytes(
                args.url,
                timeout=DEFAULT_TIMEOUT_SEC,
                max_bytes=DEFAULT_MAX_BYTES,
                redirect_limit=DEFAULT_REDIRECT_LIMIT,
            )
            ctype = headers.get("content-type", "").lower()
            url_ext = os.path.splitext(final_url)[1].lower().strip(".")
            use_ext = url_ext
            if "application/pdf" in ctype and use_ext != "pdf":
                use_ext = "pdf"
            elif "wordprocessingml" in ctype and use_ext != "docx":
                use_ext = "docx"
            elif "spreadsheetml" in ctype and use_ext != "xlsx":
                use_ext = "xlsx"

            if use_ext in ("pdf", "docx", "xlsx"):
                _cli_line(f"Detected binary format ({use_ext}). Downloading to temp file...")
                with tempfile.NamedTemporaryFile(delete=False, suffix=f".{use_ext}") as tmp:
                    tmp.write(raw_bytes)
                    tmp_path = tmp.name
                try:
                    raw = read_file_text(tmp_path)
                finally:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
            else:
                raw = decode_bytes(raw_bytes, headers)

            source = final_url
        else:
            raw = read_file_text(args.file)

        processed = raw
        if looks_like_html(raw):
            processed = extract_article_text_from_html(raw)

        text = deobfuscate_text(processed)
        iocs = extract_iocs(text)

        wl = load_warninglists()
        low_conf = compute_low_confidence(iocs, wl)

        low_unique = len({(x.ioc_type, x.value) for x in low_conf})
        for item in low_conf:
            if item.ioc_type in iocs:
                iocs[item.ioc_type].discard(item.value)

        final_total = sum(len(iocs.get(t, set())) for t in IOC_TYPES_ORDER)
        total_unique = final_total + low_unique

        out_path = args.out
        if args.format == "txt":
            write_txt(out_path, source, iocs, low_conf, user_agent=user_agent)
        else:
            write_json(out_path, source, iocs, low_conf)

        print(f"\n{c_info('Total Unique IOCs:')} {Style.BRIGHT}{total_unique}{Style.RESET_ALL}\n")
        print(c_ok("IOC results and log file have been saved into:"))
        print(out_path)

    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
