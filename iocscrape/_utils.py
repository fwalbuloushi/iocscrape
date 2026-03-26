import json
import os
from typing import Optional


def ensure_dir(p: str) -> None:
    os.makedirs(p, exist_ok=True)


def load_json_file(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None
