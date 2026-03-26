import re


def deobfuscate_text(text: str) -> str:
    t = text
    t = re.sub(r"\bhxxps\b", "https", t, flags=re.IGNORECASE)
    t = re.sub(r"\bhxxp\b", "http", t, flags=re.IGNORECASE)
    t = t.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    t = t.replace("[:]", ":").replace("[://]", "://")
    t = re.sub(r"\s+\(dot\)\s+", ".", t, flags=re.IGNORECASE)
    t = re.sub(r"\s+dot\s+", ".", t, flags=re.IGNORECASE)
    return t


def strip_trailing_punct(s: str) -> str:
    return s.strip().strip(".,;:!?)]}\"'\u201d\u2019")


def normalize_domain(d: str) -> str:
    return strip_trailing_punct(d).lower().strip(".")


def normalize_url(u: str) -> str:
    return strip_trailing_punct(u)


def normalize_hash(h: str) -> str:
    return strip_trailing_punct(h).lower()
