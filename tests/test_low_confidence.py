import json
import os

from iocscrape.low_confidence import compute_low_confidence
from iocscrape.warninglist import load_warninglists, WarninglistIndex


def _wl():
    return load_warninglists()


def test_filename_like_domain_flagged():
    iocs = {"domain": {"malware.png"}, "url": set(), "ipv4": set(), "ipv6": set(), "email": set(), "md5": set(), "sha1": set(), "sha256": set(), "cve": set()}
    low = compute_low_confidence(iocs, _wl())
    values = [item.value for item in low]
    assert "malware.png" in values

def test_static_asset_url_flagged():
    iocs = {"domain": set(), "url": {"https://cdn.example.com/style.css"}, "ipv4": set(), "ipv6": set(), "email": set(), "md5": set(), "sha1": set(), "sha256": set(), "cve": set()}
    low = compute_low_confidence(iocs, _wl())
    values = [item.value for item in low]
    assert "https://cdn.example.com/style.css" in values

def test_private_ipv4_flagged():
    iocs = {"domain": set(), "url": set(), "ipv4": {"10.0.0.1"}, "ipv6": set(), "email": set(), "md5": set(), "sha1": set(), "sha256": set(), "cve": set()}
    low = compute_low_confidence(iocs, _wl())
    values = [item.value for item in low]
    assert "10.0.0.1" in values

def test_loopback_ipv4_flagged():
    iocs = {"domain": set(), "url": set(), "ipv4": {"127.0.0.1"}, "ipv6": set(), "email": set(), "md5": set(), "sha1": set(), "sha256": set(), "cve": set()}
    low = compute_low_confidence(iocs, _wl())
    values = [item.value for item in low]
    assert "127.0.0.1" in values

def test_warninglist_domain_is_flagged():
    """A domain that is explicitly in the warninglist should be flagged as low-confidence."""
    wl = WarninglistIndex()
    wl._exact_map["google.com"] = "Test warninglist"
    iocs = {"domain": {"google.com"}, "url": set(), "ipv4": set(), "ipv6": set(), "email": set(), "md5": set(), "sha1": set(), "sha256": set(), "cve": set()}
    low = compute_low_confidence(iocs, wl)
    values = [item.value for item in low]
    assert "google.com" in values

def test_subdomain_of_warninglist_domain_is_flagged():
    """A subdomain of a warninglist entry should be flagged via suffix matching."""
    wl = WarninglistIndex()
    wl._exact_map["mitre.org"] = "Test warninglist"
    iocs = {"domain": {"sub.mitre.org"}, "url": set(), "ipv4": set(), "ipv6": set(), "email": set(), "md5": set(), "sha1": set(), "sha256": set(), "cve": set()}
    low = compute_low_confidence(iocs, wl)
    values = [item.value for item in low]
    assert "sub.mitre.org" in values

def test_bare_tld_in_warninglist_does_not_flag_all_domains():
    """A bare TLD entry in the warninglist (e.g. 'com') must not cause every
    .com domain to be flagged as low-confidence via suffix matching."""
    wl = WarninglistIndex()
    wl._exact_map["com"] = "IANA TLDs"
    iocs = {"domain": {"evil-c2.com"}, "url": set(), "ipv4": set(), "ipv6": set(), "email": set(), "md5": set(), "sha1": set(), "sha256": set(), "cve": set()}
    low = compute_low_confidence(iocs, wl)
    values = [item.value for item in low]
    assert "evil-c2.com" not in values

def test_new_static_asset_extensions_flagged():
    """URLs ending in font/image extensions added to STATIC_ASSET_EXTS
    (webp, ttf, eot, otf, bmp) should be flagged as low-confidence."""
    for ext in ("webp", "ttf", "eot", "otf", "bmp"):
        url = f"https://cdn.example.com/asset.{ext}"
        iocs = {"domain": set(), "url": {url}, "ipv4": set(), "ipv6": set(), "email": set(), "md5": set(), "sha1": set(), "sha256": set(), "cve": set()}
        low = compute_low_confidence(iocs, _wl())
        values = [item.value for item in low]
        assert url in values, f"Expected {url} to be low-confidence"

def test_ioc_domain_not_false_positive():
    """A real C2-style IOC domain whose parent is not in any warninglist
    should stay high-confidence and not be moved to low-confidence."""
    iocs = {"domain": {"c2-server.badactor-infra.com"}, "url": set(), "ipv4": set(), "ipv6": set(), "email": set(), "md5": set(), "sha1": set(), "sha256": set(), "cve": set()}
    low = compute_low_confidence(iocs, _wl())
    values = [item.value for item in low]
    assert "c2-server.badactor-infra.com" not in values

def test_bundled_psl_is_packaged():
    from iocscrape.constants import BUNDLED_PSL_FILE
    assert os.path.isfile(BUNDLED_PSL_FILE)

def test_public_suffix_parent_does_not_flag_subdomain():
    """Subdomains under public suffixes (co.uk, duckdns.org) must not match the suffix itself."""
    wl = WarninglistIndex()
    wl._exact_map["co.uk"] = "Second level TLDs"
    wl._exact_map["duckdns.org"] = "Top sites"
    iocs = {"domain": {"evil-c2.co.uk", "attacker.duckdns.org"}, "url": set(), "ipv4": set(), "ipv6": set(), "email": set(), "md5": set(), "sha1": set(), "sha256": set(), "cve": set()}
    low = compute_low_confidence(iocs, wl)
    values = [item.value for item in low]
    assert "evil-c2.co.uk" not in values
    assert "attacker.duckdns.org" not in values

def test_leading_dot_entry_matches_subdomain(tmp_path, monkeypatch):
    """Warninglist entries like '.example.org' should match subdomains."""
    lists_dir = tmp_path / "lists" / "test"
    lists_dir.mkdir(parents=True)
    (lists_dir / "list.json").write_text(json.dumps({"name": "Test list", "list": [".example.org"]}), encoding="utf-8")
    monkeypatch.setattr(WarninglistIndex, "_pick_warninglists_base_dir", staticmethod(lambda: str(tmp_path)))
    wl = load_warninglists()
    assert wl.match_domain("cdn.example.org") == "Test list"

def test_empty_file_hash_flagged():
    wl = WarninglistIndex()
    wl._exact_map["d41d8cd98f00b204e9800998ecf8427e"] = "List of known hashes for empty files"
    iocs = {"domain": set(), "url": set(), "ipv4": set(), "ipv6": set(), "email": set(), "md5": {"d41d8cd98f00b204e9800998ecf8427e"}, "sha1": set(), "sha256": set(), "cve": set()}
    low = compute_low_confidence(iocs, wl)
    assert [(x.value, x.reason) for x in low] == [("d41d8cd98f00b204e9800998ecf8427e", "Warninglist: List of known hashes for empty files")]

def test_unknown_hash_stays_high_confidence():
    wl = WarninglistIndex()
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856"
    iocs = {"domain": set(), "url": set(), "ipv4": set(), "ipv6": set(), "email": set(), "md5": set(), "sha1": set(), "sha256": {h}, "cve": set()}
    assert compute_low_confidence(iocs, wl) == []
