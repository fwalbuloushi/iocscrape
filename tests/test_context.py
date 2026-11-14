import json

from iocscrape.low_confidence import compute_context, compute_low_confidence
from iocscrape.warninglist import WarninglistIndex, load_warninglists
from iocscrape.writers import write_json


def _iocs(**kw):
    base = {"domain": set(), "url": set(), "ipv4": set(), "ipv6": set(), "email": set(), "md5": set(), "sha1": set(), "sha256": set(), "cve": set()}
    base.update(kw)
    return base


def _write_lists(tmp_path, monkeypatch, lists):
    """lists: {list_id: (name, [entries])}"""
    for list_id, (name, entries) in lists.items():
        d = tmp_path / "lists" / list_id
        d.mkdir(parents=True)
        (d / "list.json").write_text(json.dumps({"name": name, "list": entries}), encoding="utf-8")
    monkeypatch.setattr(WarninglistIndex, "_pick_warninglists_base_dir", staticmethod(lambda: str(tmp_path)))
    return load_warninglists()


def test_hosting_ip_stays_in_results_with_context(tmp_path, monkeypatch):
    wl = _write_lists(tmp_path, monkeypatch, {"vultr": ("Vultr ranges", ["45.77.0.0/16"])})
    iocs = _iocs(ipv4={"45.77.1.1"})
    assert compute_low_confidence(iocs, wl) == []
    ctx = compute_context(iocs, wl)
    assert [(c.value, c.note) for c in ctx] == [("45.77.1.1", "Vultr ranges")]

def test_tor_exit_node_not_demoted(tmp_path, monkeypatch):
    wl = _write_lists(tmp_path, monkeypatch, {"tor-exit-nodes": ("Tor exit nodes", ["185.220.101.1"])})
    iocs = _iocs(ipv4={"185.220.101.1"})
    assert compute_low_confidence(iocs, wl) == []
    assert compute_context(iocs, wl)[0].note == "Tor exit nodes"

def test_dynamic_dns_subdomain_gets_context_but_service_domain_is_demoted(tmp_path, monkeypatch):
    wl = _write_lists(tmp_path, monkeypatch, {"dynamic-dns": ("Dynamic DNS", ["duckdns.org"])})
    iocs = _iocs(domain={"attacker.duckdns.org", "duckdns.org"})
    low = {x.value for x in compute_low_confidence(iocs, wl)}
    assert low == {"duckdns.org"}
    iocs["domain"].discard("duckdns.org")
    ctx = compute_context(iocs, wl)
    assert [(c.value, c.note) for c in ctx] == [("attacker.duckdns.org", "Dynamic DNS")]

def test_personal_email_not_demoted_by_top_sites(tmp_path, monkeypatch):
    wl = _write_lists(tmp_path, monkeypatch, {
        "tranco": ("Top sites", ["gmail.com"]),
        "personal-email-domains": ("Personal email domains", ["gmail.com"]),
    })
    iocs = _iocs(email={"attacker@gmail.com"})
    assert compute_low_confidence(iocs, wl) == []
    assert compute_context(iocs, wl)[0].note == "Personal email domains"

def test_demoting_list_wins_over_context(tmp_path, monkeypatch):
    wl = _write_lists(tmp_path, monkeypatch, {
        "cloudflare": ("Cloudflare ranges", ["104.16.0.0/13"]),
        "datacenter-ipv4": ("Datacenters", ["104.16.0.0/12"]),
    })
    iocs = _iocs(ipv4={"104.21.3.4"})
    low = compute_low_confidence(iocs, wl)
    assert [(x.value, x.reason) for x in low] == [("104.21.3.4", "Warninglist: Cloudflare ranges")]

def test_json_output_has_context_key(tmp_path, monkeypatch):
    wl = _write_lists(tmp_path, monkeypatch, {"vultr": ("Vultr ranges", ["45.77.0.0/16"])})
    iocs = _iocs(ipv4={"45.77.1.1"})
    out = tmp_path / "out.json"
    write_json(str(out), "test", iocs, [], context=compute_context(iocs, wl))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["context"] == [{"type": "ipv4", "value": "45.77.1.1", "note": "Vultr ranges"}]

def test_url_on_shortener_not_demoted_by_top_sites(tmp_path, monkeypatch):
    wl = _write_lists(tmp_path, monkeypatch, {
        "tranco": ("Top sites", ["bit.ly"]),
        "url-shortener": ("URL shorteners", ["bit.ly"]),
    })
    iocs = _iocs(url={"https://bit.ly/3xYzAbc"})
    assert compute_low_confidence(iocs, wl) == []
    assert compute_context(iocs, wl)[0].note == "URL shorteners"
