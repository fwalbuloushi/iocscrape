from iocscrape.cli import extract_iocs


def test_url():
    iocs = extract_iocs("Payload was downloaded from https://malware.example.com/payload")
    assert "https://malware.example.com/payload" in iocs["url"]

def test_domain():
    iocs = extract_iocs("The threat actor used evil.example.com as a C2 server")
    assert "evil.example.com" in iocs["domain"]

def test_ipv4():
    iocs = extract_iocs("Beacon traffic was observed to 192.168.1.100 on port 443")
    assert "192.168.1.100" in iocs["ipv4"]

def test_ipv6():
    iocs = extract_iocs("C2 communication detected to 2001:db8::1 over port 8443")
    assert "2001:db8::1" in iocs["ipv6"]

def test_email():
    iocs = extract_iocs("Spear-phishing email was sent from attacker@evil.com")
    assert "attacker@evil.com" in iocs["email"]

def test_md5():
    iocs = extract_iocs("Malware sample identified with MD5: d41d8cd98f00b204e9800998ecf8427e")
    assert "d41d8cd98f00b204e9800998ecf8427e" in iocs["md5"]

def test_sha1():
    iocs = extract_iocs("Dropper hash SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709")
    assert "da39a3ee5e6b4b0d3255bfef95601890afd80709" in iocs["sha1"]

def test_sha256():
    iocs = extract_iocs("Ransomware binary SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in iocs["sha256"]

def test_cve():
    iocs = extract_iocs("The exploit targets CVE-2021-44228 to achieve remote code execution")
    assert "CVE-2021-44228" in iocs["cve"]

def test_sha256_not_in_sha1_or_md5():
    """A 64-char hash should only appear in sha256, not sha1 or md5."""
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    iocs = extract_iocs(h)
    assert h in iocs["sha256"]
    assert h not in iocs["sha1"]
    assert h not in iocs["md5"]

def test_sha1_not_in_md5():
    """A 40-char hash should only appear in sha1, not md5."""
    h = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    iocs = extract_iocs(h)
    assert h in iocs["sha1"]
    assert h not in iocs["md5"]
