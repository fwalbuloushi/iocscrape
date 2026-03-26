from iocscrape.deobfuscate import deobfuscate_text


def test_hxxps():
    assert deobfuscate_text("hxxps://evil.com") == "https://evil.com"

def test_hxxp():
    assert deobfuscate_text("hxxp://evil.com") == "http://evil.com"

def test_dot_bracket():
    assert deobfuscate_text("evil[.]com") == "evil.com"

def test_dot_paren():
    assert deobfuscate_text("evil(.)com") == "evil.com"

def test_dot_brace():
    assert deobfuscate_text("evil{.}com") == "evil.com"

def test_dot_word():
    assert deobfuscate_text("evil dot com") == "evil.com"

def test_dot_word_with_spaces():
    assert deobfuscate_text("evil (dot) com") == "evil.com"

def test_colon_bracket():
    assert deobfuscate_text("hxxps[://]evil.com") == "https://evil.com"

def test_mixed():
    result = deobfuscate_text("hxxps://evil[.]com/path")
    assert result == "https://evil.com/path"

def test_no_change():
    original = "https://legitimate.com"
    assert deobfuscate_text(original) == original
