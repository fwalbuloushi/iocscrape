from iocscrape.fetcher import looks_like_html


def test_plain_text_with_closing_tag_is_not_html():
    assert not looks_like_html("IOCs: evil.com 1.2.3.4\nsnippet: </script>")

def test_doctype_is_html():
    assert looks_like_html("<!DOCTYPE html><html><body>x</body></html>")

def test_html_tag_is_html():
    assert looks_like_html("  <html lang='en'><body>x</body></html>")
