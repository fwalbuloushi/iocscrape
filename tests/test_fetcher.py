import gzip
import threading
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from iocscrape.fetcher import _decompress, fetch_url_bytes, looks_like_html


def test_plain_text_with_closing_tag_is_not_html():
    assert not looks_like_html("IOCs: evil.com 1.2.3.4\nsnippet: </script>")

def test_doctype_is_html():
    assert looks_like_html("<!DOCTYPE html><html><body>x</body></html>")

def test_html_tag_is_html():
    assert looks_like_html("  <html lang='en'><body>x</body></html>")


# ================= #
# Local test server #
# ================= #

class _Handler(BaseHTTPRequestHandler):
    # /r<N> redirects N times before landing on /ok
    def do_GET(self):
        if self.path.startswith("/r"):
            n = int(self.path[2:])
            self.send_response(302)
            self.send_header("Location", f"/r{n - 1}" if n > 1 else "/ok")
            self.end_headers()
        elif self.path == "/file":
            self.send_response(302)
            self.send_header("Location", "file:///etc/passwd")
            self.end_headers()
        else:
            body = b"hello evil.com"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_follows_redirects_within_limit(server):
    data, final_url, _ = fetch_url_bytes(f"{server}/r2", timeout=5, max_bytes=1000, redirect_limit=5)
    assert data == b"hello evil.com"
    assert final_url.endswith("/ok")

def test_too_many_redirects(server):
    with pytest.raises(RuntimeError, match="Too many redirects"):
        fetch_url_bytes(f"{server}/r6", timeout=5, max_bytes=1000, redirect_limit=5)

def test_rejects_file_scheme():
    with pytest.raises(RuntimeError, match="Unsupported URL scheme"):
        fetch_url_bytes("file:///etc/passwd", timeout=5, max_bytes=1000, redirect_limit=5)

def test_rejects_redirect_to_file_scheme(server):
    with pytest.raises(RuntimeError, match="Unsupported URL scheme"):
        fetch_url_bytes(f"{server}/file", timeout=5, max_bytes=1000, redirect_limit=5)


# ============= #
# Decompression #
# ============= #

def test_gzip_bomb_is_capped():
    bomb = gzip.compress(b"0" * 1_000_000)
    with pytest.raises(ValueError, match="Decompressed response exceeded"):
        _decompress(bomb, "gzip", max_bytes=1000)

def test_decompress_gzip_and_deflate():
    raw = b"evil.com 1.2.3.4"
    raw_deflate = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    raw_deflate = raw_deflate.compress(raw) + raw_deflate.flush()
    assert _decompress(gzip.compress(raw), "gzip", 1000) == raw
    assert _decompress(zlib.compress(raw), "deflate", 1000) == raw
    assert _decompress(raw_deflate, "deflate", 1000) == raw
    assert _decompress(raw, "", 1000) == raw
