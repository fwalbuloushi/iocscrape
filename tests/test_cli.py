import json

from iocscrape.cli import main


def test_txt_with_html_snippet_keeps_iocs(tmp_path):
    src = tmp_path / "report.txt"
    src.write_text("C2: evil-c2-infra.com\nIP: 203.0.113.50\nSnippet: </script>\n", encoding="utf-8")
    out = tmp_path / "out.json"

    main(["--file", str(src), "--out", str(out), "--format", "json"])

    data = json.loads(out.read_text(encoding="utf-8"))
    assert "evil-c2-infra.com" in data["iocs"]["domain"]
