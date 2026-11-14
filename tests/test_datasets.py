import io
import json
import os
import zipfile

from iocscrape import datasets


class _FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _zip_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, content in members.items():
            z.writestr(name, content)
    return buf.getvalue()


def test_update_skips_path_traversal_and_replaces_cache(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    wl_dir = cache / "warninglists"
    (wl_dir / "lists" / "stale").mkdir(parents=True)
    (wl_dir / "lists" / "stale" / "list.json").write_text("{}", encoding="utf-8")

    payload = _zip_bytes({
        "misp-main/lists/good/list.json": json.dumps({"name": "Good", "list": ["a.com"]}),
        "misp-main/lists/../../../evil.json": "{}",
    })
    monkeypatch.setattr(datasets, "CACHE_DIR", str(cache))
    monkeypatch.setattr(datasets, "CACHE_WARNINGLISTS_DIR", str(wl_dir))
    monkeypatch.setattr(datasets.urllib.request, "urlopen", lambda req, timeout: _FakeResp(payload))

    datasets.update_warninglists_to_cache()

    assert (wl_dir / "lists" / "good" / "list.json").is_file()
    assert not (wl_dir / "lists" / "stale").exists()          # old lists removed
    assert not os.path.exists(tmp_path / "evil.json")          # traversal skipped
    assert not os.path.exists(cache / "evil.json")
    assert not os.path.exists(str(wl_dir) + ".tmp")
