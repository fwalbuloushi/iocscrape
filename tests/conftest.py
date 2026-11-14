import pytest


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    """Keep tests independent of the local ~/.cache/iocscrape (and fast)."""
    cache = tmp_path / "cache"
    monkeypatch.setattr("iocscrape.psl.CACHE_PSL_FILE", str(cache / "public_suffix_list.dat"))
    monkeypatch.setattr("iocscrape.warninglist.CACHE_WARNINGLISTS_DIR", str(cache / "warninglists"))
