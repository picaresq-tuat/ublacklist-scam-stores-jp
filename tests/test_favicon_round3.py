"""Round 3: generic favicon の実データ化 / corpus の集計単位 / origin 判定の対称性。

ネットワークは使わない (FakeTransport / monkeypatch / tmp_path のみ)。
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3

import probe
import pytest
from favicon_corpus import build_corpus
from features import GENERIC_FAVICON_MD5S, extract_features
from fetch import FetchResult, fetch, looks_like_image_bytes

ICO = b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x20\x00" + b"\x00" * 70
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 60
HTML_404 = b"<html><head><title>404 Not Found</title></head><body>nginx</body></html>"
WORDPRESS_ORG_FAVICON_MD5 = "53a151ba1af3acdefe16fbbdad937ee4"


class FakeResponse:
    def __init__(self, url, status=200, headers=None, body=b""):
        self.url = url
        self.status = status
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.body = body


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)

    def open(self, url, *, method="GET", headers=None, timeout=20.0):
        return self.responses.pop(0)


def _page(url: str) -> FetchResult:
    return FetchResult(url=url, status=200, final_url=url)


def public_resolver(host):
    return [".".join(["1", "1", "1", "1"])]


def _make_db(tmp_path, rows, name="scam.db"):
    db = tmp_path / name
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE decisions (domain TEXT, features_json TEXT, decision TEXT)")
    con.executemany("INSERT INTO decisions VALUES (?, ?, ?)", rows)
    con.commit()
    con.close()
    return db


def _row(domain, md5, *, source="raw", decision="block", extra=None):
    feats = {"favicon_md5": md5}
    if source is not None:
        feats["favicon_source"] = source
    feats.update(extra or {})
    return (domain, json.dumps(feats), decision)


# --- generic 集合そのもの ---


def test_generic_set_entries_are_md5_hex():
    """プレースホルダ (ダミー文字列) が混ざれば落ちる。"""
    bad = [v for v in GENERIC_FAVICON_MD5S if not re.fullmatch(r"[0-9a-f]{32}", v)]
    assert bad == []


def test_generic_set_contains_real_wordpress_favicon():
    """wordpress.org/favicon.ico の実測 md5 (2026-10-20 取得) を含む。"""
    assert WORDPRESS_ORG_FAVICON_MD5 in GENERIC_FAVICON_MD5S


def test_generic_set_does_not_contain_the_old_placeholder():
    assert "dummy-placeholder-not-a-real-hash" not in GENERIC_FAVICON_MD5S


@pytest.mark.parametrize("generic", sorted(GENERIC_FAVICON_MD5S))
def test_build_corpus_excludes_every_generic_hash(tmp_path, generic):
    from favicon_corpus import build_corpus

    db = _make_db(tmp_path, [_row("a.example", generic), _row("b.example", generic)])
    counts, origins = build_corpus(db)
    assert generic not in counts
    assert generic not in origins


# --- corpus の集計単位 (registrable domain) ---


def test_build_corpus_counts_registrable_domains_not_hosts(tmp_path):
    from favicon_corpus import build_corpus

    md5 = hashlib.md5(ICO).hexdigest()
    db = _make_db(
        tmp_path,
        [
            _row("www.a.example", md5),
            _row("shop.a.example", md5),  # 同一 registrable なので 1
            _row("a.example", md5),
        ],
    )
    counts, origins = build_corpus(db)
    assert counts[md5] == 1
    assert origins[md5] == ["a.example"]


def test_build_corpus_counts_two_registrable_domains(tmp_path):
    from favicon_corpus import build_corpus

    md5 = hashlib.md5(ICO).hexdigest()
    db = _make_db(tmp_path, [_row("a.example", md5), _row("b.example", md5)])
    counts, origins = build_corpus(db)
    assert counts[md5] == 2
    assert origins[md5] == ["a.example", "b.example"]


def test_build_corpus_collision_uses_only_block_and_hold(tmp_path):
    from favicon_corpus import build_corpus

    md5 = hashlib.md5(ICO).hexdigest()
    db = _make_db(
        tmp_path,
        [
            _row("a.example", md5, decision="block"),
            _row("b.example", md5, decision="dismissed"),
            _row("c.example", md5, decision="hold"),
        ],
    )
    counts, origins = build_corpus(db)
    # collision は「既知の悪性」2 件のみで数える (dismissed は数えない)
    assert counts[md5] == 2
    # cross_origin は dismissed も含めた全観測から代表を出す
    assert origins[md5] == ["a.example", "b.example", "c.example"]


def test_build_corpus_handles_none_path():
    from favicon_corpus import build_corpus

    assert build_corpus(None) == ({}, {})


def test_build_corpus_handles_special_chars_in_path(tmp_path):
    from favicon_corpus import build_corpus

    d = tmp_path / "db #1 50%"
    d.mkdir()
    md5 = hashlib.md5(ICO).hexdigest()
    db = _make_db(d, [_row("a.example", md5), _row("b.example", md5)])
    counts, _ = build_corpus(db)
    assert counts[md5] == 2


# --- cross_origin の対称性 ---


def test_cross_origin_is_symmetric_between_corpus_members():
    md5 = hashlib.md5(ICO).hexdigest()
    origins = {md5: ["a.example", "b.example"]}
    fa = extract_features(
        "a.example",
        _page("https://a.example/"),
        favicon_bytes=ICO,
        favicon_origin_map=origins,
    )
    fb = extract_features(
        "b.example",
        _page("https://b.example/"),
        favicon_bytes=ICO,
        favicon_origin_map=origins,
    )
    assert (fa.favicon_cross_origin, fa.favicon_cross_origin_of) == (True, "b.example")
    assert (fb.favicon_cross_origin, fb.favicon_cross_origin_of) == (True, "a.example")


def test_cross_origin_skips_same_registrable_and_picks_other():
    md5 = hashlib.md5(ICO).hexdigest()
    origins = {md5: ["shop.example", "other.example"]}
    f = extract_features(
        "shop.example",
        _page("https://shop.example/"),
        favicon_bytes=ICO,
        favicon_origin_map=origins,
    )
    assert f.favicon_cross_origin is True
    assert f.favicon_cross_origin_of == "other.example"


def test_origin_map_accepts_legacy_string_value():
    md5 = hashlib.md5(ICO).hexdigest()
    f = extract_features(
        "shop.example",
        _page("https://shop.example/"),
        favicon_bytes=ICO,
        favicon_origin_map={md5: "HTTPS://Legit.Example."},
    )
    assert f.favicon_cross_origin is True
    assert f.favicon_cross_origin_of == "legit.example"


def test_origin_normalisation_handles_protocol_relative_and_invalid():
    from features import _normalise_origin

    assert _normalise_origin("//Legit.Example./path") == "legit.example"
    assert _normalise_origin("https://[::1") == ""
    assert _normalise_origin("https://" + "a" * 300 + ".example") == ""
    assert _normalise_origin(None) == ""


# --- probe: favicon 取得の例外・truncate ---


class _FakeFavResult:
    def __init__(self, url, *, status=200, raw=b"", ctype="image/x-icon", truncated=False):
        self._r = FetchResult(
            url=url,
            status=status,
            final_url=url,
            headers={"content-type": ctype},
            raw_bytes=len(raw),
            truncated=truncated,
        )
        self._r.raw = raw

    def __getattr__(self, name):
        return getattr(self._r, name)


def _install(monkeypatch, fav):
    def _fetch(url, **kw):
        if url.endswith("/favicon.ico"):
            if isinstance(fav, Exception):
                raise fav
            return fav
        return _FakeFavResult(url, raw=b"<html>shop</html>", ctype="text/html")

    monkeypatch.setattr(probe, "fetch", _fetch, raising=False)


def test_probe_ignores_unexpected_favicon_fetch_error(monkeypatch, tmp_path):
    _install(monkeypatch, RuntimeError("boom"))
    res = probe.Pipeline(db_dir=tmp_path).run_domain("shop.example")
    assert res.features["favicon_md5"] is None
    assert res.decision == "dismissed"


def test_probe_skips_truncated_favicon(monkeypatch, tmp_path):
    _install(
        monkeypatch, _FakeFavResult("https://shop.example/favicon.ico", raw=ICO, truncated=True)
    )
    feats = probe.Pipeline(db_dir=tmp_path).run_domain("shop.example").features
    assert feats["favicon_md5"] is None


# --- fetch: magic 判定の緩和/厳格化 ---


def test_xml_without_svg_is_not_an_image():
    assert (
        looks_like_image_bytes(b'<?xml version="1.0"?><Error><Code>NoSuchKey</Code></Error>')
        is False
    )
    assert (
        looks_like_image_bytes(b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>')
        is True
    )


def test_text_plain_png_is_accepted_with_allow_binary():
    transport = FakeTransport(
        [FakeResponse("https://shop.example/favicon.ico", 200, {"Content-Type": "text/plain"}, PNG)]
    )
    r = fetch(
        "https://shop.example/favicon.ico",
        transport=transport,
        resolver=public_resolver,
        allow_binary=True,
    )
    assert r.discarded is False
    assert r.raw == PNG


def test_build_corpus_supports_schema_without_decision(tmp_path):
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE decisions (domain TEXT, features_json TEXT)")
    md5 = "aa" * 16
    con.executemany(
        "INSERT INTO decisions VALUES (?, ?)",
        [
            ("a.example", json.dumps({"favicon_md5": md5, "favicon_source": "raw"})),
            ("b.example", json.dumps({"favicon_md5": md5, "favicon_source": "raw"})),
        ],
    )
    con.commit()
    con.close()
    counts, origins = build_corpus(db)
    assert counts[md5] == 2
    assert origins[md5] == ["a.example", "b.example"]
