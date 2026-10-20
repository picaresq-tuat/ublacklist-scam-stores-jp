"""Round 2: favicon 供給の堅牢化 (soft-404 除外 / corpus 型矯正 / corpus 構築と配線)。

ネットワークは使わない。fetch は FakeTransport、probe は monkeypatch、
corpus は tmp_path の SQLite で検証する。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3

import probe
import pytest
from features import extract_features
from fetch import FetchResult, fetch

ICO = b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x20\x00" + b"\x00" * 70
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 60
WEBP = b"RIFF" + b"\x00\x00\x00\x00" + b"WEBPVP8 " + b"\x00" * 30
AVIF = b"\x00\x00\x00\x18ftypavif" + b"\x00" * 30
HTML_404 = b"<html><head><title>404 Not Found</title></head><body>nginx</body></html>"


class FakeResponse:
    def __init__(self, url, status=200, headers=None, body=b""):
        self.url = url
        self.status = status
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.body = body


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def open(self, url, *, method="GET", headers=None, timeout=20.0):
        self.calls.append(url)
        if not self.responses:
            raise AssertionError("FakeTransport ran out of queued responses")
        return self.responses.pop(0)


def public_resolver(host):
    return [".".join(["1", "1", "1", "1"])]


def _fetch_one(
    body, *, ctype, allow_binary=True, status=200, url="https://shop.example/favicon.ico"
):
    transport = FakeTransport([FakeResponse(url, status, {"Content-Type": ctype}, body)])
    return fetch(url, transport=transport, resolver=public_resolver, allow_binary=allow_binary)


# --- fetch: 画像 MIME の早期 return と octet-stream の magic 判定 ---


def test_image_mime_skips_html_decoding_and_keeps_raw_only():
    r = _fetch_one(PNG, ctype="image/png")
    assert r.discarded is False
    assert r.raw == PNG
    assert r.body is None, "画像を巨大な str にデコードしてはならない"


def test_modern_image_mimes_are_allowed_with_allow_binary():
    for ctype, body in (("image/webp", WEBP), ("image/avif", AVIF)):
        r = _fetch_one(body, ctype=ctype)
        assert r.discarded is False, ctype
        assert r.raw == body


def test_octet_stream_with_image_magic_is_accepted():
    r = _fetch_one(PNG, ctype="application/octet-stream")
    assert r.discarded is False
    assert r.raw == PNG


def test_octet_stream_without_image_magic_is_still_discarded():
    r = _fetch_one(HTML_404, ctype="application/octet-stream")
    assert r.discarded is True


def test_image_mime_is_still_discarded_without_allow_binary():
    r = _fetch_one(PNG, ctype="image/png", allow_binary=False)
    assert r.discarded is True


# --- probe: soft-404 / 非画像バイトを favicon として採用しない ---


class _FakeFavResult:
    def __init__(self, url, *, status=200, raw=b"", ctype="image/x-icon"):
        self._r = FetchResult(
            url=url,
            status=status,
            final_url=url,
            headers={"content-type": ctype},
            raw_bytes=len(raw),
        )
        self._r.raw = raw

    def __getattr__(self, name):
        return getattr(self._r, name)


@pytest.fixture()
def stub_probe_fetch(monkeypatch):
    """ページは常に 200 の HTML、favicon はテストが差し替える。"""

    def _install(fav):
        def _fetch(url, **kw):
            if url.endswith("/favicon.ico"):
                return fav
            return _FakeFavResult(url, raw=b"<html>shop</html>", ctype="text/html")

        monkeypatch.setattr(probe, "fetch", _fetch, raising=False)

    return _install


def test_probe_ignores_html_returned_for_favicon(stub_probe_fetch, tmp_path):
    stub_probe_fetch(
        _FakeFavResult(
            "https://shop.example/favicon.ico", status=404, raw=HTML_404, ctype="text/html"
        )
    )
    feats = probe.Pipeline(db_dir=tmp_path).run_domain("shop.example").features
    assert feats["favicon_md5"] is None
    assert feats["favicon_collision"] is False


def test_probe_ignores_non_image_bytes_labelled_as_image(stub_probe_fetch, tmp_path):
    stub_probe_fetch(
        _FakeFavResult("https://shop.example/favicon.ico", raw=HTML_404, ctype="image/x-icon")
    )
    feats = probe.Pipeline(db_dir=tmp_path).run_domain("shop.example").features
    assert feats["favicon_md5"] is None


def test_probe_accepts_real_icon_bytes_and_marks_source(stub_probe_fetch, tmp_path):
    stub_probe_fetch(_FakeFavResult("https://shop.example/favicon.ico", raw=ICO))
    feats = probe.Pipeline(db_dir=tmp_path).run_domain("shop.example").features
    assert feats["favicon_md5"] == hashlib.md5(ICO).hexdigest()
    assert feats["favicon_source"] == "raw"
    assert feats["favicon_bytes_len"] == len(ICO)


def test_probe_rejects_empty_and_tiny_favicon(stub_probe_fetch, tmp_path):
    for raw in (b"", b"\x00\x00\x01"):
        stub_probe_fetch(_FakeFavResult("https://shop.example/favicon.ico", raw=raw))
        feats = probe.Pipeline(db_dir=tmp_path).run_domain("shop.example").features
        assert feats["favicon_md5"] is None, raw


# --- features: 外部 corpus 値の型矯正 ---


def _browser(status=200):
    r = FetchResult(
        url="https://shop.example/",
        status=status,
        final_url="https://shop.example/",
        headers={"content-type": "text/html"},
        body="<html><title>shop</title></html>",
    )
    r.html_sanitized = r.body or ""
    return r


def test_corpus_values_with_wrong_types_never_raise():
    md5 = hashlib.md5(ICO).hexdigest()
    f = extract_features(
        "shop.example",
        _browser(),
        favicon_bytes=ICO,
        known_favicons={md5: "not-a-number"},
        favicon_origin_map={md5: 12345},
    )
    assert f.favicon_collision is False
    assert f.favicon_cross_origin is False


def test_numeric_string_count_is_honoured():
    md5 = hashlib.md5(ICO).hexdigest()
    f = extract_features("shop.example", _browser(), favicon_bytes=ICO, known_favicons={md5: "3"})
    assert f.favicon_collision is True


def test_scheme_origin_of_own_domain_is_not_cross_origin():
    md5 = hashlib.md5(ICO).hexdigest()
    f = extract_features(
        "shop.example",
        _browser(),
        favicon_bytes=ICO,
        favicon_origin_map={md5: "https://shop.example"},
    )
    assert f.favicon_cross_origin is False
    assert f.favicon_cross_origin_of == "shop.example"


def test_scheme_origin_of_other_domain_is_cross_origin():
    md5 = hashlib.md5(ICO).hexdigest()
    f = extract_features(
        "shop.example",
        _browser(),
        favicon_bytes=ICO,
        favicon_origin_map={md5: "HTTPS://Legit.Example."},
    )
    assert f.favicon_cross_origin is True


def test_favicon_source_is_none_without_bytes():
    f = extract_features("shop.example", _browser())
    assert f.favicon_source == ""
    assert f.favicon_bytes_len == 0


# --- favicon_corpus: 構築と永続層からの読み出し ---


def _make_db(tmp_path, rows):
    db = tmp_path / "scam.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE decisions (domain TEXT, features_json TEXT)")
    con.executemany("INSERT INTO decisions VALUES (?, ?)", rows)
    con.commit()
    con.close()
    return db


def _row(domain, md5, *, source="raw", extra=None):
    feats = {"favicon_md5": md5}
    if source is not None:
        feats["favicon_source"] = source
    feats.update(extra or {})
    return (domain, json.dumps(feats))


def test_build_corpus_counts_distinct_domains(tmp_path):
    from favicon_corpus import build_corpus

    md5 = hashlib.md5(ICO).hexdigest()
    db = _make_db(
        tmp_path,
        [
            _row("a.example", md5),
            _row("a.example", md5),  # 同一ドメインの再判定は 1 と数える
            _row("b.example", md5),
        ],
    )
    counts, origins = build_corpus(db)
    assert counts[md5] == 2
    assert origins[md5] == "a.example"


def test_build_corpus_ignores_legacy_records_without_raw_source(tmp_path):
    from favicon_corpus import build_corpus

    md5 = hashlib.md5(b"legacy-text-prefix").hexdigest()
    db = _make_db(
        tmp_path, [_row("a.example", md5, source=None), _row("b.example", md5, source=None)]
    )
    counts, origins = build_corpus(db)
    assert counts == {}
    assert origins == {}


def test_build_corpus_skips_generic_invalid_and_empty(tmp_path):
    from favicon_corpus import build_corpus
    from features import GENERIC_FAVICON_MD5S

    generic = sorted(GENERIC_FAVICON_MD5S)[0] if GENERIC_FAVICON_MD5S else "0" * 32
    db = _make_db(
        tmp_path,
        [
            _row("a.example", generic),
            _row("b.example", "not-a-hash"),
            ("c.example", "not-json"),
            ("d.example", json.dumps({"favicon_md5": None, "favicon_source": "raw"})),
        ],
    )
    counts, origins = build_corpus(db)
    assert generic not in counts
    assert "not-a-hash" not in counts
    assert counts == {}
    assert origins == {}


def test_build_corpus_on_missing_db_returns_empty(tmp_path):
    from favicon_corpus import build_corpus

    counts, origins = build_corpus(tmp_path / "nothing.db")
    assert counts == {} and origins == {}


# --- 配線: CLI と候補監視が corpus をパイプラインへ渡す ---


def test_cli_build_pipeline_injects_corpus(tmp_path, monkeypatch):
    import cli
    import favicon_corpus

    md5 = hashlib.md5(ICO).hexdigest()
    monkeypatch.setattr(favicon_corpus, "build_corpus", lambda p: ({md5: 2}, {md5: "a.example"}))
    monkeypatch.setattr(
        cli, "build_corpus", lambda p: ({md5: 2}, {md5: "a.example"}), raising=False
    )
    pipe = cli._build_pipeline(db_dir=tmp_path)
    assert pipe._favicon_counts == {md5: 2}
    assert pipe._favicon_origins == {md5: "a.example"}


def test_watchlist_probe_domains_injects_corpus(monkeypatch, tmp_path):
    import watchlist

    captured = {}
    md5 = hashlib.md5(ICO).hexdigest()

    class _Pipe:
        def __init__(self, **kw):
            captured.update(kw)

        def run_domain(self, dom):
            class _R:
                def __init__(self):
                    self.decision = "dismissed"
                    self.score = 0.0
                    self.reasons = {}
                    self.features = {}

            return _R()

    monkeypatch.setattr(probe, "Pipeline", _Pipe)
    import favicon_corpus

    monkeypatch.setattr(favicon_corpus, "build_corpus", lambda p: ({md5: 2}, {md5: "a.example"}))
    watchlist.probe_domains(["shop.example"], workers=1, db_path=tmp_path / "scam.db")
    assert captured["favicon_counts"] == {md5: 2}
    assert captured["favicon_origins"] == {md5: "a.example"}


def test_collision_fires_end_to_end_from_db_corpus(stub_probe_fetch, tmp_path):
    """DB の履歴 → corpus → Pipeline → 特徴量 まで実際に通し、collision が点灯する。"""
    import favicon_corpus

    md5 = hashlib.md5(ICO).hexdigest()
    db = _make_db(tmp_path, [_row("a.example", md5), _row("b.example", md5)])
    counts, origins = favicon_corpus.build_corpus(db)
    assert counts[md5] == 2
    stub_probe_fetch(_FakeFavResult("https://shop.example/favicon.ico", raw=ICO))
    pipe = probe.Pipeline(db_dir=tmp_path, favicon_counts=counts, favicon_origins=origins)
    feats = pipe.run_domain("shop.example").features
    assert feats["favicon_collision"] is True
    assert feats["favicon_cross_origin"] is True
    assert feats["favicon_cross_origin_of"] == "a.example"
