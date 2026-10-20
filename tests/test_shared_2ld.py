"""shared_2ld の供給: 同一夜の検索結果ホスト名から 2LD の使い回しを数える。

`count_2ld` (twold_corpus.py) の正規化・除外規則、features の閾値 (>=3)、
probe.Pipeline への注入、hunter が生ホスト名を集めて同じ夜の probe に渡すところまで。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import hunter
import probe
import pytest
from features import extract_features
from twold_corpus import PLATFORM_2LDS, count_2ld

HTML = """<html><head><title>中古PC 販売</title></head>
<body><a href="/product/123456">商品</a></body></html>"""


# --- count_2ld ---


def test_count_2ld_counts_distinct_hosts_not_occurrences():
    assert count_2ld(["store.x.casa", "mart.x.casa", "store.x.casa"]) == {"x.casa": 2}
    assert count_2ld(["store.x.casa", "mart.x.casa", "shop.x.casa"]) == {"x.casa": 3}


def test_count_2ld_normalises_case_port_and_trailing_dot():
    counts = count_2ld(["STORE.X.CASA:443.", "store.x.casa", "Mart.X.Casa:8443"])
    assert counts == {"x.casa": 2}
    # 3 件目が別ホストとして数えられていること (正規化で 1 件に潰れていない)
    counts = count_2ld(["STORE.X.CASA:443.", "store.x.casa", "mart.x.casa"])
    assert counts == {"x.casa": 2}


def test_count_2ld_folds_idn_unicode_and_punycode_spellings():
    """同じ IDN の Unicode 表記と punycode 表記を同一ホストに畳む。"""
    counts = count_2ld(["a.例え.jp", "b.xn--r8jz45g.jp", "c.xn--r8jz45g.jp"])
    assert counts == {"xn--r8jz45g.jp": 3}
    # Unicode 側だけでも punycode 側と同じ 2LD に集約される
    assert count_2ld(["a.例え.jp", "b.例え.jp"]) == {"xn--r8jz45g.jp": 2}


def test_count_2ld_strips_userinfo():
    """`user@host` の userinfo はホスト名ではない (別ホストとして数えない)。"""
    assert count_2ld(["alice@shop1.x.casa", "bob@shop1.x.casa", "carol@shop1.x.casa"]) == {}
    assert count_2ld(["alice@shop1.x.casa", "bob@shop2.x.casa"]) == {"x.casa": 2}


def test_count_2ld_excludes_multi_tenant_platforms():
    assert count_2ld(["a.fc2.com", "b.fc2.com", "c.fc2.com"]) == {}
    for platform in PLATFORM_2LDS:
        assert platform in {
            "fc2.com",
            "hatenablog.com",
            "blogspot.com",
            "wordpress.com",
            "ameblo.jp",
            "livedoor.blog",
            "github.io",
            "note.com",
        }
        assert count_2ld([f"a.{platform}", f"b.{platform}", f"c.{platform}"]) == {}


def test_count_2ld_skips_invalid_hosts_and_singletons():
    assert count_2ld(["", "  ", "localhost", "bad host.example", "x" * 300 + ".example"]) == {}
    # 1 ホストだけの 2LD は返さない
    assert count_2ld(["only.x.casa"]) == {}
    # 不正な要素が混ざっても例外にしない
    assert count_2ld(["a.x.casa", None, "b.x.casa"]) == {"x.casa": 2}


# --- features の境界 ---


def _fres(url="https://a.x.casa/item", body=HTML, status=200):
    from fetch import FetchResult

    return FetchResult(
        url=url,
        status=status,
        final_url=url,
        chain=[(status, url)],
        headers={"content-type": "text/html"},
        body=body,
        html_sanitized=body,
        charset="utf-8",
        discarded=False,
        raw_bytes=len(body or ""),
    )


def test_features_threshold_is_three_hosts():
    two = extract_features("a.x.casa", _fres(), domain_2ld_counts={"x.casa": 2})
    three = extract_features("a.x.casa", _fres(), domain_2ld_counts={"x.casa": 3})
    assert two.shared_2ld is False
    assert three.shared_2ld is True


# --- Pipeline への注入 ---


@pytest.fixture()
def fake_fetch(monkeypatch):
    def _fetch(url, **kw):
        return _fres(url=url)

    monkeypatch.setattr(probe, "fetch", _fetch, raising=False)


def test_pipeline_accepts_2ld_counts_and_fires(fake_fetch, tmp_path):
    p = probe.Pipeline(db_dir=tmp_path, domain_2ld_counts={"a.example": 3})
    res = p.run_domain("a.example")
    assert res.features["shared_2ld"] is True


def test_pipeline_defaults_to_no_2ld_counts(fake_fetch, tmp_path):
    # 既定 (None) では発火しない
    res = probe.Pipeline(db_dir=tmp_path).run_domain("a.example")
    assert res.features["shared_2ld"] is False


def test_set_2ld_counts_updates_behaviour_after_construction(fake_fetch, tmp_path):
    p = probe.Pipeline(db_dir=tmp_path)
    assert p.run_domain("a.example").features["shared_2ld"] is False
    p.set_2ld_counts({"a.example": 3})
    assert p.run_domain("a.example").features["shared_2ld"] is True
    p.set_2ld_counts(None)
    assert p.run_domain("a.example").features["shared_2ld"] is False


# --- hunter の配線: 同一夜の生ホスト名が apex の probe に届く ---


@dataclass
class _Result:
    domain: str
    score: float = 0.0
    reasons: dict = field(default_factory=dict)
    decision: str = "dismissed"
    features: dict = field(default_factory=dict)


class _CollectingPipeline:
    def __init__(self):
        self.probed: list[str] = []
        self.counts: list[dict[str, int]] = []

    def set_2ld_counts(self, counts):
        self.counts.append(dict(counts or {}))

    def run_domain(self, domain):
        self.probed.append(domain)
        return _Result(domain)


class _Searx:
    def __init__(self, urls):
        self.urls = urls

    def search(self, query, *, pageno):
        return [{"url": u, "title": "t"} for u in self.urls]


class _SeqSearx:
    """クエリごとに違う結果を返す (同じ夜の別クエリでホストが増える状況)。"""

    def __init__(self, batches):
        self.batches = list(batches)
        self.calls = 0

    def search(self, query, *, pageno):
        batch = self.batches[min(self.calls, len(self.batches) - 1)]
        self.calls += 1
        return [{"url": u, "title": "t"} for u in batch]


@pytest.fixture()
def empty_store(tmp_path):
    from scamstore import ScamStore

    return ScamStore(tmp_path / "scam.db")


class _RecordingPipeline:
    """実 Pipeline に委譲しつつ、注入された counts と features の両方を見る。"""

    def __init__(self, inner):
        self.inner = inner
        self.counts: list[dict[str, int]] = []

    def set_2ld_counts(self, counts):
        self.counts.append(dict(counts or {}))
        self.inner.set_2ld_counts(counts)

    def run_domain(self, domain):
        return self.inner.run_domain(domain)


def _store_features(store, domain: str) -> dict:
    row = store.get(domain)
    assert row is not None, f"{domain} が記録されていない"
    return json.loads(row["features_json"])


def _night(empty_store, tmp_path, pipeline, urls=None, *, searx=None):
    return hunter.run_night(
        night="2026-10-20",
        searx=searx if searx is not None else _Searx(urls),
        pipeline=pipeline,
        store=empty_store,
        db_dir=tmp_path,
        max_queries=3,
    )


def test_hunter_supplies_sibling_hosts_of_same_night(empty_store, tmp_path):
    pipe = _CollectingPipeline()
    _night(
        empty_store,
        tmp_path,
        pipe,
        [
            "https://shop1.night9zz.test/item/1",
            "https://shop2.night9zz.test/item/2",
            "https://shop3.night9zz.test/item/3",
        ],
    )
    assert pipe.counts, "set_2ld_counts が呼ばれていない"
    assert pipe.counts[-1] == {"night9zz.test": 3}
    # apex 1 回だけ probe される (既存の重複排除は維持)
    assert pipe.probed == ["night9zz.test"]


def test_hunter_counts_raw_hosts_when_same_apex_is_already_seen(empty_store, tmp_path):
    """2 件目以降は seen_domains で probe されないが、ホスト数には数える。"""
    pipe = _CollectingPipeline()
    # 1 本目で apex は seen になる。2 本目以降のクエリで別サブドメインが
    # 出ても、生ホスト名の集計には足され続けること。
    searx = _SeqSearx(
        [
            ["https://shop1.night9zz.test/item/1"],
            ["https://shop2.night9zz.test/item/2", "https://shop3.night9zz.test/x"],
        ]
    )
    _night(empty_store, tmp_path, pipe, searx=searx)
    assert pipe.probed == ["night9zz.test"]
    assert pipe.counts[-1]["night9zz.test"] == 3


def test_hunter_does_not_count_whitelisted_hosts(empty_store, tmp_path):
    pipe = _CollectingPipeline()
    _night(
        empty_store,
        tmp_path,
        pipe,
        [
            "https://a.panasonic.jp/x",
            "https://b.panasonic.jp/x",
            "https://c.panasonic.jp/x",
            "https://shop1.night9zz.test/x",
            "https://shop2.night9zz.test/x",
        ],
    )
    assert pipe.counts, "set_2ld_counts が呼ばれていない"
    assert set(pipe.counts[-1]) == {"night9zz.test"}
    assert "panasonic.jp" not in pipe.counts[-1]


# --- hunter 経由で count_2ld の正規化・プラットフォーム除外が効く ---


def test_hunter_excludes_platform_2ld_from_shared_2ld(fake_fetch, empty_store, tmp_path):
    """*.livedoor.blog が 3 本出ても shared_2ld は立たない (hunter 経路)。"""
    pipe = _RecordingPipeline(probe.Pipeline(db_dir=tmp_path))
    _night(
        empty_store,
        tmp_path,
        pipe,
        [
            "https://a.livedoor.blog/item/1",
            "https://b.livedoor.blog/item/2",
            "https://c.livedoor.blog/item/3",
        ],
    )
    assert pipe.counts, "set_2ld_counts が呼ばれていない"
    assert pipe.counts[-1] == {}
    assert _store_features(empty_store, "livedoor.blog")["shared_2ld"] is False


def test_hunter_normalises_trailing_dot_and_port_hosts(fake_fetch, empty_store, tmp_path):
    """末尾ドット・ポート表記は同一ホストに畳む (3 -> 2 で shared_2ld は立たない)。"""
    pipe = _RecordingPipeline(probe.Pipeline(db_dir=tmp_path))
    _night(
        empty_store,
        tmp_path,
        pipe,
        [
            "https://s1.tdot.test./item/1",
            "https://s1.tdot.test:8443/item/2",
            "https://s2.tdot.test/item/3",
        ],
    )
    assert pipe.counts, "set_2ld_counts が呼ばれていない"
    assert pipe.counts[-1] == {"tdot.test": 2}
    assert _store_features(empty_store, "tdot.test")["shared_2ld"] is False


def test_hunter_ignores_userinfo_when_counting_hosts(fake_fetch, empty_store, tmp_path):
    """`user@host` の userinfo を別ホストとして数えない (同一ホスト 3 本 → 立たない)。"""
    pipe = _CollectingPipeline()
    _night(
        empty_store,
        tmp_path,
        pipe,
        [
            "https://alice@shop1.x.casa/item/1",
            "https://bob@shop1.x.casa/item/2",
            "https://carol@shop1.x.casa/item/3",
        ],
    )
    assert pipe.counts, "set_2ld_counts が呼ばれていない"
    assert pipe.counts[-1] == {}
    assert pipe.probed == ["x.casa"]


def test_hunter_counts_distinct_hosts_despite_userinfo(fake_fetch, empty_store, tmp_path):
    """userinfo を落としても別ホストは別々に数える (畳みすぎない)。"""
    pipe = _CollectingPipeline()
    _night(
        empty_store,
        tmp_path,
        pipe,
        [
            "https://alice@shop1.x.casa/item/1",
            "https://bob@shop2.x.casa/item/2",
            "https://carol@shop3.x.casa/item/3",
        ],
    )
    assert pipe.counts[-1] == {"x.casa": 3}


def test_hunter_resets_2ld_counts_on_empty_night(empty_store, tmp_path):
    """同じ Pipeline で 2 夜目が 0 件なら、前夜の counts を残さず {} を渡す。"""
    pipe = _CollectingPipeline()
    _night(
        empty_store,
        tmp_path,
        pipe,
        [
            "https://shop1.night9zz.test/item/1",
            "https://shop2.night9zz.test/item/2",
            "https://shop3.night9zz.test/item/3",
        ],
    )
    assert pipe.counts[-1] == {"night9zz.test": 3}

    _night(empty_store, tmp_path, pipe, urls=[])
    assert len(pipe.counts) >= 2, "空の夜でも set_2ld_counts が呼ばれていない"
    assert pipe.counts[-1] == {}
