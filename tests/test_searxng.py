"""P2: SearXNG クライアント (Bing 主体 + pivot のみ Google CSE) の RED テスト。"""
import json

import pytest

from searxng import (
    PIVOT_ENGINES,
    PRIMARY_ENGINES,
    EngineUnavailable,
    SearxClient,
    SearxError,
)


def payload(results):
    return json.dumps({"results": results, "unresponsive_engines": []}).encode()


def make(pages=None, unresponsive=None):
    pages = pages or {}
    calls = []

    def http_get(url, timeout):
        calls.append(url)
        import urllib.parse as up
        q = up.parse_qs(up.urlsplit(url).query)
        key = (q.get("q", [""])[0], int(q.get("pageno", ["1"])[0]), q.get("engines", [""])[0])
        body = pages.get(key, payload([]))
        if unresponsive is not None:
            body = json.dumps({"results": [], "unresponsive_engines": unresponsive}).encode()
        return 200, body

    http_get.calls = calls
    return http_get


# --- 方針転換 (2026-09-24): Google CSE 主体へ切り替え ---
# Bing はページング非対応 (pageno>=2 で常に 0 件) のため、pageno ランダム化は
# ページング可能な Google CSE を主引擎として初めて機能する。
# 1 ページ目のみ Bing を併用 (Bing が応答できる唯一のページ)。

def test_engine_defaults_match_decision():
    assert PRIMARY_ENGINES == "google cse", "主引擎は Google CSE (ページング可能)"


def test_first_page_adds_bing_complement():
    from searxng import engines_for
    assert engines_for(1) == "google cse,bing", "Bing が応答できるのは 1 ページ目のみ"


def test_search_uses_primary_engine_and_pageno():
    g = make({("dynabook R734 ジャンク", 1, "google cse,bing"):
              payload([{"url": "https://a.example/p", "title": "a"},
                       {"url": "https://b.example/p", "title": "b"}])})
    c = SearxClient("http://localhost:8888", http_get=g, sleep_sec=0)
    res = c.search("dynabook R734 ジャンク", pageno=1)
    assert [r["url"] for r in res] == ["https://a.example/p", "https://b.example/p"]
    assert "pageno=1" in g.calls[0]
    assert "google" in g.calls[0].replace("%20", " ").replace("+", " ")
    assert "bing" in g.calls[0].replace("%20", " ").replace("+", " ")
    assert "format=json" in g.calls[0]


def test_pivot_search_uses_google_cse():
    g = make()
    c = SearxClient("http://localhost:8888", http_get=g, sleep_sec=0)
    c.search("dynabook R734 bios site:shop.example", pageno=1, pivot=True)
    assert "google+cse" in g.calls[0] or "google%20cse" in g.calls[0]


def test_empty_results_is_not_an_error_but_is_flagged():
    c = SearxClient("http://localhost:8888", http_get=make(), sleep_sec=0)
    res = c.search("x", pageno=1)
    assert res == []


def test_unresponsive_engines_raise_engine_unavailable():
    c = SearxClient("http://localhost:8888", http_get=make(unresponsive=[["bing", "Suspended"]]),
                    sleep_sec=0)
    with pytest.raises(EngineUnavailable):
        c.search("x", pageno=1)


def test_http_error_raises_searx_error():
    def boom(url, timeout):
        return 500, b"nope"

    c = SearxClient("http://localhost:8888", http_get=boom, sleep_sec=0)
    with pytest.raises(SearxError):
        c.search("x", pageno=1)


def test_malformed_json_raises_searx_error():
    def bad(url, timeout):
        return 200, b"{not json"

    c = SearxClient("http://localhost:8888", http_get=bad, sleep_sec=0)
    with pytest.raises(SearxError):
        c.search("x", pageno=1)


def test_rate_limit_sleeps_between_calls(monkeypatch):
    slept = []
    c = SearxClient("http://localhost:8888", http_get=make(), sleep_sec=1.5,
                    sleep=slept.append)
    c.search("a", pageno=1)
    c.search("b", pageno=1)
    assert slept == [1.5], "1 回目は sleep せず、2 回目で sleep する"


def test_results_are_deduped_and_normalised():
    dup = [{"url": "https://a.example/p", "title": "a", "content": "s", "pubdate": None},
           {"url": "https://a.example/p", "title": "a"},
           {"url": "https://b.example/q", "title": "b"}]
    c = SearxClient("http://localhost:8888",
                    http_get=make({("q t", 1, "google cse,bing"): payload(dup)}), sleep_sec=0)
    res = c.search("q t", pageno=1)
    assert [r["url"] for r in res] == ["https://a.example/p", "https://b.example/q"]
    assert set(res[0]) >= {"url", "title", "snippet", "pubdate"}


def test_stats_accumulate_queries_and_results():
    g = make({("q t", 1, "google cse,bing"): payload([{"url": "https://a.example/p"}])})
    c = SearxClient("http://localhost:8888", http_get=g, sleep_sec=0)
    c.search("q t", pageno=1)
    c.search("q t", pageno=2)
    assert c.stats.queries == 2
    assert c.stats.results == 1
    assert c.stats.empty_queries == 1


# --- 実測 (2026-09-24): Bing はページング非対応。pageno>=2 は常に 0 件。---
#     Google CSE は pageno<=5 で 20 件、pageno>=6 で 0 件。
#     → pageno ランダム化は「ページング可能なエンジン」に委ねる必要がある。

def test_engine_paging_caps_match_measurements():
    from searxng import (
        BING_MAX_PAGENO,
        GOOGLE_CSE_MAX_PAGENO,
        PRIMARY_MAX_PAGENO,
        engines_for,
    )
    assert BING_MAX_PAGENO == 1, "Bing はページング非対応 (実測: pageno>=2 で常に 0 件)"
    assert GOOGLE_CSE_MAX_PAGENO == 5, "Google CSE は実測 pageno<=5 で応答"
    assert PRIMARY_MAX_PAGENO == GOOGLE_CSE_MAX_PAGENO


def test_engines_for_keeps_google_cse_primary_on_all_pages():
    from searxng import engines_for
    assert engines_for(1) == "google cse,bing", "1 ページ目のみ Bing を補完"
    for pageno in (2, 3, 5):
        assert engines_for(pageno) == "google cse", f"pageno={pageno} は Google CSE 主体"


def test_engines_for_enables_google_cse_only_when_paging():
    from searxng import engines_for
    for pageno in (2, 3, 5):
        eng = engines_for(pageno)
        assert "google cse" in eng, f"pageno={pageno} はページングが必要 → Google CSE を併用"


def test_search_uses_paging_aware_engines():
    g = make()
    c = SearxClient("http://localhost:8888", http_get=g, sleep_sec=0)
    c.search("q t", pageno=1)
    c.search("q t", pageno=3)
    first, second = g.calls[0], g.calls[1]
    assert "google" in first.replace("+", " ").replace("%20", " ")
    assert "google" in second.replace("+", " ").replace("%20", " ")
    assert "bing" not in second.replace("+", " ").replace("%20", " ")


def test_pivot_still_uses_google_cse_even_on_first_page():
    g = make()
    c = SearxClient("http://localhost:8888", http_get=g, sleep_sec=0)
    c.search("q t site:shop.example", pageno=1, pivot=True)
    assert "google" in g.calls[0].replace("+", " ").replace("%20", " ")
