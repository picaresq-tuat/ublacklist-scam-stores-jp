"""P9c: 空応答連続 pageno のプール補完テスト。

- hunter.py: 空応答 pageno を「当夜の除外プール」に積み、再試行で使わない。
- searchlog.record に result_count を記録済みであることを前提とし、
  `store_empty` が true のとき空 pageno を searchlog にも記録して
  30 日窓の再利用を防ぐ。
"""

from __future__ import annotations

import random

import hunter
import pytest
from searchlog import SearchLog, pick_pageno


class FakeSearx:
    """pageno==4 だけ常に空を返す擬似エンジン。"""

    def __init__(self):
        self.calls: list[tuple[str, int]] = []

    def search(self, query, *, pageno):
        self.calls.append((query, pageno))
        if pageno == 4:
            return []
        return [{"url": f"https://d{pageno}.example/page"}]


@pytest.fixture()
def env(tmp_path):
    from queries import QueryGen
    from scamstore import ScamStore

    log = SearchLog(tmp_path / "searches.db")
    store = ScamStore(tmp_path / "scam.db")
    gen = QueryGen()
    searx = FakeSearx()
    return log, store, gen, searx, tmp_path


class _Res:
    def __init__(self, dom):
        self.domain = dom
        self.score = 0.0
        self.decision = "dismissed"
        self.features = {}
        self.reasons = []


class _Pipe:
    def run_domain(self, dom):
        return _Res(dom)


def test_pick_pageno_excludes_blacklisted_pool(env):
    log, _store, _gen, _searx, _tmp_path = env
    # 過去に p4 が空だった記録があれば candidate から外れる
    log.record("m", "t", 4, result_count=0)
    pool = {
        pick_pageno(log, "m", "t", random.Random(1), max_pageno=5, exclude={4}) for _ in range(20)
    }
    assert 4 not in pool


def test_empty_pageno_recorded_and_excluded_next_round(env):
    """空応答の pageno は searchlog に result_count=0 で記録され、
    以降の pick_pageno (30日窓) で除外される。"""
    log, _store, _gen, _searx, _tmp_path = env
    log.record("modelX", "termY", 4, result_count=0)
    used = {pick_pageno(log, "modelX", "termY", random.Random(7), max_pageno=5) for _ in range(20)}
    assert 4 not in used


def test_pick_pageno_all_empty_falls_back_to_least_recent(env):
    log, _store, _gen, _searx, _tmp_path = env
    for p in range(1, 6):
        log.record("m", "t", p, result_count=0)
    # 全部空でも PageRangeExhausted にはならない (fallback 再利用)
    got = pick_pageno(log, "m", "t", random.Random(2), max_pageno=5)
    assert got in {1, 2, 3, 4, 5}


def test_hunter_passes_result_count_to_searchlog(monkeypatch, env):
    """hunter が空応答 pageno を result_count=0 で記録すること。"""
    _log, store, gen, searx, tmp_path = env
    rng = random.Random(3)
    gen.rng = rng
    seen = []

    import searchlog as sl

    orig = sl.pick_pageno

    def spy(*a, **kw):
        r = orig(*a, **kw)
        seen.append(r)
        return r

    monkeypatch.setattr(hunter, "pick_pageno", spy)
    monkeypatch.setattr(sl, "pick_pageno", spy)
    rep = hunter.run_night(
        night="2026-09-27",
        searx=searx,
        pipeline=_Pipe(),
        store=store,
        db_dir=tmp_path / "db",
        ulist_path=None,
        gen=gen,
        models_db=None,
        max_queries=2,
        sleep=lambda *_: None,
    )
    assert rep["new_domains"] >= 1
    # run_night が自前生成した searches.db を読み直して検証する
    inner = SearchLog(tmp_path / "db" / "searches.db")
    # 空応答 pageno 4 がログに残る (result_count=0)
    empties = [e for e in inner.all() if e.result_count == 0]
    assert any(e.pageno == 4 for e in empties)
