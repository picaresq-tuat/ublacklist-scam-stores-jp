"""P2: 検索履歴 (R2) と pageno ランダム化 (R3) の RED テスト。"""
import random
from datetime import datetime, timedelta, timezone

import pytest

from searchlog import (
    DEFAULT_MAX_PAGENO,
    DEFAULT_WINDOW_DAYS,
    SearchLog,
    pick_pageno,
)

NOW = datetime(2026, 9, 24, 3, 0, tzinfo=timezone.utc)


@pytest.fixture()
def log(tmp_path):
    return SearchLog(tmp_path / "searches.db")


def test_defaults():
    assert DEFAULT_WINDOW_DAYS == 30
    assert DEFAULT_MAX_PAGENO >= 5


def test_record_and_count(log):
    assert log.count() == 0
    log.record("dynabook R734", "ジャンク", 2, engine="bing", result_count=17, ran_at=NOW)
    assert log.count() == 1


def test_entry_fields_are_persisted(log):
    log.record("dynabook R734", "中古", 3, engine="google cse,bing", result_count=5, ran_at=NOW)
    e = log.all()[0]
    assert (e.model, e.term, e.pageno, e.engine) == ("dynabook R734", "中古", 3, "google cse,bing")
    assert e.result_count == 5
    assert e.ran_at.startswith("2026-09-24")


def test_is_seen_true_inside_window(log):
    log.record("dynabook R734", "ジャンク", 2, ran_at=NOW - timedelta(days=1))
    assert log.is_seen("dynabook R734", "ジャンク", 2, now=NOW) is True


def test_is_seen_false_outside_window(log):
    log.record("dynabook R734", "ジャンク", 2, ran_at=NOW - timedelta(days=31))
    assert log.is_seen("dynabook R734", "ジャンク", 2, now=NOW) is False


def test_window_boundary_is_30_days(log):
    log.record("m1", "中古", 1, ran_at=NOW - timedelta(days=30))
    log.record("m2", "中古", 1, ran_at=NOW - timedelta(days=29, hours=23))
    assert log.is_seen("m1", "中古", 1, now=NOW) is False
    assert log.is_seen("m2", "中古", 1, now=NOW) is True


def test_different_pageno_is_not_the_same_search(log):
    log.record("dynabook R734", "ジャンク", 2, ran_at=NOW)
    assert log.is_seen("dynabook R734", "ジャンク", 3, now=NOW) is False


def test_pair_seen_ignores_pageno(log):
    log.record("dynabook R734", "ジャンク", 2, ran_at=NOW)
    assert log.is_pair_seen("dynabook R734", "ジャンク", now=NOW) is True
    assert log.is_pair_seen("dynabook R734", "整備済み", now=NOW) is False


def test_excluded_predicate_helper(log):
    log.record("dynabook R734", "ジャンク", 2, ran_at=NOW)
    pred = log.exclusion_predicate(now=NOW)
    assert pred("dynabook R734", "ジャンク") is True
    assert pred("dynabook R734", "訳あり") is False


def test_recent_pagenos_reports_used_values(log):
    log.record("dynabook R734", "ジャンク", 1, ran_at=NOW)
    log.record("dynabook R734", "ジャンク", 2, ran_at=NOW)
    assert log.recent_pagenos("dynabook R734", "ジャンク", now=NOW) == {1, 2}


def test_pick_pageno_in_range_and_not_recently_used(log):
    for p in range(1, 4):
        log.record("dynabook R734", "ジャンク", p, ran_at=NOW)
    used = log.recent_pagenos("dynabook R734", "ジャンク", now=NOW)
    picks = {pick_pageno(log, "dynabook R734", "ジャンク", random.Random(i), now=NOW) for i in range(30)}
    assert picks <= {4, 5}
    assert picks & used == set(), "過去 30 日の pageno を再使用している"


def test_pick_pageno_within_bounds_when_all_used(log):
    for p in range(1, DEFAULT_MAX_PAGENO + 1):
        log.record("m", "t", p, ran_at=NOW)
    v = pick_pageno(log, "m", "t", random.Random(0), now=NOW)
    assert 1 <= v <= DEFAULT_MAX_PAGENO


def test_pick_pageno_is_deterministic_with_seed(log):
    a = pick_pageno(log, "m", "t", random.Random(42), now=NOW)
    b = pick_pageno(log, "m", "t", random.Random(42), now=NOW)
    assert a == b


def test_pick_pageno_excludes_engine_rejected_values(log):
    v = pick_pageno(log, "m", "t", random.Random(0), now=NOW, exclude={1, 2, 3},
                    max_pageno=10)
    assert v not in {1, 2, 3}


def test_pick_pageno_raises_when_all_values_rejected():
    class Dead(SearchLog):
        pass

    from searchlog import PageRangeExhausted
    with pytest.raises(PageRangeExhausted):
        pick_pageno(None, "m", "t", random.Random(0), now=NOW, exclude=set(range(1, 11)))


def test_prune_removes_old_entries(log):
    log.record("old", "t", 1, ran_at=NOW - timedelta(days=400))
    log.record("new", "t", 1, ran_at=NOW)
    removed = log.prune(keep_days=180, now=NOW)
    assert removed == 1
    assert log.count() == 1
