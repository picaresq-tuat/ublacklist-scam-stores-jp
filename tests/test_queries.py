"""P0: クエリ生成 (16 用語 × 型番, 30 日重複回避) の RED テスト。"""
import random

import pytest

from modeldb import ModelDB, SEED_CSV
from queries import (
    QUERY_SEPARATOR,
    TERM_GROUPS,
    TERMS,
    QueriesExhausted,
    build_query,
    generate_queries,
    term_coverage,
)


@pytest.fixture()
def db(tmp_path):
    d = ModelDB(tmp_path / "models.db")
    d.load_csv(SEED_CSV)
    return d


def test_terms_are_expanded_to_16_unique():
    assert len(TERMS) == 16, TERMS
    assert len(set(TERMS)) == 16
    assert all(t.strip() == t and t for t in TERMS)


def test_terms_are_grouped_and_state_terms_present():
    assert len(TERM_GROUPS) >= 3
    flat = [t for g in TERM_GROUPS.values() for t in g]
    assert set(flat) == set(TERMS)
    assert {"ジャンク", "中古", "整備済み", "bios"} <= set(TERMS)
    assert {"格安", "在庫処分"} <= set(TERMS)


def test_generate_queries_counts_and_uniqueness(db):
    qs = generate_queries(db.all(), n_models=30, n_queries=200, rng=random.Random(1))
    assert len(qs) == 200
    assert len(set(qs)) == 200, "同一 (model, term) が重複"
    assert len({m for m, _ in qs}) <= 30
    assert len({m for m, _ in qs}) >= 2


def test_generate_queries_uses_many_terms(db):
    qs = generate_queries(db.all(), n_models=30, n_queries=200, rng=random.Random(2))
    assert term_coverage(qs) >= 12


def test_generate_queries_is_seeded(db):
    a = generate_queries(db.all(), n_models=25, n_queries=80, rng=random.Random(3))
    b = generate_queries(db.all(), n_models=25, n_queries=80, rng=random.Random(3))
    assert a == b
    c = generate_queries(db.all(), n_models=25, n_queries=80, rng=random.Random(4))
    assert a != c


@pytest.mark.parametrize("n_models", [19, 51, 0, -5])
def test_n_models_out_of_range_raises(db, n_models):
    with pytest.raises(ValueError):
        generate_queries(db.all(), n_models=n_models, n_queries=10, rng=random.Random(0))


def test_excluded_pairs_are_skipped(db):
    seen = set()

    def excluded(m, t):
        seen.add((m, t))
        return (m, t) in EXCLUDE_SET

    EXCLUDE_SET.clear()
    EXCLUDE_SET.update({(m.model, t) for m in db.all()[:5] for t in TERMS})
    qs = generate_queries(db.all(), n_models=30, n_queries=50,
                          rng=random.Random(5), is_excluded=excluded)
    assert not (set(qs) & EXCLUDE_SET)
    assert seen, "is_excluded が呼ばれていない"


def test_exhausted_pool_raises(db):
    with pytest.raises(QueriesExhausted):
        generate_queries(db.all(), n_models=20, n_queries=50, rng=random.Random(6),
                         is_excluded=lambda m, t: True)


def test_build_query_format():
    q = build_query("dynabook R734", "ジャンク")
    assert q == "dynabook R734 ジャンク"
    assert QUERY_SEPARATOR == " "


# --- QueryGen (夜間オーケストレータ用のラッパ) ---

def test_querygen_yields_query_model_pageno(db):
    from queries import QueryGen
    g = QueryGen(db=db, n_models=20, rng=random.Random(0))
    out = list(g.queries(limit=12))
    assert len(out) == 12
    for query, model, pageno in out:
        assert model in query
        assert 1 <= pageno <= 10


def test_querygen_queries_are_unique_within_a_run(db):
    from queries import QueryGen
    g = QueryGen(db=db, n_models=25, rng=random.Random(1))
    out = [(m, t) for q, m, p in g.queries(limit=60) for t in [q[len(m):].strip()]]
    assert len(set(out)) == len(out)


def test_querygen_samples_20_to_50_models(db):
    from queries import QueryGen
    g = QueryGen(db=db, rng=random.Random(2))
    models = {m for _, m, _ in g.queries(limit=300)}
    assert 20 <= len(models) <= 50, len(models)


def test_querygen_avoids_pairs_seen_within_30_days(db, tmp_path):
    from queries import QueryGen
    from searchlog import SearchLog
    log = SearchLog(tmp_path / "s.db")
    first = list(QueryGen(db=db, n_models=20, rng=random.Random(3)).queries(
        limit=40, searchlog=log))
    for query, model, pageno in first:
        log.record(model, query[len(model):].strip(), pageno)
    second = list(QueryGen(db=db, n_models=20, rng=random.Random(4)).queries(
        limit=40, searchlog=log))
    pairs_a = {(m, q[len(m):].strip()) for q, m, _ in first}
    pairs_b = {(m, q[len(m):].strip()) for q, m, _ in second}
    assert not (pairs_a & pairs_b), "過去 30 日の検索と重複している"


def test_querygen_rotate_changes_the_sample(db):
    from queries import QueryGen
    g = QueryGen(db=db, rng=random.Random(5))
    a = {m for _, m, _ in g.queries(limit=200)}
    g.rotate()
    b = {m for _, m, _ in g.queries(limit=200)}
    assert a != b or len(a) != len(b)


def test_querygen_rotate_reserves_new_pageno(db, tmp_path):
    from queries import QueryGen
    from searchlog import SearchLog
    log = SearchLog(tmp_path / "s.db")
    g = QueryGen(db=db, n_models=20, rng=random.Random(6))
    first = g.queries(limit=5, searchlog=log)
    g.rotate()
    second = g.queries(limit=5, searchlog=log)
    assert log.count() == 10                       # QueryGen 自身が記録する
    pairs_a = {(m, q[len(m):].strip()) for q, m, _ in first}
    pairs_b = {(m, q[len(m):].strip()) for q, m, _ in second}
    assert not (pairs_a & pairs_b)


def test_querygen_limit_is_respected_when_log_is_saturated(db, tmp_path):
    """30 日窓を埋め尽くしても例外を投げず、得られるだけ返す。"""
    from queries import QueryGen
    from searchlog import SearchLog
    log = SearchLog(tmp_path / "s.db")
    for m in db.all():
        for t in TERMS:
            log.record(m.model, t, 1)
    out = list(QueryGen(db=db, n_models=20, rng=random.Random(7)).queries(
        limit=10, searchlog=log))
    assert len(out) == 10
    assert {(m, q[len(m):].strip()) for q, m, _ in out}  # 中身がある


EXCLUDE_SET = set()
