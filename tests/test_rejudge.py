"""P10: cloaking リスト再判定 + 手動収集リストの取り込みのテスト (RED 先行)。"""

from __future__ import annotations

from rejudge import (
    Outcome,
    is_active,
    select_cloaking_removals,
    select_promotions,
    summarise,
)


def test_block_and_active_is_promoted():
    o = Outcome("scam.example", "block", 42.0, status=200)
    assert select_promotions([o], []) == ["scam.example"]


def test_block_but_dead_is_not_promoted():
    """応答なし (status=None) は配布しない。"""
    o = Outcome("dead.example", "block", 42.0, status=None)
    assert select_promotions([o], []) == []


def test_block_but_error_status_is_not_promoted():
    o = Outcome("gone.example", "block", 42.0, status=404)
    assert select_promotions([o], []) == []
    assert is_active(o) is False


def test_hold_is_never_promoted_even_with_high_score():
    """cloaking=True でも hold は scam リストへ行かない (既存の運用境界)。"""
    o = Outcome("hold.example", "hold", 19.0, status=200, cloaking=True)
    assert select_promotions([o], []) == []


def test_already_known_scam_is_not_duplicated():
    o = Outcome("dup.example", "block", 42.0, status=200)
    assert select_promotions([o], ["dup.example"]) == []
    assert select_promotions([o], ["DUP.example"]) == []


def test_promotions_are_sorted_and_deduped():
    rows = [
        Outcome("b.example", "block", 30.0, status=200),
        Outcome("a.example", "block", 30.0, status=200),
        Outcome("b.example", "block", 30.0, status=200),
    ]
    assert select_promotions(rows, []) == ["a.example", "b.example"]


def test_cloaking_removals_are_only_block():
    rows = [
        Outcome("promoted.example", "block", 42.0, status=200, cloaking=True),
        Outcome("still-hold.example", "hold", 14.0, status=200, cloaking=True),
        Outcome("unreachable.example", "dismissed", 0.0, status=None),
    ]
    assert select_cloaking_removals(rows) == ["promoted.example"]


def test_summarise_counts_decisions_and_active_rate():
    rows = [
        Outcome("a.example", "block", 30.0, status=200),
        Outcome("b.example", "hold", 14.0, status=200, cloaking=True),
        Outcome("c.example", "dismissed", 0.0, status=None),
        Outcome("d.example", "dismissed", 2.0, status=403),
    ]
    s = summarise(rows)
    assert s["n"] == 4
    assert s["active"] == 2
    assert s["active_rate"] == 0.5
    assert s["by_decision"] == {"block": 1, "dismissed": 2, "hold": 1}


def test_empty_input_is_safe():
    assert select_promotions([], []) == []
    assert select_cloaking_removals([]) == []
    assert summarise([]) == {"n": 0, "active": 0, "active_rate": 0.0, "by_decision": {}}
