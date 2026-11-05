"""P6b: 判定の永続化 (scam.db / decisions / domain_health) の RED テスト。"""

from datetime import UTC, datetime, timedelta

import pytest
from scamstore import DECISIONS, ScamStore


def store(tmp_path):
    return ScamStore(tmp_path / "scam.db")


def day(n: int) -> str:
    return (datetime.now(UTC) - timedelta(days=n)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_decisions_are_the_defined_ones():
    """判定値は巡回ライフサイクルの状態も含む (docs/domain-lifecycle.md)。"""
    assert set(DECISIONS) == {
        "candidate",
        "hold",
        "block",
        "expired",
        "dismissed",
        "pending_release",
        "pending_expiration",
        "released",
        "retired",
    }


def test_record_and_fetch(tmp_path):
    db = store(tmp_path)
    db.record(
        "card.hika-jp.casa",
        score=74.0,
        features={"zencart_hits": 4},
        evidence={},
        decision="block",
        night="2026-09-24",
    )
    row = db.get("card.hika-jp.casa")
    assert row["score"] == 74.0
    assert row["decision"] == "block"
    assert row["nights_confirmed"] == 1
    assert row["first_seen"][:10] == "2026-09-24"


def test_second_night_increments_confirmation(tmp_path):
    db = store(tmp_path)
    db.record("a.example", score=30, decision="block", night="2026-09-23")
    db.record("a.example", score=35, decision="block", night="2026-09-24")
    row = db.get("a.example")
    assert row["nights_confirmed"] == 2
    assert row["last_seen"][:10] == "2026-09-24"
    assert row["score"] == 35


def test_same_night_twice_does_not_double_count(tmp_path):
    db = store(tmp_path)
    db.record("a.example", score=30, decision="block", night="2026-09-24")
    db.record("a.example", score=30, decision="block", night="2026-09-24")
    assert db.get("a.example")["nights_confirmed"] == 1


def test_decision_change_is_recorded(tmp_path):
    db = store(tmp_path)
    db.record("a.example", score=14, decision="hold", night="2026-09-23")
    db.record("a.example", score=44, decision="block", night="2026-09-24")
    assert db.get("a.example")["decision"] == "block"
    assert [h["decision"] for h in db.history("a.example")] == ["hold", "block"]


def test_invalid_decision_rejected(tmp_path):
    db = store(tmp_path)
    with pytest.raises(ValueError):
        db.record("a.example", score=1, decision="maybe")


def test_eligible_for_block_requires_two_nights_or_fast_track(tmp_path):
    db = store(tmp_path)
    db.record("slow.example", score=35, decision="block", night="2026-09-23")
    db.record("fast.example", score=61, decision="block", night="2026-09-24")
    db.record("fresh.example", score=35, decision="block", night="2026-09-24")
    eligible = set(db.eligible_domains())
    assert "slow.example" not in eligible  # 1 夜だけでは早い
    assert "fast.example" in eligible  # fast_track (>=60)
    assert "fresh.example" not in eligible


def test_eligible_after_second_night(tmp_path):
    db = store(tmp_path)
    db.record("slow.example", score=35, decision="block", night="2026-09-23")
    db.record("slow.example", score=35, decision="block", night="2026-09-24")
    assert "slow.example" in set(db.eligible_domains())


def test_eligible_by_streak_score(tmp_path):
    db = store(tmp_path)
    db.record("strong.example", score=58, decision="block", night="2026-09-24")
    assert "strong.example" in set(db.eligible_domains(score_threshold=55))


def test_health_recording_and_streak(tmp_path):
    db = store(tmp_path)
    db.record_health("a.example", reachable=False, checked_on="2026-09-18")
    db.record_health("a.example", reachable=False, checked_on="2026-09-19")
    assert db.unreachable_streak("a.example") == 2
    db.record_health("a.example", reachable=True, checked_on="2026-09-20")
    assert db.unreachable_streak("a.example") == 0
    db.record_health("a.example", reachable=False, checked_on="2026-09-21")
    assert db.unreachable_streak("a.example") == 1


def test_health_recording_is_idempotent_per_day(tmp_path):
    db = store(tmp_path)
    db.record_health("a.example", reachable=False, checked_on="2026-09-19")
    db.record_health("a.example", reachable=False, checked_on="2026-09-19")
    assert db.health_count() == 1


def test_monitor_targets_require_age(tmp_path):
    db = store(tmp_path)
    db.record("old.example", score=40, decision="block", night=day(40))
    db.record("new.example", score=40, decision="block", night=day(5))
    db.record("held.example", score=14, decision="hold", night=day(40))
    assert set(db.monitor_targets(age_days=30)) == {"old.example"}


def test_expire_removes_from_block_list(tmp_path):
    db = store(tmp_path)
    db.record("dead.example", score=40, decision="block", night=day(40))
    for i in range(1, 8):
        db.record_health("dead.example", reachable=False, checked_on=f"2026-09-{10 + i:02d}")
    assert db.unreachable_streak("dead.example") == 7
    expired = db.expire_unreachable(streak_days=7)
    assert expired == ["dead.example"]
    assert db.get("dead.example")["decision"] == "expired"
    assert db.get("dead.example")["nights_confirmed"] == 1  # 履歴は残る


def test_expire_keeps_six_day_streak(tmp_path):
    db = store(tmp_path)
    db.record("flaky.example", score=40, decision="block", night=day(40))
    for i in range(1, 7):
        db.record_health("flaky.example", reachable=False, checked_on=f"2026-09-{10 + i:02d}")
    assert db.expire_unreachable(streak_days=7) == []
    assert db.get("flaky.example")["decision"] == "block"


def test_blocked_domains_lists_only_block(tmp_path):
    db = store(tmp_path)
    db.record("b.example", score=40, decision="block", night="2026-09-24")
    db.record("h.example", score=13, decision="hold", night="2026-09-24")
    db.record("d.example", score=2, decision="dismissed", night="2026-09-24")
    assert db.blocked_domains() == ["b.example"]
