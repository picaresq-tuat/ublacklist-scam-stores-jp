"""ドメイン巡回ライフサイクル (RED)。

仕様は docs/domain-lifecycle.md。ここでは
- 2 種類の降格ルート (到達不能 / スコア閾値) の状態遷移
- nightly 全体失敗時に判定を進めないこと
- 間隔を「完了した nightly run の回数」で数えること
を純粋関数と store/sweep の両方で固定する。
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

HEALTHY = True
DEAD = False
UNKNOWN = None


@dataclass
class StubResult:
    domain: str
    score: float = 0.0
    decision: str = "dismissed"
    reasons: dict = field(default_factory=dict)
    features: dict = field(default_factory=dict)


class StubPipeline:
    def __init__(self, verdicts: dict[str, tuple[str, dict]] | None = None):
        self.verdicts = verdicts or {}
        self.probed: list[str] = []

    def run_domain(self, domain: str) -> StubResult:
        self.probed.append(domain)
        decision, features = self.verdicts.get(domain, ("dismissed", {}))
        return StubResult(domain=domain, decision=decision, features=dict(features))


class StubHealth:
    def __init__(self, states: dict[str, bool | None] | None = None, default: bool | None = True):
        self.states = states or {}
        self.default = default
        self.checked: list[str] = []

    def check_state(self, domain: str) -> str:
        self.checked.append(domain)
        value = self.states.get(domain, self.default)
        return {True: "reachable", False: "unreachable", None: "unknown"}[value]

    def check(self, domain: str) -> bool:
        return self.check_state(domain) == "reachable"


@pytest.fixture()
def store(tmp_path):
    from scamstore import ScamStore

    db = ScamStore(tmp_path / "scam.db")
    yield db
    db.close()


def _state(**kw):
    from lifecycle import State

    base = {"domain": "shop.example", "status": "active", "base_decision": "block"}
    base.update(kw)
    return State(**base)


def _advance(state, *, verdict="below", reachable=HEALTHY, seq=1, recent=()):
    from lifecycle import advance

    return advance(
        state,
        verdict=verdict,
        reachable=reachable,
        seq=seq,
        night=f"2026-10-{seq:02d}",
        recent=recent,
    )


# --- 巡回スケジュール ---


def test_schedule_intervals_are_run_based():
    from lifecycle import interval_for, is_due

    assert interval_for("active") == 1
    assert interval_for("pending_release") == 1
    assert interval_for("pending_expiration") == 3
    assert interval_for("released") == 7
    assert interval_for("expired") == 7
    assert interval_for("retired") is None

    assert is_due(_state(status="active", last_check_seq=5), 6) is True
    assert is_due(_state(status="pending_expiration", last_check_seq=5), 7) is False
    assert is_due(_state(status="pending_expiration", last_check_seq=5), 8) is True
    assert is_due(_state(status="released", last_check_seq=5), 11) is False
    assert is_due(_state(status="released", last_check_seq=5), 12) is True
    assert is_due(_state(status="retired", last_check_seq=0), 100) is False


# --- ルート B: スコア閾値未満 ---


def test_active_demotes_to_pending_release_after_three_below_nights():
    s = _state()
    for seq in (1, 2):
        step = _advance(s, seq=seq)
        s = step.state
        assert step.event == ""
        assert s.status == "active"
    step = _advance(s, seq=3)
    assert step.event == "pending_release"
    assert step.state.status == "pending_release"
    assert step.state.below_streak == 0


def test_hold_domain_needs_three_below_nights_not_two():
    s = _state(base_decision="hold")
    s = _advance(s, seq=1).state
    s = _advance(s, seq=2).state
    assert s.status == "active"
    assert s.below_streak == 2
    assert _advance(s, seq=3).event == "pending_release"


def test_block_observation_resets_below_streak():
    s = _state()
    s = _advance(s, seq=1).state
    s = _advance(s, seq=2).state
    step = _advance(s, verdict="block", seq=3)
    assert step.state.below_streak == 0
    assert step.state.status == "active"
    assert step.event == "confirmed_block"


def test_pending_release_confirms_scam_on_block():
    s = _state(status="pending_release", base_decision="block")
    step = _advance(s, verdict="block", seq=1)
    assert step.event == "confirmed_block"
    assert step.state.status == "active"
    assert step.state.base_decision == "block"


def test_pending_release_confirms_cloaking_on_hold():
    s = _state(status="pending_release", base_decision="block")
    step = _advance(s, verdict="hold", seq=1)
    assert step.event == "confirmed_hold"
    assert step.state.status == "active"
    assert step.state.base_decision == "hold"


def test_pending_release_releases_after_three_below_observations():
    s = _state(status="pending_release", base_decision="block")
    for seq in (1, 2):
        step = _advance(s, seq=seq)
        s = step.state
        assert step.event == ""
        assert s.status == "pending_release"
    step = _advance(s, seq=3)
    assert step.event == "released"
    assert step.state.status == "released"


def test_released_returns_to_scam_immediately_on_block():
    s = _state(status="released", base_decision="hold")
    step = _advance(s, verdict="block", seq=1)
    assert step.event == "confirmed_block"
    assert step.state.status == "active"
    assert step.state.base_decision == "block"


def test_released_returns_to_cloaking_when_two_of_last_five_are_hold():
    s = _state(status="released", base_decision="hold")
    step = _advance(s, verdict="hold", seq=1, recent=("below", "below", "hold", "below"))
    assert step.event == "confirmed_hold"
    assert step.state.status == "active"
    assert step.state.base_decision == "hold"


def test_released_single_hold_in_window_does_not_restore():
    s = _state(status="released", base_decision="hold")
    step = _advance(s, verdict="hold", seq=1, recent=("below", "below", "below", "below"))
    assert step.event == ""
    assert step.state.status == "released"
    assert step.state.below_streak == 0


def test_released_retires_after_five_consecutive_below():
    s = _state(status="released", base_decision="hold")
    for seq in range(1, 5):
        step = _advance(s, seq=seq)
        s = step.state
        assert step.event == ""
    step = _advance(s, seq=5)
    assert step.event == "retired"
    assert step.state.status == "retired"


# --- ルート A: 到達不能 (スコア閾値に優先) ---


def test_unreachable_three_checks_demotes_to_pending_expiration():
    s = _state()
    for seq in (1, 2):
        step = _advance(s, verdict="block", reachable=DEAD, seq=seq)
        s = step.state
        assert step.event == ""
        assert s.status == "active"
    step = _advance(s, verdict="block", reachable=DEAD, seq=3)
    assert step.event == "pending_expiration"
    assert step.state.status == "pending_expiration"
    assert step.state.unreachable_streak == 0


def test_unreachable_takes_priority_over_below_threshold():
    s = _state(below_streak=2, unreachable_streak=2)
    step = _advance(s, verdict="below", reachable=DEAD, seq=3)
    assert step.event == "pending_expiration"
    assert step.state.below_streak == 2, "到達不能の夜はスコア側のカウントを動かさない"


def test_pending_expiration_expires_after_five_more_unreachable_checks():
    s = _state(status="pending_expiration", base_decision="block")
    for seq in range(1, 5):
        step = _advance(s, verdict="unknown", reachable=DEAD, seq=seq)
        s = step.state
        assert step.event == ""
    step = _advance(s, verdict="unknown", reachable=DEAD, seq=5)
    assert step.event == "expired"
    assert step.state.status == "expired"


def test_expired_retires_after_five_more_unreachable_checks():
    s = _state(status="expired", base_decision="block")
    for seq in range(1, 5):
        s = _advance(s, verdict="unknown", reachable=DEAD, seq=seq).state
        assert s.status == "expired"
    step = _advance(s, verdict="unknown", reachable=DEAD, seq=5)
    assert step.event == "retired"
    assert step.state.status == "retired"


def test_reachable_restores_pending_expiration_and_resumes_scoring():
    s = _state(status="pending_expiration", base_decision="block", unreachable_streak=4)
    step = _advance(s, verdict="unknown", reachable=HEALTHY, seq=1)
    assert step.event == "restored"
    assert step.state.status == "active"
    assert step.state.unreachable_streak == 0


def test_reachable_restores_expired_to_original_decision():
    s = _state(status="expired", base_decision="hold")
    step = _advance(s, verdict="unknown", reachable=HEALTHY, seq=1)
    assert step.event == "restored"
    assert step.state.status == "active"
    assert step.state.base_decision == "hold"


def test_unknown_observation_moves_nothing():
    s = _state(below_streak=2, unreachable_streak=1)
    step = _advance(s, verdict="unknown", reachable=UNKNOWN, seq=1)
    assert step.event == ""
    assert step.state.status == "active"
    assert step.state.below_streak == 2
    assert step.state.unreachable_streak == 1


# --- 到達性の 3 値判定 (別ドメインへの転送は到達不能にしない) ---


def _fetch_result(url, status=200, body="ok", final_url=None):
    from fetch import FetchResult

    r = FetchResult(
        url=url,
        status=status,
        final_url=final_url or url,
        body=body,
        html_sanitized=body,
        headers={},
    )
    r.raw_bytes = len(body.encode())
    return r


def test_health_state_is_reachable_for_200(monkeypatch):
    import health as health_mod

    monkeypatch.setattr(health_mod, "fetch", lambda url, **kw: _fetch_result(url))
    assert health_mod.HealthChecker().check_state("alive.example") == "reachable"


def test_health_state_same_domain_404_is_unreachable(monkeypatch):
    import health as health_mod

    monkeypatch.setattr(
        health_mod, "fetch", lambda url, **kw: _fetch_result(url, status=404, body="")
    )
    assert health_mod.HealthChecker().check_state("gone.example") == "unreachable"


def test_health_state_cross_domain_redirect_is_reachable(monkeypatch):
    import health as health_mod

    monkeypatch.setattr(
        health_mod,
        "fetch",
        lambda url, **kw: _fetch_result(url, final_url="https://shop.marketplace.example/landing"),
    )
    assert health_mod.HealthChecker().check_state("moved.example") == "reachable"


def test_health_state_cross_domain_redirect_to_error_is_unknown(monkeypatch):
    import health as health_mod

    monkeypatch.setattr(
        health_mod,
        "fetch",
        lambda url, **kw: _fetch_result(
            url, status=503, body="down", final_url="https://shop.marketplace.example/"
        ),
    )
    assert health_mod.HealthChecker().check_state("moved.example") == "unknown"


def test_health_state_fetch_error_on_the_domain_is_unreachable(monkeypatch):
    import health as health_mod
    from fetch import FetchError

    def boom(url, **kw):
        raise FetchError("dns failure")

    monkeypatch.setattr(health_mod, "fetch", boom)
    assert health_mod.HealthChecker().check_state("dead.example") == "unreachable"


# --- nightly 全体失敗とスケジュール ---


def test_failed_night_records_no_run_and_advances_nothing(store):
    import lifecycle

    store.record("stale.example", score=40, decision="block", night="2026-10-01")
    before = store.get("stale.example")
    rep = lifecycle.sweep(
        store=store,
        night="2026-10-02",
        pipeline=StubPipeline(),
        health=StubHealth(default=DEAD),
        night_ok=False,
    )
    assert rep["skipped"] == "night_failed"
    assert rep["checked"] == []
    assert store.get("stale.example")["decision"] == before["decision"]
    assert (store.lifecycle_get("stale.example") or {}).get("unreachable_streak", 0) == 0
    assert store.completed_runs() == 0


def test_failed_night_does_not_count_below_threshold(store):
    import lifecycle

    store.record("weak.example", score=40, decision="block", night="2026-10-01")
    pipe = StubPipeline({"weak.example": ("dismissed", {})})
    for _ in range(5):
        lifecycle.sweep(
            store=store,
            night="2026-10-02",
            pipeline=pipe,
            health=StubHealth(),
            night_ok=False,
        )
    assert (store.lifecycle_get("weak.example") or {}).get("below_streak", 0) == 0
    assert store.get("weak.example")["decision"] == "block"


def test_sweep_counts_three_nights_and_demotes_to_pending_release(store):
    import lifecycle

    store.record("weak.example", score=40, decision="block", night="2026-10-01")
    pipe = StubPipeline({"weak.example": ("dismissed", {})})
    events = []
    for day in ("2026-10-02", "2026-10-03", "2026-10-04"):
        rep = lifecycle.sweep(
            store=store, night=day, pipeline=pipe, health=StubHealth(), night_ok=True
        )
        events.append(rep["pending_release"])
    assert events == [[], [], ["weak.example"]]
    assert store.get("weak.example")["decision"] == "pending_release"


def test_same_night_rerun_is_idempotent(store):
    import lifecycle

    store.record("weak.example", score=40, decision="block", night="2026-10-01")
    pipe = StubPipeline({"weak.example": ("dismissed", {})})
    lifecycle.sweep(
        store=store, night="2026-10-02", pipeline=pipe, health=StubHealth(), night_ok=True
    )
    lifecycle.sweep(
        store=store, night="2026-10-02", pipeline=pipe, health=StubHealth(), night_ok=True
    )
    assert store.lifecycle_get("weak.example")["below_streak"] == 1
    assert store.completed_runs() == 1
    assert len(pipe.probed) == 1


def test_pending_expiration_is_checked_every_third_run(store):
    import lifecycle

    store.record("dead.example", score=40, decision="block", night="2026-10-01")
    health = StubHealth(default=DEAD)
    pipe = StubPipeline({"dead.example": ("block", {})})
    for day in ("2026-10-02", "2026-10-03", "2026-10-04"):
        lifecycle.sweep(store=store, night=day, pipeline=pipe, health=health, night_ok=True)
    assert store.get("dead.example")["decision"] == "pending_expiration"

    health.checked.clear()
    lifecycle.sweep(store=store, night="2026-10-05", pipeline=pipe, health=health, night_ok=True)
    assert health.checked == [], "pending_expiration は 3 run ごと"
    lifecycle.sweep(store=store, night="2026-10-06", pipeline=pipe, health=health, night_ok=True)
    lifecycle.sweep(store=store, night="2026-10-07", pipeline=pipe, health=health, night_ok=True)
    assert health.checked == ["dead.example"]


def test_unknown_health_does_not_count_as_unreachable_and_is_retried(store):
    import lifecycle

    store.record("flaky.example", score=40, decision="block", night="2026-10-01")
    pipe = StubPipeline({"flaky.example": ("block", {})})
    unknown = StubHealth(default=UNKNOWN)
    for day in ("2026-10-02", "2026-10-03", "2026-10-04"):
        lifecycle.sweep(store=store, night=day, pipeline=pipe, health=unknown, night_ok=True)
    assert store.lifecycle_get("flaky.example")["unreachable_streak"] == 0
    assert store.get("flaky.example")["decision"] == "block"
