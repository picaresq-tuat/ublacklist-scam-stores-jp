"""スコア閾値ルートの降格・復帰 (docs/domain-lifecycle.md)。

- 3 晩連続で閾値未満 → pending_release (scam から cloaking へ)
- pending_release の 3 晩観測で block 確定 / hold 確定 / released
- released は block で即 scam、直近 5 回で hold 2 回以上で cloaking、5 回連続
  hold 未満で巡回対象外
"""

from __future__ import annotations

from dataclasses import dataclass, field

import hunter
import pytest
from lifecycle import State


@dataclass
class FakeResult:
    domain: str
    score: float
    reasons: dict = field(default_factory=dict)
    decision: str = "hold"
    features: dict = field(default_factory=dict)


class FakePipeline:
    def __init__(self, verdicts: dict[str, tuple[float, dict, str]]):
        self.verdicts = verdicts
        self.probed: list[str] = []

    def run_domain(self, domain: str) -> FakeResult:
        self.probed.append(domain)
        score, reasons, decision = self.verdicts.get(domain, (0.0, {}, "dismissed"))
        return FakeResult(
            domain=domain, score=score, reasons=reasons, decision=decision, features=dict(reasons)
        )


class FakeSearx:
    def __init__(self):
        self.calls = 0

    def search(self, query: str, *, pageno: int) -> list[dict]:
        self.calls += 1
        return []


@pytest.fixture()
def store(tmp_path):
    from scamstore import ScamStore

    return ScamStore(tmp_path / "scam.db")


def _seed(store, domain: str, *, decision="block", night="2026-10-25", **lifecycle):
    store.record(domain, score=30.0, decision=decision, night=night)
    store.record(domain, score=30.0, decision=decision, night=night)
    store.save_lifecycle(
        State(
            domain=domain,
            status=lifecycle.pop("status", "active"),
            base_decision=lifecycle.pop("base_decision", decision),
            since_night=night,
            **lifecycle,
        )
    )


def _night(store, tmp_path, pipe, night):
    return hunter.run_night(
        night=night, searx=FakeSearx(), pipeline=pipe, store=store, db_dir=tmp_path
    )


def test_three_below_nights_demote_to_pending_release(tmp_path, store):
    _seed(store, "weak.example")
    pipe = FakePipeline({"weak.example": (18.0, {"favicon_collision": 18}, "hold")})

    for night in ("2026-10-26", "2026-10-27"):
        rep = _night(store, tmp_path, pipe, night)
        assert store.get("weak.example")["decision"] == "block"
        assert rep["pending_release"] == []
        assert rep["released"] == []

    rep = _night(store, tmp_path, pipe, "2026-10-28")
    assert rep["pending_release"] == ["weak.example"]
    assert store.get("weak.example")["decision"] == "pending_release"
    assert store.cloaking_holds() == ["weak.example"], "cloaking リストへ移動する"


def test_pending_release_block_confirms_scam_list(tmp_path, store):
    _seed(store, "again.example", status="pending_release", below_streak=0)
    pipe = FakePipeline({"again.example": (61.0, {"lp_redirect": 30}, "block")})

    rep = _night(store, tmp_path, pipe, "2026-10-26")

    assert rep["reconfirmed"] == ["again.example"]
    assert store.get("again.example")["decision"] == "block"
    assert store.cloaking_holds() == []


def test_pending_release_hold_confirms_cloaking_list(tmp_path, store):
    _seed(store, "cloak.example", status="pending_release")
    pipe = FakePipeline({"cloak.example": (24.0, {"cloaking": 24}, "hold")})

    rep = _night(store, tmp_path, pipe, "2026-10-26")

    assert rep["confirmed_hold"] == ["cloak.example"]
    assert store.get("cloak.example")["decision"] == "hold"
    assert store.cloaking_holds() == ["cloak.example"]


def test_pending_release_releases_after_three_below_nights(tmp_path, store):
    _seed(store, "fade.example", status="pending_release", pending_checks=2)
    pipe = FakePipeline({"fade.example": (5.0, {}, "dismissed")})

    rep = _night(store, tmp_path, pipe, "2026-10-26")

    assert rep["released"] == ["fade.example"]
    assert store.get("fade.example")["decision"] == "released"
    assert store.cloaking_holds() == []


def test_released_returns_to_scam_list_on_block(tmp_path, store):
    _seed(store, "back.example", status="released")
    pipe = FakePipeline({"back.example": (70.0, {"lp_redirect": 30}, "block")})

    rep = _night(store, tmp_path, pipe, "2026-10-26")

    assert rep["reconfirmed"] == ["back.example"]
    assert store.get("back.example")["decision"] == "block"


def test_released_returns_to_cloaking_on_two_holds_in_five(tmp_path, store):
    _seed(store, "halo.example", status="released", below_streak=3)
    store.record_observation(
        "halo.example", seq=1, night="2026-10-01", verdict="hold", reachable="reachable"
    )
    pipe = FakePipeline({"halo.example": (22.0, {"cloaking": 22}, "hold")})

    rep = _night(store, tmp_path, pipe, "2026-10-26")

    assert rep["confirmed_hold"] == ["halo.example"]
    assert store.get("halo.example")["decision"] == "hold"
    assert store.cloaking_holds() == ["halo.example"]


def test_released_retires_after_five_below_checks(tmp_path, store):
    _seed(store, "gone.example", status="released", below_streak=4)
    pipe = FakePipeline({"gone.example": (2.0, {}, "dismissed")})

    rep = _night(store, tmp_path, pipe, "2026-10-26")

    assert rep["retired"] == ["gone.example"]
    assert store.get("gone.example")["decision"] == "retired"
    assert store.lifecycle_get("gone.example")["status"] == "retired"


def test_unconfirmed_block_stays_block_when_reconfirmed(tmp_path, store):
    _seed(store, "solid.example")
    pipe = FakePipeline({"solid.example": (22.0, {"bot_only_body": 18}, "block")})

    rep = _night(store, tmp_path, pipe, "2026-10-26")

    assert store.get("solid.example")["decision"] == "block"
    assert rep["reconfirmed"] == ["solid.example"]
    assert rep["released"] == []
