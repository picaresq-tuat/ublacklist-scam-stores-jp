"""未確定 block の limbo 解消 (RED)。

`block` 判定が nights_confirmed=1 のまま再確認で block にならないドメインは、
- eligible_domains(nights_required=2) に入らない → 永久に掲載されない
- decision は block のまま → 解除もされない
という limbo に残る。連続 2 夜 block にならなければ観測値へ降格する。
"""

from __future__ import annotations

from dataclasses import dataclass, field

import hunter
import pytest


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

    def run_domain(self, domain: str) -> FakeResult:
        score, reasons, decision = self.verdicts.get(domain, (0.0, {}, "dismissed"))
        return FakeResult(domain=domain, score=score, reasons=reasons, decision=decision)


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


def test_note_reconfirm_miss_counts_and_clears(store):
    assert store.note_reconfirm_miss("a.example", "2026-10-26") == 1
    assert store.note_reconfirm_miss("a.example", "2026-10-27") == 2
    assert store.note_reconfirm_miss("a.example", "2026-10-27") == 2  # 同じ夜は重複しない
    store.clear_reconfirm_miss("a.example")
    assert store.note_reconfirm_miss("a.example", "2026-10-28") == 1


def test_unconfirmed_block_released_after_two_missed_nights(tmp_path, store):
    store.record("stuck.example", score=22, decision="block", night="2026-10-25")
    pipe = FakePipeline({"stuck.example": (18.0, {"favicon_collision": 18}, "hold")})

    rep = hunter.run_night(
        night="2026-10-26",
        searx=FakeSearx(),
        pipeline=pipe,
        store=store,
        db_dir=tmp_path,
    )
    assert store.get("stuck.example")["decision"] == "block"  # 1 夜では覆さない
    assert rep["released"] == []

    rep = hunter.run_night(
        night="2026-10-27",
        searx=FakeSearx(),
        pipeline=pipe,
        store=store,
        db_dir=tmp_path,
    )
    assert store.get("stuck.example")["decision"] == "hold"
    assert rep["released"] == ["stuck.example"]


def test_unconfirmed_block_stays_block_when_reconfirmed(tmp_path, store):
    store.record("solid.example", score=22, decision="block", night="2026-10-25")
    pipe = FakePipeline({"solid.example": (22.0, {"bot_only_body": 18}, "block")})

    rep = hunter.run_night(
        night="2026-10-26",
        searx=FakeSearx(),
        pipeline=pipe,
        store=store,
        db_dir=tmp_path,
    )

    assert store.get("solid.example")["decision"] == "block"
    assert rep["reconfirmed"] == ["solid.example"]
    assert rep["released"] == []
