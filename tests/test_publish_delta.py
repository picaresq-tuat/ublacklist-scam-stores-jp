"""publish 差分レポートの RED テスト。

nightly のログ/commit message が「累積の掲載対象数」を published として
報告していたため、実際に 1 行も追記されていない夜でも "published=23" と
表示されていた。published は「今夜 新たに追記した entry」だけを返し、
累積は published_total / 既出は already_listed で別に返す。
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
    def __init__(self, verdicts: dict[str, tuple[float, dict, str]] | None = None):
        self.verdicts = verdicts or {}

    def run_domain(self, domain: str) -> FakeResult:
        score, reasons, decision = self.verdicts.get(domain, (0.0, {}, "dismissed"))
        return FakeResult(domain=domain, score=score, reasons=reasons, decision=decision)


class FakeSearx:
    def __init__(self, result_sets: list[list[str]]):
        self.result_sets = result_sets
        self.calls = 0

    def search(self, query: str, *, pageno: int) -> list[dict]:
        self.calls += 1
        idx = (self.calls - 1) % len(self.result_sets)
        return [{"url": f"https://{d}/item", "title": "t"} for d in self.result_sets[idx]]


@pytest.fixture()
def store(tmp_path):
    from scamstore import ScamStore

    return ScamStore(tmp_path / "scam.db")


def _two_night_block(store, domain: str, score: float = 40.0) -> None:
    store.record(domain, score=score, decision="block", night="2026-10-25")
    store.record(domain, score=score, decision="block", night="2026-10-26")


def test_publish_reports_zero_when_everything_already_listed(tmp_path, store):
    from publish import render_list

    ufile = tmp_path / "uBlacklist.txt"
    # 実際の nightly 出力と同じ正規化済みの形を初期状態にする
    ufile.write_text(render_list(["old.example"]), encoding="utf-8")
    _two_night_block(store, "old.example")

    rep = hunter.run_night(
        night="2026-10-27",
        searx=FakeSearx([[]]),
        pipeline=FakePipeline(),
        store=store,
        db_dir=tmp_path,
        ulist_path=ufile,
        publish=True,
    )

    assert rep["published"] == []  # 追記ゼロ
    assert rep["published_total"] == ["*://*.old.example/*"]  # 累積は別キー
    assert rep["already_listed"] == ["*://*.old.example/*"]
    assert rep["ulist_changed"] is False
    assert ufile.read_text(encoding="utf-8").count("*://*.old.example/*") == 1


def test_publish_reports_only_newly_added_entry(tmp_path, store):
    ufile = tmp_path / "uBlacklist.txt"
    ufile.write_text("# seed\n*://*.old.example/*\n", encoding="utf-8")
    _two_night_block(store, "old.example")
    _two_night_block(store, "new.example")

    rep = hunter.run_night(
        night="2026-10-27",
        searx=FakeSearx([[]]),
        pipeline=FakePipeline(),
        store=store,
        db_dir=tmp_path,
        ulist_path=ufile,
        publish=True,
    )

    assert rep["published"] == ["*://*.new.example/*"]
    assert rep["published_total"] == ["*://*.new.example/*", "*://*.old.example/*"]
    assert rep["already_listed"] == ["*://*.old.example/*"]
    assert rep["ulist_changed"] is True


def test_publish_reports_permanent_shape_exclusion(tmp_path, store):
    """常設ルールが覆う形 (.com.br 等) は掲載しないが、除外理由として報告する。"""
    from publish import render_list

    ufile = tmp_path / "uBlacklist.txt"
    ufile.write_text(render_list([]), encoding="utf-8")
    _two_night_block(store, "shop-loja.com.br")

    rep = hunter.run_night(
        night="2026-10-27",
        searx=FakeSearx([[]]),
        pipeline=FakePipeline(),
        store=store,
        db_dir=tmp_path,
        ulist_path=ufile,
        publish=True,
    )

    assert rep["published"] == []
    assert rep["excluded_permanent_shape"] == ["shop-loja.com.br"]
    assert rep["ulist_changed"] is False


def test_publish_reports_removed_entries(tmp_path, store):
    """whitelist 済みドメインの既存行は ulist_removed として報告される。"""
    ufile = tmp_path / "uBlacklist.txt"
    ufile.write_text("# seed\n*://*.dmm.co.jp/*\n", encoding="utf-8")

    rep = hunter.run_night(
        night="2026-10-27",
        searx=FakeSearx([[]]),
        pipeline=FakePipeline(),
        store=store,
        db_dir=tmp_path,
        ulist_path=ufile,
        publish=True,
    )

    assert rep["ulist_removed"] == ["*://*.dmm.co.jp/*"]
    assert rep["ulist_changed"] is True
    assert "*://*.dmm.co.jp/*" not in ufile.read_text(encoding="utf-8")


def test_run_night_writes_new_block_into_list_across_two_nights(tmp_path, store):
    """発見→スコア→記録→掲載の全経路で、2晩目に block が実際にリストへ書かれる。"""
    from datetime import UTC, datetime, timedelta

    from publish import render_list

    ufile = tmp_path / "uBlacklist.txt"
    ufile.write_text(render_list([]), encoding="utf-8")

    # 単晩スコアでは eligible (>=55) に届かず、2晩の連続確認を要するケース
    pipe = FakePipeline({"scam-deals.example": (40.0, {"rdap": "new"}, "block")})
    today = datetime.now(UTC).date()
    first, second = str(today - timedelta(days=1)), str(today)

    rep1 = hunter.run_night(
        night=first,
        searx=FakeSearx([["scam-deals.example"]]),
        pipeline=pipe,
        store=store,
        db_dir=tmp_path,
        ulist_path=ufile,
        publish=True,
    )
    assert rep1["published"] == []  # 1晩目は未確定なので掲載しない
    assert "*://*.scam-deals.example/*" not in ufile.read_text(encoding="utf-8")

    rep2 = hunter.run_night(
        night=second,
        searx=FakeSearx([["scam-deals.example"]]),
        pipeline=pipe,
        store=store,
        db_dir=tmp_path,
        ulist_path=ufile,
        publish=True,
    )
    assert rep2["published"] == ["*://*.scam-deals.example/*"]
    assert rep2["ulist_changed"] is True
    assert "*://*.scam-deals.example/*" in ufile.read_text(encoding="utf-8")
