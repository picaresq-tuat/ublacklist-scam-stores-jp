"""P7c: 夜間オーケストレータ (hunter.py) の RED テスト。

すべての I/O (SearXNG / 実ページ取得 / DB) をスタブで注入し、
ステージの順序・データフロー・再試行 (R5: scam.db が空なら pageno を変えて最大3回)・
dry-run/publish モードを検証する。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import hunter
import pytest
from publish import PERMANENT_RULES


def _days_ago(n: int) -> str:
    return (datetime.now(UTC) - timedelta(days=n)).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- スタブ ---


@dataclass
class FakeResult:
    domain: str
    score: float
    reasons: dict = field(default_factory=dict)
    decision: str = "hold"
    features: dict = field(default_factory=dict)


class FakePipeline:
    """probe→score を模倣する注入可能スタブ。"""

    def __init__(self, verdicts: dict[str, tuple[float, dict, str]] | None = None):
        self.verdicts = verdicts or {}
        self.probed: list[str] = []

    def run_domain(self, domain: str) -> FakeResult:
        self.probed.append(domain)
        score, reasons, decision = self.verdicts.get(domain, (0.0, {}, "dismissed"))
        return FakeResult(domain=domain, score=score, reasons=reasons, decision=decision)


class FakeSearx:
    """discovery の検索スタブ。call に応じて pageno を記録する。"""

    def __init__(self, result_sets: list[list[str]]):
        self.result_sets = result_sets
        self.calls: list[dict] = []

    def search(self, query: str, *, pageno: int) -> list[dict]:
        self.calls.append({"query": query, "pageno": pageno})
        idx = (len(self.calls) - 1) % len(self.result_sets)
        return [
            {"url": f"https://{d}/item/{i}", "title": f"t{i}"}
            for i, d in enumerate(self.result_sets[idx])
        ]


@pytest.fixture()
def empty_store(tmp_path):
    from scamstore import ScamStore

    return ScamStore(tmp_path / "scam.db")


# --- RED: まずは正しい順序で部品を呼ぶこと ---


def test_hunt_discovery_calls_searx_with_query_and_pageno(empty_store, tmp_path):
    sx = FakeSearx([["shop-unknown.example"]])
    pipe = FakePipeline()
    hunter.run_night(
        night="2026-09-24",
        searx=sx,
        pipeline=pipe,
        store=empty_store,
        db_dir=tmp_path,
        max_queries=5,
    )
    assert sx.calls, "discovery must call searx.search"
    first = sx.calls[0]
    assert first["pageno"] >= 1
    assert pipe.probed == ["shop-unknown.example"]


def test_hunt_returns_report_with_counts(empty_store, tmp_path):
    sx = FakeSearx([["a.example", "b.example"]])
    pipe = FakePipeline(
        {"a.example": (74.0, {"zencart": 4}, "block"), "b.example": (0.0, {}, "dismissed")}
    )
    rep = hunter.run_night(
        night="2026-09-24",
        searx=sx,
        pipeline=pipe,
        store=empty_store,
        db_dir=tmp_path,
        max_queries=5,
    )
    assert rep["night"] == "2026-09-24"
    assert rep["domains_found"] >= 1
    assert rep["blocked"] == ["a.example"]
    assert len(rep["dismissed"]) >= 1


def test_hunt_records_decisions_in_store(empty_store, tmp_path):
    sx = FakeSearx([["a.example"]])
    pipe = FakePipeline({"a.example": (74.0, {"zencart": 4}, "block")})
    hunter.run_night(
        night="2026-09-24",
        searx=sx,
        pipeline=pipe,
        store=empty_store,
        db_dir=tmp_path,
        max_queries=5,
    )
    row = empty_store.get("a.example")
    assert row is not None
    assert row["decision"] == "block"
    assert row["score"] == 74.0


def test_hold_domains_are_recorded_as_hold(empty_store, tmp_path):
    sx = FakeSearx([["b.example"]])
    pipe = FakePipeline({"b.example": (18.0, {"dark": 3}, "hold")})
    hunter.run_night(
        night="2026-09-24",
        searx=sx,
        pipeline=pipe,
        store=empty_store,
        db_dir=tmp_path,
        max_queries=5,
    )
    assert empty_store.get("b.example")["decision"] == "hold"


# --- RED: R5 再試行 (scam.db が空なら pageno を変えて最大3回) ---


def test_empty_night_retries_with_different_pageno(empty_store, tmp_path):
    """1巡目は全ドメイン既知で scam.db に新規が入らない → pageno を変えて再試行。"""
    pre = empty_store
    pre.record("known.example", score=10, decision="hold", night="2026-09-20")

    sx = FakeSearx([["known.example"], ["fresh.example"]])
    pipe = FakePipeline({"fresh.example": (70.0, {"zencart": 5}, "block")})
    rep = hunter.run_night(
        night="2026-09-24", searx=sx, pipeline=pipe, store=pre, db_dir=tmp_path, max_queries=5
    )
    assert len(sx.calls) >= 2, "must retry when nothing new was recorded"
    assert (
        sx.calls[0]["pageno"] != sx.calls[1]["pageno"]
        or sx.calls[0]["query"] != sx.calls[1]["query"]
    )
    assert "fresh.example" in rep["blocked"]


def test_retry_caps_at_three(empty_store, tmp_path):
    """既知しか出ない夜は 3 回で諦める (無限ループ禁止)。"""
    empty_store.record("same.example", score=10, decision="hold", night="2026-09-20")
    sx = FakeSearx([["same.example"], ["same.example"], ["same.example"]])
    pipe = FakePipeline()
    rep = hunter.run_night(
        night="2026-09-24",
        searx=sx,
        pipeline=pipe,
        store=empty_store,
        db_dir=tmp_path,
        max_queries=2,
    )
    assert len(sx.calls) == 3 * 2  # クエリ数 × 試行回数
    assert rep["new_domains"] == 0
    assert rep["rounds"] == 3


def test_retry_count_in_report(empty_store, tmp_path):
    empty_store.record("same.example", score=10, decision="hold", night="2026-09-20")
    sx = FakeSearx([["same.example"], ["fresh.example"]])
    pipe = FakePipeline({"fresh.example": (70.0, {}, "block")})
    rep = hunter.run_night(
        night="2026-09-24",
        searx=sx,
        pipeline=pipe,
        store=empty_store,
        db_dir=tmp_path,
        max_queries=1,
    )
    assert rep["rounds"] == 2
    assert "fresh.example" in rep["blocked"]


# --- RED: ホワイトリストは triage で先に落とす ---


def test_whitelisted_domains_never_reach_probe(empty_store, tmp_path):
    sx = FakeSearx([["www.janpara.co.jp", "www.kakaku.com", "scam-shop.example"]])
    pipe = FakePipeline({"scam-shop.example": (74.0, {"zencart": 4}, "block")})
    rep = hunter.run_night(
        night="2026-09-24",
        searx=sx,
        pipeline=pipe,
        store=empty_store,
        db_dir=tmp_path,
        max_queries=5,
    )
    assert "www.janpara.co.jp" not in pipe.probed
    assert "www.kakaku.com" not in pipe.probed
    assert "janpara.co.jp" in rep["whitelisted"]
    assert pipe.probed == ["scam-shop.example"]


# --- RED: 既知ドメイン (scam.db 登録済) は同一夜の再 probe をしない ---


def test_already_known_domains_are_skipped(tmp_path, empty_store):
    store = empty_store
    store.record("known.example", score=10, decision="hold", night="2026-09-20")
    sx = FakeSearx([["known.example", "new.example"]])
    pipe = FakePipeline({"new.example": (70.0, {}, "block")})
    rep = hunter.run_night(
        night="2026-09-24", searx=sx, pipeline=pipe, store=store, db_dir=tmp_path, max_queries=5
    )
    assert "new.example" in pipe.probed, "新規ドメインが probe されていない"
    assert "known.example" in rep["already_known"]
    # 既知ドメインは discovery では拾わないが、ライフサイクル巡回で毎晩再評価される。
    assert pipe.probed.count("known.example") == 1


# --- RED: publish モード ---


def test_publish_mode_writes_ublacklist_file(tmp_path, empty_store):
    ufile = tmp_path / "out" / "uBlacklist.txt"
    ufile.parent.mkdir()
    ufile.write_text("# seed\n", encoding="utf-8")

    sx = FakeSearx([["a.example", "b.example"]])
    pipe = FakePipeline(
        {"a.example": (50.0, {"zencart": 4}, "block"), "b.example": (18.0, {}, "hold")}
    )
    rep = hunter.run_night(
        night="2026-09-24",
        searx=sx,
        pipeline=pipe,
        store=empty_store,
        db_dir=tmp_path,
        ulist_path=ufile,
        publish=True,
    )
    text = ufile.read_text(encoding="utf-8")
    assert "*://*.a.example/*" not in text  # 1夜目・score 50 <60 → fast track 未満
    assert "*://*.b.example/*" not in text
    assert rep["published_entries"] == 0
    assert "## Permanent rules (regex)" in text  # 常設ルールは必ず入る


def test_publish_mode_emits_eligible_domains(tmp_path, empty_store):
    ufile = tmp_path / "out" / "uBlacklist.txt"
    ufile.parent.mkdir()
    ufile.write_text("", encoding="utf-8")
    empty_store.record("old.example", score=40, decision="block", night="2026-09-22")
    empty_store.record("old.example", score=40, decision="block", night="2026-09-23")
    empty_store.record("fast.example", score=65, decision="block", night="2026-09-23")

    sx = FakeSearx([["new.example"]])
    pipe = FakePipeline({"new.example": (50.0, {"zencart": 4}, "block")})
    hunter.run_night(
        night="2026-09-24",
        searx=sx,
        pipeline=pipe,
        store=empty_store,
        db_dir=tmp_path,
        ulist_path=ufile,
        publish=True,
    )
    text = ufile.read_text(encoding="utf-8")
    assert "*://*.old.example/*" in text  # 2夜確認済み → 出る
    assert "*://*.fast.example/*" in text  # fast track (>=60) → 出る
    assert "*://*.new.example/*" not in text  # 1夜目・score 50 → 出ない


def test_dry_run_reports_would_publish(tmp_path, empty_store):
    ufile = tmp_path / "out" / "uBlacklist.txt"
    ufile.parent.mkdir()
    ufile.write_text("", encoding="utf-8")
    empty_store.record("old.example", score=40, decision="block", night="2026-09-22")
    empty_store.record("old.example", score=40, decision="block", night="2026-09-23")

    sx = FakeSearx([["x.example"]])
    pipe = FakePipeline()
    rep = hunter.run_night(
        night="2026-09-24",
        searx=sx,
        pipeline=pipe,
        store=empty_store,
        db_dir=tmp_path,
        ulist_path=ufile,
        publish=True,
        dry_run=True,
    )
    text = ufile.read_text(encoding="utf-8")
    assert "*://*.old.example/*" in text  # ファイルは書く (PR用)
    assert rep["dry_run"] is True
    assert rep["would_publish"] == ["*://*.old.example/*"]


def test_publish_drops_whitelisted_domain_from_both_lists(tmp_path, empty_store):
    """誤検知と判明して whitelist に入れたドメインは、publish で再掲載しない。

    decisions 側が block のまま残っていても (過去の誤判定)、確定リストにも
    cloaking リストにも出さず、既存行があれば取り除く。
    """
    ufile = tmp_path / "out" / "uBlacklist.txt"
    ufile.parent.mkdir()
    ufile.write_text(
        "# test\n## ドメイン\n*://*.gemini.google/*\n*://*.keep.example/*\n", encoding="utf-8"
    )
    cfile = tmp_path / "out" / "cloaking" / "uBlacklist.txt"
    cfile.parent.mkdir()
    cfile.write_text(
        "# test\n## ドメイン\n*://*.gemini.google/*\n*://*.hold.example/*\n", encoding="utf-8"
    )
    empty_store.record("gemini.google", score=80, decision="block", night="2026-09-22")
    empty_store.record("gemini.google", score=80, decision="block", night="2026-09-23")
    empty_store.record("keep.example", score=80, decision="block", night="2026-09-23")

    hunter.run_night(
        night="2026-09-24",
        searx=FakeSearx([["x.example"]]),
        pipeline=FakePipeline(),
        store=empty_store,
        db_dir=tmp_path,
        ulist_path=ufile,
        cloaking_list_path=cfile,
        publish=True,
    )
    scam = ufile.read_text(encoding="utf-8")
    cloak = cfile.read_text(encoding="utf-8")
    assert "*://*.gemini.google/*" not in scam
    assert "*://*.gemini.google/*" not in cloak
    assert "*://*.keep.example/*" in scam
    assert "*://*.hold.example/*" in cloak


# --- RED: P8 失効監視は夜次処理の一部 ---


def test_expired_domain_is_removed_from_the_list_on_publish(tmp_path, empty_store):
    ufile = tmp_path / "out" / "uBlacklist.txt"
    ufile.parent.mkdir()
    ufile.write_text("*://*.dead.example/*\n", encoding="utf-8")
    _seed_listed(empty_store, "dead.example", status="pending_expiration", unreachable_streak=4)

    rep = hunter.run_night(
        night="2026-09-24",
        searx=FakeSearx([[]]),
        pipeline=FakePipeline(),
        store=empty_store,
        db_dir=tmp_path,
        ulist_path=ufile,
        publish=True,
        health=_DeadHealth(),
        max_queries=0,
    )
    text = ufile.read_text(encoding="utf-8")
    assert "*://*.dead.example/*" not in text
    assert empty_store.get("dead.example")["decision"] == "expired"
    assert rep["expired"] == ["dead.example"]


def test_health_sweep_checks_every_registered_domain(tmp_path, empty_store):
    """登録からの経過日数ではなく、リスト上の全ドメインを巡回する。"""
    from datetime import datetime, timedelta

    old_day = (datetime.now(UTC) - timedelta(days=45)).strftime("%Y-%m-%d")
    recent_day = (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%d")
    empty_store.record("old.example", score=40, decision="block", night=old_day)
    empty_store.record("new.example", score=40, decision="block", night=recent_day)

    probed = []

    class FakeHealth:
        def check_state(self, domain: str) -> str:
            probed.append(domain)
            return "reachable"

    hunter.run_night(
        night="2026-09-24",
        searx=FakeSearx([[]]),
        pipeline=FakePipeline(),
        store=empty_store,
        db_dir=tmp_path,
        health=FakeHealth(),
    )
    assert probed == ["new.example", "old.example"]


# --- RED: クエリ数とベース URL ---

# --- R3: pageno がエンジン想定最大を超えた場合の再試行 ---


def test_retries_with_another_pageno_when_engine_returns_empty(empty_store, tmp_path):
    """pageno 超大で 0 件 → 同じ (型番, 用語) を別 pageno で引き直す。"""

    class PagedSearx:
        """最初の pageno では 0 件 (エンジン上限超え)、引き直すと返る。"""

        def __init__(self):
            self.calls = []

        def search(self, query, *, pageno):
            self.calls.append((query, pageno))
            if len(self.calls) == 1:
                return []
            return [{"url": "https://found.example/item", "title": "t"}]

    sx = PagedSearx()
    pipe = FakePipeline({"found.example": (70.0, {}, "block")})
    rep = hunter.run_night(
        night="2026-09-24",
        searx=sx,
        pipeline=pipe,
        store=empty_store,
        db_dir=tmp_path,
        max_queries=1,
        max_pageno_attempts=3,
    )
    used = [p for _, p in sx.calls]
    assert len(used) > 1, "0 件なのに pageno を引き直していない"
    assert len(set(used)) == len(used), "同じ pageno を再使用している"
    assert "found.example" in rep["blocked"]


def test_pageno_retry_is_bounded(empty_store, tmp_path):
    class DeadSearx:
        def __init__(self):
            self.n = 0

        def search(self, query, *, pageno):
            self.n += 1
            return []

    sx = DeadSearx()
    pipe = FakePipeline()
    rep = hunter.run_night(
        night="2026-09-24",
        searx=sx,
        pipeline=pipe,
        store=empty_store,
        db_dir=tmp_path,
        max_queries=2,
        max_pageno_attempts=3,
    )
    assert sx.n <= 2 * 3 * hunter.MAX_ROUNDS  # クエリ数 × 試行 × ラウンド上限
    assert rep["rounds"] == hunter.MAX_ROUNDS


def test_saturated_pageno_range_does_not_crash(empty_store, tmp_path):
    """全 pageno が空を返しても PageRangeExhausted で落ちない。"""

    class AlwaysEmpty:
        def search(self, query, *, pageno):
            return []

    rep = hunter.run_night(
        night="2026-09-24",
        searx=AlwaysEmpty(),
        pipeline=FakePipeline(),
        store=empty_store,
        db_dir=tmp_path,
        max_queries=3,
        max_pageno_attempts=5,
    )
    assert rep["new_domains"] == 0
    assert rep["empty_queries"] >= 1


# --- 実測整合: エンジン suspension (Google CSE 429) で夜全体を落とさない ---


def test_engine_unavailable_does_not_abort_night(empty_store, tmp_path):
    """1 クエリの 429 (EngineUnavailable) で夜間実行全体を異常終了させない。"""
    from searxng import EngineUnavailable

    class Flaky:
        def __init__(self):
            self.n = 0

        def search(self, query, *, pageno):
            self.n += 1
            if self.n == 1:
                raise EngineUnavailable("engines unavailable: ['google cse']")
            return [{"url": "https://found.example/i", "title": "t"}]

    sx = Flaky()
    rep = hunter.run_night(
        night="2026-09-24",
        searx=sx,
        pipeline=FakePipeline({"found.example": (70.0, {}, "block")}),
        store=empty_store,
        db_dir=tmp_path,
        max_queries=3,
        sleep=lambda _sec: None,
    )
    assert rep["engine_failures"] >= 1
    assert rep["aborted"] is False
    assert rep["blocked"] == ["found.example"]


def test_repeated_engine_failures_abort_early(empty_store, tmp_path):
    """429 が続く夜は叩き続けず早期に切り上げる (IP レピュテーション悪化の防止)。"""
    from searxng import EngineUnavailable

    class Dead:
        def __init__(self):
            self.n = 0

        def search(self, query, *, pageno):
            self.n += 1
            raise EngineUnavailable("engines unavailable: ['google cse']")

    sx = Dead()
    rep = hunter.run_night(
        night="2026-09-24",
        searx=sx,
        pipeline=FakePipeline(),
        store=empty_store,
        db_dir=tmp_path,
        max_queries=10,
        max_engine_failures=4,
        sleep=lambda _sec: None,
    )
    assert rep["aborted"] is True
    assert rep["engine_failures"] == 4
    assert sx.n == 4, "failure 上限を超えて検索し続けている"


def test_engine_failure_count_is_in_report_by_default(empty_store, tmp_path):
    sx = FakeSearx([["a.example"]])
    rep = hunter.run_night(
        night="2026-09-24",
        searx=sx,
        pipeline=FakePipeline(),
        store=empty_store,
        db_dir=tmp_path,
        max_queries=2,
    )
    assert rep["engine_failures"] == 0
    assert rep["aborted"] is False


# --- 実測整合: 429 は連投が原因。失敗時はバックオフして次の夜を守る ---


def test_engine_failure_backs_off_before_next_search(empty_store, tmp_path):
    """EngineUnavailable の後は間隔を空ける (連投で IP レピュテーションを悪化させない)。"""
    from searxng import EngineUnavailable

    slept: list[float] = []

    class Dead:
        def search(self, query, *, pageno):
            raise EngineUnavailable("engines unavailable: ['google cse']")

    rep = hunter.run_night(
        night="2026-09-24",
        searx=Dead(),
        pipeline=FakePipeline(),
        store=empty_store,
        db_dir=tmp_path,
        max_queries=10,
        max_engine_failures=3,
        engine_backoff_sec=10.0,
        sleep=slept.append,
    )
    assert slept == [10.0, 20.0], "失敗 1 回目は 10 秒、2 回目は 20 秒待つ"
    assert rep["aborted"] is True
    assert rep["engine_failures"] == 3


def test_engine_backoff_is_capped(empty_store, tmp_path):
    """バックオフは上限で頭打ちにする (夜が無駄に長くならない)。"""
    from searxng import EngineUnavailable

    slept: list[float] = []

    class Dead:
        def search(self, query, *, pageno):
            raise EngineUnavailable("engines unavailable: ['google cse']")

    hunter.run_night(
        night="2026-09-24",
        searx=Dead(),
        pipeline=FakePipeline(),
        store=empty_store,
        db_dir=tmp_path,
        max_queries=20,
        max_engine_failures=5,
        engine_backoff_sec=100.0,
        engine_backoff_max_sec=250.0,
        sleep=slept.append,
    )
    assert slept == [100.0, 200.0, 250.0, 250.0]


def test_no_backoff_sleep_on_successful_night(empty_store, tmp_path):
    slept: list[float] = []
    sx = FakeSearx([["a.example"]])
    hunter.run_night(
        night="2026-09-24",
        searx=sx,
        pipeline=FakePipeline({"a.example": (70.0, {}, "block")}),
        store=empty_store,
        db_dir=tmp_path,
        max_queries=2,
        engine_backoff_sec=10.0,
        sleep=slept.append,
    )
    assert slept == []


# --- 巡回ライフサイクル: 到達不能ルートを hunter 経由で検証 ---


class _DeadHealth:
    """常に到達不能と判定する HealthChecker のスタブ。"""

    def __init__(self):
        self.checked: list[str] = []

    def check_state(self, domain: str) -> str:
        self.checked.append(domain)
        return "unreachable"

    def check(self, domain: str) -> bool:
        return self.check_state(domain) == "reachable"


class _AliveHealth:
    def __init__(self):
        self.checked: list[str] = []

    def check_state(self, domain: str) -> str:
        self.checked.append(domain)
        return "reachable"

    def check(self, domain: str) -> bool:
        return True


def _seed_listed(store, domain: str, *, night="2026-09-20", **lifecycle):
    """2 夜確認済み = scam リスト掲載中のドメインを作る。"""
    from lifecycle import State

    store.record(domain, score=80.0, decision="block", night=night)
    store.record(domain, score=80.0, decision="block", night=night)
    if lifecycle:
        store.save_lifecycle(
            State(
                domain=domain,
                status=lifecycle.pop("status", "active"),
                base_decision="block",
                since_night=lifecycle.pop("since_night", night),
                **lifecycle,
            )
        )


def test_every_listed_domain_is_probed_every_night(empty_store, tmp_path):
    """30 日経過を待たず、リスト上のドメインは毎晩巡回する。"""
    _seed_listed(empty_store, "fresh.example", night=_days_ago(2))
    health = _AliveHealth()
    rep = hunter.run_night(
        night="2026-09-24",
        searx=FakeSearx([[]]),
        pipeline=FakePipeline({"fresh.example": (80.0, {}, "block")}),
        store=empty_store,
        db_dir=tmp_path,
        max_queries=0,
        health=health,
    )
    assert health.checked == ["fresh.example"]
    assert rep["lifecycle_checked"] == ["fresh.example"]


def test_unreachable_three_nights_demote_to_pending_expiration(empty_store, tmp_path):
    """3 晩連続で到達不能 → pending_expiration。リストからの削除はまだ行わない。"""
    _seed_listed(empty_store, "dead.example")
    health = _DeadHealth()
    nights = ["2026-09-24", "2026-09-25", "2026-09-26"]
    for night in nights[:2]:
        rep = hunter.run_night(
            night=night,
            searx=FakeSearx([[]]),
            pipeline=FakePipeline(),
            store=empty_store,
            db_dir=tmp_path,
            max_queries=0,
            health=health,
        )
        assert rep["pending_expiration"] == []
        assert empty_store.get("dead.example")["decision"] == "block"

    rep = hunter.run_night(
        night=nights[2],
        searx=FakeSearx([[]]),
        pipeline=FakePipeline(),
        store=empty_store,
        db_dir=tmp_path,
        max_queries=0,
        health=health,
    )
    assert rep["pending_expiration"] == ["dead.example"]
    assert empty_store.get("dead.example")["decision"] == "pending_expiration"
    assert empty_store.eligible_domains() == [], "スコア算出を停止し、掲載候補から外す"


def test_pending_expiration_expires_after_five_more_unreachable_checks(empty_store, tmp_path):
    _seed_listed(empty_store, "gone.example", status="pending_expiration", unreachable_streak=4)
    ulist = tmp_path / "uBlacklist.txt"
    ulist.write_text(
        "# uBlacklist - scam stores JP (Hermes nightly)\n"
        "\n"
        "## Permanent rules (regex)\n" + "\n".join(PERMANENT_RULES) + "\n"
        "\n"
        "## Hermes nightly\n"
        "*://*.gone.example/*\n"
        "*://*.other.example/*\n",
        encoding="utf-8",
    )

    rep = hunter.run_night(
        night="2026-09-24",
        searx=FakeSearx([[]]),
        pipeline=FakePipeline(),
        store=empty_store,
        db_dir=tmp_path,
        max_queries=0,
        health=_DeadHealth(),
        ulist_path=ulist,
        publish=True,
    )
    assert rep["expired"] == ["gone.example"]
    assert empty_store.get("gone.example")["decision"] == "expired"
    text = ulist.read_text(encoding="utf-8")
    assert "gone.example" not in text, "失効ドメインが uBlacklist に残っている"
    assert "other.example" in text, "失効していないエントリまで消してはいけない"
    assert ".*\\.co\\/.*" in text, "常設ルールまで消してはいけない"


def test_expired_domain_is_restored_and_relisted_when_reachable(empty_store, tmp_path):
    _seed_listed(empty_store, "revive.example", status="expired", unreachable_streak=3)
    ulist = tmp_path / "uBlacklist.txt"
    ulist.write_text(
        "# uBlacklist - scam stores JP (Hermes nightly)\n"
        "\n"
        "## Permanent rules (regex)\n" + "\n".join(PERMANENT_RULES) + "\n"
        "\n"
        "## Hermes nightly\n",
        encoding="utf-8",
    )

    rep = hunter.run_night(
        night="2026-09-24",
        searx=FakeSearx([[]]),
        pipeline=FakePipeline({"revive.example": (80.0, {}, "block")}),
        store=empty_store,
        db_dir=tmp_path,
        max_queries=0,
        health=_AliveHealth(),
        ulist_path=ulist,
        publish=True,
    )
    assert rep["restored"] == ["revive.example"]
    assert empty_store.get("revive.example")["decision"] == "block"
    assert "*://*.revive.example/*" in ulist.read_text(encoding="utf-8")


def test_failed_night_does_not_count_unreachable(empty_store, tmp_path):
    """nightly 全体が失敗した夜は到達不能として数えない。"""
    from searxng import EngineUnavailable

    _seed_listed(empty_store, "dead.example")

    class Dead:
        def search(self, query, *, pageno):
            raise EngineUnavailable("engines unavailable")

    for night in ("2026-09-24", "2026-09-25", "2026-09-26", "2026-09-27"):
        rep = hunter.run_night(
            night=night,
            searx=Dead(),
            pipeline=FakePipeline(),
            store=empty_store,
            db_dir=tmp_path,
            max_queries=2,
            max_engine_failures=1,
            engine_backoff_sec=0.0,
            health=_DeadHealth(),
            sleep=lambda _s: None,
        )
        assert rep["lifecycle_skipped"] == "night_failed"
        assert rep["pending_expiration"] == []
    assert empty_store.get("dead.example")["decision"] == "block"
    assert (empty_store.lifecycle_get("dead.example") or {}).get("unreachable_streak", 0) == 0
    assert empty_store.completed_runs() == 0


def test_without_health_checker_unreachable_route_is_disabled(empty_store, tmp_path):
    _seed_listed(empty_store, "nodead.example")
    rep = hunter.run_night(
        night="2026-09-24",
        searx=FakeSearx([[]]),
        pipeline=FakePipeline({"nodead.example": (80.0, {}, "block")}),
        store=empty_store,
        db_dir=tmp_path,
        max_queries=0,
        health=None,
    )
    assert rep["pending_expiration"] == []
    assert empty_store.get("nodead.example")["decision"] == "block"


def test_retired_domain_is_rediscovered_like_a_new_domain(empty_store, tmp_path):
    """巡回対象外のドメインが再発見されたら、新規と同じ経路で巡回する。"""

    _seed_listed(
        empty_store, "return.example", status="retired", since_night="2026-08-01", last_check_seq=9
    )
    rep = hunter.run_night(
        night="2026-09-24",
        searx=FakeSearx([["return.example"]]),
        pipeline=FakePipeline({"return.example": (80.0, {}, "block")}),
        store=empty_store,
        db_dir=tmp_path,
        max_queries=1,
        health=_AliveHealth(),
    )
    assert rep["new_domains"] == 1
    assert empty_store.get("return.example")["decision"] == "block"
    assert empty_store.lifecycle_get("return.example")["status"] == "active"
    assert empty_store.lifecycle_get("return.example")["last_check_seq"] == 0


def test_max_queries_bounds_search_calls(empty_store, tmp_path):
    sx = FakeSearx([["d1.example"]] * 50)
    pipe = FakePipeline()
    hunter.run_night(
        night="2026-09-24",
        searx=sx,
        pipeline=pipe,
        store=empty_store,
        db_dir=tmp_path,
        max_queries=4,
    )
    assert len(sx.calls) <= 4


def test_run_night_is_idempotent_per_domain(empty_store, tmp_path):
    """同じ夜に2回走らせても nights_confirmed は進まない。"""
    sx = FakeSearx([["a.example"]])
    pipe = FakePipeline({"a.example": (74.0, {}, "block")})
    hunter.run_night(
        night="2026-09-24",
        searx=sx,
        pipeline=pipe,
        store=empty_store,
        db_dir=tmp_path,
        max_queries=5,
    )
    hunter.run_night(
        night="2026-09-24",
        searx=sx,
        pipeline=pipe,
        store=empty_store,
        db_dir=tmp_path,
        max_queries=5,
    )
    assert empty_store.get("a.example")["nights_confirmed"] == 1


# --- 実測整合: pageno 上限はエンジンのページング能力に合わせる ---


def test_default_max_pageno_matches_engine_cap():
    """Bing はページング非対応なので、上限は Google CSE の実測上限に合わせる。"""
    from searxng import PRIMARY_MAX_PAGENO

    assert hunter.DEFAULT_MAX_PAGENO == PRIMARY_MAX_PAGENO


def test_pageno_never_exceeds_engine_cap(empty_store, tmp_path):
    """実際に使われた pageno が上限を超えない (超えると必ず 0 件になる)。"""
    from searxng import PRIMARY_MAX_PAGENO

    class Recording:
        def __init__(self):
            self.pagenos = []

        def search(self, query, *, pageno):
            self.pagenos.append(pageno)
            return [{"url": "https://x.example/i", "title": "t"}]

    sx = Recording()
    hunter.run_night(
        night="2026-09-24",
        searx=sx,
        pipeline=FakePipeline(),
        store=empty_store,
        db_dir=tmp_path,
        max_queries=8,
    )
    assert sx.pagenos, "クエリが 1 本も実行されていない"
    assert max(sx.pagenos) <= PRIMARY_MAX_PAGENO


# --- 実バグ回帰: pageno 引き直し中のエンジン失敗で None を反復しない ---

# 実測 (2026-10-11): 10-05 / 10-08 の cron 実行が
#   File "hunter.py", line 183, in run_night
#     for item in results:
#   TypeError: 'NoneType' object is not iterable
# で失敗した。初回 0 件 → pageno 引き直しで 429 (None) となった場合に起きる。


def test_engine_failure_during_pageno_retry_does_not_crash(empty_store, tmp_path):
    from searxng import EngineUnavailable

    class EmptyThenDead:
        def __init__(self):
            self.n = 0

        def search(self, query, *, pageno):
            self.n += 1
            if self.n == 1:
                return []
            raise EngineUnavailable("engines unavailable: ['google cse']")

    rep = hunter.run_night(
        night="2026-09-24",
        searx=EmptyThenDead(),
        pipeline=FakePipeline(),
        store=empty_store,
        db_dir=tmp_path,
        max_queries=1,
        max_pageno_attempts=3,
        sleep=lambda _sec: None,
    )
    assert rep["engine_failures"] >= 1
    # エンジン失敗を「空応答」として二重計上しない
    assert rep["empty_queries"] == 0
    assert rep["new_domains"] == 0


# --- 実バグ回帰: block 判定は翌夜に再評価され nights_confirmed が進む ---

# 実測 (2026-10-11): decisions 530 行すべて nights_confirmed=1、複数夜に現れた
# ドメインは 0 件。既判定ドメインが known_before で除外されるため
# eligible_domains(nights_required=2) の「連続2夜確認」が永久に発火しなかった。


def _seed_block(store, domain, score=35.0, night="2026-09-24"):
    store.record(domain, score=score, decision="block", features={}, night=night)


def test_block_domain_is_reconfirmed_on_a_later_night(empty_store, tmp_path):
    _seed_block(empty_store, "repeat.example")
    pipe = FakePipeline({"repeat.example": (35.0, {}, "block")})
    rep = hunter.run_night(
        night="2026-09-25",
        searx=FakeSearx([["other.example"]]),
        pipeline=pipe,
        store=empty_store,
        db_dir=tmp_path,
        max_queries=1,
    )
    assert "repeat.example" in pipe.probed, "block ドメインが再評価されていない"
    assert empty_store.get("repeat.example")["nights_confirmed"] == 2
    assert rep["reconfirmed"] == ["repeat.example"]


def test_confirmed_domains_are_rechecked_nightly(empty_store, tmp_path):
    """2 夜確認済みでも毎晩再評価する (降格ルートの入力になる)。"""
    empty_store.record("done.example", score=35.0, decision="block", night="2026-09-24")
    empty_store.record("done.example", score=35.0, decision="block", night="2026-09-25")
    empty_store.record("weak.example", score=20.0, decision="hold", night="2026-09-24")
    pipe = FakePipeline(
        {
            "done.example": (35.0, {}, "block"),
            "weak.example": (20.0, {"favicon_collision": 18}, "hold"),
        }
    )
    rep = hunter.run_night(
        night="2026-09-26",
        searx=FakeSearx([["other.example"]]),
        pipeline=pipe,
        store=empty_store,
        db_dir=tmp_path,
        max_queries=1,
    )
    assert "done.example" in pipe.probed
    assert "weak.example" in pipe.probed
    assert rep["reconfirmed"] == ["done.example"]


def test_reconfirmed_block_domain_becomes_eligible(empty_store, tmp_path):
    """再確認で nights_confirmed が 2 に達した block ドメインは登録候補になる。"""
    _seed_block(empty_store, "repeat.example")
    assert empty_store.eligible_domains() == []
    hunter.run_night(
        night="2026-09-25",
        searx=FakeSearx([["other.example"]]),
        pipeline=FakePipeline({"repeat.example": (35.0, {}, "block")}),
        store=empty_store,
        db_dir=tmp_path,
        max_queries=1,
    )
    assert empty_store.eligible_domains() == ["repeat.example"]


# --- RED: 実測で cloaking でないと確認した 2 サイトは probe に到達しない (2026-10-12) ---


def test_measured_non_cloaking_sites_never_reach_probe(empty_store, tmp_path):
    sx = FakeSearx([["bandai-hobby.net", "www.dmm.co.jp", "scam-shop.example"]])
    pipe = FakePipeline({"scam-shop.example": (74.0, {"zencart": 4}, "block")})
    rep = hunter.run_night(
        night="2026-10-12",
        searx=sx,
        pipeline=pipe,
        store=empty_store,
        db_dir=tmp_path,
        max_queries=5,
    )
    assert "bandai-hobby.net" in rep["whitelisted"]
    assert "dmm.co.jp" in rep["whitelisted"]
    assert pipe.probed == ["scam-shop.example"]
