"""ドメイン巡回ライフサイクル (docs/domain-lifecycle.md)。

2 種類の降格ルートを明示的に分ける。

* 到達不能ルート: 3 回連続で到達不能 → pending_expiration（スコア算出を停止）
  → さらに 5 回 → expired（リストから削除）→ さらに 5 回 → retired（巡回対象外）
* スコア閾値ルート: 3 晩連続で閾値未満 → pending_release（scam → cloaking）
  → 3 晩の観測で block 確定 / hold 確定 / released（cloaking からも削除）
  → released で 5 回連続 hold 未満 → retired

到達不能の判定はスコア閾値に優先する。nightly 全体が失敗した夜は sweep 自体を
実行しないため、どちらのカウントも進まない。間隔は壁時計ではなく完了した
nightly run の回数で数える。
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import Protocol, TypedDict

STATUSES: tuple[str, ...] = (
    "active",
    "pending_release",
    "pending_expiration",
    "released",
    "expired",
    "retired",
)

# 到達不能ルート
UNREACHABLE_TO_PENDING = 3
PENDING_EXPIRATION_TO_EXPIRED = 5
EXPIRED_TO_RETIRED = 5
# スコア閾値ルート
BELOW_TO_PENDING_RELEASE = 3
PENDING_RELEASE_OBSERVATIONS = 3
RELEASED_HOLD_WINDOW = 5
RELEASED_HOLD_MIN = 2
RELEASED_TO_RETIRED = 5

# 巡回間隔 (完了した nightly run の回数)
INTERVALS: dict[str, int | None] = {
    "active": 1,
    "pending_release": 1,
    "pending_expiration": 3,
    "released": 7,
    "expired": 7,
    "retired": None,
}

REACHABLE = "reachable"
UNREACHABLE = "unreachable"
UNKNOWN = "unknown"

VERDICTS: tuple[str, ...] = ("block", "hold", "below", "unknown")


class ProbeResult(Protocol):
    """`pipeline.run_domain` が返す 1 ドメイン分の判定結果。"""

    score: float
    features: Mapping[str, object]
    reasons: Mapping[str, object]
    decision: str


class PipelineProtocol(Protocol):
    def run_domain(self, domain: str) -> ProbeResult: ...


class HealthProtocol(Protocol):
    def check_state(self, domain: str) -> str: ...


class WhitelistProtocol(Protocol):
    def match(self, domain: str) -> bool: ...


class StoreProtocol(Protocol):
    """`scamstore.ScamStore` のうち lifecycle が使う面だけ。"""

    def night_completed(self, night: str) -> bool: ...
    def ensure_lifecycle(self) -> int: ...
    def completed_runs(self) -> int: ...
    def lifecycle_all(self) -> list[Mapping[str, object]]: ...
    def lifecycle_domains(self, statuses: tuple[str, ...]) -> list[str]: ...
    def recent_verdicts(self, domain: str, *, limit: int) -> list[str]: ...
    def record_observation(
        self, domain: str, *, seq: int, night: str, verdict: str, reachable: str
    ) -> None: ...
    def record(
        self,
        domain: str,
        *,
        score: float,
        decision: str,
        features: Mapping[str, object],
        evidence: list[object],
        night: str,
    ) -> None: ...
    def set_decision(self, domain: str, *, decision: str, night: str) -> None: ...
    def save_lifecycle(self, state: State) -> None: ...
    def complete_run(self, night: str) -> None: ...


class SweepReport(TypedDict):
    night: str
    skipped: str
    checked: list[str]
    pending_release: list[str]
    pending_expiration: list[str]
    released: list[str]
    expired: list[str]
    retired: list[str]
    restored: list[str]
    reconfirmed: list[str]
    confirmed_hold: list[str]
    unknown: list[str]


@dataclass(frozen=True)
class State:
    domain: str
    status: str = "active"
    base_decision: str = "block"
    since_night: str = ""
    last_check_seq: int = 0
    unreachable_streak: int = 0
    below_streak: int = 0
    pending_checks: int = 0


@dataclass(frozen=True)
class Step:
    state: State
    event: str = ""


def interval_for(status: str) -> int | None:
    return INTERVALS.get(status)


def is_due(state: State, seq: int) -> bool:
    """その run で巡回すべきか。retired は常に False。"""
    interval = interval_for(state.status)
    if interval is None:
        return False
    if state.last_check_seq <= 0:
        return True  # 未巡回 (bootstrap 直後) は常に対象
    return seq - state.last_check_seq >= interval


def _to_active(state: State, *, seq: int, base: str | None = None) -> State:
    return replace(
        state,
        status="active",
        base_decision=base or state.base_decision,
        last_check_seq=seq,
        unreachable_streak=0,
        below_streak=0,
        pending_checks=0,
    )


def _on_unreachable(state: State, night: str) -> Step:
    """到達不能ルート。スコアの判定より優先する。"""
    s = replace(state, unreachable_streak=state.unreachable_streak + 1)
    if s.status in ("active", "pending_release", "released"):
        if s.unreachable_streak < UNREACHABLE_TO_PENDING:
            return Step(s)
        return Step(
            replace(
                s,
                status="pending_expiration",
                since_night=night,
                unreachable_streak=0,
                pending_checks=0,
            ),
            "pending_expiration",
        )
    if s.status == "pending_expiration":
        if s.unreachable_streak < PENDING_EXPIRATION_TO_EXPIRED:
            return Step(s)
        return Step(
            replace(s, status="expired", since_night=night, unreachable_streak=0), "expired"
        )
    if s.status == "expired" and s.unreachable_streak >= EXPIRED_TO_RETIRED:
        return Step(
            replace(s, status="retired", since_night=night, unreachable_streak=0), "retired"
        )
    return Step(s)


def _on_active(state: State, verdict: str, seq: int, night: str, recent: tuple[str, ...]) -> Step:
    if verdict == "block":
        return Step(_to_active(state, seq=seq, base="block"), "confirmed_block")
    weak = verdict == "below" or (verdict == "hold" and state.base_decision == "block")
    if not weak:
        return Step(replace(state, below_streak=0))
    below = state.below_streak + 1
    if below < BELOW_TO_PENDING_RELEASE:
        return Step(replace(state, below_streak=below))
    return Step(
        replace(
            state,
            status="pending_release",
            since_night=night,
            below_streak=0,
            pending_checks=0,
        ),
        "pending_release",
    )


def _on_pending_release(
    state: State, verdict: str, seq: int, night: str, recent: tuple[str, ...]
) -> Step:
    if verdict == "block":
        return Step(_to_active(state, seq=seq, base="block"), "confirmed_block")
    if verdict == "hold":
        return Step(_to_active(state, seq=seq, base="hold"), "confirmed_hold")
    checks = state.pending_checks + 1
    if checks < PENDING_RELEASE_OBSERVATIONS:
        return Step(replace(state, pending_checks=checks))
    return Step(
        replace(state, status="released", since_night=night, below_streak=0, pending_checks=0),
        "released",
    )


def _on_released(state: State, verdict: str, seq: int, night: str, recent: tuple[str, ...]) -> Step:
    if verdict == "block":
        return Step(_to_active(state, seq=seq, base="block"), "confirmed_block")
    holds = sum(1 for v in recent[-RELEASED_HOLD_WINDOW + 1 :] if v == "hold")
    if verdict == "hold":
        holds += 1
        if holds >= RELEASED_HOLD_MIN:
            return Step(_to_active(state, seq=seq, base="hold"), "confirmed_hold")
        return Step(replace(state, below_streak=0))
    below = state.below_streak + 1
    if below < RELEASED_TO_RETIRED:
        return Step(replace(state, below_streak=below))
    return Step(replace(state, status="retired", since_night=night, below_streak=0), "retired")


def advance(
    state: State,
    *,
    verdict: str,
    reachable: bool | None,
    seq: int,
    night: str,
    recent: tuple[str, ...] = (),
) -> Step:
    """1 回の観測を反映した次の状態を返す (純粋関数)。

    `reachable` は True / False / None(不明)。`recent` は直近の観測 verdict
    (古い順、今回を含まない)。
    """
    if verdict not in VERDICTS:
        raise ValueError(f"unknown verdict: {verdict!r}")
    s = replace(state, last_check_seq=seq)

    # --- ルート A: 到達不能 (スコア閾値に優先) ---
    if reachable is False:
        return _on_unreachable(s, night)

    if reachable is True:
        s = replace(s, unreachable_streak=0)
        if s.status in ("pending_expiration", "expired"):
            # 元の判定に戻し、スコアの算出を再開する。expired は再掲載対象。
            return Step(_to_active(s, seq=seq), "restored")

    # --- ルート B: スコア閾値 ---
    if verdict == "unknown":
        return Step(s)
    handler = _HANDLERS.get(s.status)
    # pending_expiration / expired は到達性だけを見る (スコア算出停止中)。
    if handler is None:
        return Step(s)
    return handler(s, verdict, seq, night, recent)


_HANDLERS: dict[str, Callable[[State, str, int, str, tuple[str, ...]], Step]] = {
    "active": _on_active,
    "pending_release": _on_pending_release,
    "released": _on_released,
}


def verdict_of(result: ProbeResult) -> str:
    """probe の結果を block / hold / below / unknown に落とす。"""
    if result.features.get("error"):
        return "unknown"
    return {"block": "block", "hold": "hold", "dismissed": "below"}.get(result.decision, "unknown")


def reachability_of(health: HealthProtocol | None, domain: str) -> str:
    """HealthChecker を 3 値に正規化する。"""
    if health is None:
        return UNKNOWN
    value = health.check_state(domain)
    return value if value in (REACHABLE, UNREACHABLE, UNKNOWN) else UNKNOWN


def _as_int(value: object) -> int:
    """SQLite から来た値を int に窄める (NULL・型違いは 0)。"""
    return value if isinstance(value, int) else 0


def _state_of(row: Mapping[str, object]) -> State:
    return State(
        domain=str(row["domain"]),
        status=str(row["status"]),
        base_decision=str(row["base_decision"]),
        since_night=str(row.get("since_night") or ""),
        last_check_seq=_as_int(row.get("last_check_seq")),
        unreachable_streak=_as_int(row.get("unreachable_streak")),
        below_streak=_as_int(row.get("below_streak")),
        pending_checks=_as_int(row.get("pending_checks")),
    )


def _persist(
    store: StoreProtocol, state: State, verdict: str, result: ProbeResult | None, night: str
) -> None:
    """状態を decisions / lifecycle の両方へ書く (判定値は状態から導く)。"""
    decision = _decision_for(state)
    if result is not None and verdict in ("block", "hold", "below"):
        # probe が通った夜は観測値も更新する (nights_confirmed は record 側で進む)。
        store.record(
            state.domain,
            score=float(result.score or 0.0),
            decision=decision,
            features=result.features,
            evidence=[result.reasons],
            night=night,
        )
    else:
        store.set_decision(state.domain, decision=decision, night=night)
    store.save_lifecycle(state)


def _visit(
    *,
    store: StoreProtocol,
    state: State,
    seq: int,
    night: str,
    pipeline: PipelineProtocol,
    health: HealthProtocol | None,
) -> tuple[str, int]:
    """1 ドメインを巡回する。戻り値は (イベント, 実際に probe した回数)。

    `unknown` は到達性もスコアも不明だった夜で、カウントも last_check_seq も
    動かさない (次夜に再試行)。
    """
    reach = reachability_of(health, state.domain)
    probed = 0
    result: ProbeResult | None = None
    verdict = "unknown"
    if reach != UNREACHABLE:
        probed = 1
        try:
            result = pipeline.run_domain(state.domain)
        except Exception:  # 1 ドメインの失敗で夜を止めない
            result = None
        verdict = verdict_of(result) if result is not None else "unknown"

    if reach == UNKNOWN and verdict == "unknown":
        return "unknown", 0

    recent = tuple(store.recent_verdicts(state.domain, limit=RELEASED_HOLD_WINDOW - 1))
    step = advance(
        state,
        verdict=verdict,
        reachable={REACHABLE: True, UNREACHABLE: False, UNKNOWN: None}[reach],
        seq=seq,
        night=night,
        recent=recent,
    )
    store.record_observation(state.domain, seq=seq, night=night, verdict=verdict, reachable=reach)
    _persist(store, step.state, verdict, result, night)
    return step.event, probed


def sweep(
    *,
    store: StoreProtocol,
    night: str,
    pipeline: PipelineProtocol,
    health: HealthProtocol | None = None,
    whitelist: WhitelistProtocol | None = None,
    night_ok: bool = True,
    max_probes: int | None = None,
    skip: set[str] | None = None,
) -> SweepReport:
    """1 夜分のライフサイクル巡回。

    `night_ok=False` のときは何も記録しない (全体失敗の夜を判定に数えない)。
    """
    report: SweepReport = {
        "night": night,
        "skipped": "",
        "checked": [],
        "pending_release": [],
        "pending_expiration": [],
        "released": [],
        "expired": [],
        "retired": [],
        "restored": [],
        "reconfirmed": [],
        "confirmed_hold": [],
        "unknown": [],
    }
    if not night_ok:
        report["skipped"] = "night_failed"
        return report
    if store.night_completed(night):
        report["skipped"] = "already_completed"
        return report

    store.ensure_lifecycle()
    seq = store.completed_runs() + 1
    probes = 0
    skipped_domains = {d.strip().lower() for d in (skip or set())}
    # 遷移イベント名 → レポートのリスト。confirmed_block だけは reconfirmed へ。
    by_event: dict[str, list[str]] = {
        "pending_release": report["pending_release"],
        "pending_expiration": report["pending_expiration"],
        "released": report["released"],
        "expired": report["expired"],
        "retired": report["retired"],
        "restored": report["restored"],
        "confirmed_hold": report["confirmed_hold"],
    }

    for row in store.lifecycle_all():
        state = _state_of(row)
        domain = state.domain
        if domain in skipped_domains:
            # 今夜すでに discovery 経由で probe 済み。二重取得しない。
            continue
        if whitelist is not None and whitelist.match(domain):
            continue
        if not is_due(state, seq):
            continue
        if max_probes is not None and probes >= max_probes:
            break

        event, probed = _visit(
            store=store, state=state, seq=seq, night=night, pipeline=pipeline, health=health
        )
        probes += probed
        if event == "unknown":
            report["unknown"].append(domain)
            continue
        report["checked"].append(domain)
        if event == "confirmed_block":
            report["reconfirmed"].append(domain)
        elif event in by_event:
            by_event[event].append(domain)
    # 正常に終わった夜だけを 1 run として数える (間隔・連続カウントの基準)。
    store.complete_run(night)
    return report


def _decision_for(state: State) -> str:
    """ライフサイクル状態を decisions.decision に書く値へ。"""
    if state.status == "active":
        return state.base_decision
    return state.status
