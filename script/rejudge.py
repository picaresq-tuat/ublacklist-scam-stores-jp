"""cloaking リスト再判定 + 手動収集リストの取り込み (P10)。

判定の材料は `probe.Pipeline.run_domain()` の結果だけ。本モジュールは
「どのドメインを昇格 / 降格するか」という純粋な選別ロジックを持ち、
ネットワーク I/O はランナー (`scripts/rejudge_lists.py`) 側に置く。
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Outcome:
    """1 ドメインの再判定結果。"""

    domain: str
    decision: str  # block / hold / dismissed
    score: float
    status: int | None = None  # 通常ブラウザ取得の HTTP status (応答なしは None)
    cloaking: bool = False
    reasons: dict = field(default_factory=dict)


def is_active(o: Outcome) -> bool:
    """現在活動している (通常ブラウザで 2xx が返る) か。

    判定 `block` は特徴量の組み合わせで決まるため、取得に失敗した行
    (status=None) が混ざり得る。活動していないサイトを配布リストへ入れると
    ドメイン使い捨ての踏み台を焼き払うだけで、防御効果がない。
    """
    return o.status is not None and 200 <= o.status < 300


def select_promotions(outcomes: Iterable[Outcome], known_scam: Iterable[str]) -> list[str]:
    """scam リストへ昇格するドメイン (block かつ現役、既登録は除く)。"""
    known = {d.lower() for d in known_scam}
    out = {
        o.domain.lower()
        for o in outcomes
        if o.decision == "block" and is_active(o) and o.domain.lower() not in known
    }
    return sorted(out)


def select_cloaking_removals(outcomes: Iterable[Outcome]) -> list[str]:
    """cloaking リストから外すドメイン (scam と判定されたもの)。

    hold のまま (cloaking だが scam 断定に届かない) 行は残す。判定できなかった行
    (dismissed / 応答なし) も残す — 一時的な取得失敗で正当な検知を消さない。
    """
    return sorted({o.domain.lower() for o in outcomes if o.decision == "block"})


def summarise(outcomes: Iterable[Outcome]) -> dict:
    """監査用の集計 (判定分布・現役率)。"""
    rows = list(outcomes)
    n = len(rows)
    active = sum(1 for o in rows if is_active(o))
    by_decision: dict[str, int] = {}
    for o in rows:
        by_decision[o.decision] = by_decision.get(o.decision, 0) + 1
    return {
        "n": n,
        "active": active,
        "active_rate": round(active / n, 4) if n else 0.0,
        "by_decision": dict(sorted(by_decision.items())),
    }
