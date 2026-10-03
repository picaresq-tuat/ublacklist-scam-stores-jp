"""クエリ生成 (P0)。

型番 × 16 用語を組み合わせ、重複なしのクエリ列を生成する。
30 日窓の重複回避は is_excluded コールバック (searchlog 側) で注入する。
"""
from __future__ import annotations

import random
from typing import Callable, Iterable, Sequence

from modeldb import Model
from searchlog import pick_pageno

QUERY_SEPARATOR = " "

# 16 語を 3 群に分類 (状態系 / 技術系 / 価格系)
TERM_GROUPS: dict[str, tuple[str, ...]] = {
    "condition": (
        "ジャンク", "ジャンク品", "中古", "整備済み", "訳あり",
        "部品取り", "再生品", "リファビッシュ", "新古品", "展示品", "型落ち",
    ),
    "technical": ("bios", "BIOS 更新", "ドライバ"),
    "price": ("格安", "在庫処分"),
}

TERMS: tuple[str, ...] = tuple(t for grp in TERM_GROUPS.values() for t in grp)

MIN_MODELS, MAX_MODELS = 20, 50
MAX_RETRIES = 3


class QueriesExhausted(RuntimeError):
    """除外条件が厳しすぎて要求件数を満たせない。"""


def build_query(model: str, term: str) -> str:
    return f"{model}{QUERY_SEPARATOR}{term}"


def term_coverage(queries: Sequence[tuple[str, str]]) -> int:
    return len({t for _, t in queries})


def generate_queries(
    models: Iterable[Model],
    n_models: int,
    n_queries: int,
    rng: random.Random | None = None,
    is_excluded: Callable[[str, str], bool] | None = None,
) -> list[tuple[str, str]]:
    """(model, term) の一意なペアを n_queries 件返す。

    is_excluded(model, term) が真のペアは採用しない。プールを使い切っても
    足りない場合は QueriesExhausted を送出する。
    """
    rng = rng or random.Random()
    if not (MIN_MODELS <= n_models <= MAX_MODELS):
        raise ValueError(f"n_models must be {MIN_MODELS}..{MAX_MODELS}, got {n_models}")
    if n_queries < 0:
        raise ValueError("n_queries must be >= 0")

    pool = list(models)
    if n_models > len(pool):
        raise ValueError(f"n_models={n_models} exceeds available models={len(pool)}")
    chosen = rng.sample(pool, n_models)
    names = [m.model for m in chosen]

    # 型番 × 用語をラウンドロビンで巡回しつつ、型番内の用語順は毎回シャッフル
    shuffled: list[list[str]] = []
    for _ in names:
        t = list(TERMS)
        rng.shuffle(t)
        shuffled.append(t)

    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    cursors = [0] * len(names)
    total = len(names) * len(TERMS)
    while len(pairs) < n_queries and len(seen) < total:
        progressed = False
        for i, model in enumerate(names):
            if len(pairs) >= n_queries:
                break
            tlist = shuffled[i]
            while cursors[i] < len(tlist):
                term = tlist[cursors[i]]
                cursors[i] += 1
                progressed = True
                if (model, term) in seen:
                    continue
                seen.add((model, term))  # 除外判定の前に既訪扱い (無限ループ防止)
                if is_excluded and is_excluded(model, term):
                    continue
                pairs.append((model, term))
                break
        if not progressed:
            break

    if len(pairs) < n_queries:
        raise QueriesExhausted(
            f"only {len(pairs)} usable queries from {len(names)} models x {len(TERMS)} terms"
        )
    return pairs


class QueryGen:
    """夜間オーケストレータ用ラッパ。

    - ModelDB から n_models (20..50) 件をサンプリング
    - generate_queries で (model, term) を生成し、build_query で結合
    - pageno は pick_pageno (過去 30 日で未使用の値をランダムに選択)
    - searchlog が与えられれば生成時に実行済みペアを除外し、実行後に記録する
    - rotate() はサンプルと除外を組み直す (R5 再試行用)
    """

    def __init__(self, db=None, *, n_models: int = 30, rng=None,
                 db_path=None, max_pageno: int | None = None):
        self.db = db
        self.db_path = db_path
        self.n_models = n_models
        self.rng = rng or random.Random()
        self._models = None
        self._excluded = None
        self.max_pageno = max_pageno

    def _ensure_models(self):
        if self._models is None:
            if self.db is None:
                from modeldb import ModelDB, DEFAULT_DB
                self.db = ModelDB(self.db_path if self.db_path is not None else DEFAULT_DB)
            pool = self.db.all()
            n = min(max(self.n_models, MIN_MODELS), MAX_MODELS, len(pool))
            self._models = self.rng.sample(pool, n)
        return self._models

    def rotate(self) -> None:
        """R5: クエリ生成と pageno の取り直し (サンプルを組み直す)。"""
        self._models = None
        self._excluded = None

    def queries(self, limit: int, *, searchlog=None, now=None):
        models = self._ensure_models()
        if searchlog is not None:
            self._excluded = searchlog.exclusion_predicate(now=now)
        try:
            pairs = generate_queries(models, n_models=len(models),
                                     n_queries=limit, rng=self.rng,
                                     is_excluded=self._excluded)
        except QueriesExhausted:
            # 除外が厳しく満たせない場合でも、得られるだけ返す (夜間を止めない)。
            pairs = generate_queries(models, n_models=len(models),
                                     n_queries=limit, rng=self.rng,
                                     is_excluded=None)
        out = []
        kwargs = {"now": now}
        if self.max_pageno is not None:
            kwargs["max_pageno"] = self.max_pageno
        for model, term in pairs:
            pageno = pick_pageno(searchlog, model, term, self.rng, **kwargs)
            out.append((build_query(model, term), model, pageno))
            if searchlog is not None:
                searchlog.record(model, term, pageno)
        return out
