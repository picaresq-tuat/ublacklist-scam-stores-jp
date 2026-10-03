"""検索履歴 (R2) と pageno ランダム化 (R3)。

実行日時・型番・クエリ・pageno を記録し、過去 30 日と同一の検索を避ける。
"""
from __future__ import annotations

import random
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

DEFAULT_WINDOW_DAYS = 30
# 実測 (2026-09-24): Bing はページング非対応 (pageno>=2 で常に 0 件)、
# Google CSE は pageno<=5 で応答。上限はページング可能な側に合わせる。
# (searxng.PRIMARY_MAX_PAGENO と同値。循環 import 回避のためここに直値)
DEFAULT_MAX_PAGENO = 5
DEFAULT_KEEP_DAYS = 180

SCHEMA = """
CREATE TABLE IF NOT EXISTS search_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    model        TEXT NOT NULL,
    term         TEXT NOT NULL,
    pageno       INTEGER NOT NULL,
    engine       TEXT NOT NULL DEFAULT '',
    result_count INTEGER NOT NULL DEFAULT 0,
    ran_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_searchlog_pair ON search_log(model, term, pageno);
CREATE INDEX IF NOT EXISTS idx_searchlog_ran_at ON search_log(ran_at);
"""


class PageRangeExhausted(RuntimeError):
    """使用可能な pageno が残っていない。"""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


@dataclass(frozen=True)
class SearchEntry:
    model: str
    term: str
    pageno: int
    engine: str
    result_count: int
    ran_at: str


class SearchLog:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._con = sqlite3.connect(self.path)
        self._con.executescript(SCHEMA)
        self._con.commit()

    def close(self) -> None:
        self._con.close()

    def count(self) -> int:
        return int(self._con.execute("SELECT COUNT(*) FROM search_log").fetchone()[0])

    def record(self, model: str, term: str, pageno: int, *, engine: str = "",
               result_count: int = 0, ran_at: Optional[datetime] = None) -> None:
        self._con.execute(
            "INSERT INTO search_log(model, term, pageno, engine, result_count, ran_at)"
            " VALUES (?,?,?,?,?,?)",
            (model, term, int(pageno), engine, int(result_count), _iso(ran_at or _utcnow())),
        )
        self._con.commit()

    def all(self) -> list[SearchEntry]:
        cur = self._con.execute(
            "SELECT model, term, pageno, engine, result_count, ran_at"
            " FROM search_log ORDER BY id"
        )
        return [SearchEntry(*row) for row in cur.fetchall()]

    def _cutoff(self, now: Optional[datetime], window_days: int) -> str:
        return _iso((now or _utcnow()) - timedelta(days=window_days))

    def is_seen(self, model: str, term: str, pageno: int, *, now: Optional[datetime] = None,
                window_days: int = DEFAULT_WINDOW_DAYS) -> bool:
        """過去 window_days 日以内に同一 (model, term, pageno) を実行済みか。

        実行時刻が cutoff と同時刻 (ちょうど 30 日前) のものは窓外として扱う。
        """
        cur = self._con.execute(
            "SELECT COUNT(*) FROM search_log WHERE model=? AND term=? AND pageno=?"
            " AND ran_at > ?",
            (model, term, int(pageno), self._cutoff(now, window_days)),
        )
        return int(cur.fetchone()[0]) > 0

    def is_pair_seen(self, model: str, term: str, *, now: Optional[datetime] = None,
                     window_days: int = DEFAULT_WINDOW_DAYS) -> bool:
        cur = self._con.execute(
            "SELECT COUNT(*) FROM search_log WHERE model=? AND term=? AND ran_at > ?",
            (model, term, self._cutoff(now, window_days)),
        )
        return int(cur.fetchone()[0]) > 0

    def recent_pagenos(self, model: str, term: str, *, now: Optional[datetime] = None,
                       window_days: int = DEFAULT_WINDOW_DAYS) -> set[int]:
        cur = self._con.execute(
            "SELECT DISTINCT pageno FROM search_log WHERE model=? AND term=? AND ran_at > ?",
            (model, term, self._cutoff(now, window_days)),
        )
        return {int(r[0]) for r in cur.fetchall()}

    def record_result(self, model: str, term: str, pageno: int, *, result_count: int,
                      engine: str = "", ran_at: Optional[datetime] = None) -> None:
        """直近の同一 (model, term, pageno) 行に実結果数を反映する (P9c)。

        生成時に result_count=0 で仮記録されるため、検索後に実件数を上書きする。
        該当行がなければ何もしない (record が仮記録を担う)。
        """
        cur = self._con.execute(
            "SELECT id FROM search_log WHERE model=? AND term=? AND pageno=?"
            " ORDER BY id DESC LIMIT 1",
            (model, term, int(pageno)),
        )
        row = cur.fetchone()
        if row is None:
            return
        self._con.execute(
            "UPDATE search_log SET result_count=? WHERE id=?",
            (int(result_count), row[0]),
        )
        self._con.commit()

    def recent_empty_pagenos(self, model: str, term: str, *, now: Optional[datetime] = None,
                             window_days: int = DEFAULT_WINDOW_DAYS) -> set[int]:
        """過去 window_days 日で空応答 (result_count=0) だった pageno (P9c)。"""
        cur = self._con.execute(
            "SELECT DISTINCT pageno FROM search_log"
            " WHERE model=? AND term=? AND ran_at > ? AND result_count=0",
            (model, term, self._cutoff(now, window_days)),
        )
        return {int(r[0]) for r in cur.fetchall()}

    def exclusion_predicate(self, *, now: Optional[datetime] = None,
                            window_days: int = DEFAULT_WINDOW_DAYS) -> Callable[[str, str], bool]:
        """generate_queries に渡す is_excluded (= 過去に同じ (型番, 用語) を実行済み)。"""
        snapshot = {(e.model, e.term) for e in self.all() if e.ran_at > self._cutoff(now, window_days)}
        return lambda model, term: (model, term) in snapshot

    def prune(self, keep_days: int = DEFAULT_KEEP_DAYS, *, now: Optional[datetime] = None) -> int:
        cur = self._con.execute("DELETE FROM search_log WHERE ran_at <= ?",
                                (self._cutoff(now, keep_days),))
        self._con.commit()
        return int(cur.rowcount or 0)


def pick_pageno(log: "SearchLog | None", model: str, term: str, rng: random.Random | None = None,
                *, now: Optional[datetime] = None, max_pageno: int = DEFAULT_MAX_PAGENO,
                exclude: Optional[set[int]] = None) -> int:
    """過去 30 日で未使用の pageno をランダムに選ぶ。

    エンジンが想定最大を超える値で 0 件を返す場合に備え、exclude で除外もできる。
    """
    rng = rng or random.Random()
    if max_pageno < 1:
        raise ValueError("max_pageno must be >= 1")
    candidates = list(range(1, max_pageno + 1))
    rejected = set(exclude or ())
    empty = log.recent_empty_pagenos(model, term, now=now) if log is not None else set()
    used = log.recent_pagenos(model, term, now=now) if log is not None else set()
    fresh = [p for p in candidates if p not in used and p not in rejected and p not in empty]
    if not fresh:
        # 全値が使用済み/却下/空応答。空応答・使用済み pageno を最後のフォールバックとして
        # 再利用する (PageRangeExhausted で夜間を止めない)。ただし明示的に exclude された
        # (rejected) pageno は例外でも再利用しない — 既存契約を維持する。
        fallback = [p for p in candidates
                    if p not in rejected and (p in empty or p in used)]
        if not fallback:
            raise PageRangeExhausted(f"no usable pageno (1..{max_pageno}) for {model!r}/{term!r}")
        return rng.choice(fallback)
    return rng.choice(fresh)
