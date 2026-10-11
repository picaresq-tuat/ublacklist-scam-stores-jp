"""判定の永続化 (P6)。

- `decisions`: ドメイン判定 (スコア・根拠・連続確認夜数)
- `domain_health`: P8 失効監視用の日次到達性
履歴は消さずに残す (expired にしても行は残る)。
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parent.parent  # リポジトリルート
DB_DIR = PKG_ROOT / "db"
DEFAULT_DB = DB_DIR / "scam.db"

DECISIONS: tuple[str, ...] = ("candidate", "hold", "block", "expired", "dismissed")

FAST_TRACK_SCORE = 60.0
MIN_STREAK_SCORE = 55.0

SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    domain           TEXT PRIMARY KEY,
    score            REAL NOT NULL,
    night_score      REAL NOT NULL DEFAULT 0,
    features_json    TEXT NOT NULL DEFAULT '{}',
    evidences_json   TEXT NOT NULL DEFAULT '[]',
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    nights_confirmed INTEGER NOT NULL DEFAULT 0,
    decision         TEXT NOT NULL,
    decided_at       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS decision_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    domain     TEXT NOT NULL,
    decision   TEXT NOT NULL,
    score      REAL NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS domain_health (
    domain     TEXT NOT NULL,
    checked_on TEXT NOT NULL,
    reachable  INTEGER NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (domain, checked_on)
);
CREATE TABLE IF NOT EXISTS search_hits (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    domain   TEXT NOT NULL,
    url      TEXT NOT NULL,
    query    TEXT NOT NULL,
    pageno   INTEGER NOT NULL,
    night    TEXT NOT NULL
);
"""


def _utcnow() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _norm_night(night: str | None) -> str:
    if not night:
        return datetime.now(UTC).strftime("%Y-%m-%d")
    return night[:10]


def _night_iso(day: str) -> str:
    """実行日 (YYYY-MM-DD) を first/last_seen 用の ISO 時刻に直す。"""
    return f"{day}T00:00:00Z"


class ScamStore:
    def __init__(self, path: Path | str = DEFAULT_DB):
        self.path = Path(path)
        self._con = sqlite3.connect(str(self.path))
        self._con.row_factory = sqlite3.Row
        self._con.executescript(SCHEMA)
        self._con.commit()

    def close(self) -> None:
        self._con.close()

    def __enter__(self) -> ScamStore:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- decisions ---
    def record(
        self,
        domain: str,
        *,
        score: float,
        decision: str,
        features: dict | None = None,
        evidence: Iterable | None = None,
        night: str | None = None,
    ) -> dict:
        if decision not in DECISIONS:
            raise ValueError(f"unknown decision: {decision!r}")
        domain = domain.strip().lower()
        if not domain:
            raise ValueError("empty domain")
        day = _norm_night(night)
        seen = _night_iso(day)
        now = _utcnow()
        row = self._con.execute("SELECT * FROM decisions WHERE domain=?", (domain,)).fetchone()
        feats = json.dumps(features or {}, ensure_ascii=False, sort_keys=True)
        evid = json.dumps(list(evidence or []), ensure_ascii=False, default=str)

        if row is None:
            self._con.execute(
                "INSERT INTO decisions(domain, score, night_score, features_json, evidences_json,"
                " first_seen, last_seen, nights_confirmed, decision, decided_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (domain, float(score), float(score), feats, evid, seen, seen, 1, decision, now),
            )
        else:
            last_day = str(row["last_seen"])[:10]
            nights = int(row["nights_confirmed"])
            if day != last_day:
                nights += 1
            self._con.execute(
                "UPDATE decisions SET score=?, night_score=?, features_json=?, evidences_json=?,"
                " last_seen=?, nights_confirmed=?, decision=?, decided_at=? WHERE domain=?",
                (float(score), float(score), feats, evid, seen, nights, decision, now, domain),
            )
        self._con.execute(
            "INSERT INTO decision_history(domain, decision, score, recorded_at) VALUES(?,?,?,?)",
            (domain, decision, float(score), now),
        )
        self._con.commit()
        return self.get(domain)

    def get(self, domain: str) -> dict | None:
        row = self._con.execute(
            "SELECT * FROM decisions WHERE domain=?", (domain.strip().lower(),)
        ).fetchone()
        return dict(row) if row else None

    def history(self, domain: str) -> list[dict]:
        cur = self._con.execute(
            "SELECT decision, score, recorded_at FROM decision_history WHERE domain=? ORDER BY id",
            (domain.strip().lower(),),
        )
        return [dict(r) for r in cur.fetchall()]

    def all_decisions(self) -> list[dict]:
        cur = self._con.execute("SELECT * FROM decisions ORDER BY score DESC, domain")
        return [dict(r) for r in cur.fetchall()]

    def blocked_domains(self) -> list[str]:
        cur = self._con.execute(
            "SELECT domain FROM decisions WHERE decision='block' ORDER BY domain"
        )
        return [str(r[0]) for r in cur.fetchall()]

    def cloaking_holds(self) -> list[str]:
        """cloaking 検知かつ decision=='hold' のドメイン (昇順)。

        features_json.cloaking が真 (cloaking_promoted を含む) であることを要求する。
        features が空/壊れている行は対象外。
        """
        out: list[str] = []
        for row in self._con.execute(
            "SELECT domain, features_json FROM decisions WHERE decision='hold' ORDER BY domain"
        ):
            try:
                feats = json.loads(row["features_json"] or "{}")
            except (ValueError, TypeError):
                continue
            if not isinstance(feats, dict):
                continue
            if feats.get("cloaking"):
                out.append(str(row["domain"]))
        return out

    def reconfirm_targets(
        self, *, nights_required: int = 2, score_threshold: float = MIN_STREAK_SCORE
    ) -> list[str]:
        """翌夜に再評価すべき `block` ドメイン (連続 2 夜確認が未了のもの)。

        `known_before` は既判定ドメインを discovery から除外するため、これが無いと
        `nights_confirmed` が 1 のまま固定され `eligible_domains(nights_required=2)` が
        永久に発火しない (実バグ)。fast_track (score >= score_threshold) は 1 夜で
        登録されるので対象外。
        """
        cur = self._con.execute(
            "SELECT domain FROM decisions WHERE decision='block'"
            " AND nights_confirmed < ? AND score < ? ORDER BY domain",
            (nights_required, score_threshold),
        )
        return [str(r[0]) for r in cur.fetchall()]

    def eligible_domains(
        self, *, score_threshold: float = MIN_STREAK_SCORE, nights_required: int = 2
    ) -> list[str]:
        """登録候補: 連続 2 夜確認 または 高スコア (fast track)。"""
        cur = self._con.execute(
            "SELECT domain FROM decisions WHERE decision='block'"
            " AND (nights_confirmed >= ? OR score >= ?)"
            " ORDER BY score DESC, domain",
            (nights_required, score_threshold),
        )
        return [str(r[0]) for r in cur.fetchall()]

    # --- domain_health (P8) ---
    def record_health(
        self, domain: str, *, reachable: bool, checked_on: str | None = None, reason: str = ""
    ) -> None:
        day = (checked_on or _utcnow())[:10]
        self._con.execute(
            "INSERT OR REPLACE INTO domain_health(domain, checked_on, reachable, reason)"
            " VALUES(?,?,?,?)",
            (domain.strip().lower(), day, 0 if reachable else 1, reason),
        )
        self._con.commit()

    def health_count(self) -> int:
        return int(self._con.execute("SELECT COUNT(*) FROM domain_health").fetchone()[0])

    def unreachable_streak(self, domain: str) -> int:
        cur = self._con.execute(
            "SELECT reachable FROM domain_health WHERE domain=? ORDER BY checked_on DESC",
            (domain.strip().lower(),),
        )
        streak = 0
        for r in cur.fetchall():
            if int(r[0]) == 1:
                streak += 1
            else:
                break
        return streak

    def monitor_targets(self, *, age_days: int = 30, now: str | None = None) -> list[str]:
        """登録後 age_days 以上経過した block ドメインのみを監視対象にする。"""
        cutoff = ((_parse(now) if now else datetime.now(UTC)) - timedelta(days=age_days)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        cur = self._con.execute(
            "SELECT domain FROM decisions WHERE decision='block' AND first_seen <= ?"
            " ORDER BY domain",
            (cutoff,),
        )
        return [str(r[0]) for r in cur.fetchall()]

    def expire_unreachable(self, *, streak_days: int = 7) -> list[str]:
        expired: list[str] = []
        for domain in self.blocked_domains():
            if self.unreachable_streak(domain) >= streak_days:
                row = self.get(domain)
                # 失効は「夜の観測」ではないので nights_confirmed を進めない。
                self.record(
                    domain,
                    score=float(row["score"]),
                    decision="expired",
                    features=json.loads(row["features_json"] or "{}"),
                    night=str(row["last_seen"])[:10],
                )
                expired.append(domain)
        return expired

    # --- search hits (任意: 夜次レポート用) ---
    def record_hit(
        self, domain: str, url: str, query: str, pageno: int, night: str | None = None
    ) -> None:
        self._con.execute(
            "INSERT INTO search_hits(domain, url, query, pageno, night) VALUES(?,?,?,?,?)",
            (domain.strip().lower(), url, query, int(pageno), _norm_night(night)),
        )
        self._con.commit()

    def hit_count(self) -> int:
        return int(self._con.execute("SELECT COUNT(*) FROM search_hits").fetchone()[0])


def _parse(value: str) -> datetime:
    text = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt
