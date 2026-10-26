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

DECISIONS: tuple[str, ...] = (
    "candidate",
    "hold",
    "block",
    "expired",
    "dismissed",
    # 巡回ライフサイクル (docs/domain-lifecycle.md)
    "pending_release",
    "pending_expiration",
    "released",
    "retired",
)

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
CREATE TABLE IF NOT EXISTS lifecycle (
    domain             TEXT PRIMARY KEY,
    status             TEXT NOT NULL,
    base_decision      TEXT NOT NULL,
    since_night        TEXT NOT NULL DEFAULT '',
    last_check_seq     INTEGER NOT NULL DEFAULT 0,
    unreachable_streak INTEGER NOT NULL DEFAULT 0,
    below_streak       INTEGER NOT NULL DEFAULT 0,
    pending_checks     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS lifecycle_observations (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    domain    TEXT NOT NULL,
    seq       INTEGER NOT NULL,
    night     TEXT NOT NULL,
    verdict   TEXT NOT NULL,
    reachable TEXT NOT NULL,
    UNIQUE(domain, seq)
);
CREATE TABLE IF NOT EXISTS nightly_runs (
    seq          INTEGER PRIMARY KEY,
    night        TEXT NOT NULL UNIQUE,
    completed_at TEXT NOT NULL
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
        """cloaking リストに載せるドメイン (昇順)。

        - `decision='hold'` かつ features_json.cloaking が真
        - `decision='pending_release'`（scam から cloaking へ移した観測待ち。
          spec 上は hold 未満のスコアでも cloaking リストに置く）
        features が空/壊れている行は hold 側では対象外。
        """
        out: list[str] = []
        for row in self._con.execute(
            "SELECT domain, decision, features_json FROM decisions"
            " WHERE decision IN ('hold','pending_release') ORDER BY domain"
        ):
            if str(row["decision"]) == "pending_release":
                out.append(str(row["domain"]))
                continue
            try:
                feats = json.loads(row["features_json"] or "{}")
            except (ValueError, TypeError):
                continue
            if not isinstance(feats, dict):
                continue
            if feats.get("cloaking"):
                out.append(str(row["domain"]))
        return out

    def lifecycle_domains(self, statuses: Iterable[str]) -> list[str]:
        """指定ステータスのドメイン (昇順)。リストからの削除対象を引くのに使う。"""
        wanted = tuple(statuses)
        if not wanted:
            return []
        marks = ",".join("?" for _ in wanted)
        cur = self._con.execute(
            f"SELECT domain FROM lifecycle WHERE status IN ({marks}) ORDER BY domain",
            wanted,
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

    # --- 巡回ライフサイクル (docs/domain-lifecycle.md) ---
    def ensure_lifecycle(self) -> int:
        """decisions の block / hold / expired を lifecycle 行へ取り込む。

        既存 DB には lifecycle 行が無いため、初回の sweep で後方互換に補完する。
        戻り値は追加した行数。
        """
        added = 0
        rows = self._con.execute(
            "SELECT d.domain, d.decision, d.last_seen FROM decisions d"
            " LEFT JOIN lifecycle l ON l.domain = d.domain"
            " WHERE l.domain IS NULL AND d.decision IN ('block','hold','expired')"
        ).fetchall()
        for row in rows:
            decision = str(row["decision"])
            status = "active" if decision in ("block", "hold") else "expired"
            base = decision if decision in ("block", "hold") else "block"
            self._con.execute(
                "INSERT INTO lifecycle(domain, status, base_decision, since_night, last_check_seq)"
                " VALUES(?,?,?,?,0)",
                (str(row["domain"]), status, base, str(row["last_seen"])[:10]),
            )
            added += 1
        self._con.commit()
        return added

    def lifecycle_all(self) -> list[dict]:
        cur = self._con.execute("SELECT * FROM lifecycle ORDER BY domain")
        return [dict(r) for r in cur.fetchall()]

    def lifecycle_get(self, domain: str) -> dict | None:
        row = self._con.execute(
            "SELECT * FROM lifecycle WHERE domain=?", (domain.strip().lower(),)
        ).fetchone()
        return dict(row) if row else None

    def save_lifecycle(self, state) -> None:
        """lifecycle 行を丸ごと保存する (State は lifecycle.State)。"""
        self._con.execute(
            "INSERT INTO lifecycle(domain, status, base_decision, since_night, last_check_seq,"
            " unreachable_streak, below_streak, pending_checks) VALUES(?,?,?,?,?,?,?,?)"
            " ON CONFLICT(domain) DO UPDATE SET status=excluded.status,"
            " base_decision=excluded.base_decision, since_night=excluded.since_night,"
            " last_check_seq=excluded.last_check_seq,"
            " unreachable_streak=excluded.unreachable_streak,"
            " below_streak=excluded.below_streak, pending_checks=excluded.pending_checks",
            (
                state.domain,
                state.status,
                state.base_decision,
                state.since_night,
                int(state.last_check_seq),
                int(state.unreachable_streak),
                int(state.below_streak),
                int(state.pending_checks),
            ),
        )
        self._con.commit()

    def clear_lifecycle(self, domain: str) -> None:
        """再発見した retired ドメインを新しいドメインとして扱うために破棄する。"""
        domain = domain.strip().lower()
        self._con.execute("DELETE FROM lifecycle WHERE domain=?", (domain,))
        self._con.execute("DELETE FROM lifecycle_observations WHERE domain=?", (domain,))
        self._con.commit()

    def record_observation(
        self, domain: str, *, seq: int, night: str, verdict: str, reachable: str
    ) -> None:
        self._con.execute(
            "INSERT OR REPLACE INTO lifecycle_observations(domain, seq, night, verdict, reachable)"
            " VALUES(?,?,?,?,?)",
            (domain.strip().lower(), int(seq), _norm_night(night), verdict, reachable),
        )
        self._con.commit()

    def recent_verdicts(self, domain: str, *, limit: int = 4) -> list[str]:
        """直近の観測 verdict (古い順)。unknown は数えない。"""
        cur = self._con.execute(
            "SELECT verdict FROM lifecycle_observations WHERE domain=? AND verdict!='unknown'"
            " ORDER BY seq DESC, id DESC LIMIT ?",
            (domain.strip().lower(), int(limit)),
        )
        return [str(r[0]) for r in reversed(cur.fetchall())]

    def set_decision(
        self,
        domain: str,
        *,
        decision: str,
        night: str | None = None,
        score: float | None = None,
        features: dict | None = None,
        evidence: Iterable | None = None,
    ) -> dict | None:
        """判定だけを差し替える (nights_confirmed は動かさない)。

        到達性だけを見た夜や集計上の降格で使う。
        """
        if decision not in DECISIONS:
            raise ValueError(f"unknown decision: {decision!r}")
        domain = domain.strip().lower()
        row = self.get(domain)
        if row is None:
            raise ValueError(f"unknown domain: {domain!r}")
        day = _norm_night(night)
        sets = ["decision=?", "last_seen=?", "decided_at=?"]
        params: list[object] = [decision, _night_iso(day), _utcnow()]
        if score is not None:
            sets += ["score=?", "night_score=?"]
            params += [float(score), float(score)]
        if features is not None:
            sets.append("features_json=?")
            params.append(json.dumps(features, ensure_ascii=False, sort_keys=True))
        if evidence is not None:
            sets.append("evidences_json=?")
            params.append(json.dumps(list(evidence), ensure_ascii=False, default=str))
        params.append(domain)
        self._con.execute(f"UPDATE decisions SET {', '.join(sets)} WHERE domain=?", params)
        current_score = float(row["score"]) if score is None else float(score)
        self._con.execute(
            "INSERT INTO decision_history(domain, decision, score, recorded_at) VALUES(?,?,?,?)",
            (domain, decision, current_score, _utcnow()),
        )
        self._con.commit()
        return self.get(domain)

    # --- nightly run カウンタ (間隔を壁時計で数えない) ---
    def completed_runs(self) -> int:
        return int(self._con.execute("SELECT COUNT(*) FROM nightly_runs").fetchone()[0])

    def night_completed(self, night: str) -> bool:
        row = self._con.execute(
            "SELECT 1 FROM nightly_runs WHERE night=?", (_norm_night(night),)
        ).fetchone()
        return row is not None

    def complete_run(self, night: str) -> int:
        """正常に終わった夜を 1 run として記録する。同じ夜は 1 回だけ。"""
        day = _norm_night(night)
        if self.night_completed(day):
            row = self._con.execute("SELECT seq FROM nightly_runs WHERE night=?", (day,)).fetchone()
            return int(row[0])
        seq = self.completed_runs() + 1
        self._con.execute(
            "INSERT INTO nightly_runs(seq, night, completed_at) VALUES(?,?,?)",
            (seq, day, _utcnow()),
        )
        self._con.commit()
        return seq

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
