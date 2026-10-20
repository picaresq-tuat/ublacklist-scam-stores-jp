"""legacy 行の favicon を取り直して corpus の材料にする (P11 backfill)。

旧実装は favicon を取得しておらず、`features_json` の `favicon_md5` は
本文テキスト先頭 64 文字の MD5 だった。corpus は `favicon_source == "raw"`
の行しか使わないため、既存 DB は corpus が空のままになる。

このスクリプトは block / hold の既存行について `/favicon.ico` だけを再取得し、
`favicon_md5` / `favicon_source` / `favicon_bytes_len` を上書きする。
ページ全体は取り直さない (スコアや判定は変更しない)。

    python script/favicon_backfill.py --db db/scam.db --limit 200
    python script/favicon_backfill.py --db db/scam.db --dry-run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sqlite3
from pathlib import Path

from fetch import fetch, looks_like_image_bytes
from probe import MIN_FAVICON_BYTES
from scamstore import DEFAULT_DB

logger = logging.getLogger(__name__)

_BAD_DECISIONS = ("block", "hold")


def _fetch_icon(domain: str, fetch_fn) -> tuple[str, int] | None:
    """favicon の (md5, バイト数)。取得失敗・soft-404 は None。"""
    r = fetch_fn(f"https://{domain}/favicon.ico", allow_binary=True)
    raw = getattr(r, "raw", b"") or b""
    if getattr(r, "discarded", False) or getattr(r, "status", 0) >= 400:
        return None
    if getattr(r, "truncated", False):
        return None
    if len(raw) < MIN_FAVICON_BYTES or not looks_like_image_bytes(raw):
        return None
    return hashlib.md5(raw).hexdigest(), len(raw)


def backfill(
    db_path: Path | str = DEFAULT_DB,
    *,
    fetch_fn=fetch,
    limit: int | None = None,
    dry_run: bool = False,
) -> dict[str, int]:
    """既存行の favicon を更新し、統計を返す。"""
    stats = {"candidates": 0, "updated": 0, "skipped": 0, "failed": 0}
    path = Path(db_path)
    if not path.exists():
        logger.warning("favicon backfill: DB がありません: %s", path)
        return stats

    con = sqlite3.connect(path)
    try:
        try:
            rows = con.execute("SELECT domain, features_json, decision FROM decisions").fetchall()
        except sqlite3.Error as exc:
            logger.warning("favicon backfill: 読み出し失敗: %s", exc)
            return stats

        todo: list[tuple[str, dict]] = []
        for domain, raw, decision in rows:
            if decision not in _BAD_DECISIONS:
                continue
            if not isinstance(domain, str) or not domain.strip():
                continue
            try:
                feats = json.loads(raw or "{}")
            except (TypeError, ValueError):
                continue
            if not isinstance(feats, dict):
                continue
            if feats.get("favicon_source") == "raw":
                continue
            todo.append((domain.strip().lower(), feats))

        if limit is not None:
            todo = todo[:limit]
        stats["candidates"] = len(todo)

        updates: list[tuple[str, str]] = []
        for domain, feats in todo:
            try:
                got = _fetch_icon(domain, fetch_fn)
            except Exception as exc:  # 1 件の失敗で backfill 全体を止めない
                logger.debug("favicon backfill: %s: %s", domain, exc)
                stats["failed"] += 1
                continue
            if got is None:
                stats["skipped"] += 1
                continue
            md5, size = got
            feats = dict(feats)
            feats["favicon_md5"] = md5
            feats["favicon_source"] = "raw"
            feats["favicon_bytes_len"] = size
            updates.append((json.dumps(feats, ensure_ascii=False), domain))
            stats["updated"] += 1

        if updates and not dry_run:
            con.executemany("UPDATE decisions SET features_json=? WHERE domain=?", updates)
            con.commit()
    finally:
        con.close()
    return stats


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="legacy favicon の backfill (corpus 用)")
    p.add_argument("--db", default=str(DEFAULT_DB))
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    stats = backfill(args.db, limit=args.limit, dry_run=args.dry_run)
    print(json.dumps(stats, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
