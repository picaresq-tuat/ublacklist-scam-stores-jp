"""legacy 行の favicon を再取得して corpus の材料にする backfill のテスト。"""

from __future__ import annotations

import hashlib
import json
import sqlite3

from favicon_backfill import backfill

ICO = b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x20\x00" + b"\x00" * 70
HTML = b"<html><head><title>404</title></head><body>nginx</body></html>"


class _R:
    def __init__(self, url, *, status=200, raw=ICO, ctype="image/x-icon", discarded=False):
        self.url = url
        self.status = status
        self.final_url = url
        self.headers = {"content-type": ctype}
        self.raw = raw
        self.raw_bytes = len(raw)
        self.truncated = False
        self.discarded = discarded


def _make_db(tmp_path, rows):
    db = tmp_path / "scam.db"
    con = sqlite3.connect(db)
    con.execute(
        "CREATE TABLE decisions (domain TEXT PRIMARY KEY, features_json TEXT, decision TEXT)"
    )
    con.executemany("INSERT INTO decisions VALUES (?, ?, ?)", rows)
    con.commit()
    con.close()
    return db


def _row(domain, *, decision="block", source=None, md5="0" * 32):
    feats = {"favicon_md5": md5, "score": 1}
    if source:
        feats["favicon_source"] = source
    return (domain, json.dumps(feats), decision)


def _read(db, domain):
    con = sqlite3.connect(db)
    row = con.execute("SELECT features_json FROM decisions WHERE domain=?", (domain,)).fetchone()
    con.close()
    return json.loads(row[0])


def test_backfill_sets_raw_favicon_for_legacy_block_row(tmp_path):
    db = _make_db(tmp_path, [_row("a.example")])
    calls = []

    def fake_fetch(url, **kw):
        calls.append((url, kw))
        return _R(url)

    stats = backfill(db, fetch_fn=fake_fetch)
    md5 = hashlib.md5(ICO).hexdigest()
    feats = _read(db, "a.example")
    assert feats["favicon_source"] == "raw"
    assert feats["favicon_md5"] == md5
    assert feats["favicon_bytes_len"] == len(ICO)
    assert feats["score"] == 1  # 既存キーは保持
    assert stats == {"candidates": 1, "updated": 1, "skipped": 0, "failed": 0}
    assert calls[0][1]["allow_binary"] is True


def test_backfill_skips_rows_already_raw_and_dismissed(tmp_path):
    db = _make_db(
        tmp_path,
        [
            _row("raw.example", source="raw"),
            _row("dismissed.example", decision="dismissed"),
        ],
    )

    def fake_fetch(url, **kw):  # pragma: no cover - 呼ばれたら失敗
        raise AssertionError("fetch must not be called")

    stats = backfill(db, fetch_fn=fake_fetch)
    assert stats["candidates"] == 0
    assert stats["updated"] == 0


def test_backfill_ignores_html_error_page(tmp_path):
    db = _make_db(tmp_path, [_row("a.example")])
    stats = backfill(db, fetch_fn=lambda url, **kw: _R(url, raw=HTML, ctype="text/html"))
    assert stats["updated"] == 0
    assert stats["skipped"] == 1
    assert "favicon_source" not in _read(db, "a.example")


def test_backfill_counts_fetch_errors_as_failed(tmp_path):
    db = _make_db(tmp_path, [_row("a.example")])

    def boom(url, **kw):
        raise OSError("dns")

    stats = backfill(db, fetch_fn=boom)
    assert stats["failed"] == 1
    assert stats["updated"] == 0


def test_backfill_dry_run_does_not_write(tmp_path):
    db = _make_db(tmp_path, [_row("a.example")])
    before = _read(db, "a.example")
    stats = backfill(db, fetch_fn=lambda url, **kw: _R(url), dry_run=True)
    assert stats["updated"] == 1
    assert _read(db, "a.example") == before


def test_backfill_respects_limit(tmp_path):
    db = _make_db(tmp_path, [_row("a.example"), _row("b.example")])
    stats = backfill(db, fetch_fn=lambda url, **kw: _R(url), limit=1)
    assert stats["candidates"] == 1


def test_backfill_on_missing_db_returns_zero(tmp_path):
    stats = backfill(tmp_path / "nothing.db", fetch_fn=lambda url, **kw: _R(url))
    assert stats == {"candidates": 0, "updated": 0, "skipped": 0, "failed": 0}
