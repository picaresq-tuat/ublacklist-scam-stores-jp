"""手動収集リストの継続監視 (P10) のテスト。

ネットワークは使わない: probe は差し替え可能な callable。
"""

from __future__ import annotations

import publish
import watchlist
from rejudge import Outcome

SCAM_TEXT = """# uBlacklist - test
# 手動編集しない。

## Hermes nightly
*://*.already.example/*
"""


def _o(dom, decision="block", status=200, score=30.0):
    return Outcome(dom, decision, score, status=status)


def test_load_candidates_dedupes_and_ignores_noise():
    text = "# c\n*://*.a.example/*\n*://*.A.example/*\n\n*://*.b.example/*\nnot-a-rule\n"
    assert watchlist.load_candidates(text) == ["a.example", "b.example"]


def test_promote_adds_active_blocks_only():
    outs = [
        _o("new1.example"),
        _o("dead.example", status=None),
        _o("hold.example", decision="hold", score=14.0),
        _o("already.example"),
    ]
    text, promoted = watchlist.promote(SCAM_TEXT, outs)
    assert promoted == ["new1.example"]
    entries = publish.existing_entries(text)
    assert "*://*.new1.example/*" in entries
    assert "*://*.dead.example/*" not in entries
    assert "*://*.hold.example/*" not in entries
    # 元のエントリは保持され、重複もしない
    assert entries.count("*://*.already.example/*") == 1


def test_promote_is_idempotent():
    outs = [_o("new1.example")]
    once, _ = watchlist.promote(SCAM_TEXT, outs)
    twice, promoted = watchlist.promote(once, outs)
    assert twice == once
    assert promoted == []


def test_monitor_without_candidate_file_is_a_noop(tmp_path):
    (tmp_path / "db").mkdir()
    (tmp_path / "uBlacklist.txt").write_text(SCAM_TEXT, encoding="utf-8")
    res = watchlist.monitor(tmp_path, probe=lambda d: [_o(d)], dry_run=False)
    assert res["promoted"] == []
    assert res["candidates"] == 0
    assert (tmp_path / "uBlacklist.txt").read_text(encoding="utf-8") == SCAM_TEXT


def test_monitor_promotes_and_reports(tmp_path):
    (tmp_path / "db").mkdir()
    (tmp_path / "db" / "manual_candidates.txt").write_text(
        "*://*.new1.example/*\n*://*.quiet.example/*\n", encoding="utf-8"
    )
    (tmp_path / "uBlacklist.txt").write_text(SCAM_TEXT, encoding="utf-8")

    seen = []

    def probe(domains):
        seen.extend(domains)
        return [_o("new1.example"), _o("quiet.example", decision="dismissed", score=2.0)]

    res = watchlist.monitor(tmp_path, probe=probe, dry_run=False)
    assert sorted(seen) == ["new1.example", "quiet.example"]
    assert res["promoted"] == ["new1.example"]
    assert res["candidates"] == 2
    assert "*://*.new1.example/*" in (tmp_path / "uBlacklist.txt").read_text(encoding="utf-8")


def test_monitor_dry_run_does_not_write(tmp_path):
    (tmp_path / "db").mkdir()
    (tmp_path / "db" / "manual_candidates.txt").write_text("*://*.new1.example/*\n", "utf-8")
    (tmp_path / "uBlacklist.txt").write_text(SCAM_TEXT, encoding="utf-8")
    res = watchlist.monitor(tmp_path, probe=lambda d: [_o(d[0])], dry_run=True)
    assert res["promoted"] == ["new1.example"]
    assert (tmp_path / "uBlacklist.txt").read_text(encoding="utf-8") == SCAM_TEXT
