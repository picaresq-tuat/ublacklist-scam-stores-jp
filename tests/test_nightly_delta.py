"""nightly のログ集計 / 変更判定の RED テスト。

- blocked/hold/dismissed/whitelisted は hunter が list を返すため
  int(list) が失敗し常に 0 と表示されていた。
- has_changes は累積の published / cloaking_holds を見ていたため、
  ファイルが 1 byte も変わらない夜でも「変更あり」と判定していた。
"""

from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

import nightly

JST = ZoneInfo("Asia/Tokyo")


def _report(**kw) -> dict:
    base = {
        "night": "2026-10-27",
        "rounds": 1,
        "empty_queries": 0,
        "engine_failures": 0,
        "domains_found": 3,
        "new_domains": 1,
        "blocked": [],
        "hold": [],
        "dismissed": [],
        "whitelisted": [],
        "published": [],
        "would_publish": [],
        "expired": [],
        "cloaking_holds": [],
        "cloaking_added": [],
        "candidate_checked": 0,
        "candidate_promoted": [],
    }
    base.update(kw)
    return base


def test_format_log_block_counts_list_values():
    block = nightly.format_log_block(
        _report(blocked=["a.example", "b.example"], hold=["c.example"], dismissed=["d.example"]),
        now=datetime(2026, 10, 27, 4, 30, tzinfo=JST),
    )
    assert "blocked=2" in block
    assert "hold=1" in block
    assert "dismissed=1" in block
    assert "whitelisted=0" in block


def test_has_changes_false_when_only_cumulative_lists_present():
    """掲載対象の累積リストだけがあっても、実ファイルが変わらなければ False。"""
    assert (
        nightly.has_changes(
            _report(
                published=[],
                published_total=["*://*.old.example/*"],
                already_listed=["*://*.old.example/*"],
                ulist_changed=False,
                cloaking_holds=["cloak.example"],
                cloaking_added=[],
            )
        )
        is False
    )


def test_has_changes_true_when_ulist_changed():
    assert nightly.has_changes(_report(ulist_changed=True)) is True


def test_has_changes_true_when_cloaking_added():
    assert nightly.has_changes(_report(ulist_changed=False, cloaking_added=["x.example"])) is True


def test_has_changes_true_when_entries_removed():
    assert (
        nightly.has_changes(_report(ulist_changed=False, ulist_removed=["*://*.bad.example/*"]))
        is True
    )
