"""P9: クエリ間隔の運用設計 (実測 429 対策) の RED テスト。

実測 (2026-09-24, localhost:8888):
    Google CSE は 1.5 秒間隔の連投で約 6 クエリ/約 30 クエリで 429
    ("unusual traffic") を返す。夜間バッチの既定間隔 1.5 秒は不足。

方針: 間隔を CLI から設定可能にする (`--sleep-sec`)。既定は夜間運用に足る
値とし、Google CSE の 429 を踏みにくくする。
"""
from __future__ import annotations

import json

import cli
from searxng import DEFAULT_SLEEP_SEC, SearxClient


# --- 1. クライアントは間隔を受け取れる ---

def test_client_exposes_sleep_sec_default():
    """後方互換: 明示しなければ従来の既定値を使う。"""
    assert SearxClient(base_url="http://x").sleep_sec == DEFAULT_SLEEP_SEC


def test_build_searx_accepts_sleep_sec():
    c = cli._build_searx(engine="google cse", base_url="http://x", sleep_sec=12.5)
    assert c.sleep_sec == 12.5


# --- 2. CLI は --sleep-sec を公開する ---

def test_cli_exposes_sleep_sec_flag():
    args = cli.build_parser().parse_args(["--sleep-sec", "12.5"])
    assert args.sleep_sec == 12.5


def test_cli_sleep_sec_default_is_not_the_too_fast_value():
    """実測で 429 を踏んだ 1.5 秒を既定にしてはいけない。"""
    args = cli.build_parser().parse_args([])
    assert args.sleep_sec > DEFAULT_SLEEP_SEC


def test_cli_rejects_negative_sleep_sec():
    import pytest
    with pytest.raises(SystemExit):
        cli.main(["--sleep-sec", "-1"])


def test_cli_passes_sleep_sec_to_client(monkeypatch, tmp_path):
    """CLI の値がクライアントまで届くこと (配線の検証)。"""
    seen = {}
    real = cli.SearxClient

    def spy(*, base_url, sleep_sec=None):
        seen["sleep_sec"] = sleep_sec
        return real(base_url=base_url, sleep_sec=sleep_sec if sleep_sec is not None
                    else DEFAULT_SLEEP_SEC)

    monkeypatch.setattr(cli, "SearxClient", spy)

    class NullPipe:
        def run_domain(self, domain):
            from probe import DomainResult
            return DomainResult(domain=domain, score=0.0, decision="dismissed")

    monkeypatch.setattr(cli, "_build_pipeline", lambda **kw: NullPipe())
    out = tmp_path / "r.json"
    rc = cli.main(["--db-dir", str(tmp_path / "db"), "--scam-db", str(tmp_path / "s.db"),
                   "--report", str(out), "--max-queries", "0", "--sleep-sec", "7.25"])
    assert rc == 0
    assert seen["sleep_sec"] == 7.25
    assert json.loads(out.read_text(encoding="utf-8"))["night"]
