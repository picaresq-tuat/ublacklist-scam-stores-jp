"""P7d: 実パイプライン (probe.py) / 到達性チェック (health.py) / CLI の RED テスト。"""

from __future__ import annotations

import json

import health as health_mod
import probe
import pytest

HTML = """<html><head><title>dynabook R734 中古 格安</title>
<link rel="icon" href="/favicon.ico"></head>
<body><img src="https://cdn.askul.co.jp/img/1.jpg">通常価格 98000円 が今だけ 980円 期間限定</body></html>"""


class FakeFetchResult:
    def __init__(self, url, status=200, body=HTML, **kw):
        from fetch import FetchResult

        self._r = FetchResult(
            url=url,
            status=status,
            final_url=url,
            headers=kw.get("headers", {}) or {},
            body=None if kw.get("discarded") else body,
            discarded=bool(kw.get("discarded")),
            discard_reason=kw.get("discard_reason", ""),
        )
        self._r.html_sanitized = body if not kw.get("discarded") else ""
        self._r.raw_bytes = len(body.encode())
        self._r.chain = kw.get("chain", [])

    def __getattr__(self, name):
        return getattr(self._r, name)


@pytest.fixture()
def fake_fetch(monkeypatch):
    calls = []

    def _fetch(url, **kw):
        calls.append((url, kw))
        return FakeFetchResult(url)

    monkeypatch.setattr(probe, "fetch", _fetch, raising=False)
    return calls


# --- probe: 3 UA で取得しスコアを返す ---


def test_probe_run_domain_returns_scored_result(fake_fetch, tmp_path):
    p = probe.Pipeline(db_dir=tmp_path)
    res = p.run_domain("scam-shop.example")
    assert res.domain == "scam-shop.example"
    assert res.score >= 0
    assert res.decision in {"block", "hold", "dismissed"}
    assert isinstance(res.reasons, dict)


def test_probe_calls_browser_and_bot_user_agents(fake_fetch, tmp_path):
    p = probe.Pipeline(db_dir=tmp_path)
    p.run_domain("scam-shop.example")
    uas = {kw.get("ua") for _, kw in fake_fetch}
    assert "browser" in uas
    assert {"googlebot", "bingbot"} & uas, "クローキング判定には bot UA が必要"


def test_probe_uses_https_first_then_http(fake_fetch, tmp_path):
    p = probe.Pipeline(db_dir=tmp_path)
    p.run_domain("scam-shop.example")
    urls = [u for u, _ in fake_fetch]
    assert urls[0].startswith("https://")


def test_probe_fetches_favicon(fake_fetch, tmp_path):
    p = probe.Pipeline(db_dir=tmp_path)
    p.run_domain("scam-shop.example")
    assert any("favicon" in u for u, _ in fake_fetch)


def test_probe_never_raises_on_fetch_failure(monkeypatch, tmp_path):
    from fetch import FetchError

    def boom(url, **kw):
        raise FetchError("connection refused")

    monkeypatch.setattr(probe, "fetch", boom, raising=False)
    p = probe.Pipeline(db_dir=tmp_path)
    res = p.run_domain("dead-shop.example")
    assert res.decision == "dismissed"
    assert res.features.get("error") or res.score == 0


def test_probe_dismisses_whitelisted_shaped_private_targets(tmp_path):
    p = probe.Pipeline(db_dir=tmp_path)
    # 取得前の時点で private アドレスは fetch 側が BlockedURL を投げる
    res = p.run_domain("localhost")
    assert res.decision == "dismissed"


def test_probe_records_pages_for_pivot(tmp_path, monkeypatch):
    p = probe.Pipeline(db_dir=tmp_path)
    assert p.pivot_queries("dynabook R734") == []
    p.note_hit("dynabook R734", "https://scam-shop.example/item/1")
    qs = p.pivot_queries("dynabook R734")
    assert qs and all("site:" in q for q in qs)


# --- health: 到達性チェック ---


def test_health_check_true_for_200(monkeypatch):
    monkeypatch.setattr(health_mod, "fetch", lambda url, **kw: FakeFetchResult(url, status=200))
    assert health_mod.HealthChecker().check("alive.example") is True


def test_health_check_false_for_404(monkeypatch):
    monkeypatch.setattr(health_mod, "fetch", lambda url, **kw: FakeFetchResult(url, status=404))
    assert health_mod.HealthChecker().check("gone.example") is False


def test_health_check_false_on_error(monkeypatch):
    from fetch import FetchError

    def boom(url, **kw):
        raise FetchError("dns failure")

    monkeypatch.setattr(health_mod, "fetch", boom)
    assert health_mod.HealthChecker().check("dead.example") is False


def test_health_check_false_on_dns_wildcard_parking(monkeypatch):
    """到達しても「ドメイン売ります」ページなら失効扱い。"""
    parked = "<html><title>This domain is for sale</title><body>Buy this domain</body></html>"
    monkeypatch.setattr(
        health_mod, "fetch", lambda url, **kw: FakeFetchResult(url, status=200, body=parked)
    )
    assert health_mod.HealthChecker().check("parked.example") is False


def test_health_blocked_url_is_unreachable(monkeypatch, tmp_path):
    from fetch import BlockedURL

    def blocked(url, **kw):
        raise BlockedURL("private address not allowed")

    monkeypatch.setattr(health_mod, "fetch", blocked)
    assert health_mod.HealthChecker().check("174.1.2.3") is False


# --- CLI ---


def test_cli_dry_run_writes_report(tmp_path, monkeypatch):
    import cli

    out = tmp_path / "report.json"
    monkeypatch.setattr(cli, "_build_searx", lambda **kw: _EmptySearx())
    monkeypatch.setattr(cli, "_build_pipeline", lambda **kw: _NullPipeline())
    rc = cli.main(
        [
            "--night",
            "2026-09-24",
            "--db-dir",
            str(tmp_path / "db"),
            "--scam-db",
            str(tmp_path / "scam.db"),
            "--report",
            str(out),
            "--dry-run",
            "--max-queries",
            "0",
        ]
    )
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["night"] == "2026-09-24"
    assert data["dry_run"] is True


def test_cli_rejects_unknown_engine(tmp_path):
    import cli

    with pytest.raises(SystemExit):
        cli.main(["--db-dir", str(tmp_path), "--engine", "yandex"])


def test_cli_default_engine_is_google_cse():
    """方針転換 (2026-09-24): 主引擎は Google CSE。CLI 既定もそれに合わせる。"""
    import cli

    parser = cli.build_parser()
    args = parser.parse_args([])
    assert args.engine == "google cse"
    engine_action = next(a for a in parser._actions if a.dest == "engine")
    assert "google cse" in engine_action.choices


def test_cli_accepts_google_cse_engine(tmp_path, monkeypatch):
    import cli

    monkeypatch.setattr(cli, "_build_searx", lambda **kw: _EmptySearx())
    monkeypatch.setattr(cli, "_build_pipeline", lambda **kw: _NullPipeline())
    out = tmp_path / "r.json"
    rc = cli.main(
        [
            "--db-dir",
            str(tmp_path / "db"),
            "--scam-db",
            str(tmp_path / "s.db"),
            "--engine",
            "google cse",
            "--report",
            str(out),
            "--max-queries",
            "0",
        ]
    )
    assert rc == 0
    assert json.loads(out.read_text(encoding="utf-8"))["engine_failures"] == 0


def test_cli_report_includes_engine_failure_fields(tmp_path, monkeypatch):
    """429 で中止した夜もレポートに理由が残る。"""
    import cli
    from searxng import EngineUnavailable

    class Dead:
        """実 SearxClient と同じ契約: 失敗時に stats.engine_failures を増やしてから送出する。"""

        def __init__(self):
            from searxng import SearxStats

            self.stats = SearxStats()

        def search(self, query, *, pageno):
            self.stats.engine_failures += 1
            raise EngineUnavailable("engines unavailable: ['google cse']")

    monkeypatch.setattr(cli, "_build_searx", lambda **kw: Dead())
    monkeypatch.setattr(cli, "_build_pipeline", lambda **kw: _NullPipeline())
    out = tmp_path / "r.json"
    rc = cli.main(
        [
            "--db-dir",
            str(tmp_path / "db"),
            "--scam-db",
            str(tmp_path / "s.db"),
            "--report",
            str(out),
            "--max-queries",
            "10",
            "--engine-backoff-sec",
            "0",
            "--engine-backoff-max-sec",
            "0",
        ]
    )
    assert rc == 0, "エンジン停止で CLI が異常終了してはいけない"
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["aborted"] is True
    assert data["engine_failures"] >= 1
    assert data["searx_stats"]["engine_failures"] >= 1


def test_cli_publish_requires_ulist(tmp_path):
    import cli

    with pytest.raises(SystemExit):
        cli.main(["--db-dir", str(tmp_path), "--publish"])


def test_cli_pr_requires_token_and_repo(tmp_path, monkeypatch):
    import cli

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with pytest.raises(SystemExit):
        cli.main(["--db-dir", str(tmp_path), "--pr"])


class _EmptySearx:
    def __init__(self):
        self.calls = 0

    def search(self, query, *, pageno):
        self.calls += 1
        return []


class _NullPipeline:
    def run_domain(self, domain):
        from probe import DomainResult

        return DomainResult(domain=domain, score=0.0, decision="dismissed")
