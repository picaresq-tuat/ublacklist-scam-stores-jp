"""夜間ランナー (nightly.py) の RED テスト。

- 実行 → 編集済みログ (`logs/nightly_scan.log`) 追記 → 変化があれば push & PR。
- ログには絶対パス・トークンを書かない (編集済みログの約束)。
- 変化がない夜は push も PR もしない。
"""

from __future__ import annotations

import subprocess
from datetime import datetime, timedelta, timezone

import nightly
import pytest

JST = timezone(timedelta(hours=9))


def _report(**kw):
    base = {
        "night": "2026-10-05",
        "empty_queries": 1,
        "engine_failures": 0,
        "aborted": False,
        "new_domains": 2,
        "domains_found": 5,
        "blocked": 1,
        "hold": 0,
        "dismissed": 3,
        "whitelisted": 1,
        "expired": [],
        "published": ["*://*.scam.example/*"],
        "cloaking_holds": [],
        "dry_run": False,
    }
    base.update(kw)
    return base


# --- ログ整形 ---


def test_format_log_block_has_counts():
    block = nightly.format_log_block(_report(), now=datetime(2026, 10, 5, 4, 30, tzinfo=JST))
    assert "night=2026-10-05" in block
    assert "mode=publish" in block
    assert "2026-10-05T04:30+09:00" in block
    assert "published=1" in block
    assert "expired=0" in block
    assert "domains_found=5" in block
    assert "new_domains=2" in block


def test_format_log_block_has_no_paths_or_secrets():
    block = nightly.format_log_block(_report(), now=datetime(2026, 10, 5, 4, 30, tzinfo=JST))
    assert "/root" not in block
    assert "ghp_" not in block
    assert "github_pat_" not in block


def test_format_log_block_dry_run_mode():
    block = nightly.format_log_block(
        _report(dry_run=True, published=[], would_publish=[1]), now=datetime.now(JST)
    )
    assert "mode=dry-run" in block


# --- 追記と月次ローテーション ---

HEADER = "# nightly_scan log — scam_hunter 夜間実行ログ (編集済み)\n"


def test_append_log_creates_file_with_header(tmp_path):
    log = tmp_path / "logs" / "nightly_scan.log"
    nightly.append_log(log, _report(), now=datetime(2026, 10, 5, 4, 30, tzinfo=JST))
    text = log.read_text(encoding="utf-8")
    assert "nightly_scan log" in text
    assert "night=2026-10-05" in text


def test_append_log_no_rotation_within_same_month(tmp_path):
    log = tmp_path / "nightly_scan.log"
    log.write_text(HEADER + "\n[2026-10-01T04:30+09:00] night=2026-10-01 mode=publish\n", "utf-8")
    nightly.append_log(log, _report(), now=datetime(2026, 10, 5, 4, 30, tzinfo=JST))
    assert not (tmp_path / "nightly_scan.log.202610").exists()
    text = log.read_text(encoding="utf-8")
    assert "night=2026-10-01" in text
    assert "night=2026-10-05" in text


def test_append_log_rotates_on_month_change(tmp_path):
    log = tmp_path / "nightly_scan.log"
    log.write_text(HEADER + "\n[2026-09-30T04:30+09:00] night=2026-09-30 mode=publish\n", "utf-8")
    nightly.append_log(log, _report(), now=datetime(2026, 10, 5, 4, 30, tzinfo=JST))
    rotated = tmp_path / "nightly_scan.log.202609"
    assert rotated.exists()
    assert "night=2026-09-30" in rotated.read_text(encoding="utf-8")
    text = log.read_text(encoding="utf-8")
    assert "night=2026-09-30" not in text
    assert "night=2026-10-05" in text


# --- 変化判定 ---


def test_has_changes_true_when_published():
    assert nightly.has_changes(_report()) is True


def test_has_changes_true_when_expired():
    assert nightly.has_changes(_report(published=[], expired=["gone.example"])) is True


def test_has_changes_true_when_cloaking_holds():
    assert nightly.has_changes(_report(published=[], cloaking_holds=["cloak.example"])) is True


def test_has_changes_false_when_nothing_changed():
    assert nightly.has_changes(_report(published=[], expired=[], cloaking_holds=[])) is False


# --- オーケストレーション ---


@pytest.fixture()
def repo(tmp_path):
    origin = tmp_path / "origin.git"
    work = tmp_path / "work"
    origin.mkdir()
    subprocess.run(
        ["git", "init", "--bare", "--initial-branch=main", str(origin)],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "clone", str(origin), str(work)], cwd=tmp_path, check=True, capture_output=True
    )
    subprocess.run(["git", "config", "user.name", "tester"], cwd=work, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.test"], cwd=work, check=True)
    (work / "uBlacklist.txt").write_text("# seed\n", encoding="utf-8")
    (work / "logs").mkdir()
    (work / "logs" / "nightly_scan.log").write_text(HEADER, encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=work, check=True)
    subprocess.run(["git", "commit", "-m", "seed"], cwd=work, check=True, capture_output=True)
    subprocess.run(
        ["git", "push", "-u", "origin", "main"], cwd=work, check=True, capture_output=True
    )
    return work


def _fake_stage(report, ulist_text="# new\n", cloaking_text=None):
    def stage(**kw):
        repo_dir = kw["repo_dir"]
        (repo_dir / "uBlacklist.txt").write_text(ulist_text, encoding="utf-8")
        if cloaking_text is not None:
            (repo_dir / "cloaking_detected").mkdir(exist_ok=True)
            (repo_dir / "cloaking_detected" / "uBlacklist.txt").write_text(
                cloaking_text, encoding="utf-8"
            )
        return report

    return stage


def test_run_commits_and_opens_pr(repo, monkeypatch):
    calls = {}

    def fake_open_pr(**kw):
        calls["pr"] = kw
        return {"number": 9, "url": "https://github.com/o/r/pull/9"}

    monkeypatch.setattr(nightly.gitops, "open_pr", fake_open_pr)
    monkeypatch.setattr(nightly.gitops, "token_from_env", lambda: "[REDACTED]")

    res = nightly.run(
        repo_dir=repo,
        owner_repo="owner/repo",
        night="2026-10-05",
        stage=_fake_stage(_report()),
        api=lambda *a, **kw: (200, {}),
        now=datetime(2026, 10, 5, 4, 30, tzinfo=JST),
    )

    assert res["changes"] is True
    assert res["pr"]["number"] == 9
    assert calls["pr"]["head"] == "nightly/2026-10-05"
    log = subprocess.run(
        ["git", "log", "--oneline", "-1", "--name-only"], cwd=repo, capture_output=True, text=True
    ).stdout
    assert "uBlacklist.txt" in log
    assert "logs/nightly_scan.log" in log
    remote = subprocess.run(
        ["git", "ls-remote", "--heads", "origin", "nightly/2026-10-05"],
        cwd=repo,
        capture_output=True,
        text=True,
    ).stdout
    assert "nightly/2026-10-05" in remote


def test_run_skips_push_and_pr_when_no_changes(repo, monkeypatch):
    called = {"pr": 0}

    def fake_open_pr(**kw):
        called["pr"] += 1
        return {"number": 1, "url": "u"}

    monkeypatch.setattr(nightly.gitops, "open_pr", fake_open_pr)
    monkeypatch.setattr(nightly.gitops, "token_from_env", lambda: "[REDACTED]")

    res = nightly.run(
        repo_dir=repo,
        owner_repo="owner/repo",
        night="2026-10-05",
        stage=_fake_stage(
            _report(published=[], expired=[], cloaking_holds=[]), ulist_text="# seed\n"
        ),
        now=datetime(2026, 10, 5, 4, 30, tzinfo=JST),
    )

    assert res["changes"] is False
    assert res["pr"] is None
    assert called["pr"] == 0
    branches = subprocess.run(
        ["git", "branch", "--list", "--all"], cwd=repo, capture_output=True, text=True
    ).stdout
    assert "origin/nightly/2026-10-05" not in branches


def test_run_dry_run_never_pushes(repo, monkeypatch):
    monkeypatch.setattr(
        nightly.gitops, "open_pr", lambda **kw: pytest.fail("dry-run で PR を開いてはいけない")
    )
    res = nightly.run(
        repo_dir=repo,
        owner_repo="owner/repo",
        night="2026-10-05",
        dry_run=True,
        stage=_fake_stage(_report(dry_run=True)),
        now=datetime(2026, 10, 5, 4, 30, tzinfo=JST),
    )
    assert res["stage"] == "dry-run"
    assert res["pr"] is None


# --- 本番パイプラインの配線 (実検索はせず、引数の受け渡しだけ検証) ---


def test_default_stage_forwards_max_queries(tmp_path, monkeypatch):
    import hunter

    seen = {}

    def fake_run_night(**kw):
        seen.update(kw)
        return _report(dry_run=kw["dry_run"])

    monkeypatch.setattr(hunter, "run_night", fake_run_night)
    import cli

    monkeypatch.setattr(cli, "_build_searx", lambda **kw: object())
    monkeypatch.setattr(cli, "_build_pipeline", lambda **kw: object())

    rep = nightly._default_stage(
        repo_dir=tmp_path, night="2026-10-05", dry_run=True, db_dir=tmp_path / "db", max_queries=1
    )

    assert rep["dry_run"] is True
    assert seen["max_queries"] == 1
    assert seen["dry_run"] is True
    assert seen["publish"] is False
    assert str(seen["ulist_path"]).endswith("uBlacklist.txt")
    assert seen["cloaking_list_path"] is not None
    # models_db はパス文字列ではなく ModelDB インスタンスを渡す (実バグの回帰テスト)
    from modeldb import ModelDB

    assert isinstance(seen["models_db"], ModelDB)
    assert seen["models_db"].count() > 0
    assert (tmp_path / "db").is_dir()


def test_default_stage_publishes_when_not_dry_run(tmp_path, monkeypatch):
    import hunter

    seen = {}
    monkeypatch.setattr(hunter, "run_night", lambda **kw: seen.update(kw) or _report())
    import cli

    monkeypatch.setattr(cli, "_build_searx", lambda **kw: object())
    monkeypatch.setattr(cli, "_build_pipeline", lambda **kw: object())

    nightly._default_stage(
        repo_dir=tmp_path, night="2026-10-05", dry_run=False, db_dir=tmp_path / "db"
    )
    assert seen["publish"] is True
    assert seen["dry_run"] is False


def test_searx_url_accepts_bare_host(monkeypatch):
    monkeypatch.setenv("SEARXNG_URL", "127.0.0.1:8888")
    assert nightly._searx_url() == "http://127.0.0.1:8888"
    monkeypatch.setenv("SEARXNG_URL", "http://searx.local:8888")
    assert nightly._searx_url() == "http://searx.local:8888"
    monkeypatch.delenv("SEARXNG_URL")
    assert nightly._searx_url() == "http://127.0.0.1:8888"
