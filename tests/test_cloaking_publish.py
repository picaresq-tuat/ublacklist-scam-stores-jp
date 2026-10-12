"""(b) hunter 統合 + PR 運用テスト: run_night の cloaking リスト書き出しと cli --pr の統合。"""

from __future__ import annotations

import hunter
import pytest
from publish import existing_entries
from scamstore import ScamStore


class _FakeRes:
    def __init__(self, url):
        self.url = url


class _FakeResult:
    def __init__(self, domain, url=None):
        self.url = url or f"https://{domain}/"


def _res(domain):
    return {"url": f"https://{domain}/"}


class _FakeSearx:
    """1 クエリだけ結果を返し、後は空応答。"""

    def __init__(self, results):
        self._results = results
        self.calls = []

    def search(self, query, *, pageno):
        self.calls.append((query, pageno))
        if len(self.calls) == 1:
            return self._results
        return []


class _NullPipe:
    def run_domain(self, domain):
        r = _FakeResult(domain)
        r.features = {}
        r.score = 0
        r.reasons = {}
        r.decision = "dismiss"
        return r


class _CloakPipe:
    """cloaking 特徴を返すパイプライン (features は dict)。"""

    def __init__(self, score, reasons):
        self.score = score
        self.reasons = reasons

    def run_domain(self, domain):
        r = _FakeResult(domain)
        r.features = {"cloaking": True}
        r.score = self.score
        r.reasons = dict(self.reasons)
        r.decision = "hold" if self.score >= 50 else "block" if self.score >= 100 else "dismiss"
        return r


@pytest.fixture()
def env(tmp_path):
    return {
        "db": tmp_path / "db",
        "scam": tmp_path / "scam.db",
        "ulist": tmp_path / "uBlacklist.txt",
        "cloaking": tmp_path / "cloaking_detected" / "uBlacklist.txt",
    }


def test_run_night_writes_cloaking_list(env):
    """cloaking+hold ドメインが cloaking_list_path に出力される。"""
    sx = _FakeSearx([_res("cloak-shop.example")])
    pipe = _CloakPipe(score=60, reasons={"cloaking": 45})
    rep = hunter.run_night(
        night="2026-09-27",
        searx=sx,
        pipeline=pipe,
        store=ScamStore(env["scam"]),
        db_dir=env["db"],
        ulist_path=None,
        publish=False,
        dry_run=False,
        max_queries=1,
        cloaking_list_path=env["cloaking"],
    )
    text = env["cloaking"].read_text(encoding="utf-8")
    assert "*://*.cloak-shop.example/*" in existing_entries(text)
    assert rep["cloaking_holds"] == ["cloak-shop.example"]


def test_run_night_cloaking_dry_run(env):
    """dry-run では書かず、would_cloaking_holds に載せる。"""
    sx = _FakeSearx([_res("cloak-shop.example")])
    pipe = _CloakPipe(score=60, reasons={"cloaking": 45})
    rep = hunter.run_night(
        night="2026-09-27",
        searx=sx,
        pipeline=pipe,
        store=ScamStore(env["scam"]),
        db_dir=env["db"],
        ulist_path=None,
        publish=False,
        dry_run=True,
        max_queries=1,
        cloaking_list_path=env["cloaking"],
    )
    assert not env["cloaking"].exists()
    assert rep["would_cloaking_holds"] == ["*://*.cloak-shop.example/*"]


def test_run_night_cloaking_merge_is_idempotent(env):
    """既存 cloaking リストに重複追記しない。"""
    sx = _FakeSearx([_res("cloak-shop.example")])
    pipe = _CloakPipe(score=60, reasons={"cloaking": 45})
    for _ in range(2):
        hunter.run_night(
            night="2026-09-27",
            searx=sx,
            pipeline=pipe,
            store=ScamStore(env["scam"]),
            db_dir=env["db"],
            ulist_path=None,
            publish=False,
            dry_run=False,
            max_queries=1,
            cloaking_list_path=env["cloaking"],
        )
    text = env["cloaking"].read_text(encoding="utf-8")
    assert text.count("*://*.cloak-shop.example/*") == 1


def test_cli_pr_commits_cloaking_list(tmp_path, monkeypatch):
    """--pr 時に cloaking_detected/uBlacklist.txt も同一ブランチへコミットされ PR に載る。"""
    import cli

    calls = {}

    def fake_ensure_branch(repo_dir, branch):
        calls["ensure"] = (repo_dir, branch)

    def fake_write_and_commit(repo_dir, rel, text, *, message, branch):
        calls.setdefault("commits", []).append((rel, text, message, branch))
        return True

    def fake_push(repo_dir, branch):
        calls["push"] = (repo_dir, branch)

    def fake_open_pr(**kw):
        calls["pr"] = kw
        return {"number": 2, "url": "https://github.com/o/r/pull/2"}

    monkeypatch.setattr(cli, "ensure_branch", fake_ensure_branch)
    monkeypatch.setattr(cli, "write_and_commit", fake_write_and_commit)
    monkeypatch.setattr(cli, "push", fake_push)
    monkeypatch.setattr(cli, "open_pr", fake_open_pr)
    monkeypatch.setattr(cli, "git_run", lambda *a, **kw: None)
    monkeypatch.setenv("GITHUB_TOKEN", "[REDACTED]")
    monkeypatch.setattr(cli, "_build_searx", lambda **kw: _FakeSearx([]))
    monkeypatch.setattr(cli, "_build_pipeline", lambda **kw: _NullPipe())

    ulist = tmp_path / "uBlacklist.txt"
    cloak = tmp_path / "cloaking_detected" / "uBlacklist.txt"
    rc = cli.main(
        [
            "--night",
            "2026-09-27",
            "--db-dir",
            str(tmp_path / "db"),
            "--scam-db",
            str(tmp_path / "s.db"),
            "--ulist",
            str(ulist),
            "--cloaking-list",
            str(cloak),
            "--max-queries",
            "0",
            "--repo",
            "owner/repo",
            "--pr",
        ]
    )
    assert rc == 0
    rels = [c[0] for c in calls.get("commits", [])]
    assert "uBlacklist.txt" in rels
    assert "cloaking_detected/uBlacklist.txt" in rels
    assert calls["pr"]["head"].startswith("nightly/")
    assert calls["pr"]["title"].startswith("nightly:")


def test_cli_pr_cloaking_only_still_opens_pr(tmp_path, monkeypatch):
    """通常リストに変化がなくても cloaking リストの変化だけで push/PR する。"""
    import cli

    calls = {"push": 0, "commits": []}

    monkeypatch.setattr(cli, "ensure_branch", lambda *a: None)
    monkeypatch.setattr(
        cli,
        "write_and_commit",
        lambda repo_dir, rel, text, *, message, branch: calls["commits"].append(rel) or True,
    )
    monkeypatch.setattr(cli, "push", lambda *a: calls.__setitem__("push", calls["push"] + 1))
    monkeypatch.setattr(cli, "git_run", lambda *a, **kw: None)

    def fake_open_pr(**kw):
        calls["pr"] = kw
        return {"number": 3, "url": "u"}

    monkeypatch.setattr(cli, "open_pr", fake_open_pr)
    monkeypatch.setenv("GITHUB_TOKEN", "[REDACTED]")
    monkeypatch.setattr(cli, "_build_searx", lambda **kw: _FakeSearx([]))
    monkeypatch.setattr(cli, "_build_pipeline", lambda **kw: _NullPipe())

    ulist = tmp_path / "uBlacklist.txt"
    ulist.write_text("# empty\n", encoding="utf-8")
    cloak = tmp_path / "cloaking_detected" / "uBlacklist.txt"
    cloak.parent.mkdir()
    cloak.write_text("# c\n\n## Hermes nightly\n\n*://*.already.example/*\n", encoding="utf-8")

    # store に既存ドメインと同一の cloaking hold を仕込む → マージで変化なし
    from scamstore import ScamStore

    store = ScamStore(tmp_path / "s.db")
    store.record("already.example", score=60, decision="hold", features={"cloaking": True})

    rc = cli.main(
        [
            "--night",
            "2026-09-27",
            "--db-dir",
            str(tmp_path / "db"),
            "--scam-db",
            str(tmp_path / "s.db"),
            "--ulist",
            str(ulist),
            "--cloaking-list",
            str(cloak),
            "--max-queries",
            "0",
            "--repo",
            "owner/repo",
            "--pr",
        ]
    )
    assert rc == 0
    assert "cloaking_detected/uBlacklist.txt" in calls["commits"]
    assert calls["push"] >= 1
    assert "pr" in calls


# ---------------------------------------------------------------------------
# 元 (b) リスト生成テストの復元 (2026-09-27 上書き事故からの復旧)
# ---------------------------------------------------------------------------


def _rec(
    store, dom, *, decision="hold", score=60.0, cloaking=True, promoted=False, night="2026-09-27"
):
    feats = {}
    if cloaking:
        feats["cloaking"] = True
    if promoted:
        feats["cloaking_promoted"] = True
    return store.record(dom, score=score, decision=decision, features=feats, night=night)


@pytest.fixture()
def store(tmp_path):
    return ScamStore(tmp_path / "scam.db")


def test_cloaking_holds_returns_hold_with_cloaking(store):
    _rec(store, "blog.shop.example", decision="hold", cloaking=True)
    assert store.cloaking_holds() == ["blog.shop.example"]


def test_cloaking_holds_includes_promoted(store):
    _rec(store, "blog.shop.example", cloaking=True, promoted=True)
    assert store.cloaking_holds() == ["blog.shop.example"]


def test_cloaking_holds_requires_both_conditions(store):
    _rec(store, "a.example", decision="hold", cloaking=False)
    _rec(store, "b.example", decision="block", cloaking=True)
    assert store.cloaking_holds() == []


def test_cloaking_holds_sorted(store):
    _rec(store, "z.example")
    _rec(store, "a.example")
    assert store.cloaking_holds() == ["a.example", "z.example"]


def test_cloaking_holds_ignores_missing_features(store):
    store.record("plain.example", score=60, decision="hold", features=None)
    assert store.cloaking_holds() == []


def test_cloaking_list_render_and_validate(store):
    from cloaking_publish import render_cloaking_list
    from publish import validate

    text = render_cloaking_list(["blog.shop.example"])
    assert validate(text) == []
    assert "blog.shop.example" in text


def test_cloaking_list_skips_permanent_shape(store):
    from cloaking_publish import render_cloaking_list
    from publish import validate

    text = render_cloaking_list(["blog.shop.example"])
    # 汎用 .co / xn-- 正規表現が cloaking ドメインのせいで広がらないこと
    assert not any("*.co/*" in ln for ln in text.splitlines())
    assert validate(text) == []


def test_cloaking_list_idempotent_merge(store):
    from cloaking_publish import merge_cloaking_list, render_cloaking_list
    from publish import existing_entries

    first = render_cloaking_list(["blog.shop.example"])
    merged = merge_cloaking_list(first, ["blog.shop.example"])
    assert sorted(existing_entries(merged)) == sorted(existing_entries(first))


def test_cloaking_pr_body_includes_evidence(store):
    from cloaking_publish import cloaking_pr_body

    body = cloaking_pr_body(
        "2026-09-27", [{"domain": "blog.shop.example", "score": 60, "reasons": {"cloaking": 45}}]
    )
    assert "blog.shop.example" in body
    assert "2026-09-27" in body
    assert "cloaking" in body


def test_cloaking_holds_feature_flag_semantics(store):
    _rec(store, "a.example", cloaking=True, promoted=False)
    _rec(store, "b.example", cloaking=False, promoted=True)
    # promoted 単体では cloaking とみなさない (features.cloaking が真であること)
    assert store.cloaking_holds() == ["a.example"]


# --- cron 応答に載せる cloaking 追加数 ---


def _run(env, night, domain="cloak-shop.example", dry_run=False):
    return hunter.run_night(
        night=night,
        searx=_FakeSearx([_res(domain)]),
        pipeline=_CloakPipe(score=60, reasons={"cloaking": 45}),
        store=ScamStore(env["scam"]),
        db_dir=env["db"],
        ulist_path=None,
        publish=False,
        dry_run=dry_run,
        max_queries=1,
        cloaking_list_path=env["cloaking"],
    )


def test_run_night_reports_cloaking_added(env):
    """初回は追加 1 件、2 回目 (冪等) は追加 0 件を report に載せる。"""
    rep1 = _run(env, "2026-09-27")
    assert rep1["cloaking_added"] == ["*://*.cloak-shop.example/*"]

    rep2 = _run(env, "2026-09-28")
    assert rep2["cloaking_added"] == []


def test_run_night_reports_cloaking_added_in_dry_run(env):
    """dry-run でも「追加されるはずの件数」を report に載せる。"""
    rep = _run(env, "2026-09-27", dry_run=True)
    assert rep["cloaking_added"] == ["*://*.cloak-shop.example/*"]
    assert not env["cloaking"].exists()
