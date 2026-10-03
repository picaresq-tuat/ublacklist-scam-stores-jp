"""P7b: git / GitHub 操作 (gitops.py) の RED テスト。

ネットワークは Api スタブで置換。トークンは決して戻り値・例外に出さない。
"""

import subprocess

import gitops
import pytest


def git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


@pytest.fixture()
def repo(tmp_path):
    """bare origin + clone の最小フィクスチャ。"""
    origin = tmp_path / "origin.git"
    work = tmp_path / "work"
    origin.mkdir()
    assert git("init", "--bare", "--initial-branch=main", str(origin), cwd=tmp_path).returncode == 0
    assert git("clone", str(origin), str(work), cwd=tmp_path).returncode == 0
    assert git("config", "user.name", "tester", cwd=work).returncode == 0
    assert git("config", "user.email", "t@example.test", cwd=work).returncode == 0
    (work / "uBlacklist.txt").write_text("# seed\n", encoding="utf-8")
    git("add", "-A", cwd=work)
    git("commit", "-m", "seed", cwd=work)
    git("push", "-u", "origin", "main", cwd=work)
    return work


class FakeApi:
    """GitHub REST の最小スタブ。呼び出しを記録する。"""

    def __init__(self, pr_number=42, fail_pull=False):
        self.calls: list[tuple[str, str, dict]] = []
        self.pr_number = pr_number
        self.fail_pull = fail_pull

    def __call__(self, method, path, payload=None, token=None):
        self.calls.append((method, path, payload or {}))
        if method == "POST" and path.endswith("/pulls"):
            if self.fail_pull:
                return 422, {"message": "Validation Failed"}
            return 201, {
                "number": self.pr_number,
                "html_url": f"https://github.com/o/r/pull/{self.pr_number}",
            }
        if method == "GET":
            return 200, {"number": self.pr_number, "state": "open"}
        return 200, {}


def test_branch_name_is_date_based():
    assert gitops.branch_name("2026-09-24") == "nightly/2026-09-24"


def test_branch_name_rejects_bad_date():
    with pytest.raises(ValueError):
        gitops.branch_name("24/09/2026")


def test_run_rejects_nonzero(tmp_path):
    with pytest.raises(gitops.GitError):
        gitops.run(["git", "status", "--definitely-not-a-flag"], cwd=tmp_path)


def test_commit_and_push_cycle(repo):
    gitops.write_and_commit(
        repo,
        "uBlacklist.txt",
        "# new\n*://*.a.example/*\n",
        message="nightly: +1",
        branch="nightly/2026-09-24",
    )
    log = git("log", "--oneline", "-1", cwd=repo).stdout
    assert "nightly: +1" in log
    branches = git("branch", "--list", cwd=repo).stdout
    assert "nightly/2026-09-24" in branches
    gitops.push(repo, "nightly/2026-09-24")
    remote = git("ls-remote", "--heads", "origin", "nightly/2026-09-24", cwd=repo).stdout
    assert "nightly/2026-09-24" in remote


def test_write_and_commit_without_changes_is_noop(repo):
    gitops.write_and_commit(
        repo, "uBlacklist.txt", "# seed\n", message="x", branch="nightly/2026-09-24"
    )
    changed = gitops.has_changes(repo)
    assert changed is False


def test_open_pr_returns_number_and_url(repo):
    api = FakeApi(pr_number=7)
    res = gitops.open_pr(
        api=api,
        token="[REDACTED]",
        owner="picaresq-tuat",
        repo_name="ublacklist-scam-stores-jp",
        head="nightly/2026-09-24",
        title="nightly 2026-09-24",
        body="table here",
    )
    assert res["number"] == 7
    assert res["url"].endswith("/pull/7")
    method, path, payload = api.calls[-1]
    assert method == "POST"
    assert path.endswith("/repos/picaresq-tuat/ublacklist-scam-stores-jp/pulls")
    assert payload["head"] == "nightly/2026-09-24"
    assert payload["base"] == "main"


def test_open_pr_failure_raises_without_token(repo):
    api = FakeApi(fail_pull=True)
    with pytest.raises(gitops.GitError) as exc:
        gitops.open_pr(
            api=api,
            token="[REDACTED]",
            owner="o",
            repo_name="r",
            head="nightly/2026-09-24",
            title="t",
            body="b",
        )
    assert "[REDACTED]" not in str(exc.value)
    assert "422" in str(exc.value)


def test_token_never_appears_in_arguments_or_errors(repo):
    api = FakeApi(fail_pull=True)
    with pytest.raises(gitops.GitError) as exc:
        gitops.open_pr(
            api=api,
            token="sentinel-SHOULDNEVERLEAK",
            owner="o",
            repo_name="r",
            head="nightly/2026-09-24",
            title="t",
            body="b",
        )
    assert "SHOULDNEVERLEAK" not in str(exc.value)
    for _, _, payload in api.calls:
        assert "SHOULDNEVERLEAK" not in str(payload)


def test_api_payload_never_contains_token_field(repo):
    api = FakeApi()
    gitops.open_pr(
        api=api,
        token="dummy-pat-value",
        owner="o",
        repo_name="r",
        head="nightly/2026-09-24",
        title="t",
        body="b",
    )
    for _, _, payload in api.calls:
        assert set(payload) == {"title", "body", "head", "base", "draft"}


def test_env_token_is_read_but_never_echoed(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "dummy-token-env-only")
    assert gitops.token_from_env() == "dummy-token-env-only"
    monkeypatch.delenv("GITHUB_TOKEN")
    with pytest.raises(gitops.GitError) as exc:
        gitops.token_from_env()
    assert "GITHUB_TOKEN is not set" in str(exc.value)


def test_merge_uses_no_ff(repo):
    gitops.write_and_commit(
        repo, "uBlacklist.txt", "# 2\n*://*.b.example/*\n", message="m", branch="nightly/2026-09-24"
    )
    gitops.push(repo, "nightly/2026-09-24")
    gitops.merge_no_ff(repo, "nightly/2026-09-24", message="merge nightly")
    log = git("log", "--oneline", "--graph", cwd=repo).stdout
    assert "merge nightly" in log
    assert "*" in log or "|" in log  # merge commit が存在する
    parents = git("rev-list", "--parents", "-1", "HEAD", cwd=repo).stdout.split()
    assert len(parents) == 3  # <commit> <p1> <p2>


def test_default_branch_guard():
    assert gitops.ALLOWED_BRANCH_PREFIX == "nightly/"
    with pytest.raises(ValueError):
        gitops.assert_feature_branch("main")


def test_assert_feature_branch_passes():
    assert gitops.assert_feature_branch("nightly/2026-09-24") == "nightly/2026-09-24"


def test_git_error_is_not_silent_on_push(tmp_path):
    with pytest.raises(gitops.GitError):
        gitops.push(tmp_path, "nightly/2026-09-24")
