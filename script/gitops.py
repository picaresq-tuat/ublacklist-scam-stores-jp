"""git / GitHub 操作 (P7b)。

- コミット・push は feature branch (`nightly/YYYY-MM-DD`) のみ許可する (`main` への直 push 禁止)。
- PR 作成は GitHub REST (`POST /repos/{owner}/{repo}/pulls`)。
- **トークンは絶対に引数・ログ・例外メッセージ・コミットに載せない。**
  実装は `os.environ` から読み、値を一切印字しない (エラー時もステータスコードのみ)。
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path

API_ROOT = "https://api.github.com"
ALLOWED_BRANCH_PREFIX = "nightly/"
DEFAULT_BASE = "main"
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_AUTHOR = ("-c", "user.name=scam-hunter", "-c", "user.email=scam-hunter@localhost")


class GitError(RuntimeError):
    """git / GitHub API の失敗。メッセージにトークンを含めない。"""


def branch_name(night: str) -> str:
    if not _DATE_RE.match((night or "").strip()):
        raise ValueError(f"night must be YYYY-MM-DD, got {night!r}")
    return f"{ALLOWED_BRANCH_PREFIX}{night.strip()}"


def assert_feature_branch(branch: str) -> str:
    if not (branch or "").startswith(ALLOWED_BRANCH_PREFIX):
        raise ValueError(f"refusing to operate on non-feature branch: {branch!r}")
    return branch


def run(
    args: Sequence[str], *, cwd: Path | str, check: bool = True, timeout: float = 120.0
) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        [str(a) for a in args], cwd=str(cwd), capture_output=True, text=True, timeout=timeout
    )
    if check and proc.returncode != 0:
        first = (proc.stderr or proc.stdout or "").strip().splitlines()
        detail = first[0] if first else f"exit {proc.returncode}"
        raise GitError(f"{' '.join(str(a) for a in args[:2])} failed: {detail}")
    return proc


def git(repo: Path | str, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return run(["git", *args], cwd=repo, check=check)


def current_branch(repo: Path | str) -> str:
    return git(repo, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()


def has_changes(repo: Path | str) -> bool:
    return bool(git(repo, "status", "--porcelain").stdout.strip())


def ensure_branch(repo: Path | str, branch: str) -> str:
    assert_feature_branch(branch)
    if current_branch(repo) != branch:
        exists = git(repo, "rev-parse", "--verify", branch, check=False).returncode == 0
        if exists:
            git(repo, "checkout", branch)
        else:
            git(repo, "checkout", "-b", branch)
    return branch


def write_and_commit(
    repo: Path | str, rel_path: str, content: str, *, message: str, branch: str
) -> bool:
    """ブランチを用意して内容を書き、変化があればコミットする。無変化なら False。"""
    ensure_branch(repo, branch)
    target = Path(repo) / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    git(repo, "add", "--", rel_path)
    if not has_changes(repo):
        return False
    git(repo, *_AUTHOR, "commit", "-m", message)
    return True


def push(repo: Path | str, branch: str, *, remote: str = "origin") -> None:
    assert_feature_branch(branch)
    git(repo, "push", "-u", remote, branch)


def merge_no_ff(
    repo: Path | str, branch: str, *, message: str, base: str = DEFAULT_BASE, push_base: bool = True
) -> None:
    """人手承認後にだけ呼ぶ。`--no-ff` でマージコミットを作る。"""
    assert_feature_branch(branch)
    if base.startswith(ALLOWED_BRANCH_PREFIX):
        raise ValueError("base must not be a nightly branch")
    git(repo, "checkout", base)
    git(repo, *_AUTHOR, "merge", "--no-ff", "--no-edit", "-m", message, branch)
    if push_base:
        git(repo, "push", "origin", base)


# --- HTTP ---


def _default_api(
    method: str,
    path: str,
    payload: dict | None = None,
    token: str | None = None,
    timeout: float = 30.0,
) -> tuple[int, dict]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(API_ROOT + path, data=data, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "scam-hunter")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            return int(resp.status), (json.loads(body) if body else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return int(exc.code), json.loads(raw or b"{}")
        except ValueError:
            return int(exc.code), {}
    except Exception as exc:
        raise GitError(f"api call failed: {type(exc).__name__}") from exc


def token_from_env(var: str = "GITHUB_TOKEN") -> str:
    tok = os.environ.get(var, "")
    if not tok:
        raise GitError(f"{var} is not set")
    return tok


def open_pr(
    *,
    head: str,
    title: str,
    body: str,
    owner: str,
    repo_name: str,
    token: str | None = None,
    base: str = DEFAULT_BASE,
    api: Callable[..., tuple[int, dict]] | None = None,
    draft: bool = False,
) -> dict:
    assert_feature_branch(head)
    api = api or _default_api
    payload = {"title": title, "body": body, "head": head, "base": base, "draft": draft}
    status, data = api("POST", f"/repos/{owner}/{repo_name}/pulls", payload, token=token)
    if status not in (200, 201):
        msg = str(data.get("message", ""))[:120]
        raise GitError(f"PR creation failed with HTTP {status}: {msg}")
    return {"number": int(data.get("number", 0)), "url": str(data.get("html_url", ""))}


def get_pr(
    *,
    number: int,
    owner: str,
    repo_name: str,
    token: str | None = None,
    api: Callable[..., tuple[int, dict]] | None = None,
) -> dict:
    api = api or _default_api
    status, data = api("GET", f"/repos/{owner}/{repo_name}/pulls/{number}", None, token=token)
    if status != 200:
        raise GitError(f"PR fetch failed with HTTP {status}")
    return data


def pr_body(
    night: str,
    rows: Sequence[dict],
    *,
    permanent_rules: Sequence[str],
    added: int,
    removed: int,
    dry_run: bool = False,
) -> str:
    """PR 本文 (判定根拠つき)。レビュー担当が表だけで判断できる形にする。"""
    lines = [f"## nightly {night}", ""]
    if dry_run:
        lines += ["> **dry-run**: 実マージ前のレビュー用差分です。", ""]
    lines += [f"- 追加: {added} 件", f"- 削除 (失効): {removed} 件", ""]
    if rows:
        lines += [
            "| domain | score | nights | decision | reasons |",
            "| --- | ---: | ---: | --- | --- |",
        ]
        for r in rows:
            reasons = ", ".join(
                f"{k}:{v:g}"
                for k, v in sorted((r.get("reasons") or {}).items(), key=lambda kv: -kv[1])
            )
            lines.append(
                f"| `{r.get('domain', '')}` | {r.get('score', 0):g} | "
                f"{r.get('nights', 0)} | {r.get('decision', '')} | {reasons} |"
            )
        lines.append("")
    lines += ["### 常設正規表現", ""]
    lines += [f"- `{rule}`" for rule in permanent_rules]
    lines += ["", "生成: `scam_hunter` (自動)。人手承認後に `git merge --no-ff` で取り込みます。"]
    return "\n".join(lines) + "\n"
