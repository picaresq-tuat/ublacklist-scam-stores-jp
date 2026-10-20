"""リポジトリ衛生: DB の実データを公開しない (l4)。

判定履歴・検索履歴には未検証のドメインが入るため、db/ 配下の DB は
追跡しない。models.db / whitelist.db は seed から再生成できる。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(REPO), *args], capture_output=True, text=True, check=False
    )


@pytest.fixture(scope="module")
def git_repo() -> Path:
    if _git("rev-parse", "--is-inside-work-tree").returncode != 0:
        pytest.skip("git リポジトリではない")
    return REPO


@pytest.mark.parametrize("name", ["scam.db", "searches.db", "models.db", "whitelist.db"])
def test_db_files_are_ignored(git_repo, name):
    r = _git("check-ignore", "-q", f"db/{name}")
    assert r.returncode == 0, f"db/{name} が .gitignore で除外されていない"


def test_db_keepfile_is_not_ignored(git_repo):
    r = _git("check-ignore", "-q", "db/.gitkeep")
    assert r.returncode == 1, "db/.gitkeep は追跡対象のままにする"


def test_no_db_file_is_tracked(git_repo):
    out = _git("ls-files", "db").stdout.split()
    assert out == ["db/.gitkeep"], f"db/ に追跡された実データがある: {out}"
