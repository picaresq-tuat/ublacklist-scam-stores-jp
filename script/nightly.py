"""夜間ランナー (cron 実行の入口)。

1 回の実行でやること:

1. `hunter.run_night` を publish モードで回す (uBlacklist.txt / cloaking リストを更新)
2. `logs/nightly_scan.log` に編集済みログを 1 ブロック追記 (月替わりで .YYYYMM へ退避)
3. 変更があれば feature branch (`nightly/YYYY-MM-DD`) に commit & push し、PR を作る

人手承認が前提のため、`main` への push や merge は決して行わない。
トークンは `GITHUB_TOKEN` 環境変数からのみ読み、引数・ログ・コミットに載せない。

  python3 script/nightly.py --repo picaresq-tuat/ublacklist-scam-stores-jp
  python3 script/nightly.py --dry-run          # 検索も出版もせずログだけ(検証用)
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path

import gitops
import watchlist
from gitops import GitError

HEADER = (
    "# nightly_scan log — scam_hunter 夜間実行ログ (編集済み)\n"
    "#\n"
    "# 本ファイルは uBlacklist.txt の更新履歴である。生ログ (logs/*.raw.log) と DB (db/*.db) は\n"
    "# .gitignore で除外し、リポジトリには本ファイルのみを含める。\n"
    "# 記載しないもの: トークン・認証情報・ローカル絶対パス・生 HTML・Cookie。\n"
)

LOG_NAME = "nightly_scan.log"
LOG_REL = f"logs/{LOG_NAME}"
JST = timezone(timedelta(hours=9))
DEFAULT_REPO = "picaresq-tuat/ublacklist-scam-stores-jp"
MAX_LOG_BYTES = 2 * 1024 * 1024
_ROTATED_RE = re.compile(r"^" + re.escape(LOG_NAME) + r"\.(\d{6})$")


def _now(tz: tzinfo = JST) -> datetime:
    return datetime.now(tz)


def _safe_int(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def format_log_block(report: dict, *, now: datetime) -> str:
    """1 実行分の編集済みログ行を組み立てる (絶対パス・トークンを含めない)。"""
    mode = "dry-run" if report.get("dry_run") else "publish"
    night = str(report.get("night") or "")
    stamp = now.strftime("%Y-%m-%dT%H:%M%z")
    stamp = stamp[:-2] + ":" + stamp[-2:] if len(stamp) >= 5 else stamp
    lines = [
        "",
        f"[{stamp}] night={night} mode={mode}",
        f"  queries={_safe_int(report.get('rounds'))} "
        f"empty_queries={_safe_int(report.get('empty_queries'))} "
        f"engine_failures={_safe_int(report.get('engine_failures'))}",
        f"  domains_found={_safe_int(report.get('domains_found'))} "
        f"new_domains={_safe_int(report.get('new_domains'))} "
        f"aborted={bool(report.get('aborted'))}",
        f"  blocked={_safe_int(report.get('blocked'))} "
        f"hold={_safe_int(report.get('hold'))} "
        f"dismissed={_safe_int(report.get('dismissed'))} "
        f"whitelisted={_safe_int(report.get('whitelisted'))}",
        f"  uBlacklist.txt: published={len(report.get('published') or [])} "
        f"would_publish={len(report.get('would_publish') or [])} "
        f"expired={len(report.get('expired') or [])} "
        f"cloaking_holds={len(report.get('cloaking_holds') or [])} "
        f"cloaking_added={len(report.get('cloaking_added') or [])}",
        f"  manual_candidates: checked={_safe_int(report.get('candidate_checked'))} "
        f"promoted={len(report.get('candidate_promoted') or [])}",
    ]
    return "\n".join(lines) + "\n"


def _month_of_line(line: str) -> str:
    m = re.match(r"^\[(\d{4})-(\d{2})-\d{2}T", line.strip())
    return f"{m.group(1)}{m.group(2)}" if m else ""


def append_log(path: Path | str, report: dict, *, now: datetime | None = None) -> Path | None:
    """編集済みログを追記する。月が変わっていれば旧月分を .YYYYMM へ退避する。

    戻り値: 退避した旧ログのパス (退避が起きた場合のみ)。
    """
    now = now or _now()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    if not existing:
        existing = HEADER + "\n# 当月分。月替わりで nightly_scan.log.YYYYMM へ退避する。\n"

    current_month = now.strftime("%Y%m")
    rotated: Path | None = None
    keep_lines: list[str] = []
    old_lines: list[str] = []
    for line in existing.splitlines():
        if line.strip() and line.strip()[0] not in "#[":
            keep_lines.append(line)
            continue
        month = _month_of_line(line)
        if month and month != current_month:
            old_lines.append(line)
        else:
            keep_lines.append(line)

    if old_lines:
        rotated = path.with_name(f"{LOG_NAME}.{_month_of_line(old_lines[0])}")
        header = (
            HEADER
            + f"\n## {_month_of_line(old_lines[0])[:4]}-{_month_of_line(old_lines[0])[4:]} (uBlacklist.txt 更新履歴)\n"
        )
        prev = rotated.read_text(encoding="utf-8") if rotated.exists() else header
        rotated.write_text(
            prev.rstrip("\n") + "\n" + "\n".join(old_lines).strip("\n") + "\n", "utf-8"
        )

    body = "\n".join(keep_lines).rstrip("\n") + "\n"
    body += format_log_block(report, now=now)
    path.write_text(body, encoding="utf-8")
    return rotated


def has_changes(report: dict) -> bool:
    """uBlacklist.txt / cloaking リストに実変化があったか。"""
    return bool(
        report.get("published")
        or report.get("expired")
        or report.get("cloaking_holds")
        or report.get("candidate_promoted")
    )


def _default_stage(
    *,
    repo_dir: Path,
    night: str,
    dry_run: bool,
    db_dir: Path,
    max_queries: int | None = None,
) -> dict:
    """本番パイプライン (cli.py と同じ配線) を 1 夜分回す。"""
    from cli import _build_pipeline, _build_searx
    from health import HealthChecker
    from hunter import (
        DEFAULT_ENGINE_BACKOFF_SEC,
        MAX_ENGINE_BACKOFF_SEC,
        MAX_ENGINE_FAILURES,
        run_night,
    )
    from modeldb import ModelDB
    from scamstore import ScamStore

    db_dir.mkdir(parents=True, exist_ok=True)
    store = ScamStore(db_dir / "scam.db")
    searx = _build_searx(engine="google cse", base_url=_searx_url())
    models_db = ModelDB(db_dir / "models.db")
    if models_db.count() == 0:
        models_db.load_csv()
    return run_night(
        night=night,
        searx=searx,
        pipeline=_build_pipeline(db_dir=db_dir),
        store=store,
        db_dir=db_dir,
        ulist_path=repo_dir / "uBlacklist.txt",
        publish=not dry_run,
        dry_run=dry_run,
        max_queries=max_queries if max_queries is not None else 40,
        max_engine_failures=MAX_ENGINE_FAILURES,
        engine_backoff_sec=DEFAULT_ENGINE_BACKOFF_SEC,
        engine_backoff_max_sec=MAX_ENGINE_BACKOFF_SEC,
        health=HealthChecker(),
        models_db=models_db,
        cloaking_list_path=repo_dir / "cloaking_detected" / "uBlacklist.txt",
    )


def _searx_url() -> str:
    env = os.environ.get("SEARXNG_URL", "")
    if env and not env.startswith("http"):
        return f"http://{env}"
    return env or "http://127.0.0.1:8888"


def run(
    *,
    repo_dir: Path | str,
    owner_repo: str,
    night: str,
    stage=None,
    dry_run: bool = False,
    max_queries: int | None = None,
    now: datetime | None = None,
    api=None,
    candidate_probe=None,
) -> dict:
    """1 夜分の実行 → ログ追記 → (変化があれば) push & PR。"""
    now = now or _now()
    repo_dir = Path(repo_dir)
    db_dir = repo_dir / "db"
    stage = stage or _default_stage
    report = stage(
        repo_dir=repo_dir, night=night, dry_run=dry_run, db_dir=db_dir, max_queries=max_queries
    )
    report.setdefault("dry_run", dry_run)

    # P10: 手動収集リストの継続監視。probe はテストで差し替え可能。
    cand = watchlist.monitor(
        repo_dir, probe=candidate_probe or watchlist.probe_domains, dry_run=dry_run
    )
    report["candidate_checked"] = cand.get("candidates", 0)
    report["candidate_promoted"] = list(cand.get("promoted") or [])

    log_path = repo_dir / "logs" / LOG_NAME
    rotated = append_log(log_path, report, now=now)

    result: dict = {
        "night": night,
        "stage": "dry-run" if dry_run else "publish",
        "report": report,
        "changes": False,
        "pr": None,
    }
    if dry_run or not has_changes(report):
        return result

    branch = gitops.branch_name(night)
    gitops.ensure_branch(repo_dir, branch)
    paths = ["uBlacklist.txt", "cloaking_detected/uBlacklist.txt", LOG_REL]
    if rotated is not None:
        paths.append(f"logs/{rotated.name}")
    existing_paths = [p for p in paths if (repo_dir / p).exists()]
    gitops.git(repo_dir, "add", "--", *existing_paths)
    if gitops.has_changes(repo_dir):
        gitops.git(
            repo_dir,
            "-c",
            "user.name=scam-hunter",
            "-c",
            "user.email=scam-hunter@localhost",
            "commit",
            "-m",
            f"nightly {night}: +{len(report.get('published') or [])} domains",
        )
    else:
        return result

    gitops.push(repo_dir, branch)
    result["changes"] = True
    owner, _, name = owner_repo.partition("/")
    if not (owner and name):
        raise GitError("--repo must be owner/name")
    from gitops import pr_body
    from publish import PERMANENT_RULES

    body = pr_body(
        night,
        report.get("rows", []),
        permanent_rules=PERMANENT_RULES,
        added=len(report.get("published") or []),
        removed=len(report.get("expired") or []),
        dry_run=False,
    )
    result["pr"] = gitops.open_pr(
        token=gitops.token_from_env(),
        owner=owner,
        repo_name=name,
        head=branch,
        title=f"nightly: {night}",
        body=body,
        api=api,
    )
    return result


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nightly", description="scam_hunter nightly runner")
    p.add_argument("--repo-dir", default=str(Path(__file__).resolve().parent.parent))
    p.add_argument("--repo", default=DEFAULT_REPO, help="owner/name (PR 先)")
    p.add_argument("--night", default="")
    p.add_argument("--dry-run", action="store_true", help="出版も push もせず、ログのみ")
    p.add_argument("--max-queries", type=int, default=None, help="1 夜の検索クエリ上限")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    night = args.night or _now().strftime("%Y-%m-%d")
    try:
        res = run(
            repo_dir=Path(args.repo_dir),
            owner_repo=args.repo,
            night=night,
            dry_run=bool(args.dry_run),
            max_queries=args.max_queries,
        )
    except GitError as exc:
        print(f"nightly failed: {exc}", file=sys.stderr)
        return 1
    rep = res["report"]
    added_cloak = len(rep.get("cloaking_added") or [])
    if res["pr"]:
        print(
            f"night={night} changes=yes published={len(rep.get('published') or [])} "
            f"expired={len(rep.get('expired') or [])} "
            f"cloaking_added={added_cloak} "
            f"PR #{res['pr']['number']}: {res['pr']['url']}"
        )
    else:
        print(
            f"night={night} changes=no published=0 expired=0 cloaking_added={added_cloak} "
            f"(uBlacklist.txt に変化なし。push / PR は行いません)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
