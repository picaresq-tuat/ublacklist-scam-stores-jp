"""夜間 CLI (P7e)。

  python3 script/cli.py --night 2026-09-24 --dry-run --report logs/report.json
  python3 script/cli.py --publish --ulist uBlacklist.txt --pr   # PR 送信 (手動承認前提)

トークンは環境変数 GITHUB_TOKEN からのみ読む。引数では受け取らない。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from gitops import (
    GitError,
    branch_name,
    ensure_branch,
    open_pr,
    pr_body,
    push,
    token_from_env,
    write_and_commit,
)
from gitops import (
    run as git_run,
)
from health import HealthChecker
from hunter import (
    DEFAULT_ENGINE_BACKOFF_SEC,
    MAX_ENGINE_BACKOFF_SEC,
    MAX_ENGINE_FAILURES,
    run_night,
)
from probe import Pipeline
from publish import PERMANENT_RULES
from scamstore import ScamStore
from searxng import DEFAULT_NIGHT_SLEEP_SEC, SearxClient


def _build_searx(*, engine: str, base_url: str, sleep_sec: float | None = None) -> SearxClient:
    """engine に応じてクライアントを作る。

    方針転換 (2026-09-24): 既定は Google CSE 主体 (ページング可能)。
    Bing はページング非対応のため補完としてのみ使う。
    sleep_sec はクエリ間隔。実測 429 対策として CLI から設定できる。
    """
    if engine not in ("google cse", "google cse,bing", "bing", "auto"):
        raise ValueError(f"unknown engine: {engine}")
    kw = {}
    if sleep_sec is not None:
        kw["sleep_sec"] = sleep_sec
    return SearxClient(base_url=base_url, **kw)


def _build_pipeline(*, db_dir: Path, config=None) -> Pipeline:
    return Pipeline(db_dir=db_dir, config=config)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="scam_hunter", description="nightly scam hunter")
    p.add_argument("--night", default="")
    p.add_argument("--db-dir", default=str(Path(__file__).resolve().parent.parent / "db"))
    p.add_argument("--scam-db", default="")
    p.add_argument("--ulist", default="")
    p.add_argument("--cloaking-list", default="")
    p.add_argument("--models-db", default="")
    p.add_argument("--report", default="")
    p.add_argument(
        "--engine", default="google cse", choices=["google cse", "google cse,bing", "bing", "auto"]
    )
    p.add_argument("--searx-url", default="http://localhost:8888")
    p.add_argument(
        "--sleep-sec",
        type=float,
        default=DEFAULT_NIGHT_SLEEP_SEC,
        help="クエリ間隔(秒)。実測 429 対策 (既定 30 秒)",
    )
    p.add_argument("--max-queries", type=int, default=40)
    p.add_argument(
        "--max-engine-failures",
        type=int,
        default=MAX_ENGINE_FAILURES,
        help="エンジン suspension (429) がこの回数に達したらその夜は中止",
    )
    p.add_argument(
        "--engine-backoff-sec",
        type=float,
        default=DEFAULT_ENGINE_BACKOFF_SEC,
        help="429 後の初回待機秒 (以降は指数的に増加)",
    )
    p.add_argument(
        "--engine-backoff-max-sec",
        type=float,
        default=MAX_ENGINE_BACKOFF_SEC,
        help="バックオフの上限秒",
    )
    p.add_argument("--publish", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--pr", action="store_true")
    p.add_argument("--repo", default="")
    p.add_argument(
        "--allow-private",
        action="store_true",
        help="テスト用: SSRF ガードを緩める (本番では使わない)",
    )
    return p


def _validate(args) -> None:
    if args.engine not in ("google cse", "google cse,bing", "bing", "auto"):
        sys.exit(f"unknown engine: {args.engine}")
    if args.publish and not args.ulist:
        sys.exit("--publish requires --ulist")
    if args.sleep_sec < 0:
        sys.exit("--sleep-sec must be >= 0")
    if args.pr:
        if not args.repo:
            sys.exit("--pr requires --repo owner/name")
        if not os.environ.get("GITHUB_TOKEN"):
            sys.exit("--pr requires GITHUB_TOKEN in the environment")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _validate(args)

    db_dir = Path(args.db_dir)
    db_dir.mkdir(parents=True, exist_ok=True)
    store = ScamStore(args.scam_db or (db_dir / "scam.db"))
    searx = _build_searx(engine=args.engine, base_url=args.searx_url, sleep_sec=args.sleep_sec)
    pipe = _build_pipeline(db_dir=db_dir)
    health = HealthChecker()

    report = run_night(
        night=args.night or None,
        searx=searx,
        pipeline=pipe,
        store=store,
        db_dir=db_dir,
        ulist_path=args.ulist or None,
        publish=bool(args.publish),
        dry_run=bool(args.dry_run),
        max_queries=args.max_queries,
        max_engine_failures=args.max_engine_failures,
        engine_backoff_sec=args.engine_backoff_sec,
        engine_backoff_max_sec=args.engine_backoff_max_sec,
        health=health,
        models_db=args.models_db or None,
        cloaking_list_path=args.cloaking_list or None,
    )
    stats = getattr(searx, "stats", None)
    report["searx_stats"] = dict(vars(stats)) if stats is not None else {}

    if args.report:
        Path(args.report).write_text(
            json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8"
        )

    if args.pr:
        ufile = Path(args.ulist)
        repo_dir = ufile.parent
        text = ufile.read_text(encoding="utf-8") if ufile.exists() else ""
        try:
            token = token_from_env()
            owner, _, name = args.repo.partition("/")
            if not (owner and name):
                sys.exit("--repo must be owner/name")
            branch = branch_name(report["night"])
            message = f"nightly {report['night']}: +{len(report['published'])} domains"
            ensure_branch(repo_dir, branch)
            git_run(["git", "add", "--", ufile.name], cwd=repo_dir)
            committed = write_and_commit(repo_dir, ufile.name, text, message=message, branch=branch)
            cloaking_committed = False
            if args.cloaking_list:
                cfile = Path(args.cloaking_list)
                ctext = cfile.read_text(encoding="utf-8") if cfile.exists() else ""
                cloaking_committed = write_and_commit(
                    repo_dir,
                    str(cfile.relative_to(repo_dir))
                    if cfile.is_relative_to(repo_dir)
                    else cfile.name,
                    ctext,
                    message=f"nightly {report['night']}: scam_hunter cloaking list "
                    f"(+{len(report.get('cloaking_holds', []))} holds)",
                    branch=branch,
                )
            if not (committed or cloaking_committed):
                print("no list changes; nothing to push", file=sys.stderr)
            else:
                push(repo_dir, branch)
            body = pr_body(
                report["night"],
                report.get("rows", []),
                permanent_rules=PERMANENT_RULES,
                added=len(report["published"]),
                removed=len(report["expired"]),
                dry_run=bool(args.dry_run),
            )
            if args.cloaking_list and report.get("cloaking_holds"):
                from cloaking_publish import cloaking_pr_body

                body += "\n\n" + cloaking_pr_body(
                    report["night"],
                    [
                        {"domain": d, "score": r.get("score", 0), "reasons": r.get("reasons", {})}
                        for d, r in zip(
                            report["cloaking_holds"], report.get("rows", []), strict=False
                        )
                    ],
                )
            res = open_pr(
                token=token,
                owner=owner,
                repo_name=name,
                head=branch,
                title=f"nightly: {report['night']}",
                body=body,
            )
            report["pr"] = res
            if args.report:
                Path(args.report).write_text(
                    json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n",
                    encoding="utf-8",
                )
        except (GitError, ValueError) as exc:
            sys.exit(f"PR failed: {exc}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
