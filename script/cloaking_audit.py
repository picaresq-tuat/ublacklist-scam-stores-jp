"""P9c: 既存 cloaking リストの偽陽性 (非 200) 検知と剪定。

cloaking 判定 (`features.py`) は「通常ブラウザ取得が 200 で、bot 取得と差がある」ことを
証拠にする。ところが 2026-10-12 より前は status を見ていなかったため、通常取得が
400/403/404 等のエラーページを返すドメインまで cloaking リストに載ってしまった (偽陽性)。

本モジュールは配布中の cloaking リストを 1 件ずつ再取得し、非 200 を返した行を検出して
取り除く。判定基準は feature 側と揃える:

  * `status == 200` → ok (添付・非 HTML で `discarded` でも証拠として残す)
  * `status != 200` (HTTP 応答あり) → 偽陽性 = 除外候補
  * 応答なし (DNS 失敗 / 接続失敗 / タイムアウト) → unreachable
    **既定では除外しない**。一時障害で正当な検知を消さないため `--include-unreachable`
    を明示したときだけ除外する (恒久的な失効は P8 の 7 日連続監視で扱う)。

`prune()` は行の削除のみを行い、ヘッダ・常設正規表現・セクション見出しには触らない。
結果は `publish.validate()` を通してから書く (壊れたリストを書かない)。

  python3 script/cloaking_audit.py --dry-run            # 検出だけ
  python3 script/cloaking_audit.py --json logs/cloak_audit.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import gitops
from fetch import BlockedURL, FetchError, fetch
from gitops import GitError
from publish import domains_to_remove, existing_entries, validate

JST = timezone(timedelta(hours=9))
NIGHTLY_PREFIX = "nightly/"
_NIGHT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

DEFAULT_TIMEOUT = 10.0
DEFAULT_DELAY_SEC = 2.0
DEFAULT_LIST_REL = "cloaking_detected/uBlacklist.txt"
SCHEMES: tuple[str, ...] = ("https", "http")
VERDICTS: tuple[str, ...] = ("ok", "non200", "unreachable")

_ENTRY_RE = re.compile(r"^\*://\*\.(.+?)/\*$")
_FETCH_ERRORS = (BlockedURL, FetchError, OSError, ValueError)


@dataclass(frozen=True)
class Probe:
    """1 ドメインの再取得結果。"""

    domain: str
    status: int | None = None
    scheme: str = ""
    error: str = ""
    discarded: bool = False

    @property
    def verdict(self) -> str:
        if self.status is None:
            return "unreachable"
        return "ok" if self.status == 200 else "non200"


def probe_domain(
    domain: str,
    *,
    fetch_fn: Callable[..., object] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Probe:
    """1 ドメインを再取得して判定する (https → http の順に試す)。"""
    fetch_fn = fetch_fn or fetch
    dom = (domain or "").strip().lower().rstrip(".")
    if not dom:
        return Probe(domain=domain or "", error="empty domain")
    last = ""
    for scheme in SCHEMES:
        try:
            res = fetch_fn(f"{scheme}://{dom}/", ua="browser", timeout=timeout)
        except _FETCH_ERRORS as exc:  # 応答が得られない = 到達不能の可能性
            last = type(exc).__name__
            continue
        return Probe(
            domain=dom,
            status=int(getattr(res, "status", 0) or 0),
            scheme=scheme,
            discarded=bool(getattr(res, "discarded", False)),
            error=str(getattr(res, "error", "") or ""),
        )
    return Probe(domain=dom, error=last or "FetchError")


def domains_from_list(text: str) -> list[str]:
    """リスト本文の個別ドメイン行 (`*://*.d/*`) からドメインを取り出す。"""
    out: list[str] = []
    for entry in existing_entries(text or ""):
        m = _ENTRY_RE.match(entry)
        if m:
            out.append(m.group(1))
    return out


def audit(
    domains: Iterable[str],
    *,
    fetch_fn: Callable[..., object] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    delay_sec: float = DEFAULT_DELAY_SEC,
    sleep: Callable[[float], None] = time.sleep,
    progress: Callable[[Probe], None] | None = None,
) -> list[Probe]:
    """ドメイン群を順に再取得する (1 件ごとに待機して負荷をかけない)。"""
    probes: list[Probe] = []
    for i, domain in enumerate(domains):
        if i and delay_sec > 0:
            sleep(delay_sec)
        probe = probe_domain(domain, fetch_fn=fetch_fn, timeout=timeout)
        probes.append(probe)
        if progress is not None:
            progress(probe)
    return probes


def false_positives(probes: Sequence[Probe], *, include_unreachable: bool = False) -> list[str]:
    """除外すべきドメイン (既定では非 200 のみ。到達不能は明示時のみ)。"""
    wanted = {"non200"} | ({"unreachable"} if include_unreachable else set())
    out: list[str] = []
    for probe in probes:
        if probe.verdict in wanted and probe.domain not in out:
            out.append(probe.domain)
    return out


def build_report(probes: Sequence[Probe]) -> dict:
    counts = dict.fromkeys(VERDICTS, 0)
    for probe in probes:
        counts[probe.verdict] += 1
    return {
        "total": len(probes),
        "counts": counts,
        "non200": [
            {"domain": p.domain, "status": p.status, "scheme": p.scheme}
            for p in probes
            if p.verdict == "non200"
        ],
        "unreachable": [
            {"domain": p.domain, "error": p.error or "FetchError"}
            for p in probes
            if p.verdict == "unreachable"
        ],
        "ok": [p.domain for p in probes if p.verdict == "ok"],
    }


def prune(text: str, domains: Iterable[str]) -> str:
    """偽陽性ドメインの行だけを取り除く。ヘッダ・常設ルール・見出しは保持する。"""
    return domains_to_remove(text, domains)


def pr_body(night: str, report: dict, removed: Sequence[str], *, dry_run: bool = False) -> str:
    """PR 本文。レビュー担当者が表だけで可否を判断できる形にする。"""
    counts = report.get("counts") or {}
    non200 = {d["domain"]: d for d in (report.get("non200") or [])}
    unreachable = [d["domain"] for d in (report.get("unreachable") or [])]
    lines = [f"## cloaking リスト監査 {night}", ""]
    if dry_run:
        lines += ["> **dry-run**: 実マージ前のレビュー用差分です。", ""]
    lines += [
        f"- 対象: {report.get('total', 0)} ドメイン / "
        f"非200: {counts.get('non200', 0)} 件 / 到達不能: {counts.get('unreachable', 0)} 件",
        "- 判定: 通常ブラウザ取得の HTTP ステータス (`status == 200` 以外は cloaking の証拠にならない)",
        "",
    ]
    if not removed:
        lines += ["除外なし (非200 は検出されませんでした)。", ""]
    else:
        lines += [f"### 除外 ({len(removed)} 件)", "", "| domain | status |", "| --- | ---: |"]
        for domain in removed:
            status = non200.get(domain, {}).get("status", "")
            lines.append(f"| `{domain}` | {status} |")
        lines.append("")
    lines += [
        "### 到達不能 (残置)",
        "",
        "応答が得られなかったドメインは一時障害の可能性があるため、この PR では除外しません。",
        "(恒久的な失効は P8 の 7 日連続監視で扱う)",
        "",
    ]
    lines += [f"- `{d}`" for d in unreachable] or ["- なし"]
    lines += [
        "",
        "ヘッダ・常設正規表現・セクション見出しは変更していません (`publish.validate()` 通過済み)。",
        "",
        "生成: `script/cloaking_audit.py` (自動)。人手承認後に `git merge --no-ff` で取り込みます。",
    ]
    return "\n".join(lines) + "\n"


def push_pr(
    *,
    repo_dir: Path | str,
    owner_repo: str,
    night: str,
    body: str,
    rel_path: str,
    message: str,
    branch: str = "",
    title: str = "",
    api: Callable[..., tuple[int, dict]] | None = None,
) -> dict:
    """剪定済みリストを feature branch (`nightly/YYYY-MM-DD`) に commit & push し PR を作る。

    `main` への push は行わない (人手承認後に `git merge --no-ff`)。
    トークンは `GITHUB_TOKEN` 環境変数からのみ読む。
    """
    if not _NIGHT_RE.match((night or "").strip()):
        raise ValueError(f"night must be YYYY-MM-DD, got {night!r}")
    owner, _, name = (owner_repo or "").partition("/")
    if not (owner and name):
        raise ValueError("--repo must be owner/name")
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise GitError("GITHUB_TOKEN is not set")

    branch = branch or gitops.branch_name(night)
    if not branch.startswith(NIGHTLY_PREFIX):
        raise ValueError(f"refusing to push non-nightly branch: {branch!r}")
    gitops.ensure_branch(repo_dir, branch)
    gitops.git(repo_dir, "add", "--", rel_path)
    gitops.git(
        repo_dir,
        "-c",
        "user.name=scam-hunter",
        "-c",
        "user.email=scam-hunter@localhost",
        "commit",
        "-m",
        message,
    )
    gitops.push(repo_dir, branch)
    return gitops.open_pr(
        token=token,
        owner=owner,
        repo_name=name,
        head=branch,
        title=title or f"cloaking 監査 {night}",
        body=body,
        base="main",
        api=api,
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cloaking_audit", description="cloaking リストの非 200 偽陽性を剪定する"
    )
    p.add_argument("--repo-dir", default=str(Path(__file__).resolve().parent.parent))
    p.add_argument("--list", default="", help=f"対象リスト (既定 {DEFAULT_LIST_REL})")
    p.add_argument("--dry-run", action="store_true", help="検出のみ。ファイルを書かない")
    p.add_argument(
        "--include-unreachable",
        action="store_true",
        help="応答が得られないドメインも除外する (既定は残す)",
    )
    p.add_argument("--delay-sec", type=float, default=DEFAULT_DELAY_SEC)
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--json", default="", help="監査レポート (JSON) の出力先")
    p.add_argument("--night", default="", help="feature branch 名に使う日付 (既定: JST の今日)")
    p.add_argument(
        "--branch",
        default="",
        help=f"push 先ブランチ (既定 nightly/<night>)。{NIGHTLY_PREFIX} 接頭辞のみ許可",
    )
    p.add_argument("--repo", default="picaresq-tuat/ublacklist-scam-stores-jp", help="owner/name")
    p.add_argument(
        "--pr", action="store_true", help="剪定結果を feature branch に push し PR を作る"
    )
    return p


def main(argv: list[str] | None = None, *, fetch_fn: Callable[..., object] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo_dir = Path(args.repo_dir)
    path = Path(args.list) if args.list else repo_dir / DEFAULT_LIST_REL
    if not path.exists():
        print(f"{path} not found", file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8")
    domains = domains_from_list(text)
    night = args.night or datetime.now(JST).strftime("%Y-%m-%d")
    branch = args.branch or f"{NIGHTLY_PREFIX}{night}"
    if args.pr and not args.dry_run and not branch.startswith(NIGHTLY_PREFIX):
        print(f"refusing to push non-nightly branch: {branch!r}", file=sys.stderr)
        return 1

    def show(probe: Probe) -> None:
        where = f"{probe.status}" if probe.status is not None else (probe.error or "no response")
        print(f"  {probe.verdict:<11} {probe.domain} ({where})", flush=True)

    probes = audit(
        domains,
        fetch_fn=fetch_fn,
        timeout=args.timeout,
        delay_sec=args.delay_sec,
        progress=show,
    )
    report = build_report(probes)
    counts = report["counts"]
    drop = false_positives(probes, include_unreachable=args.include_unreachable)
    report["removed"] = len(drop)
    report["removed_domains"] = drop
    report["dry_run"] = bool(args.dry_run)
    report["include_unreachable"] = bool(args.include_unreachable)
    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(
        f"audit: total={report['total']} ok={counts['ok']} "
        f"non200={counts['non200']} unreachable={counts['unreachable']}"
    )
    if not drop:
        print("偽陽性 (非200) は検出されませんでした。リストは変更しません。")
        return 0

    new_text = prune(text, drop)
    problems = validate(new_text)
    if problems:
        print(f"refusing to write invalid list: {problems}", file=sys.stderr)
        return 1
    if args.dry_run:
        print(f"dry-run: 除外予定 {len(drop)} 件: {', '.join(drop)}")
        print("ファイルは変更しません。")
        return 0
    path.write_text(new_text, encoding="utf-8")
    print(f"removed={len(drop)} 件を {path.name} から除外しました。")
    if not args.pr:
        return 0

    rel_path = str(path.relative_to(repo_dir)) if path.is_relative_to(repo_dir) else str(path)
    try:
        pr = push_pr(
            repo_dir=repo_dir,
            owner_repo=args.repo,
            night=night,
            branch=branch,
            body=pr_body(night, report, drop),
            rel_path=rel_path,
            message=f"cloaking 監査 {night}: -{len(drop)} 件 (非200 偽陽性の除外)",
            title=f"cloaking 監査 {night}: -{len(drop)} 件",
        )
    except (GitError, ValueError) as exc:
        print(f"PR 作成に失敗しました: {exc}", file=sys.stderr)
        return 1
    if pr.get("url"):
        print(f"PR #{pr['number']}: {pr['url']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
