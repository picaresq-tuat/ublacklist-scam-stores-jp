"""P10: cloaking リストの再判定と手動収集リストの取り込み (実 I/O 側)。

  python3 scripts/rejudge_lists.py --dry-run                 # 判定だけ (JSON 出力)
  python3 scripts/rejudge_lists.py --apply                   # リストへ反映
  python3 scripts/rejudge_lists.py --only manual --dry-run

`cloaking_detected/uBlacklist.txt` の全ドメインと、手動収集リスト
(`scam_list_manually_added.txt`) を同じパイプラインで再判定する。

  * decision=block かつ現役 (2xx) → `uBlacklist.txt` へ昇格、cloaking リストから除く
  * decision=hold → cloaking リストに残す (scam 断定に届かない)
  * 応答なし / dismissed → 除外しない (一時障害で正当な検知を消さない)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "script"))

import publish
from probe import Pipeline
from rejudge import Outcome, select_cloaking_removals, select_promotions, summarise
from whitelist import WhitelistDB

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CLOAKING = ROOT / "cloaking_detected" / "uBlacklist.txt"
DEFAULT_ULIST = ROOT / "uBlacklist.txt"
DEFAULT_MANUAL = ROOT / "db" / "manual_candidates.txt"

_ENTRY = re.compile(r"^\*://\*\.([^/]+)/\*$")


def domains_in(text: str) -> list[str]:
    """uBlacklist / 手動リストの `*://*.example.com/*` 行からドメインを抽出。"""
    out: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        m = _ENTRY.match(line.strip())
        if not m:
            continue
        d = m.group(1).strip().lower()
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def probe_all(domains: list[str], workers: int) -> list[Outcome]:
    pipe = Pipeline(rdap_fn=None)
    from whois_rdap import fetch_rdap

    pipe.rdap_fn = fetch_rdap

    def one(dom: str) -> Outcome:
        r = pipe.run_domain(dom)
        f = r.features or {}
        status = f.get("status")
        return Outcome(
            domain=dom,
            decision=r.decision,
            score=float(r.score or 0.0),
            status=status if isinstance(status, int) else None,
            cloaking=bool(f.get("cloaking")),
            reasons=dict(r.reasons or {}),
        )

    if workers <= 1:
        return [one(d) for d in domains]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(one, domains))


def _write_lists(scam_path: Path, cloak_path: Path, promote: list[str], remove: list[str]) -> None:
    scam_text = scam_path.read_text(encoding="utf-8")
    new_scam = publish.merge_list(scam_text, promote)
    problems = publish.validate(new_scam)
    if problems:
        raise SystemExit(f"scam list validation failed: {problems}")

    cloak_text = cloak_path.read_text(encoding="utf-8")
    drop = {f"*://*.{d}/*" for d in remove}
    keep = [ln for ln in cloak_text.splitlines() if ln.strip() not in drop]
    new_cloak = "\n".join(keep).rstrip("\n") + "\n"
    problems = publish.validate(new_cloak)
    if problems:
        raise SystemExit(f"cloaking list validation failed: {problems}")

    scam_path.write_text(new_scam, encoding="utf-8")
    cloak_path.write_text(new_cloak, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="rejudge_lists")
    ap.add_argument("--cloaking-list", default=str(DEFAULT_CLOAKING))
    ap.add_argument("--ulist", default=str(DEFAULT_ULIST))
    ap.add_argument("--manual", default=str(DEFAULT_MANUAL))
    ap.add_argument("--only", choices=("all", "cloaking", "manual"), default="all")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--json", default=str(ROOT / "logs" / "rejudge_lists.json"))
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument(
        "--from-json",
        default="",
        help="既存の監査 JSON から判定を読み、再走査せずリストへ反映する",
    )
    args = ap.parse_args(argv)

    cloak_path = Path(args.cloaking_list)
    scam_path = Path(args.ulist)
    manual_path = Path(args.manual)

    if args.from_json:
        report = json.loads(Path(args.from_json).read_text(encoding="utf-8"))
        known = set(domains_in(scam_path.read_text(encoding="utf-8")))
        promote = [d for d in report["promote"] if d not in known]
        remove = list(report["cloaking_removals"])
        print(f"from-json: promote={len(promote)} remove={len(remove)}")
        if args.apply and not args.dry_run:
            _write_lists(scam_path, cloak_path, promote, remove)
            print("applied")
        return 0

    cloak_domains = (
        domains_in(cloak_path.read_text(encoding="utf-8"))
        if args.only in ("all", "cloaking")
        else []
    )
    manual_domains = (
        domains_in(manual_path.read_text(encoding="utf-8"))
        if args.only in ("all", "manual")
        else []
    )

    known_scam = domains_in(scam_path.read_text(encoding="utf-8"))
    # whitelist.db があれば除外 (手動リストに正規店が混ざるため)
    try:
        with WhitelistDB(ROOT / "db" / "whitelist.db") as wdb:
            allow = set(wdb.all())
    except Exception:  # DB 未初期化でも判定は続ける
        allow = set()
    if allow:
        cloak_domains = [d for d in cloak_domains if d not in allow]
        manual_domains = [d for d in manual_domains if d not in allow]

    targets = cloak_domains + [d for d in manual_domains if d not in cloak_domains]
    print(
        f"targets: cloaking={len(cloak_domains)} manual={len(manual_domains)} probing={len(targets)}"
    )
    outcomes = probe_all(targets, args.workers)

    promote = select_promotions(outcomes, known_scam)
    remove = select_cloaking_removals([o for o in outcomes if o.domain in set(cloak_domains)])
    report = {
        "generated_at": __import__("datetime")
        .datetime.now(__import__("datetime").timezone.utc)
        .isoformat(timespec="seconds"),
        "summary": {
            "cloaking": summarise([o for o in outcomes if o.domain in set(cloak_domains)]),
            "manual": summarise([o for o in outcomes if o.domain in set(manual_domains)]),
        },
        "promote": promote,
        "cloaking_removals": remove,
        "outcomes": [
            {
                "domain": o.domain,
                "decision": o.decision,
                "score": o.score,
                "status": o.status,
                "cloaking": o.cloaking,
                "reasons": o.reasons,
            }
            for o in sorted(outcomes, key=lambda x: (-x.score, x.domain))
        ],
    }
    out = Path(args.json)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")

    print(json.dumps(report["summary"], ensure_ascii=False))
    print(f"promote={len(promote)} remove_from_cloaking={len(remove)} -> {out}")
    for d in promote:
        print(f"  + {d}")

    if args.apply and not args.dry_run:
        _write_lists(scam_path, cloak_path, promote, remove)
        print("applied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
