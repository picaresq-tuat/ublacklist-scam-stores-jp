"""Spike S3: ZenCart 構造指紋の正規店 FP 計測.

sagidame.com の直近検知ドメイン (scam コーパス) と正規通販 (legit コーパス) を
実ネットワークで取得し、ZENCART_MARKERS のヒット数を計測する。
結果は logs/spike_s3_zencart.json に保存。

実行: python3 scripts/spike_s3_zencart_fp.py [--n-pages 4] [--legit-only]
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "script"))

from fetch import BlockedURL, FetchError, fetch

ROOT = Path(__file__).resolve().parent.parent
LEGIT = [
    "dynabook.com",
    "www.askul.co.jp",
    "www.suruga-ya.jp",
    "used.sofmap.com",
    "biccamera.com",
    "pc-master.jp",
    "hyperlab.jp",
    "www.janpara.co.jp",
    "dospara.co.jp",
    "www.iosys.co.jp",
    "www.pc-koubou.jp",
    "www2.elecom.co.jp",
    "shop.kakaku.com",
    "store.shopping.yahoo.co.jp",
    "www.sansindo.co.jp",
    "www.pcexpress.co.jp",
    "socalshop.com",
    "www.buy-it.jp",
    "www.zencart-jp.com",
    "store.navyweb.jp",
]


def collect_scam_domains(n_pages: int) -> list[str]:
    doms: list[str] = []
    for page in range(1, n_pages + 1):
        try:
            r = fetch(f"https://sagidame.com/?page={page}", ua="browser", timeout=20)
        except (FetchError, BlockedURL) as exc:
            print(f"page {page}: {exc}", file=sys.stderr)
            continue
        for m in re.findall(r"/result/([A-Za-z0-9.-]+\.[a-z]{2,})", r.body or ""):
            d = m.lower()
            if d not in doms:
                doms.append(d)
        time.sleep(1.0)  # sagidame レート制限: 1 リクエスト/秒以下
    return doms


def measure(domain: str) -> dict:
    from features import ZENCART_MARKERS, extract_features
    from fetch import FetchResult

    rec: dict = {"domain": domain, "zencart_hits": None, "hits": [], "error": ""}
    try:
        browser = fetch(f"https://{domain}/", ua="browser", timeout=15.0)
        bot = FetchResult(
            url=f"https://{domain}/", status=0, final_url=f"https://{domain}/", error="skip"
        )
        f = extract_features(domain, browser, bot)
        low = (browser.html_sanitized or browser.body or "").lower()
        rec["zencart_hits"] = f.zencart_hits
        rec["hits"] = [m for m in ZENCART_MARKERS if m.lower() in low]
        rec["status"] = browser.status
    except (FetchError, BlockedURL) as exc:
        rec["error"] = f"{type(exc).__name__}: {exc}"
    return rec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-pages", type=int, default=4)
    ap.add_argument("--out", default=str(ROOT / "logs" / "spike_s3_zencart.json"))
    ap.add_argument("--legit-only", action="store_true")
    args = ap.parse_args()

    out: dict = {"scam": [], "legit": []}
    if not args.legit_only:
        doms = collect_scam_domains(args.n_pages)
        print(f"sagidame domains collected: {len(doms)}")
        with cf.ThreadPoolExecutor(max_workers=8) as ex:
            for rec in ex.map(measure, doms):
                out["scam"].append(rec)
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        for rec in ex.map(measure, LEGIT):
            out["legit"].append(rec)

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    for label in ("scam", "legit"):
        ok = [r for r in out[label] if r["zencart_hits"] is not None]
        err = [r for r in out[label] if r["zencart_hits"] is None]
        dist: dict[int, int] = {}
        for r in ok:
            dist[r["zencart_hits"]] = dist.get(r["zencart_hits"], 0) + 1
        print(f"{label}: measured={len(ok)} error={len(err)} hit-dist={dict(sorted(dist.items()))}")
        flagged = [
            (r["domain"], r["zencart_hits"], r["hits"]) for r in ok if r["zencart_hits"] >= 2
        ]
        print(f"{label} >=2 hits: {flagged}")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
