"""Spike S4: stolen_image / dark_pattern / affiliate の正規店 FP と scam 検知率を実測.

sagidame.com の直近検知ドメイン (scam コーパス) と正規 EC (legit コーパス) を
実ネットワークで取得し、以下を計測する。
- stolen_image: 旧 substring 照合 vs 新境界一致の発火率とヒット数分布
- dark_pattern: 用語ごとの scam/legit ヒット数 (非生産的マーカーの棚卸し)
- affiliate: リンク先が affiliate 広告ネットワークのドメイン数 (正規店 FP 実測)
結果は logs/spike_s4_signals.json に保存。

実行: python3 scripts/spike_s4_signals.py [--n-pages 5] [--legit-only]
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "script"))

from fetch import BlockedURL, FetchError, fetch

ROOT = Path(__file__).resolve().parent.parent

LEGIT = [
    # 正規 EC / 通販
    "dynabook.com",
    "www.askul.co.jp",
    "www.suruga-ya.jp",
    "used.sofmap.com",
    "pc-master.jp",
    "hyperlab.jp",
    "www.janpara.co.jp",
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
    "cms-server.ne.jp",
    "shop.obitastar.co.jp",
    "www.bigmouse.co.jp",
    "www.amazon.co.jp",
    "www.rakuten.co.jp",
    "kakaku.com",
    "netshop.impress.co.jp",
    "www.iherb.co.jp",
    "shop.tsukumo.co.jp",
    "www.faith-go.co.jp",
    "www.creema.jp",
    "www.nitori-net.co.jp",
    "ec.toranoana.jp",
    "www.toranoana.jp",
    "shop.muji.com",
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


def _old_substring_stolen(src: str, own_reg: str) -> bool:
    """旧実装 (substring 照合) の再現。"""
    from features import STORE_ASSET_HOSTS, registrable_domain

    if not src or any(c in src for c in ("\n", " ", "\t")):
        return False
    host = urlsplit(src).netloc.lower().split(":")[0]
    if not host:
        return False
    if not any(h in host for h in STORE_ASSET_HOSTS):
        return False
    return registrable_domain(host) != (own_reg or "")


def measure(domain: str) -> dict:
    from features import DARK_PATTERN_TERMS, STORE_ASSET_HOSTS, extract_features
    from fetch import FetchResult

    rec: dict = {"domain": domain, "error": ""}
    try:
        browser = fetch(f"https://{domain}/", ua="browser", timeout=15.0)
        bot = FetchResult(
            url=f"https://{domain}/", status=0, final_url=f"https://{domain}/", error="skip"
        )
        f = extract_features(domain, browser, bot)
        text = browser.html_sanitized or browser.body or ""
        low = text.lower()
        reg = f.registrable
        img_srcs = re.findall(r"<img[^>]+src=[\"']([^\"']+)", text, re.I)
        rec["status"] = browser.status
        rec["n_img"] = f.n_img
        rec["stolen_image_new"] = f.stolen_image
        rec["stolen_image_hits_new"] = f.stolen_image_hits
        rec["stolen_image_old"] = any(_old_substring_stolen(s, reg) for s in img_srcs)
        rec["stolen_image_old_hits"] = sum(1 for s in img_srcs if _old_substring_stolen(s, reg))
        rec["stolen_hosts"] = sorted(
            {
                urlsplit(s).netloc
                for s in img_srcs
                if f.stolen_image and _old_substring_stolen(s, reg)
            }
        )[:8]
        rec["dark_hits"] = {t: text.count(t) for t in DARK_PATTERN_TERMS if t in text}
        rec["affiliate_hits"] = f.affiliate_hits
        rec["affiliate_hosts"] = sorted(
            {
                urlsplit(h).netloc
                for h in re.findall(r"<a[^>]+href=[\"']([^\"']+)", text, re.I)
                if any(
                    m in urlsplit(h).netloc
                    for m in (
                        "a8.net",
                        "afl.rakuten",
                        "linksynergy",
                        "valuecommerce",
                        "amazon-adsystem",
                        "rentracks",
                        "trafficgate",
                        "adsistant",
                        "affiliate",
                    )
                )
            }
        )[:8]
        rec["asset_hosts_seen"] = sorted({h for h in STORE_ASSET_HOSTS if h in low})[:8]
    except (FetchError, BlockedURL) as exc:
        rec["error"] = f"{type(exc).__name__}: {exc}"
    return rec


def summarize(label: str, rows: list[dict]) -> None:
    ok = [r for r in rows if not r["error"]]
    err = [r for r in rows if r["error"]]
    print(f"== {label}: measured={len(ok)} error={len(err)}")
    old = sum(1 for r in ok if r["stolen_image_old"])
    new = sum(1 for r in ok if r["stolen_image_new"])
    print(
        f"  stolen_image: old-substring {old}/{len(ok)} ({old / len(ok):.0%}), new-boundary {new}/{len(ok)} ({new / len(ok):.0%})"
    )
    hits = [r["stolen_image_hits_new"] for r in ok if r["stolen_image_new"]]
    print(f"  new-hits dist: {dict(sorted((h, hits.count(h)) for h in set(hits)))}")
    aff = [r for r in ok if r["affiliate_hits"]]
    print(
        f"  affiliate: {len(aff)}/{len(ok)} ({len(aff) / len(ok):.0%})  {[r['domain'] for r in aff][:15]}"
    )
    term: dict[str, int] = {}
    for r in ok:
        for t in r["dark_hits"]:
            term[t] = term.get(t, 0) + 1
    print(f"  dark terms (domains firing): {dict(sorted(term.items(), key=lambda kv: -kv[1]))}")
    n_dark = sum(1 for r in ok if r["dark_hits"])
    print(f"  dark_hits>0: {n_dark}/{len(ok)} ({n_dark / len(ok):.0%})")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-pages", type=int, default=5)
    ap.add_argument("--out", default=str(ROOT / "logs" / "spike_s4_signals.json"))
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
        summarize(label, out[label])
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
