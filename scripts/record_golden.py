"""ゴールデンセット記録スクリプト (P5 用フィクスチャ生成)。

2026-09-24 に実ネットワークで 40 ドメインを実測し、特徴量を JSON に記録する。
正解ラベル: sagidame.com 掲載の既知詐欺 20 件 = scam / 型番検索でヒットした正規 20 件 = legit。
再実行: python3 scripts/record_golden.py
"""
from __future__ import annotations

import concurrent.futures as cf
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "script"))

from features import STORE_ASSET_HOSTS, extract_features  # noqa: E402
from fetch import FetchError, BlockedURL, fetch  # noqa: E402

SCAM = [
    "store.hika-jp.casa", "mart.hika-jp.casa", "zips.hika-jp.casa", "zone.hika-jp.casa",
    "enjoy.hika-jp.casa", "fire.hika-jp.casa", "flag.hika-jp.casa", "full.hika-jp.casa",
    "goal.hika-jp.casa", "hold.hika-jp.casa", "huge.hika-jp.casa", "later.hika-jp.casa",
    "mami.hika-jp.casa", "nine.hika-jp.casa", "shap.hika-jp.casa", "wind.hika-jp.casa",
    "auto.hika-jp.casa", "abpvdb.quervia.biz", "uplast.bepark.shop", "yuguoyinxi.love",
]
LEGIT = [
    "dynabook.com", "www.askul.co.jp", "www.suruga-ya.jp", "used.sofmap.com",
    "biccamera.com", "pc-master.jp", "hyperlab.jp", "kakakumag.com",
    "nisesuka.hatenablog.com", "fuji-x-life.tokyo", "blog.htkyama.org", "limonenote.com",
    "gadgetken.com", "heeeee.jp", "websumaho.blog.fc2.com", "www.janpara.co.jp",
    "dospara.co.jp", "www.iosys.co.jp", "www.pc-koubou.jp", "www2.elecom.co.jp",
]


def probe(domain: str) -> tuple[str, dict | None, str]:
    from fetch import FetchResult
    try:
        browser = fetch(f"https://{domain}/", ua="browser", timeout=15.0)
        try:
            bot = fetch(f"https://{domain}/", ua="googlebot", timeout=15.0)
        except FetchError as exc:
            bot = FetchResult(url=f"https://{domain}/", status=0, final_url=f"https://{domain}/",
                              error=str(exc))
        return domain, {"browser": _ser(browser), "bot": _ser(bot)}, ""
    except (FetchError, BlockedURL) as exc:
        return domain, None, f"{type(exc).__name__}: {exc}"


def _ser(r) -> dict:
    return {"url": r.url, "status": r.status, "final_url": r.final_url, "chain": r.chain,
            "headers": r.headers, "body": r.body, "html_sanitized": r.html_sanitized,
            "charset": r.charset, "discarded": r.discarded, "discard_reason": r.discard_reason,
            "truncated": r.truncated, "raw_bytes": r.raw_bytes, "error": r.error}


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    out: dict = {"recorded_at": None, "probe_errors": {}, "scam": [], "legit": []}
    raws: dict[str, dict] = {}
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        for domain, rec, err in ex.map(probe, SCAM + LEGIT):
            if rec is None:
                out["probe_errors"][domain] = err
                continue
            raws[domain] = rec

    favicon_bytes: dict[str, bytes | None] = {}
    for domain in raws:
        try:
            import urllib.request
            req = urllib.request.Request(f"https://{domain}/favicon.ico",
                                         headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                favicon_bytes[domain] = resp.read(64 * 1024)
        except Exception:
            favicon_bytes[domain] = None

    feats = {}
    for domain, rec in raws.items():
        from fetch import FetchResult
        browser = FetchResult(**rec["browser"])
        bot = FetchResult(**rec["bot"])
        feats[domain] = extract_features(domain, browser, bot,
                                        favicon_bytes=favicon_bytes.get(domain))
    fav_counts = Counter(f.favicon_md5 for f in feats.values() if f.favicon_md5)
    reg_counts = Counter(f.registrable for f in feats.values())

    for label, domains in (("scam", SCAM), ("legit", LEGIT)):
        for domain in domains:
            f = feats.get(domain)
            out[label].append({
                "domain": domain,
                "recorded": f is not None,
                "features": f.to_dict() if f else None,
                "favicon_md5": f.favicon_md5 if f else None,
                "favicon_collision": bool(f and f.favicon_md5 and fav_counts[f.favicon_md5] > 1),
                "shared_2ld": bool(f and reg_counts[f.registrable] >= 3),
                "probe_error": out["probe_errors"].get(domain, ""),
            })
    # 生レスポンスも保存 (テストが extract_features を再実行して検証できるようにする)
    import gzip
    raw_dump = {d: {"browser": rec["browser"], "bot": rec["bot"]} for d, rec in raws.items()}
    for entry in raw_dump.values():
        for side in ("browser", "bot"):
            body = entry[side].get("body")
            if body and len(body) > 300_000:
                entry[side]["body"] = body[:300_000]
                entry[side]["truncated_for_fixture"] = True
    gz = root / "tests" / "golden" / "raw.json.gz"
    gz.write_bytes(gzip.compress(json.dumps(raw_dump, ensure_ascii=False).encode("utf-8"), 9))
    print(f"wrote {gz} ({gz.stat().st_size} bytes)")

    import datetime
    out["recorded_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out["store_asset_hosts"] = list(STORE_ASSET_HOSTS)
    dest = root / "tests" / "golden" / "domains.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"wrote {dest} ({dest.stat().st_size} bytes)")
    print("scam recorded:", sum(1 for d in out["scam"] if d["recorded"]), "/", len(SCAM))
    print("legit recorded:", sum(1 for d in out["legit"] if d["recorded"]), "/", len(LEGIT))
    print("probe errors:", len(out["probe_errors"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
