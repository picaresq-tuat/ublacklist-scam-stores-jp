"""S5 スパイク: RDAP (rdap.org) 実測。

golden legit 20 件 + sagidame scam コーパス 30 件程度の RDAP を 1 req/sec 以下で取得し、
whois 相当情報 (registrar URL / abuse phone) と所要時間を記録する。
出力: logs/spike_s5_rdap.json (生データ) / tests/golden/rdap.json (テスト用)
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "script"))

LEGIT_DOMAINS = [
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
]


SCAM_TARGET = 30
UA = "scam-hunter-research/1.0 (contact: repo owner)"
RDAP_TIMEOUT = 10.0
SLEEP_SEC = 1.1  # rdap.org 公開サービス: 1 req/sec 以下を厳守


def fetch_rdap(domain: str) -> dict:
    t0 = time.monotonic()
    url = f"https://rdap.org/domain/{domain}"
    rec: dict = {"domain": domain, "ok": False, "error": "", "elapsed_ms": 0}
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": UA, "Accept": "application/rdap+json"}
        )
        with urllib.request.urlopen(req, timeout=RDAP_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", "replace")
        rec["elapsed_ms"] = int((time.monotonic() - t0) * 1000)
        rec["ok"] = True
        rec["rdap"] = json.loads(body)
    except Exception as exc:
        rec["elapsed_ms"] = int((time.monotonic() - t0) * 1000)
        rec["error"] = f"{type(exc).__name__}: {exc}"
    return rec


def summarize(rec: dict) -> dict:
    """特徴量判定に使う最小フィールドだけ残す (tests/golden 用)。"""
    out = {
        "domain": rec["domain"],
        "ok": rec["ok"],
        "error": rec["error"],
        "elapsed_ms": rec["elapsed_ms"],
    }
    data = rec.get("rdap") or {}
    out["registrar_name"] = RdapLite.registrar_name(data)
    out["registrar_url"] = RdapLite.registrar_url(data)
    out["abuse_phone"] = RdapLite.abuse_phone(data)
    return out


class RdapLite:
    """spike 用の簡易パーサ (本実装は script/whois_rdap.py を使う)。"""

    @staticmethod
    def registrar_name(data: dict) -> str:
        for ent in data.get("entities") or []:
            if "registrar" in (ent.get("roles") or []):
                return RdapLite._vcard(ent, "fn")
        return ""

    @staticmethod
    def registrar_url(data: dict) -> str:
        for ent in data.get("entities") or []:
            if "registrar" in (ent.get("roles") or []):
                return RdapLite._vcard(ent, "url")
        return ""

    @staticmethod
    def abuse_phone(data: dict) -> str:
        for ent in data.get("entities") or []:
            if "abuse" in (ent.get("roles") or []):
                return RdapLite._vcard(ent, "tel")
        return ""

    @staticmethod
    def _vcard(ent: dict, kind: str) -> str:
        arr = ent.get("vcardArray") or []
        for item in arr[1] if len(arr) > 1 else []:
            if item and item[0] == kind:
                return str(item[3] or "")
        return ""


def main() -> int:
    # sagidame から scam ドメインを収集
    from fetch import fetch

    scam_doms: list[str] = []
    page = 1
    while len(scam_doms) < SCAM_TARGET and page <= 8:
        try:
            r = fetch(f"https://sagidame.com/?page={page}", ua="browser", timeout=20)
        except Exception as exc:
            print(f"sagidame page {page}: {exc}", file=sys.stderr)
            break
        import re

        for m in re.findall(r"/result/([A-Za-z0-9.-]+\.[a-z]{2,})", r.body or ""):
            d = m.lower()
            if d not in scam_doms:
                scam_doms.append(d)
        page += 1
        time.sleep(1.0)
    scam_doms = scam_doms[:SCAM_TARGET]
    print(f"scam domains: {len(scam_doms)}")

    results: dict = {"scam": [], "legit": []}
    all_domains = [(d, "legit") for d in LEGIT_DOMAINS] + [(d, "scam") for d in scam_doms]
    for dom, lab in all_domains:
        rec = fetch_rdap(dom)
        results[lab].append(rec)
        flag = "" if rec["ok"] else f"  ERR {rec['error'][:60]}"
        print(
            f"[{lab}] {dom:34s} {rec['elapsed_ms']:5d}ms "
            f"url_tld={RdapLite.registrar_url(rec.get('rdap') or {}).split('//')[-1].split('/')[0]:30s} "
            f"tel={RdapLite.abuse_phone(rec.get('rdap') or '') if False else RdapLite.abuse_phone(rec.get('rdap') or {})}{flag}",
            flush=True,
        )
        time.sleep(SLEEP_SEC)

    Path(ROOT / "logs").mkdir(exist_ok=True)
    (ROOT / "logs" / "spike_s5_rdap.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    slim = {lab: [summarize(r) for r in recs] for lab, recs in results.items()}
    (ROOT / "tests" / "golden" / "rdap.json").write_text(
        json.dumps(slim, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
