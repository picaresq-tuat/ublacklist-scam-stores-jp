"""S5 スパイク追加解析: 保存済み RDAP JSON を正しい抽出ルールで再集計する。

- registrar URL: registrar entity の links のうち rel != self の href (レジストラ公式サイト)
- abuse phone: registrar entity の入れ子 entities (roles に abuse) の tel
- 海外メーカー例外 (KNOWN_FOREIGN_MAKERS) の候補検証
ネットワークアクセスなし (logs/spike_s5_rdap.json の生データを使用)。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

KNOWN_FOREIGN_MAKERS = {
    "asus.com": {"tlds": {"tw"}, "ccs": {"886"}},
    "sony.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "sony.co.jp": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "panasonic.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "panasonic.co.jp": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "canon.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "canon.co.jp": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "nikon.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "nikon-image.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "lenovo.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81", "86"}},
    "samsung.com": {"tlds": {"com", "jp", "kr"}, "ccs": {"1", "81", "82"}},
    "xiaomi.com": {"tlds": {"com", "jp", "cn"}, "ccs": {"1", "81", "86"}},
    "mi.com": {"tlds": {"com", "jp", "cn"}, "ccs": {"1", "81", "86"}},
    "apple.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "dyson.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81", "44"}},
    "dyson.co.jp": {"tlds": {"com", "jp"}, "ccs": {"1", "81", "44"}},
    "bose.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "gopro.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "anker.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "ankerjapan.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "seagate.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81", "65"}},
    "buffalo.jp": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
}


def extract(data: dict) -> dict:
    reg_url = ""
    reg_name = ""
    abuse_tel = ""
    for ent in data.get("entities") or []:
        if "registrar" not in (ent.get("roles") or []):
            continue
        vcard = (ent.get("vcardArray") or [None, []])[1]
        for item in vcard:
            if item and item[0] == "fn" and not reg_name:
                reg_name = str(item[3] or "")
        for link in ent.get("links") or []:
            href = str(link.get("href") or "")
            rel = str(link.get("rel") or "")
            if rel != "self" and href.startswith(("http://", "https://")):
                reg_url = href
                break
        for sub in ent.get("entities") or []:
            if "abuse" not in (sub.get("roles") or []):
                continue
            sub_vcard = (sub.get("vcardArray") or [None, []])[1]
            for item in sub_vcard:
                if item and item[0] == "tel" and not abuse_tel:
                    abuse_tel = str(item[3] or "")
    return {"registrar_name": reg_name, "registrar_url": reg_url, "abuse_phone": abuse_tel}


def url_tld(url: str) -> str:
    m = re.match(r"https?://([^/:]+)", url or "")
    if not m:
        return ""
    host = m.group(1).lower().rstrip(".")
    host = host[4:] if host.startswith("www.") else host
    labels = host.split(".")
    if len(labels) >= 2 and ".".join(labels[-2:]) in {"co.jp", "ne.jp", "or.jp"}:
        return ".".join(labels[-3:]) if len(labels) >= 3 else host
    return labels[-1] if labels else ""


def phone_cc(tel: str) -> str:
    t = (tel or "").replace("tel:", "")
    m = re.match(r"\+(\d+)", t)
    return m.group(1) if m else ""


def main() -> None:
    data = json.loads((ROOT / "logs" / "spike_s5_rdap.json").read_text(encoding="utf-8"))
    out = {"scam": [], "legit": []}
    for lab, recs in data.items():
        for r in recs:
            slim = {
                "domain": r["domain"],
                "ok": r["ok"],
                "error": r["error"],
                "elapsed_ms": r["elapsed_ms"],
            }
            if r["ok"]:
                slim.update(extract(r.get("rdap") or {}))
            out[lab].append(slim)

    (ROOT / "tests" / "golden" / "rdap.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8"
    )

    # 集計
    for lab in ("legit", "scam"):
        recs = out[lab]
        ok = [r for r in recs if r["ok"]]
        n = len(recs)
        slow = [r for r in ok if r["elapsed_ms"] > 3000]
        tld_f = [
            r for r in ok if (t := url_tld(r.get("registrar_url", ""))) and t not in {"com", "jp"}
        ]
        tel_f = [r for r in ok if (c := phone_cc(r.get("abuse_phone", ""))) and c != "81"]
        print(f"== {lab}: {n} 件 (RDAP 成功 {len(ok)}, 404/失敗 {n - len(ok)})")
        print(f"  rdap_slow (>3s): {len(slow)}  {[r['domain'] for r in slow]}")
        print(f"  registrar url tld != com/jp: {len(tld_f)}")
        for r in tld_f:
            print(f"    {r['domain']:34s} {r.get('registrar_url', '')[:60]}")
        print(f"  abuse phone cc != 81: {len(tel_f)}")
        for r in tel_f:
            print(f"    {r['domain']:34s} {r.get('abuse_phone', '')[:30]}")
        lat = sorted(r["elapsed_ms"] for r in ok)
        if lat:
            print(f"  elapsed: min={lat[0]} med={lat[len(lat) // 2]} max={lat[-1]}")

    print("\n-- 全レジストラ内訳 --")
    for lab in ("legit", "scam"):
        names = {}
        for r in out[lab]:
            if r["ok"]:
                names[r.get("registrar_name", "?")] = names.get(r.get("registrar_name", "?"), 0) + 1
        print(lab, names)


if __name__ == "__main__":
    main()
