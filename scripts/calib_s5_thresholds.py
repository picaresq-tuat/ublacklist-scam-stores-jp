"""S5/T4: 閾値・重みの再校正 (オフライン)。

入力 (ネットワークアクセスなし):
- tests/golden/ : 実採取 40 ドメイン (scam 20 / legit 20) の生レスポンス → 現行 extract_features で再計算
- tests/golden/rdap.json : 上記の RDAP 取得結果 (成功分のみ特徴量化)
- logs/spike_s4_signals.json : scam 100 件 (有効 96) / legit 33 件 (有効 25) の部分特徴量

出力:
- logs/calib_s5_scores.tsv   : ドメイン別スコア内訳 (シグナル寄与)
- logs/calib_s5_sweep.tsv    : auto_block 20..45 の recall / FP スイープ
- logs/calib_s5_summary.json : adopt 判定に使った集計

部分特徴量コーパス (spike_s4) は favicon/zencart/cloaking 等を持たないため、
スコアは下限値 (保守側)。recall は「部分特徴量だけでも閾値に届く件数」を意味する。
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "script"))

from features import RISKY_TLDS, PageFeatures, registrable_domain, young_domain  # noqa: E402
from scorer import Scorer  # noqa: E402
from whois_rdap import RdapInfo  # noqa: E402

GOLDEN = ROOT / "tests" / "golden"
S4 = ROOT / "logs" / "spike_s4_signals.json"
OUT_SCORES = ROOT / "logs" / "calib_s5_scores.tsv"
OUT_SWEEP = ROOT / "logs" / "calib_s5_sweep.tsv"
OUT_SUMMARY = ROOT / "logs" / "calib_s5_summary.json"

SIGNALS = [
    "redirect_to_google",
    "offsite_redirect",
    "rdap_slow",
    "registrar_url_tld_foreign",
    "abuse_phone_foreign",
    "favicon_collision",
    "favicon_cross_origin",
    "zencart",
    "cloaking",
    "bot_only_body",
    "stolen_image",
    "dark_pattern",
    "risky_tld",
    "shared_2ld",
    "deep_product_path",
]


def load_golden():
    """tests/conftest.py の load_golden を再利用 (同じ特徴量算出経路で採点するため)。"""
    spec = importlib.util.spec_from_file_location("golden_conftest", GOLDEN.parent / "conftest.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["golden_conftest"] = mod
    spec.loader.exec_module(mod)
    return mod.load_golden()


def load_rdap() -> dict[str, RdapInfo]:
    raw = json.loads((GOLDEN / "rdap.json").read_text(encoding="utf-8"))
    out: dict[str, RdapInfo] = {}
    for rec in (r for lab in ("scam", "legit") for r in raw[lab]):
        out[rec["domain"]] = RdapInfo(
            domain=rec["domain"],
            ok=bool(rec.get("ok")),
            elapsed_ms=int(rec.get("elapsed_ms") or 0),
            registrar_name=rec.get("registrar_name", ""),
            registrar_url=rec.get("registrar_url", ""),
            abuse_phone=rec.get("abuse_phone", ""),
            registration_date=rec.get("registration_date", ""),
            error=rec.get("error", ""),
        )
    return out


def attach_rdap(f: PageFeatures, info: RdapInfo | None, now=None) -> None:
    """features.extract_features の RDAP 取り込みと同じ規則で注入する。"""
    if info is None:
        return
    f.rdap_ok = bool(info.ok)
    f.rdap_elapsed_ms = int(info.elapsed_ms)
    f.rdap_registrar_name = info.registrar_name
    f.rdap_registrar_url = info.registrar_url
    f.rdap_abuse_phone = info.abuse_phone
    if info.ok:
        f.young_index = young_domain(info, now)
        tld_f, phone_f, exc = info.flags(f.domain)
        f.rdap_registrar_tld_foreign = tld_f
        f.rdap_phone_foreign = phone_f
        f.rdap_exception = exc


def golden_corpus(rdap: dict[str, RdapInfo]) -> list[dict]:
    gs = load_golden()
    rows = []
    for domain, f in gs.features.items():
        attach_rdap(f, rdap.get(domain))
        rows.append(
            {"corpus": "golden", "label": gs.labels[domain], "domain": domain, "features": f}
        )
    return rows


def partial_corpus(rdap: dict[str, RdapInfo]) -> list[dict]:
    """spike_s4 の部分特徴量から PageFeatures を組む (未計測シグナルは False のまま)。"""
    raw = json.loads(S4.read_text(encoding="utf-8"))
    rows = []
    for lab in ("scam", "legit"):
        recs = [r for r in raw[lab] if not r.get("error")]
        reg = Counter(registrable_domain(r["domain"]) for r in recs)
        for r in recs:
            domain = r["domain"]
            tld = domain.rsplit(".", 1)[-1]
            f = PageFeatures(
                domain=domain,
                registrable=registrable_domain(domain),
                tld=tld,
                risky_tld=tld in RISKY_TLDS,
                stolen_image=bool(r.get("stolen_image_new")),
                dark_hits=len(r.get("dark_hits") or {}),
                shared_2ld=reg[registrable_domain(domain)] >= 3,
                status=int(r.get("status") or 0),
            )
            attach_rdap(f, rdap.get(domain))
            rows.append({"corpus": "spike_s4", "label": lab, "domain": domain, "features": f})
    return rows


def score_rows(rows: list[dict], scorer: Scorer) -> list[dict]:
    out = []
    for row in rows:
        s = scorer.score(row["features"])
        out.append({**row, "score": s.total, "verdict": s.verdict, "reasons": s.reasons})
    return out


def write_scores(rows: list[dict], path: Path) -> None:
    header = ["corpus", "label", "domain", "total", "verdict", *SIGNALS]
    lines = ["\t".join(header)]
    for r in sorted(rows, key=lambda x: (x["corpus"], x["label"], -x["score"])):
        cells = [r["corpus"], r["label"], r["domain"], f"{r['score']:.1f}", r["verdict"]]
        cells += [f"{r['reasons'].get(k, 0):.1f}" for k in SIGNALS]
        lines.append("\t".join(cells))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def sweep(rows: list[dict], hold: int, lo: int = 16, hi: int = 45) -> list[dict]:
    """auto_block を lo..hi で振り、corpus 別の recall / FP / hold 滞留を集計。

    探索域の下端は adopt 値より十分下に取る (adopt 値が下端に張り付くと
    「FP=0 制約下の最良」が探索域の都合で決まってしまうため)。
    """
    table = []
    for t in range(lo, hi + 1):
        entry = {"auto_block": t, "hold": hold}
        for corpus in ("golden", "spike_s4"):
            sub = [r for r in rows if r["corpus"] == corpus]
            scam = [r for r in sub if r["label"] == "scam"]
            legit = [r for r in sub if r["label"] == "legit"]
            entry[corpus] = {
                "scam_n": len(scam),
                "recall": sum(1 for r in scam if r["score"] >= t),
                "legit_n": len(legit),
                "fp": sum(1 for r in legit if r["score"] >= t),
                "hold_fp": sum(1 for r in legit if hold <= r["score"] < t),
            }
        table.append(entry)
    return table


def write_sweep(table: list[dict], path: Path) -> None:
    header = [
        "auto_block",
        "hold",
        "golden_recall/20",
        "golden_FP/20",
        "golden_holdFP/20",
        "s4_recall/96",
        "s4_FP/25",
        "s4_holdFP/25",
    ]
    lines = ["\t".join(header)]
    for e in table:
        g, s = e["golden"], e["spike_s4"]
        lines.append(
            "\t".join(
                [
                    str(e["auto_block"]),
                    str(e["hold"]),
                    f"{g['recall']}/{g['scam_n']}",
                    f"{g['fp']}/{g['legit_n']}",
                    f"{g['hold_fp']}/{g['legit_n']}",
                    f"{s['recall']}/{s['scam_n']}",
                    f"{s['fp']}/{s['legit_n']}",
                    f"{s['hold_fp']}/{s['legit_n']}",
                ]
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    rdap = load_rdap()
    rows = score_rows(golden_corpus(rdap) + partial_corpus(rdap), Scorer())
    write_scores(rows, OUT_SCORES)

    t = Scorer().thresholds
    table = sweep(rows, int(t["hold"]))
    write_sweep(table, OUT_SWEEP)

    max_legit = {
        c: max((r["score"] for r in rows if r["corpus"] == c and r["label"] == "legit"), default=0)
        for c in ("golden", "spike_s4")
    }
    summary_max_legit = max(max_legit.values(), default=0)
    min_scam = {
        c: min((r["score"] for r in rows if r["corpus"] == c and r["label"] == "scam"), default=0)
        for c in ("golden", "spike_s4")
    }

    def best_at(fp_zero_only: bool, min_headroom: int = 9) -> dict | None:
        legit_max = summary_max_legit
        cands = [
            e
            for e in table
            if (
                not fp_zero_only
                or (
                    e["golden"]["fp"] == 0
                    and e["spike_s4"]["fp"] == 0
                    and e["auto_block"] - legit_max >= min_headroom
                )
            )
        ]
        if not cands:
            return None
        # FP=0 制約下で recall 最大。同 recall なら閾値が高い (= 保守的) 方を採る。
        return max(
            cands, key=lambda e: (e["golden"]["recall"], e["spike_s4"]["recall"], e["auto_block"])
        )

    summary = {
        "config_version": 1,
        "note": (
            "spike_s4 は部分特徴量 (zencart/favicon/cloaking/offsite 未計測) のため、"
            "スコアも FP も下限値。FP 0 は『真の FP 率 0』ではなく『この corpus で未観測』。"
        ),
        "thresholds": t,
        "weights": Scorer().weights,
        "corpora": {
            "golden": {
                "scam": sum(1 for r in rows if r["corpus"] == "golden" and r["label"] == "scam"),
                "legit": sum(1 for r in rows if r["corpus"] == "golden" and r["label"] == "legit"),
                "note": "full features (raw.json.gz + rdap.json)",
            },
            "spike_s4": {
                "scam": sum(1 for r in rows if r["corpus"] == "spike_s4" and r["label"] == "scam"),
                "legit": sum(
                    1 for r in rows if r["corpus"] == "spike_s4" and r["label"] == "legit"
                ),
                "note": "partial features (risky_tld/stolen_image/dark/shared_2ld + RDAP); scores are lower bounds",
            },
        },
        "best_in_range_fp_zero": best_at(True),
        "best_in_range_any": best_at(False),
        "selection_rule": (
            "FP 0 (両コーパス) かつ auto_block - max(legit) >= 9 の範囲で recall 最大。"
            "max(legit) は両コーパスの最大値 (保守側) を採る。"
        ),
        "max_legit_score": max_legit,
        "min_scam_score": min_scam,
    }
    OUT_SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")

    print(OUT_SWEEP.read_text(encoding="utf-8"))
    print(
        json.dumps(summary["max_legit_score"], ensure_ascii=False),
        json.dumps(summary["min_scam_score"]),
    )
    print(
        "best_in_range_fp_zero:", json.dumps(summary["best_in_range_fp_zero"], ensure_ascii=False)
    )


if __name__ == "__main__":
    main()
