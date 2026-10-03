"""共有フィクスチャ。

`golden` は 2026-09-24 に実ネットワークで採取した 40 ドメイン (既知詐欺 20 / 正規 20)
の生レスポンスを読み込み、テスト実行時点の extract_features で特徴量を再計算する。
つまり「記録した特徴量」ではなく「現在の実装が実際に出した特徴量」で検証できる。
"""
from __future__ import annotations

import gzip
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from features import PageFeatures, extract_features
from fetch import FetchResult

GOLDEN_DIR = Path(__file__).resolve().parent / "golden"
FETCH_FIELDS = {f.name for f in FetchResult.__dataclass_fields__.values()}


def _fetch_result(rec: dict) -> FetchResult:
    data = {k: v for k, v in rec.items() if k in FETCH_FIELDS}
    data["chain"] = [tuple(x) for x in data.get("chain", [])]
    return FetchResult(**data)


@dataclass
class GoldenSet:
    labels: dict[str, str] = field(default_factory=dict)
    features: dict[str, PageFeatures] = field(default_factory=dict)
    recorded: dict[str, dict] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)
    recorded_at: str = ""
    probe_errors: dict = field(default_factory=dict)

    def domains(self, label: str | None = None) -> list[str]:
        return [d for d, lab in self.labels.items() if label is None or lab == label]

    def scam(self) -> list[str]:
        return self.domains("scam")

    def legit(self) -> list[str]:
        return self.domains("legit")

    def rating(self, domain: str) -> str:
        return self.recorded[domain]["favicon_md5"] or ""

    def unscorable(self) -> list[str]:
        return list(self.missing)


def load_golden() -> GoldenSet:
    meta = json.loads((GOLDEN_DIR / "domains.json").read_text(encoding="utf-8"))
    raws = json.loads(gzip.decompress((GOLDEN_DIR / "raw.json.gz").read_bytes()))
    gs = GoldenSet(recorded_at=meta.get("recorded_at", ""),
                   probe_errors=meta.get("probe_errors", {}))
    md5_counts = Counter(e["favicon_md5"] for lab in ("scam", "legit")
                         for e in meta[lab] if e.get("favicon_md5"))
    reg_counts: Counter = Counter()
    for lab in ("scam", "legit"):
        for e in meta[lab]:
            f = e.get("features")
            if f:
                reg_counts[f["registrable"]] += 1

    for lab in ("scam", "legit"):
        for entry in meta[lab]:
            domain = entry["domain"]
            gs.labels[domain] = lab
            gs.recorded[domain] = entry
            rec = raws.get(domain)
            if rec is None:
                gs.missing.append(domain)
                continue
            fav = entry.get("favicon_md5")
            f = extract_features(
                domain, _fetch_result(rec["browser"]), _fetch_result(rec["bot"]),
            )
            f.favicon_md5 = fav
            f.favicon_collision = bool(fav and md5_counts[fav] > 1)
            f.shared_2ld = reg_counts.get(f.registrable, 0) >= 3
            gs.features[domain] = f
    return gs


@pytest.fixture(scope="session")
def golden() -> GoldenSet:
    return load_golden()
