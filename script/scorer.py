"""スコアラ (P4)。

重み・閾値は scoring.yaml のみを源とする (ハードコード禁止)。
verdict: allow (<hold) / hold (hold<=x<auto_block) / auto_block (>=auto_block)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from features import PageFeatures

DEFAULT_CONFIG = Path(__file__).resolve().parent / "scoring.yaml"

_FALLBACK = {
    "weights": {
        "redirect_to_google": 35, "favicon_collision": 30, "favicon_cross_origin": 5, "zencart": 25,
        "bot_only_body": 20, "cloaking": 12, "cloaking_promoted": 20,
        "stolen_image": 15, "dark_pattern_per_hit": 3, "dark_pattern_cap": 9,
        "risky_tld": 8, "shared_2ld": 6, "offsite_redirect": 10,
        "deep_product_path": 2, "young_index": 5,
    },
    "thresholds": {"auto_block": 30, "hold": 12, "fast_track": 60,
                   "zencart_min_hits": 2, "nights_required": 2},
    "pivot": {"max_queries": 4, "hold_trigger": 12},
    "domain": {"general_hit": 3, "pivot_hit": 1, "pivot_cap": 4},
}


def load_weights(path: Path | str = DEFAULT_CONFIG) -> dict:
    """YAML を読み、不足キーを既定値で補う。"""
    data = {}
    p = Path(path)
    if p.exists():
        text = p.read_text(encoding="utf-8")
        if p.suffix in (".yaml", ".yml"):
            try:
                import yaml  # type: ignore
                data = yaml.safe_load(text) or {}
            except ImportError:
                data = _mini_yaml(text)
        else:
            import json
            data = json.loads(text)
    merged = {k: dict(v) for k, v in _FALLBACK.items()}
    for section, values in (data or {}).items():
        if isinstance(values, dict):
            merged.setdefault(section, {}).update(values)
        else:
            merged[section] = values
    return merged


def _mini_yaml(text: str) -> dict:
    """PyYAML 非依存の最小パーサ (2 階層の key: value のみ)。"""
    out: dict = {}
    section = None
    for raw in text.splitlines():
        line = raw.split("#")[0].rstrip()
        if not line.strip():
            continue
        if not line.startswith((" ", "\t")) and line.rstrip().endswith(":"):
            section = line.strip()[:-1]
            out[section] = {}
            continue
        if ":" in line:
            key, _, val = line.strip().partition(":")
            val = val.strip()
            if val == "":
                continue
            try:
                parsed = float(val) if "." in val else int(val)
            except ValueError:
                parsed = val
            (out.setdefault(section or "_root", {}))[key] = parsed
    return out


@dataclass
class Score:
    domain: str
    total: float
    verdict: str
    reasons: dict = field(default_factory=dict)
    reasons_src: dict = field(default_factory=dict)
    fast_track: bool = False
    evidence: dict = field(default_factory=dict)

    def explain(self) -> str:
        lines = [f"{name}:{self.reasons[name]:+.0f}" for name in
                 sorted(self.reasons, key=lambda n: -self.reasons[n])]
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain, "total": self.total, "verdict": self.verdict,
            "reasons": dict(self.reasons), "reasons_src": dict(self.reasons_src),
            "fast_track": self.fast_track, "evidence": dict(self.evidence),
        }


class Scorer:
    def __init__(self, config: Path | str = DEFAULT_CONFIG):
        cfg = load_weights(config)
        self.weights: dict = cfg["weights"]
        self.thresholds: dict = cfg["thresholds"]
        self.pivot_cfg: dict = cfg["pivot"]
        self.domain_cfg: dict = cfg.get("domain", dict(_FALLBACK["domain"]))

    # --- ページスコア ---
    def score(self, f: PageFeatures) -> Score:
        w = self.weights
        t = self.thresholds
        reasons: dict = {}
        src: dict = {}

        def add(key: str, weight: float, source: Optional[str] = None) -> None:
            if weight <= 0:
                return
            reasons[key] = reasons.get(key, 0) + weight
            src[key] = source or key

        if f.redirect_to_google:
            add("redirect_to_google", w["redirect_to_google"])
        elif f.offsite_redirect:
            add("offsite_redirect", w["offsite_redirect"])

        if f.favicon_collision:
            add("favicon_collision", w["favicon_collision"])
        elif f.favicon_cross_origin:
            add("favicon_cross_origin", w["favicon_cross_origin"])
        if f.zencart_hits >= t["zencart_min_hits"]:
            add("zencart", w["zencart"])
        if f.cloaking:
            if f.bot_only_body or f.status >= 400:
                add("cloaking", w["cloaking_promoted"], "cloaking_promoted")
            else:
                add("cloaking", w["cloaking"])
        elif f.bot_only_body:
            add("bot_only_body", w["bot_only_body"])
        if f.stolen_image:
            add("stolen_image", w["stolen_image"])
        if f.dark_hits:
            add("dark_pattern", min(f.dark_hits * w["dark_pattern_per_hit"], w["dark_pattern_cap"]))
        if f.risky_tld:
            add("risky_tld", w["risky_tld"])
        if f.shared_2ld:
            add("shared_2ld", w["shared_2ld"])
        if f.deep_product_path:
            add("deep_product_path", w["deep_product_path"])
        if (f.extra or {}).get("young_index"):
            add("young_index", w["young_index"])

        total = round(float(sum(reasons.values())), 1)
        return Score(
            domain=f.domain, total=total, verdict=self._verdict(total),
            reasons=reasons, reasons_src=src,
            fast_track=total >= t["fast_track"],
            evidence={"features": f.to_dict()},
        )

    def _verdict(self, total: float) -> str:
        if total >= self.thresholds["auto_block"]:
            return "auto_block"
        if total >= self.thresholds["hold"]:
            return "hold"
        return "allow"

    # --- ドメインスコア ---
    def domain_score(self, domain: str, page_scores: list[Score], *,
                     pivot_hits: int = 0, general_hits: int = 0) -> Score:
        max_page = max((s.total for s in page_scores), default=0.0)
        general_w = self.domain_cfg["general_hit"] * max(0, general_hits)
        pivot_w = self.domain_cfg["pivot_hit"] * max(0, min(pivot_hits, self.domain_cfg["pivot_cap"]))
        total = round(max_page + general_w + pivot_w, 1)
        reasons: dict = {}
        if max_page:
            reasons["page_max"] = max_page
        if general_w:
            reasons["general_hits"] = general_w
        if pivot_w:
            reasons["pivot_hits"] = pivot_w
        return Score(
            domain=domain, total=total, verdict=self._verdict(total), reasons=reasons,
            reasons_src={},
            fast_track=total >= self.thresholds["fast_track"],
            evidence={
                "pages_scored": len(page_scores),
                "pivot_hits": pivot_hits,
                "general_hits": general_hits,
                "max_page_score": max_page,
                "reasons_of_pages": [s.reasons for s in page_scores],
            },
        )
