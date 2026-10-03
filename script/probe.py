"""実パイプライン (P7d): 1 ドメインを 3 UA で取得し、特徴量 → スコア → 判定を返す。

取得は fetch.py の厳格ポリシーをそのまま使う (R5)。
WAF チャレンジ・タイムアウト・DNS 失敗などのノイズで夜間を止めない
(例外は握って dismissed に落とす)。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from fetch import BlockedURL, FetchError, fetch
from features import extract_features, registrable_domain
from scorer import Scorer

PIVOT_QUERY_CAP = 4


@dataclass
class DomainResult:
    domain: str
    score: float
    decision: str
    reasons: dict = field(default_factory=dict)
    features: dict = field(default_factory=dict)


class Pipeline:
    """ページ取得 → 特徴量 → スコア を 1 ドメイン単位で実行する。"""

    def __init__(self, *, db_dir: Path | str = ".", scorer=None, config=None,
                 timeout: float = 12.0):
        self.db_dir = Path(db_dir)
        self.scorer = scorer or Scorer(config) if config else (scorer or Scorer())
        self.timeout = timeout
        self._hits: dict[str, list[str]] = {}
        self._favicon_counts: dict[str, int] = {}

    # --- pivot (R: 保留ドメインを site: で再検索) ---
    def note_hit(self, model: str, url: str) -> None:
        self._hits.setdefault(model, []).append(url)

    def pivot_queries(self, model: str) -> list[str]:
        return [f"site:{u} {model}" for u in self._hits.get(model, [])][:PIVOT_QUERY_CAP]

    # --- 1 ドメイン ---
    def run_domain(self, domain: str) -> DomainResult:
        dom = (domain or "").strip().lower()
        if not dom or "/" in dom or " " in dom:
            return DomainResult(domain=dom, score=0.0, decision="dismissed",
                                features={"error": "invalid_domain"})
        try:
            return self._probe(dom)
        except (BlockedURL, FetchError, OSError, ValueError) as exc:
            return DomainResult(domain=dom, score=0.0, decision="dismissed",
                                features={"error": f"{type(exc).__name__}: {exc}"})

    def _probe(self, dom: str) -> DomainResult:
        base = f"https://{dom}/"
        browser = fetch(base, ua="browser", timeout=self.timeout)
        if browser.status >= 400 or browser.discarded:
            # http へフォールバック (古い詐欺サイトは http のみのことがある)
            alt = fetch(f"http://{dom}/", ua="browser", timeout=self.timeout)
            if alt.status < 400 and not alt.discarded:
                browser = alt
        bot = None
        for ua in ("googlebot", "bingbot"):
            try:
                cand = fetch(f"https://{dom}/", ua=ua, timeout=self.timeout)
            except (BlockedURL, FetchError, OSError):
                continue
            if cand.status < 400 and not cand.discarded:
                bot = cand
                break

        favicon_bytes = None
        for path in ("/favicon.ico",):
            try:
                fav = fetch(f"https://{dom}{path}", ua="browser", timeout=self.timeout)
            except (BlockedURL, FetchError, OSError):
                continue
            if fav.raw_bytes and not fav.discarded:
                favicon_bytes = (fav.body or "").encode("utf-8", "replace")[:64] or b"fav"
                break

        reg = registrable_domain(dom)
        feats = extract_features(dom, browser, bot, favicon_bytes=favicon_bytes,
                                known_favicons=self._favicon_counts,
                                domain_2ld_counts=None)
        score = self.scorer.score(feats)
        decision = {"auto_block": "block", "hold": "hold", "allow": "dismissed"}[score.verdict]
        return DomainResult(domain=dom, score=score.total, decision=decision,
                            reasons=dict(score.reasons), features=feats.to_dict())
