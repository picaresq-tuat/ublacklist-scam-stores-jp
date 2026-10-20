"""実パイプライン (P7d): 1 ドメインを 3 UA で取得し、特徴量 → スコア → 判定を返す。

取得は fetch.py の厳格ポリシーをそのまま使う (R5)。
WAF チャレンジ・タイムアウト・DNS 失敗などのノイズで夜間を止めない
(例外は握って dismissed に落とす)。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from features import extract_features
from fetch import BlockedURL, FetchError, fetch, looks_like_image_bytes
from scorer import Scorer
from whois_rdap import rdap_supported

PIVOT_QUERY_CAP = 4
# 実 favicon の最小サイズ。これ未満はヘッダ片/エラーページとみなす。
MIN_FAVICON_BYTES = 8


@dataclass
class DomainResult:
    domain: str
    score: float
    decision: str
    reasons: dict = field(default_factory=dict)
    features: dict = field(default_factory=dict)


class Pipeline:
    """ページ取得 → 特徴量 → スコア を 1 ドメイン単位で実行する。"""

    def __init__(
        self,
        *,
        db_dir: Path | str = ".",
        scorer=None,
        config=None,
        timeout: float = 12.0,
        rdap_fn=None,
        favicon_counts: dict[str, int] | None = None,
        favicon_origins: dict[str, str] | None = None,
    ):
        self.db_dir = Path(db_dir)
        self.scorer = scorer or Scorer(config) if config else (scorer or Scorer())
        self.timeout = timeout
        self.rdap_fn = rdap_fn
        self._hits: dict[str, list[str]] = {}
        # favicon corpus (md5 -> 観測ドメイン数 / md5 -> 代表オリジン)。
        self._favicon_counts: dict[str, int] = dict(favicon_counts or {})
        self._favicon_origins: dict[str, str] = dict(favicon_origins or {})

    # --- pivot (R: 保留ドメインを site: で再検索) ---
    def note_hit(self, model: str, url: str) -> None:
        self._hits.setdefault(model, []).append(url)

    def pivot_queries(self, model: str) -> list[str]:
        return [f"site:{u} {model}" for u in self._hits.get(model, [])][:PIVOT_QUERY_CAP]

    # --- 1 ドメイン ---
    def run_domain(self, domain: str) -> DomainResult:
        dom = (domain or "").strip().lower()
        if not dom or "/" in dom or " " in dom:
            return DomainResult(
                domain=dom, score=0.0, decision="dismissed", features={"error": "invalid_domain"}
            )
        try:
            return self._probe(dom)
        except (BlockedURL, FetchError, OSError, ValueError) as exc:
            return DomainResult(
                domain=dom,
                score=0.0,
                decision="dismissed",
                features={"error": f"{type(exc).__name__}: {exc}"},
            )

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
        try:
            # 画像 MIME は通常 discard されるため allow_binary で生バイトを受け取る。
            fav = fetch(
                f"https://{dom}/favicon.ico",
                ua="browser",
                timeout=self.timeout,
                allow_binary=True,
            )
        except (BlockedURL, FetchError, OSError):
            fav = None
        if fav is not None and not fav.discarded and fav.status < 400:
            # soft-404 (404 の HTML 等) を favicon として採用しない。
            # HTML の定型エラーページを MD5 化すると、corpus を汚染して
            # favicon_collision の偽陽性を量産するため magic で弾く。
            raw = getattr(fav, "raw", b"") or b""
            if len(raw) >= MIN_FAVICON_BYTES and looks_like_image_bytes(raw):
                favicon_bytes = raw

        rdap = None
        if self.rdap_fn is not None and rdap_supported(dom):
            try:
                rdap = self.rdap_fn(dom)
            except Exception:  # RDAP の失敗で probe 全体を落とさない (特徴量 0)
                rdap = None

        feats = extract_features(
            dom,
            browser,
            bot,
            favicon_bytes=favicon_bytes,
            known_favicons=self._favicon_counts,
            favicon_origin_map=self._favicon_origins,
            domain_2ld_counts=None,
            rdap=rdap,
        )
        score = self.scorer.score(feats)
        decision = {"auto_block": "block", "hold": "hold", "allow": "dismissed"}[score.verdict]
        return DomainResult(
            domain=dom,
            score=score.total,
            decision=decision,
            reasons=dict(score.reasons),
            features=feats.to_dict(),
        )
