"""P8: 到達性チェック (登録から 1 ヶ月以上経過したドメインの監視)。

「到達不能」の定義:
  * DNS 失敗 / 接続失敗 / タイムアウト
  * 4xx / 5xx (恒久的なもの)
  * ドメイン売却・パーキングページ
  * SSRF ポリシーで拒否された (private アドレス等)
"""

from __future__ import annotations

from fetch import BlockedURL, FetchError, fetch

PARKING_MARKERS: tuple[str, ...] = (
    "this domain is for sale",
    "buy this domain",
    "domain for sale",
    "this domain may be for sale",
    "ドメインを売り",
    "このドメインは販売中",
    "parked",
    "sedo.com",
    "afternic",
)


class HealthChecker:
    """1 ドメインの到達性を判定する (副作用なし)。"""

    def __init__(self, *, timeout: float = 10.0):
        self.timeout = timeout

    def check(self, domain: str) -> bool:
        dom = (domain or "").strip().lower()
        if not dom:
            return False
        for scheme in ("https", "http"):
            try:
                res = fetch(f"{scheme}://{dom}/", ua="browser", timeout=self.timeout)
            except (BlockedURL, FetchError, OSError, ValueError):
                continue
            if res.status >= 400 or res.discarded:
                continue
            head = (res.html_sanitized or res.body or "")[:4096].lower()
            return not any(m in head for m in PARKING_MARKERS)
        return False
