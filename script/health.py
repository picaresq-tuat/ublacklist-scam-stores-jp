"""P8: 到達性チェック (登録から 1 ヶ月以上経過したドメインの監視)。

「到達不能」の定義:
  * DNS 失敗 / 接続失敗 / タイムアウト
  * 4xx / 5xx (恒久的なもの)
  * ドメイン売却・パーキングページ
  * SSRF ポリシーで拒否された (private アドレス等)
"""

from __future__ import annotations

import urllib.parse

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

REACHABLE = "reachable"
UNREACHABLE = "unreachable"
UNKNOWN = "unknown"


def _host(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _same_site(domain: str, host: str) -> bool:
    if not host:
        return True
    return host == domain or host.endswith("." + domain)


class HealthChecker:
    """1 ドメインの到達性を判定する (副作用なし)。"""

    def __init__(self, *, timeout: float = 10.0):
        self.timeout = timeout

    def check(self, domain: str) -> bool:
        return self.check_state(domain) == REACHABLE

    def check_state(self, domain: str) -> str:
        """reachable / unreachable / unknown の 3 値を返す。

        別ドメインへの転送は到達不能としない。転送先が正常なら reachable、
        転送先で失敗した場合は unknown (元ドメインの生死は判断できない)。
        """
        dom = (domain or "").strip().lower().rstrip(".")
        if not dom:
            return UNREACHABLE
        saw_offsite = False
        for scheme in ("https", "http"):
            try:
                res = fetch(f"{scheme}://{dom}/", ua="browser", timeout=self.timeout)
            except (BlockedURL, FetchError, OSError, ValueError):
                continue
            final_host = _host(getattr(res, "final_url", "") or "")
            if final_host and not _same_site(dom, final_host):
                saw_offsite = True
            if res.status >= 400 or res.discarded:
                continue
            head = (res.html_sanitized or res.body or "")[:4096].lower()
            if any(m in head for m in PARKING_MARKERS):
                continue
            return REACHABLE
        return UNKNOWN if saw_offsite else UNREACHABLE
