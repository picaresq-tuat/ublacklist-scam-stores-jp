"""SearxNG クライアント。

方針転換 (2026-09-24) に従い、主引擎は Google CSE (ページング可能、pageno<=5)。
Bing はページング非対応のため 1 ページ目の補完としてのみ併用する。
`engines` の明示指定は必須 (無指定だと suspension したエンジンが混じり 0 件応答になる)。
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

PRIMARY_ENGINES = "google cse"
PIVOT_ENGINES = "google cse,bing"

# --- 実測 (2026-09-24, localhost:8888) ---
# Bing: ページング非対応 (searx/engines/bing.py の docstring に明記)。
#   pageno=1 → 10 件 / pageno>=2 → 常に 0 件 (unresponsive_engines は空)。
# Google CSE: pageno<=5 → 20 件 / pageno>=6 → 0 件。
BING_MAX_PAGENO = 1
GOOGLE_CSE_MAX_PAGENO = 5
# ランダム pageno を使う以上、上限はページング可能なエンジンの側に合わせる。
PRIMARY_MAX_PAGENO = GOOGLE_CSE_MAX_PAGENO


def engines_for(pageno: int, *, pivot: bool = False) -> str:
    """pageno に応じた engines 指定を返す (主引擎 = Google CSE)。

    Google CSE は pageno<=5 でページング可能。Bing はページング非対応のため
    1 ページ目のみ補完として併用する。pivot は常に Google CSE を含む。
    """
    if pivot:
        return PIVOT_ENGINES
    if int(pageno) <= BING_MAX_PAGENO:
        return "google cse,bing"
    return PRIMARY_ENGINES

DEFAULT_URL = "http://localhost:8888"
DEFAULT_TIMEOUT = 30.0
# ライブラリ既定 (テスト・単発呼び出し向け)。実測 429 を踏む値なので夜間運用には使わない。
DEFAULT_SLEEP_SEC = 1.5
# 夜間運用の既定間隔。実測 (2026-09-24): Google CSE は 1.5 秒間隔の連投で
# 約 6 クエリで 429 ("unusual traffic") を返した。夜間バッチは 30 秒間隔を既定とする。
DEFAULT_NIGHT_SLEEP_SEC = 30.0


class SearxError(RuntimeError):
    pass


class EngineUnavailable(SearxError):
    """`unresponsive_engines` が返った = 0 件は「異常」。"""


@dataclass
class SearxStats:
    queries: int = 0
    results: int = 0
    empty_queries: int = 0
    engine_failures: int = 0
    html_results: int = 0
    bytes: int = 0


@dataclass
class SearxClient:
    base_url: str = DEFAULT_URL
    http_get: object = None
    sleep_sec: float = DEFAULT_SLEEP_SEC
    timeout: float = DEFAULT_TIMEOUT
    sleep: object = time.sleep
    stats: SearxStats = field(default_factory=SearxStats)
    _calls: int = 0

    def _get(self, url: str) -> tuple[int, bytes]:
        if self.http_get is not None:
            return self.http_get(url, self.timeout)
        with urllib.request.urlopen(url, timeout=self.timeout) as resp:
            return int(getattr(resp, "status", 200)), resp.read()

    def _pace(self) -> None:
        if self._calls:
            self.sleep(self.sleep_sec)
        self._calls += 1

    def search(self, query: str, pageno: int = 1, *, pivot: bool = False,
               language: str = "ja") -> list[dict]:
        engines = engines_for(pageno, pivot=pivot)
        params = {
            "q": query,
            "format": "json",
            "engines": engines,
            "pageno": int(pageno),
            "language": language,
            "safesearch": "0",
        }
        url = f"{self.base_url.rstrip('/')}/search?" + urllib.parse.urlencode(
            params, quote_via=urllib.parse.quote)
        self._pace()
        try:
            status, body = self._get(url)
        except urllib.error.HTTPError as exc:
            self.stats.engine_failures += 1
            raise SearxError(f"HTTP {exc.code} from SearXNG") from exc
        except Exception as exc:
            self.stats.engine_failures += 1
            raise SearxError(f"{type(exc).__name__}: {exc}") from exc
        if status != 200:
            self.stats.engine_failures += 1
            raise SearxError(f"HTTP {status} from SearXNG")
        self.stats.bytes += len(body)
        try:
            data = json.loads(body.decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise SearxError("malformed JSON from SearXNG") from exc
        unresponsive = data.get("unresponsive_engines") or []
        wanted = {e.strip() for e in engines.split(",")}
        dead = {str(u[0]) for u in unresponsive if u} & wanted
        if dead and not data.get("results"):
            self.stats.engine_failures += 1
            raise EngineUnavailable(f"engines unavailable: {sorted(dead)}")

        out: list[dict] = []
        seen: set[str] = set()
        for item in data.get("results") or []:
            url_ = (item.get("url") or "").strip()
            if not url_ or url_ in seen:
                continue
            seen.add(url_)
            out.append({
                "url": url_,
                "title": (item.get("title") or "").strip(),
                "snippet": (item.get("content") or item.get("snippet") or "").strip(),
                "pubdate": item.get("pubdate") or item.get("publishedDate"),
                "engine": item.get("engine") or engines,
                "query": query,
                "pageno": int(pageno),
            })
        self.stats.queries += 1
        self.stats.results += len(out)
        if not out:
            self.stats.empty_queries += 1
        return out
