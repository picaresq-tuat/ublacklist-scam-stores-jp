"""取得層 (P1)。

実ページは敵性コンテンツとして扱い、通常ブラウザより厳格な制御を行う (R5):
  * スキームは http(s) のみ / ポートは 80,443 のみ
  * SSRF 防止 (private・loopback・link-local・CGNAT への解決を拒否。転送先でも再検証)
  * Content-Type 許可リスト外・Content-Disposition: attachment は本文を読み捨てる
  * サイズ上限・タイムアウト・リダイレクト上限
  * <script>/<iframe>/on* 等を除去したサニタイズ済 HTML のみを特徴量抽出に渡す
  * cookie / authorization ヘッダは送らない
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field

USER_AGENTS = {
    "browser": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        " (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "googlebot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "bingbot": "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
}

ALLOWED_CONTENT_TYPES = frozenset(
    {
        "text/html",
        "text/plain",
        "application/xhtml+xml",
        "application/json",
        "text/xml",
        "application/xml",
    }
)
# allow_binary=True のときだけ通す画像 MIME (favicon 取得用)。
BINARY_CONTENT_TYPES = frozenset(
    {
        "image/x-icon",
        "image/vnd.microsoft.icon",
        "image/png",
        "image/gif",
        "image/jpeg",
        "image/svg+xml",
    }
)
BLOCKED_PORTS = frozenset({22, 23, 25, 110, 143, 3306, 5432, 6379, 8080, 8443, 9200, 11211})
ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({80, 443})

DEFAULT_TIMEOUT = 20.0
DEFAULT_MAX_BYTES = 5 * 1024 * 1024
DEFAULT_MAX_REDIRECTS = 6

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_CHARSET_ALIASES = {
    "shift_jis": "cp932",
    "shift-jis": "cp932",
    "sjis": "cp932",
    "windows-31j": "cp932",
    "ms_kanji": "cp932",
    "x-sjis": "cp932",
    "utf8": "utf-8",
    "euc-jp": "euc_jp",
}
_DANGEROUS_HEADER_NAMES = frozenset({"cookie", "authorization", "proxy-authorization"})


class FetchError(RuntimeError):
    """取得に失敗した (DNS・接続・タイムアウト等)。"""


class BlockedURL(FetchError):
    """セキュリティポリシーにより取得を拒否した。"""


class TooManyRedirects(FetchError):
    pass


@dataclass
class FetchResult:
    url: str
    status: int
    final_url: str
    chain: list[tuple[int, str]] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    html_sanitized: str = ""
    charset: str | None = None
    discarded: bool = False
    discard_reason: str = ""
    truncated: bool = False
    raw_bytes: int = 0
    raw: bytes = b""
    error: str = ""


def host_is_private(ip: str) -> bool:
    """IP 文字列が非公開アドレス空間か判定する。"""
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return True  # 解釈不能なら拒否側に倒す
    if addr.is_loopback or addr.is_private or addr.is_link_local:
        return True
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return True
    if isinstance(addr, ipaddress.IPv4Address):
        cgnat = ipaddress.ip_network("100.64.0.0/10")
        if addr in cgnat:
            return True
        for net in ("192.0.0.0/24", "198.18.0.0/15", "224.0.0.0/4"):
            if addr in ipaddress.ip_network(net):
                return True
    return False


def _default_resolver(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise FetchError(f"dns failure for {host!r}: {exc}") from exc
    return sorted({info[4][0] for info in infos})


def _normalise_charset(raw: str) -> str:
    c = (raw or "").strip().strip("\"'").lower()
    return _CHARSET_ALIASES.get(c, c or "utf-8")


def _sniff_charset(payload: bytes) -> str:
    m = re.search(rb'<meta[^>]+charset=["\']?([\w\-]+)', payload[:4096], re.I)
    if m:
        return _normalise_charset(m.group(1).decode("ascii", "replace"))
    return "utf-8"


_SCRIPTY = ("script", "iframe", "object", "embed", "applet", "noscript", "template")


def sanitize_html(html: str) -> str:
    """実行経路に載る要素を除去したテキストを返す (抽出用の安全な HTML)。"""
    if not html:
        return ""
    out = html
    # 中身ごと除去する要素
    for tag in _SCRIPTY:
        out = re.sub(rf"<{tag}\b[^>]*>.*?</{tag}\s*>", " ", out, flags=re.I | re.S)
        out = re.sub(rf"<{tag}\b[^>]*/?>", " ", out, flags=re.I)
    # meta refresh 等はタグごと落とす
    out = re.sub(r"<meta\b[^>]*http-equiv[^>]*>", " ", out, flags=re.I)
    out = re.sub(r"<link\b[^>]*rel=[\"']?import[^>]*>", " ", out, flags=re.I)
    # インラインイベントハンドラ
    out = re.sub(r"\son[a-z]+\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", " ", out, flags=re.I)
    # javascript: / vbscript: / data: の href
    out = re.sub(
        r"(href|src)\s*=\s*([\"'])\s*(?:javascript|vbscript|data)\s*:[^\"']*\2",
        r'\1="#"',
        out,
        flags=re.I,
    )
    return re.sub(r"<(base|form)\b[^>]*>", " ", out, flags=re.I)


class _HttpTransport:
    """http.client ベースの既定トランスポート (リダイレクトは追わない)。"""

    def open(self, url, *, method="GET", headers=None, timeout=DEFAULT_TIMEOUT):
        parts = urllib.parse.urlsplit(url)
        conn_cls = (
            http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
        )
        port = parts.port or (443 if parts.scheme == "https" else 80)
        conn = conn_cls(parts.hostname, port, timeout=timeout)
        path = urllib.parse.urlunsplit(("", "", parts.path or "/", parts.query, ""))
        try:
            conn.request(method, path, headers=headers or {})
            raw = conn.getresponse()
            body = raw.read(DEFAULT_MAX_BYTES + 1)
            return _RawResponse(url, raw.status, dict(raw.getheaders()), body)
        finally:
            conn.close()


@dataclass
class _RawResponse:
    url: str
    status: int
    headers: dict
    body: bytes


def _check_url(
    url: str, resolver: Callable[[str], list[str]], allow_private: bool
) -> urllib.parse.SplitResult:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise BlockedURL(f"scheme not allowed: {parts.scheme!r}")
    if not parts.hostname:
        raise BlockedURL(f"no host in url: {url!r}")
    if allow_private:
        # テスト用ローカルサーバ等の例外経路。明示指定時のみスキーム/ポート制限も緩める。
        return parts
    try:
        port = parts.port
    except ValueError as exc:
        raise BlockedURL(f"bad port in {url!r}") from exc
    if port is not None and port not in ALLOWED_PORTS:
        raise BlockedURL(f"port not allowed: {port}")
    host = parts.hostname
    try:
        ipaddress.ip_address(host.split("%")[0])
        ips = [host]
    except ValueError:
        ips = resolver(host)
        if not ips:
            raise FetchError(f"no address for {host!r}") from None
    bad = [ip for ip in ips if host_is_private(ip)]
    if bad:
        raise BlockedURL(f"private address not allowed: {host} -> {bad[0]}")
    return parts


def fetch(
    url: str,
    *,
    transport=None,
    resolver: Callable[[str], list[str]] | None = None,
    ua: str = "browser",
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    allow_private: bool = False,
    allow_binary: bool = False,
) -> FetchResult:
    if ua not in USER_AGENTS:
        raise ValueError(f"unknown ua key: {ua!r} (choose from {sorted(USER_AGENTS)})")
    resolver = resolver or _default_resolver
    transport = transport or _HttpTransport()
    headers = {
        "User-Agent": USER_AGENTS[ua],
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5",
        "Accept-Language": "ja,en;q=0.8",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    for name in headers:
        if name.lower() in _DANGEROUS_HEADER_NAMES:  # 念のため (到達しない)
            raise AssertionError(f"refusing to send {name}")

    current = url
    chain: list[tuple[int, str]] = []
    hops = 0
    while True:
        _check_url(current, resolver, allow_private)
        try:
            resp = transport.open(current, method="GET", headers=dict(headers), timeout=timeout)
        except FetchError:
            raise
        except Exception as exc:  # 接続失敗・TLS 失敗等
            raise FetchError(f"{type(exc).__name__}: {exc}") from exc

        status = int(resp.status)
        hdr = {str(k).lower(): str(v) for k, v in (resp.headers or {}).items()}
        chain.append((status, current))

        if status in _REDIRECT_STATUSES:
            location = hdr.get("location", "").strip()
            if not location:
                return FetchResult(
                    url=url, status=status, final_url=current, chain=chain, headers=hdr
                )
            hops += 1
            if hops > max_redirects:
                raise TooManyRedirects(f"{hops} redirects from {url!r}")
            current = urllib.parse.urljoin(current, location)
            continue

        raw = resp.body if isinstance(resp.body, (bytes, bytearray)) else (resp.body or b"")
        raw = bytes(raw)
        result = FetchResult(
            url=url, status=status, final_url=current, chain=chain, headers=hdr, raw_bytes=len(raw)
        )

        # --- 読み捨て判定 (R5) ---
        disposition = hdr.get("content-disposition", "")
        if "attachment" in disposition.lower():
            result.discarded = True
            result.discard_reason = "content-disposition:attachment"
            return result
        ctype = hdr.get("content-type", "").split(";")[0].strip().lower()
        # favicon 等: allow_binary=True なら明示的に許可した画像 MIME のみ通す
        # (content-disposition:attachment と content-length 超過の判定は維持)。
        if (
            ctype
            and ctype not in ALLOWED_CONTENT_TYPES
            and not (allow_binary and ctype in BINARY_CONTENT_TYPES)
        ):
            result.discarded = True
            result.discard_reason = f"content-type:{ctype}"
            return result
        declared = hdr.get("content-length", "")
        if declared.isdigit() and int(declared) > max_bytes:
            result.discarded = True
            result.discard_reason = "content-length"
            result.body = None
            return result

        declared_charset = re.search(r"charset=([\w\-]+)", hdr.get("content-type", ""), re.I)
        if declared_charset:
            result.charset = _normalise_charset(declared_charset.group(1))
        else:
            result.charset = _sniff_charset(raw)
        if len(raw) > max_bytes:
            result.truncated = True
            raw = raw[:max_bytes]
        result.raw = raw
        try:
            text = raw.decode(result.charset, errors="replace")
        except LookupError:
            result.charset = "utf-8"
            text = raw.decode("utf-8", errors="replace")
        result.body = text
        result.html_sanitized = sanitize_html(text)
        return result
