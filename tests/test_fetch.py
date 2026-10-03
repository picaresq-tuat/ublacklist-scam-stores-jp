"""P1: 取得層 (fetch.py) の RED テスト。

ネットワークは FakeTransport / resolver 注入でスタブする。
R5: 通常ブラウザより厳格な防御 (添付・非 HTML 読み捨て、SSRF 拒否、スキーム制限) を検証。
"""
import pytest

from fetch import (
    ALLOWED_CONTENT_TYPES,
    BlockedURL,
    FetchError,
    TooManyRedirects,
    USER_AGENTS,
    fetch,
    sanitize_html,
    host_is_private,
)


class FakeResponse:
    def __init__(self, url, status=200, headers=None, body=b""):
        self.url = url
        self.status = status
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.body = body


class FakeTransport:
    """呼ばれた回数とヘッダを記録する。応答は事前に積んだリストから返す。"""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def open(self, url, *, method="GET", headers=None, timeout=20.0):
        self.calls.append({"url": url, "method": method, "headers": dict(headers or {}),
                           "timeout": timeout})
        if not self.responses:
            raise AssertionError("FakeTransport ran out of queued responses")
        return self.responses.pop(0)


def public_resolver(host):
    return ["93.184.216.34"]


HTML = b"<html><head><title>t</title></head><body>hello <script>x()</script></body></html>"


def ok(body=HTML, headers=None, url="https://shop.example/item"):
    h = {"Content-Type": "text/html; charset=UTF-8"}
    h.update(headers or {})
    return [FakeResponse(url, 200, h, body)]


# ---- 正常系 ----

def test_fetch_returns_text_for_html():
    r = fetch("https://shop.example/item", transport=FakeTransport(ok()), resolver=public_resolver)
    assert r.status == 200
    assert "hello" in r.body
    assert r.discarded is False
    assert r.final_url == "https://shop.example/item"


def test_fetch_never_sends_cookie_or_auth_headers():
    t = FakeTransport(ok())
    fetch("https://shop.example/item", transport=t, resolver=public_resolver)
    sent = {k.lower() for k in t.calls[0]["headers"]}
    assert not (sent & {"cookie", "authorization", "proxy-authorization"})
    assert "user-agent" in sent


def test_default_ua_is_browser_and_three_ua_variants_exist():
    assert set(USER_AGENTS) == {"browser", "googlebot", "bingbot"}
    t = FakeTransport(ok())
    fetch("https://shop.example/", transport=t, resolver=public_resolver)
    assert t.calls[0]["headers"]["User-Agent"] == USER_AGENTS["browser"]
    t2 = FakeTransport(ok())
    fetch("https://shop.example/", transport=t2, resolver=public_resolver, ua="googlebot")
    assert t2.calls[0]["headers"]["User-Agent"] == USER_AGENTS["googlebot"]


def test_unknown_ua_key_raises():
    with pytest.raises(ValueError):
        fetch("https://shop.example/", transport=FakeTransport(ok()),
              resolver=public_resolver, ua="nope")


def test_shift_jis_is_decoded_as_cp932():
    body = "<html><body>ジャンク品</body></html>".encode("cp932")
    r = fetch("https://shop.example/", transport=FakeTransport(
        ok(body, {"Content-Type": "text/html; charset=Shift_JIS"})), resolver=public_resolver)
    assert "ジャンク品" in r.body
    assert r.charset == "cp932"


def test_charset_meta_sniffed_when_header_missing():
    body = '<html><head><meta charset="shift_jis"></head><body>中古</body></html>'.encode("cp932")
    r = fetch("https://shop.example/", transport=FakeTransport(ok(body, {"Content-Type": "text/html"})),
              resolver=public_resolver)
    assert "中古" in r.body
    assert r.charset == "cp932"


def test_redirect_chain_is_recorded_and_final_url_returned():
    chain = [
        FakeResponse("https://shop.example/", 301, {"Location": "https://shop.example/item"}, b""),
        FakeResponse("https://shop.example/item", 200, {"Content-Type": "text/html"}, HTML),
    ]
    r = fetch("https://shop.example/", transport=FakeTransport(chain), resolver=public_resolver)
    assert r.final_url == "https://shop.example/item"
    assert [s for s, _ in r.chain] == [301, 200]


def test_language_header_and_no_execution_surface():
    r = fetch("https://shop.example/", transport=FakeTransport(ok()), resolver=public_resolver)
    assert "<script" not in r.html_sanitized
    assert "onerror" not in r.html_sanitized


# ---- セキュリティ: スキーム / ポート / SSRF ----

@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "ftp://shop.example/x",
    "javascript:alert(1)",
    "data:text/html,<b>x</b>",
    "gopher://shop.example/",
    "//shop.example/x",
])
def test_disallowed_schemes_are_blocked(url):
    with pytest.raises(BlockedURL):
        fetch(url, transport=FakeTransport(ok()), resolver=public_resolver)


@pytest.mark.parametrize("url", [
    "http://shop.example:8080/x",
    "https://shop.example:22/x",
    "http://shop.example:3306/x",
])
def test_nonstandard_ports_are_blocked(url):
    with pytest.raises(BlockedURL):
        fetch(url, transport=FakeTransport(ok()), resolver=public_resolver)


@pytest.mark.parametrize("host", [
    "127.0.0.1", "10.0.0.5", "172.16.9.9", "192.168.1.10", "169.254.169.254",
    "100.64.0.1", "0.0.0.0", "::1", "fc00::1", "fe80::1",
])
def test_private_literal_hosts_are_blocked(host):
    with pytest.raises(BlockedURL):
        fetch(f"http://{host}/x", transport=FakeTransport(ok()), resolver=public_resolver)


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "172.20.0.1", "192.168.0.1",
                                "169.254.169.254", "100.100.0.1", "::1", "fd00::1", "93.184.216.34"])
def test_host_is_private_classification(ip):
    expected_private = not ip.startswith("93.")
    assert host_is_private(ip) is expected_private


def test_hostname_resolving_to_private_ip_is_blocked():
    with pytest.raises(BlockedURL):
        fetch("http://rebind.example/x", transport=FakeTransport(ok()),
              resolver=lambda h: ["127.0.0.1"])


def test_private_allowed_only_with_explicit_flag():
    r = fetch("http://127.0.0.1:8000/x", transport=FakeTransport(ok()),
              resolver=lambda h: ["127.0.0.1"], allow_private=True)
    assert r.status == 200


def test_redirect_to_private_ip_is_blocked():
    chain = [
        FakeResponse("https://shop.example/", 302, {"Location": "http://127.0.0.1/admin"}, b""),
    ]
    with pytest.raises(BlockedURL):
        fetch("https://shop.example/", transport=FakeTransport(chain), resolver=public_resolver)


def test_redirect_to_disallowed_scheme_is_blocked():
    chain = [FakeResponse("https://shop.example/", 302, {"Location": "ftp://evil/x"}, b"")]
    with pytest.raises(BlockedURL):
        fetch("https://shop.example/", transport=FakeTransport(chain), resolver=public_resolver)


def test_too_many_redirects_raises():
    chain = [FakeResponse(f"https://shop.example/{i}", 302,
                          {"Location": f"https://shop.example/{i+1}"}, b"") for i in range(9)]
    with pytest.raises(TooManyRedirects):
        fetch("https://shop.example/", transport=FakeTransport(chain),
              resolver=public_resolver, max_redirects=3)


# ---- セキュリティ: 添付・非テキストの読み捨て ----

def test_binary_content_type_body_is_discarded():
    for ct in ("application/octet-stream", "application/pdf", "application/zip",
               "image/png", "application/x-msdownload"):
        r = fetch("https://shop.example/f.bin", transport=FakeTransport(
            ok(b"\x00\x01\x02binary", {"Content-Type": ct, "Content-Length": "8"})),
            resolver=public_resolver)
        assert r.body is None, ct
        assert r.discarded is True
        assert r.discard_reason.startswith("content-type")


def test_attachment_disposition_is_discarded():
    r = fetch("https://shop.example/x.exe", transport=FakeTransport(
        ok(b"MZ\x90\x00", {"Content-Type": "application/x-msdownload; "
                           "name=\"x.exe\"", "Content-Disposition": "attachment; filename=x.exe"})),
        resolver=public_resolver)
    assert r.body is None and r.discarded is True
    assert r.discard_reason == "content-disposition:attachment"


def test_attachment_disposition_discards_even_html():
    r = fetch("https://shop.example/x.html", transport=FakeTransport(
        ok(HTML, {"Content-Disposition": "attachment; filename=x.html"})), resolver=public_resolver)
    assert r.body is None and r.discarded is True


def test_allowed_content_types_set():
    assert "text/html" in ALLOWED_CONTENT_TYPES and "application/json" in ALLOWED_CONTENT_TYPES
    assert "application/x-msdownload" not in ALLOWED_CONTENT_TYPES


def test_oversized_body_is_truncated_not_kept():
    body = b"A" * 5000
    r = fetch("https://shop.example/big", transport=FakeTransport(
        ok(body, {"Content-Type": "text/html"})), resolver=public_resolver, max_bytes=1024)
    assert r.truncated is True
    assert len(r.body.encode(r.charset or "utf-8")) <= 1024
    assert r.raw_bytes == 5000


def test_content_length_header_over_limit_is_discarded_early():
    r = fetch("https://shop.example/big", transport=FakeTransport(
        ok(b"", {"Content-Type": "text/html", "Content-Length": str(99_000_000)})),
        resolver=public_resolver, max_bytes=1024)
    assert r.discarded is True
    assert r.discard_reason == "content-length"
    assert r.body is None


def test_transport_error_is_wrapped():
    class Boom:
        def open(self, url, **kw):
            raise OSError("connection refused")

    with pytest.raises(FetchError):
        fetch("https://shop.example/", transport=Boom(), resolver=public_resolver)


def test_timeout_is_passed_to_transport():
    t = FakeTransport(ok())
    fetch("https://shop.example/", transport=t, resolver=public_resolver, timeout=7.5)
    assert t.calls[0]["timeout"] == 7.5


# ---- サニタイズ ----

@pytest.mark.parametrize("snippet", [
    "<script>alert(1)</script>", "<iframe src=//evil></iframe>",
    "<object data=x></object>", "<embed src=x>", "<applet code=x></applet>",
    "<meta http-equiv=refresh content='0;url=http://evil'>",
])
def test_dangerous_blocks_removed(snippet):
    out = sanitize_html(f"<div>ok</div>{snippet}<p>after</p>")
    assert "ok" in out and "after" in out
    for bad in ("<script", "<iframe", "<object", "<embed", "<applet", "http-equiv"):
        assert bad not in out


def test_inline_event_handlers_removed():
    out = sanitize_html('<a href="x" onclick="evil()" onerror="x">link</a>')
    assert "onclick" not in out and "onerror" not in out
    assert "link" in out


def test_javascript_href_neutralised():
    out = sanitize_html('<a href="javascript:alert(1)">x</a>')
    assert "javascript:" not in out


def test_link_and_img_src_are_preserved_for_features():
    out = sanitize_html('<a href="https://shop.example/p">p</a>'
                        '<img src="https://image.rakuten.co.jp/x.jpg">')
    assert "https://shop.example/p" in out
    assert "https://image.rakuten.co.jp/x.jpg" in out
