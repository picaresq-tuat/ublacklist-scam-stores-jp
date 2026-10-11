"""P3: 特徴量抽出 (features.py) の RED テスト。"""

from features import (
    DARK_PATTERN_TERMS,
    RISKY_TLDS,
    STORE_ASSET_HOSTS,
    ZENCART_MARKERS,
    PageFeatures,
    extract_features,
    registrable_domain,
)

HTML_BASE = """
<html><head><title>中古PC販売</title>
<link rel="icon" href="/favicon.ico"></head>
<body>
<img src="https://image.rakuten.co.jp/shop/x.jpg">
<a href="/product/123456">商品</a>
<div>タイムセール 80%OFF 送料無料 在庫限り</div>
<div>index.php?main_page=product_info&products_id=9</div>
<div>zenid=abc; manufacturers_id=3; template_default</div>
</body></html>
"""


def res(
    url="https://shop.example/item",
    body=HTML_BASE,
    status=200,
    headers=None,
    chain=None,
    charset="utf-8",
    discarded=False,
):
    from fetch import FetchResult

    chain = chain or [(status, url)]
    return FetchResult(
        url=url,
        status=status,
        final_url=chain[-1][1],
        chain=chain,
        headers=headers or {"content-type": "text/html"},
        body=body,
        html_sanitized=body,
        charset=charset,
        discarded=discarded,
        raw_bytes=len(body or ""),
    )


def test_registrable_domain():
    assert registrable_domain("a.b.hika-jp.casa") == "hika-jp.casa"
    assert registrable_domain("shop.example.co.jp") == "example.co.jp"
    assert registrable_domain("store.vaio.com") == "vaio.com"
    assert registrable_domain("www.dynabook.com") == "dynabook.com"
    assert registrable_domain("localhost") == "localhost"


def test_extract_returns_pagefeatures_object():
    f = extract_features("shop.example", res())
    assert isinstance(f, PageFeatures)
    assert f.domain == "shop.example"
    assert f.registrable == "shop.example"


def test_title_and_lengths():
    f = extract_features("shop.example", res())
    assert f.title == "中古PC販売"
    assert f.body_len > 0


def test_zencart_markers_counted_from_constants():
    f = extract_features("shop.example", res())
    for m in ("main_page=", "products_id=", "zenid=", "manufacturers_id", "template_default"):
        assert m in ZENCART_MARKERS
    assert f.zencart_hits >= 4


def test_dark_pattern_terms_and_hits():
    f = extract_features("shop.example", res())
    assert {"タイムセール", "在庫限り", "%OFF"} <= set(DARK_PATTERN_TERMS)
    assert f.dark_hits >= 3


def test_stolen_image_detected_from_store_hosts():
    f = extract_features("shop.example", res())
    assert any("rakuten" in h for h in STORE_ASSET_HOSTS)
    assert f.stolen_image is True
    assert f.n_img == 1


def test_no_stolen_image_for_relative_src():
    f = extract_features("shop.example", res(body='<html><body><img src="/i/x.jpg"></body></html>'))
    assert f.stolen_image is False
    assert f.n_img == 1


def test_tld_and_risky_flag():
    assert extract_features("shop.example", res()).tld == "example"
    assert extract_features("shop.example", res()).risky_tld is False
    for d in ("x.casa", "x.shop", "x.love", "x.click", "x.xyz", "x.top"):
        assert extract_features(d, res()).risky_tld is True, d
    assert extract_features("shop.co.jp", res()).risky_tld is False
    assert "casa" in RISKY_TLDS


def test_offsite_redirect_flag():
    f = extract_features(
        "shop.example", res(chain=[(301, "https://shop.example/"), (200, "https://other.example/")])
    )
    assert f.offsite_redirect is True
    assert f.redirect_to_google is False


def test_redirect_to_search_engine_flagged():
    f = extract_features(
        "shop.example",
        res(chain=[(302, "https://shop.example/"), (200, "https://www.google.com/")]),
    )
    assert f.redirect_to_google is True


def test_deep_product_path():
    assert (
        extract_features(
            "shop.example", res(body='<html><a href="/product/abc">x</a></html>')
        ).deep_product_path
        is True
    )
    assert (
        extract_features("shop.example", res(body="<html>plain</html>")).deep_product_path is False
    )


def test_favicon_hash_from_fixture_bytes():
    f = extract_features("shop.example", res(), favicon_bytes=b"\x89PNG\r\n\x1a\nfake")
    assert f.favicon_md5 is not None and len(f.favicon_md5) == 32
    assert (
        f.favicon_md5
        == extract_features("s.example", res(), favicon_bytes=b"\x89PNG\r\n\x1a\nfake").favicon_md5
    )


def test_favicon_absent_gives_none():
    f = extract_features("shop.example", res(), favicon_bytes=None)
    assert f.favicon_md5 is None


def test_cloaking_requires_title_gap_and_length_ratio():
    a = res(body="<html><head><title>A</title></head><body>" + "x" * 1000 + "</body></html>")
    b = res(body="<html><head><title>B</title></head><body>" + "y" * 100 + "</body></html>")
    f = extract_features("shop.example", browser=a, bot=b)
    assert f.cloaking is True
    assert f.bot_only_body is False


def test_title_only_difference_is_not_cloaking():
    a = res(body="<html><head><title>A</title></head><body>" + "x" * 1000 + "</body></html>")
    b = res(body="<html><head><title>B</title></head><body>" + "x" * 1000 + "</body></html>")
    assert extract_features("shop.example", browser=a, bot=b).cloaking is False


def test_bot_only_body_when_browser_denied():
    a = res(status=403, body="", headers={"content-type": "text/html"})
    b = res(body="<html>" + "z" * 500 + "</html>")
    f = extract_features("shop.example", browser=a, bot=b)
    assert f.bot_only_body is True
    # 実バグ回帰: 非 200 (拒否ページ) は cloaking としない。拒否は bot_only_body 側の
    # 信号であり、cloaking は「双方が 200 で応答し内容が違う」ことを指す。
    assert f.cloaking is False


def test_browser_served_binary_and_bot_served_html_is_cloaking():
    """ブラウザには添付/非 HTML を返し bot には HTML を返す = クローキングの強い証拠。"""
    a = res(status=200, discarded=True, body=None)
    b = res(body="<html>" + "z" * 500 + "</html>")
    f = extract_features("shop.example", browser=a, bot=b)
    assert f.cloaking is True
    assert f.bot_only_body is True


def test_waf_challenge_page_is_not_bot_content():
    """Cloudflare のチャレンジ/拒否ページは bot への本文提示ではない (実測: quervia.biz)。"""
    a = res(
        body="<html><head><title>安心・安全なお届け！</title></head>"
        "<body><a href='/index.php?main_page=product_info&products_id=9'>x</a>"
        "</body></html>"
    )
    b = res(
        status=403,
        body="<html><head><title>Attention Required! | Cloudflare</title>"
        "</head><body>" + "z" * 4000 + "</body></html>",
        headers={"content-type": "text/html"},
    )
    f = extract_features("abpvdb.quervia.biz", browser=a, bot=b)
    assert f.cloaking is False
    assert f.bot_only_body is False


def test_own_domain_images_are_not_stolen():
    """自ドメインの画像は盗用ではない (実測: askul.co.jp / suruga-ya.jp の偽陽性)。"""
    body = (
        '<html><body><img src="https://cdn.askul.co.jp/x.png"><img src="/local.png"></body></html>'
    )
    f = extract_features("www.askul.co.jp", res(url="https://www.askul.co.jp/", body=body))
    assert f.n_img == 2
    assert f.stolen_image is False


def test_another_store_host_image_is_stolen():
    body = '<html><body><img src="https://cdn.askul.co.jp/x.png"></body></html>'
    f = extract_features("card.hika-jp.casa", res(url="https://card.hika-jp.casa/", body=body))
    assert f.stolen_image is True


def test_429_rate_limit_is_not_cloaking():
    """ブラウザ側が 429 を返しただけの場合はクローキング扱いにしない (実測: hatenablog)。"""
    a = res(status=429, body="Too Many Requests", headers={"content-type": "text/html"})
    b = res(body="<html><head><title>blog</title></head><body>" + "z" * 4000 + "</body></html>")
    f = extract_features("nisesuka.hatenablog.com", browser=a, bot=b)
    assert f.cloaking is False
    assert f.bot_only_body is False


def test_bot_blocked_by_site_is_not_cloaking():
    """bot 側だけ 403 になるのは「ブロック」であってクローキングではない (実測: janpara)。"""
    a = res(
        body="<html><head><title>じゃんぱら</title></head><body>" + "x" * 300000 + "</body></html>"
    )
    b = res(
        status=403,
        body="<html><title>403 Forbidden</title></html>",
        headers={"content-type": "text/html"},
    )
    f = extract_features("www.janpara.co.jp", browser=a, bot=b)
    assert f.cloaking is False
    assert f.bot_only_body is False


def test_cloaking_requires_bot_side_to_be_usable():
    a = res(body="<html><head><title>A</title></head><body>" + "x" * 1000 + "</body></html>")
    b = res(status=503, body="<html><title>B</title></html>")
    assert extract_features("shop.example", browser=a, bot=b).cloaking is False


def test_tiny_bot_body_is_not_bot_only_body():
    a = res(status=403, body="", headers={"content-type": "text/html"})
    b = res(body="<html><title>Access Denied</title></html>")
    assert extract_features("shop.example", browser=a, bot=b).bot_only_body is False


def test_features_are_json_serialisable():
    import json

    f = extract_features("shop.example", res())
    assert json.loads(json.dumps(f.to_dict()))["domain"] == "shop.example"


def test_every_feature_is_a_plain_type():
    d = extract_features("shop.example", res()).to_dict()
    for k, v in d.items():
        assert isinstance(v, (str, int, float, bool, type(None))), (k, type(v))


def test_extract_never_raises_on_garbage():
    for body in ("", "not html at all", "<html>", "\x00\x01\x02", "<html><body><script>x</script>"):
        f = extract_features("shop.example", res(body=body))
        assert f.domain == "shop.example"


# --- 実バグ回帰: cloaking は「双方が実際に取得できた」ときだけ成立する ---


def _html(title: str, pad: int) -> str:
    return f"<html><head><title>{title}</title></head><body>{'x' * pad}</body></html>"


def test_cloaking_is_false_when_browser_fetch_was_rejected():
    """通常取得が 400 (エラーページ) のとき、bot との差を cloaking と呼ばない。

    実測 (2026-10-11): facebook.com が status=400/title="Error"/1542B を返し、
    bot は 469KB を返した。これは「内容を出し分けた」ではなく
    「我々の通常取得が拒否された」だけ (実バグ) 。
    """
    browser = res(status=400, body=_html("Error", 1500))
    bot = res(status=200, body=_html("Facebook", 460000))
    f = extract_features("facebook.com", browser, bot)
    assert f.cloaking is False


def test_cloaking_is_false_when_browser_fetch_forbidden():
    browser = res(status=403, body=_html("403 Forbidden", 900))
    bot = res(status=200, body=_html("Shop", 60000))
    f = extract_features("waf-shop.example", browser, bot)
    assert f.cloaking is False


def test_cloaking_still_detected_when_both_fetches_succeed():
    """両方 200 で title が違い本文長比 >= 0.3 なら cloaking (機能を壊していない)。"""
    browser = res(status=200, body=_html("Shop A", 1000))
    bot = res(status=200, body=_html("Shop B", 50000))
    f = extract_features("cloaker.example", browser, bot)
    assert f.cloaking is True
    assert f.len_ratio_gap >= 0.3


def test_cloaking_is_false_when_both_fetches_agree():
    browser = res(status=200, body=_html("Shop", 5000))
    bot = res(status=200, body=_html("Shop", 5000))
    f = extract_features("plain.example", browser, bot)
    assert f.cloaking is False
