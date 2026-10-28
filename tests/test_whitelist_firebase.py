# P11c: Firebase Hosting (web.app) をホワイトリストに追加
#
# web.app は Google が運営する Firebase Hosting の共有基盤で、
# `project.web.app` 形式の全サブドメインが同一 2LD を共有する。
# ホワイトリストはラベル境界の末尾一致なので、`web.app` を 1 件入れれば
# サブドメイン全体を覆える (前方一致・部分一致には広がらない)。

import whitelist
from whitelist import SEED, Whitelist


def test_web_app_is_in_seed():
    assert "web.app" in SEED


def test_web_app_category_is_platform_not_store():
    """共有ホスティング基盤なので blog_platform に置く (公式ストアではない)."""
    assert whitelist._EXPLICIT_CATEGORIES.get("web.app") == "blog_platform"


def test_web_app_and_its_subdomains_match():
    wl = Whitelist(SEED)
    assert wl.match("web.app") == "web.app"
    assert wl.match("my-project.web.app") == "web.app"
    assert wl.match("https://my-project.web.app/index.html?x=1") == "web.app"


def test_web_app_lookalikes_are_not_whitelisted():
    """`web.app` を部分文字列に含むだけの別ドメインは巻き込まない."""
    wl = Whitelist(SEED)
    assert wl.match("web.app.evil.example") is None
    assert wl.match("notweb.app") is None
    assert wl.match("web-app.example") is None


def test_web_app_is_counted_once_in_seed():
    """タプルへの重複追加で whitelist.db の行数が水増しされないこと."""
    assert SEED.count("web.app") == 1
