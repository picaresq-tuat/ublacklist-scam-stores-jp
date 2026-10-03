# P11b: google.co.jp をホワイトリストに追加
from whitelist import SEED, Whitelist


def test_google_co_jp_is_in_seed():
    assert "google.co.jp" in SEED


def test_google_co_jp_matches():
    wl = Whitelist(SEED)
    assert wl.match("google.co.jp") is not None
    assert wl.match("https://www.google.co.jp/search?q=x") is not None


def test_lookalike_still_not_whitelisted():
    """notgoogle.co.jp 等の見かけ相似は巻き込まない."""
    wl = Whitelist(SEED)
    assert wl.match("notgoogle.co.jp") is None
    assert wl.match("google.co.jp.evil.example") is None
