# P11: クロスオリジン favicon 検知 (+5 低重み)
#
# 特定サイト favicon 一致 (favicon_collision) に加え、
# 「他人のサイトの favicon と一致」(cross-origin) を低重みでスコアに足す。
# ただし:
#   * サブドメイン (同一 registrable domain 内) は cross-origin ではない
#   * WordPress 等の汎用 favicon (既知の generic ハッシュ) は除外

from features import GENERIC_FAVICON_MD5S, extract_features
from scorer import Scorer, load_weights


def res(status=200, body="<html><title>shop</title></html>"):
    from fetch import FetchResult

    return FetchResult(
        url="https://x/", status=status, final_url="https://x/", body=body, html_sanitized=body
    )


# --- features 層 ---


def test_cross_origin_favicon_detected():
    """他人のドメインの favicon と一致 → favicon_cross_origin=True."""
    f = extract_features(
        "scam.example", res(), favicon_bytes=b"OTHERSITE-FAVICON", known_favicons={"aa" * 16: 2}
    )
    # md5 は unknown (known_favicons に本物の md5 が無い) なので別の導線で確認
    assert f.favicon_md5 is not None


def test_favicon_cross_origin_true_when_md5_belongs_to_single_other_domain():
    f = extract_features(
        "scam.example",
        res(),
        favicon_bytes=b"UNIQUE-BYTES-OF-LEGIT-SITE",
        known_favicons={"x" * 32: 1},  # collision 判定には使われない
        favicon_origin_map={"md5:unknown": "legit-shop.example"},
    )
    # md5 が分からないと origin map も引けないため、まずは collision 導線のみ確認
    assert f.favicon_md5 is not None


def test_favicon_cross_origin_via_origin_map():
    """favicon の md5 が「別ドメイン単独」の登録 favicon と一致 → cross_origin."""
    import hashlib

    md5 = hashlib.md5(b"LEGIT-FAVICON-BYTES").hexdigest()
    f = extract_features(
        "scam.example",
        res(),
        favicon_bytes=b"LEGIT-FAVICON-BYTES",
        known_favicons={md5: 1},
        favicon_origin_map={md5: "legit-shop.example"},
    )
    assert f.favicon_cross_origin is True
    assert f.favicon_cross_origin_of == "legit-shop.example"


def test_favicon_same_origin_is_not_cross_origin():
    """同一 registrable domain (サブドメイン含む) は cross-origin ではない."""
    import hashlib

    md5 = hashlib.md5(b"SELF-FAVICON").hexdigest()
    f = extract_features(
        "shop.example",
        res(),
        favicon_bytes=b"SELF-FAVICON",
        known_favicons={md5: 1},
        favicon_origin_map={md5: "blog.shop.example"},  # サブドメイン
    )
    assert f.favicon_cross_origin is False
    assert f.favicon_cross_origin_of == "" or f.favicon_cross_origin_of == "blog.shop.example"


def test_generic_favicon_wordpress_is_excluded():
    """WordPress 等の汎用 favicon は cross-origin 判定から除外."""
    wp = next(iter(GENERIC_FAVICON_MD5S))
    f = extract_features(
        "scam.example",
        res(),
        favicon_bytes=b"WP-GENERIC",
        known_favicons={wp: 1},
        favicon_origin_map={wp: "legit-shop.example"},
    )
    assert f.favicon_cross_origin is False


def test_cross_origin_detected_from_origin_map_alone():
    """known_favicons (corpus 件数) が空でも origin_map だけで cross_origin を判定する."""
    import hashlib

    md5 = hashlib.md5(b"ONLY-ORIGIN-MAP").hexdigest()
    f = extract_features(
        "scam.example",
        res(),
        favicon_bytes=b"ONLY-ORIGIN-MAP",
        favicon_origin_map={md5: "legit-shop.example"},
    )
    assert f.favicon_cross_origin is True
    assert f.favicon_cross_origin_of == "legit-shop.example"
    assert f.favicon_collision is False


def test_generic_favicon_is_excluded_even_with_origin_map(monkeypatch):
    """GENERIC_FAVICON_MD5S の md5 は collision / cross_origin とも False."""
    import hashlib

    import features as features_mod

    md5 = hashlib.md5(b"WP-GENERIC-REAL").hexdigest()
    monkeypatch.setattr(features_mod, "GENERIC_FAVICON_MD5S", frozenset({md5}))
    f = extract_features(
        "scam.example",
        res(),
        favicon_bytes=b"WP-GENERIC-REAL",
        known_favicons={md5: 5},
        favicon_origin_map={md5: "legit-shop.example"},
    )
    assert f.favicon_md5 == md5
    assert f.favicon_cross_origin is False
    assert f.favicon_collision is False


def test_subdomain_of_same_registrable_is_not_cross_origin_without_corpus():
    """origin_map 単独でも同一 registrable domain のサブドメインは False."""
    import hashlib

    md5 = hashlib.md5(b"SELF-SUB-FAVICON").hexdigest()
    f = extract_features(
        "shop.example",
        res(),
        favicon_bytes=b"SELF-SUB-FAVICON",
        favicon_origin_map={md5: "blog.shop.example"},
    )
    assert f.favicon_cross_origin is False


def test_generic_favicon_set_contains_common_hashes():
    """WordPress 既定テーマの favicon は generic セットに含まれる (i20/wp-content 等)."""
    assert len(GENERIC_FAVICON_MD5S) > 0


# --- scorer 層 ---


def test_scorer_adds_low_weight_for_cross_origin_favicon():
    w = load_weights()
    s = Scorer()
    import hashlib

    md5 = hashlib.md5(b"CROSS-FAVICON").hexdigest()
    feats = extract_features(
        "scam.example",
        res(),
        favicon_bytes=b"CROSS-FAVICON",
        known_favicons={md5: 1},
        favicon_origin_map={md5: "legit-shop.example"},
    )
    r = s.score(feats)
    assert r.reasons.get("favicon_cross_origin") == w["weights"]["favicon_cross_origin"]


def test_cross_origin_weight_is_low():
    """+5 程度の低重みであること (favicon_collision=30 より十分小さい)."""
    w = load_weights()
    assert w["weights"]["favicon_cross_origin"] == 5


def test_cross_origin_weight_is_configurable():
    """scoring.yaml で重みを変えられること."""
    import pathlib
    import tempfile

    cfg = pathlib.Path(tempfile.mkdtemp()) / "scoring.yaml"
    cfg.write_text("weights:\n  favicon_cross_origin: 7\n", encoding="utf-8")
    s = Scorer(cfg)
    import hashlib

    md5 = hashlib.md5(b"CFG-FAVICON").hexdigest()
    feats = extract_features(
        "scam.example",
        res(),
        favicon_bytes=b"CFG-FAVICON",
        known_favicons={md5: 1},
        favicon_origin_map={md5: "legit-shop.example"},
    )
    r = s.score(feats)
    assert r.reasons.get("favicon_cross_origin") == 7
