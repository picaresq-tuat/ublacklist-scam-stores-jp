"""whitelist の誤検知追加・大規模拡充・公式エイリアス対応の RED テスト。"""

from __future__ import annotations

import whitelist as wl
from whitelist import ALIASES, SEED, Whitelist, WhitelistDB

# 2026-10-27 に運用者が誤検知として報告した 3 件。
REPORTED_FALSE_POSITIVES: tuple[str, ...] = (
    "yahoo.jp",
    "dailymotion.com",
    "jsmjapan.com",
)


def _db(tmp_path):
    return WhitelistDB(tmp_path / "whitelist.db")


# --- 誤検知の取り込み ---


def test_reported_false_positives_are_in_seed() -> None:
    for domain in REPORTED_FALSE_POSITIVES:
        assert domain in SEED, domain


def test_reported_false_positives_match_with_subdomains(tmp_path) -> None:
    guard = Whitelist(SEED)
    assert guard.match("yahoo.jp") == "yahoo.jp"
    assert guard.match("https://www.yahoo.jp/") == "yahoo.jp"
    assert guard.match("cdn.dailymotion.com") == "dailymotion.com"
    assert guard.match("jsmjapan.com") == "jsmjapan.com"

    db = _db(tmp_path)
    db.load_seed()
    assert db.match("yahoo.jp") is not None
    assert db.match("www.dailymotion.com") is not None
    assert db.match("www.jsmjapan.com") is not None


def test_reported_false_positives_do_not_leak_lookalikes() -> None:
    guard = Whitelist(SEED)
    assert guard.match("yahoo.jp.evil.example") is None
    assert guard.match("notyahoo.jp") is None
    assert guard.match("dailymotion.com.evil.example") is None
    assert guard.match("jsmjapan.com.evil.example") is None


# --- 200 ドメイン規模への拡充 ---


def test_seed_has_around_two_hundred_domains() -> None:
    assert len(set(SEED)) >= 200, len(set(SEED))


def test_expanded_seed_covers_major_legit_sites(tmp_path) -> None:
    db = _db(tmp_path)
    db.load_seed()
    for domain, category in (
        ("amazon.co.jp", "aggregator"),
        ("rakuten.co.jp", "aggregator"),
        ("yodobashi.com", "official_store"),
        ("nhk.or.jp", "news_media"),
        ("asahi.com", "news_media"),
        ("hatena.ne.jp", "blog_platform"),
        ("intel.com", "vendor_support"),
        ("nojima.co.jp", "official_store"),
        ("geo-online.co.jp", "used_store"),
    ):
        assert db.match(domain) == category, domain


def test_expanded_seed_still_never_matches_scam_golden(tmp_path) -> None:
    import json
    from pathlib import Path

    db = _db(tmp_path)
    db.load_seed()
    golden = json.loads(
        (Path(__file__).resolve().parent / "golden" / "domains.json").read_text(encoding="utf-8")
    )
    leaked = [(e["domain"], db.match(e["domain"])) for e in golden["scam"] if db.match(e["domain"])]
    assert leaked == [], leaked


# --- 大手サイトの公式エイリアス ---


def test_aliases_reference_seed_canonicals() -> None:
    assert ALIASES, "ALIASES must not be empty"
    for canonical, aliases in ALIASES.items():
        assert canonical in SEED, canonical
        assert aliases, canonical
        for alias in aliases:
            assert alias != canonical, alias
            assert alias not in SEED, f"{alias} must stay an alias of {canonical}"


def test_whitelist_alone_covers_official_aliases() -> None:
    """hunter は Whitelist(SEED) を直接使う。DB を経由せずとも別名が効くこと。"""
    guard = Whitelist(SEED)
    assert guard.match("yahoo.jp") == "yahoo.jp"
    assert guard.match("www.yahoo.com") == "yahoo.com"
    assert guard.match("www.rakuten.com") == "rakuten.com"
    assert guard.match("www.amazon.jp") == "amazon.jp"
    assert guard.match("www.apple.co.jp") == "apple.co.jp"
    assert guard.match("www.dmm.com") == "dmm.com"
    assert guard.match("www.dai.ly") == "dai.ly"
    assert guard.match("www.wikipedia.com") == "wikipedia.com"


def test_aliases_keep_the_canonical_category_in_db(tmp_path) -> None:
    db = _db(tmp_path)
    db.load_seed()
    assert db.match("www.yahoo.jp") == "aggregator"
    assert db.match("www.dmm.com") == "aggregator"
    assert db.match("www.apple.co.jp") == "vendor_support"
    assert db.match("www.dai.ly") == "blog_platform"

    sources = {
        str(row[0])
        for row in db._con.execute("SELECT domain FROM whitelist WHERE source LIKE 'alias:%'")
    }
    assert {"dmm.com", "apple.co.jp", "dai.ly"} <= sources
    # 報告済み誤検知の yahoo.jp は canonical (seed) として登録する。
    row = db._con.execute("SELECT source FROM whitelist WHERE domain='yahoo.jp'").fetchone()
    assert row is not None and str(row[0]) == "seed"


def test_alias_matching_is_label_bounded() -> None:
    guard = Whitelist(SEED)
    assert guard.match("yahoo.com.evil.example") is None
    assert guard.match("notyahoo.com") is None
    assert guard.match("apple.co.jp.evil.example") is None
    assert guard.match("dai.ly.evil.example") is None


def test_published_lists_do_not_contain_reported_false_positives() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    for rel in ("uBlacklist.txt", "cloaking_detected/uBlacklist.txt"):
        text = (root / rel).read_text(encoding="utf-8")
        for domain in REPORTED_FALSE_POSITIVES:
            assert f"*://*.{domain}/*" not in text, (rel, domain)


def test_seed_loading_is_idempotent_with_aliases(tmp_path) -> None:
    db = _db(tmp_path)
    first = db.load_seed()
    count = db.count()
    assert db.load_seed() == 0
    assert db.count() == count
    assert first >= 200
    assert wl.SEED


def test_alias_targets_are_normalised() -> None:
    for canonical, aliases in ALIASES.items():
        assert wl.normalise_host(canonical) == canonical
        for alias in aliases:
            assert wl.normalise_host(alias) == alias
