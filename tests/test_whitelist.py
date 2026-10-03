"""P6a: ホワイトリスト (triage ゲート) の RED テスト。"""
import pytest

from whitelist import CATEGORIES, Whitelist, WhitelistDB


def wl(tmp_path):
    return WhitelistDB(tmp_path / "whitelist.db")


def test_categories_are_the_defined_ones():
    assert set(CATEGORIES) == {
        "vendor_support", "official_store", "used_store",
        "news_media", "blog_platform", "favicon_reference", "aggregator",
    }


def test_seed_csv_loads_expected_majors(tmp_path):
    db = wl(tmp_path)
    n = db.load_seed()
    assert n >= 60, n
    assert db.count() == n


def test_exact_and_subdomain_match(tmp_path):
    db = wl(tmp_path)
    db.load_seed()
    assert db.match("panasonic.jp") == "vendor_support"
    assert db.match("www.janpara.co.jp") == "used_store"
    assert db.match("shop.askul.co.jp") is not None


def test_unknown_domain_is_not_matched(tmp_path):
    db = wl(tmp_path)
    db.load_seed()
    assert db.match("card.hika-jp.casa") is None
    assert db.match("abpvdb.quervia.biz") is None


def test_suffix_lookalike_is_not_matched(tmp_path):
    """`notpanasonic.jp` や `panasonic.jp.evil.com` を巻き込まないこと。"""
    db = wl(tmp_path)
    db.load_seed()
    assert db.match("notpanasonic.jp") is None
    assert db.match("panasonic.jpx") is None
    assert db.match("www.panasonic.co.jp") == "vendor_support"


def test_seed_domains_are_never_the_known_scam_cluster(tmp_path):
    db = wl(tmp_path)
    db.load_seed()
    from whitelist import SEED
    joined = " ".join(SEED)
    for bad in ("hika-jp", "quervia", "sagidame"):
        assert bad not in joined


def test_seed_covers_all_measured_legit_domains(tmp_path):
    """2026-09-24 のゴールデン採取で「正規」と確認した 20 件を triage が除外できること。"""
    import json
    from pathlib import Path
    db = wl(tmp_path)
    db.load_seed()
    golden = json.loads(
        (Path(__file__).resolve().parent / "golden" / "domains.json").read_text(encoding="utf-8"))
    uncovered = [e["domain"] for e in golden["legit"] if not db.match(e["domain"])]
    assert uncovered == [], uncovered


def test_no_measured_scam_domain_is_whitelisted(tmp_path):
    import json
    from pathlib import Path
    db = wl(tmp_path)
    db.load_seed()
    golden = json.loads(
        (Path(__file__).resolve().parent / "golden" / "domains.json").read_text(encoding="utf-8"))
    leaked = [(e["domain"], db.match(e["domain"])) for e in golden["scam"] if db.match(e["domain"])]
    assert leaked == [], leaked


def test_add_and_remove(tmp_path):
    db = wl(tmp_path)
    db.load_seed()
    before = db.count()
    assert db.add("example.test", "official_store", source="manual") is True
    assert db.add("example.test", "official_store", source="manual") is False
    assert db.count() == before + 1
    assert db.match("www.example.test") == "official_store"
    assert db.remove("example.test") is True
    assert db.match("www.example.test") is None


def test_invalid_category_rejected(tmp_path):
    db = wl(tmp_path)
    with pytest.raises(ValueError):
        db.add("example.test", "not_a_category")


def test_matching_is_case_and_port_insensitive(tmp_path):
    db = wl(tmp_path)
    db.load_seed()
    assert db.match("WWW.JANPARA.CO.JP:443") == "used_store"
    assert db.match("https://www.janpara.co.jp/item/1") == "used_store"
