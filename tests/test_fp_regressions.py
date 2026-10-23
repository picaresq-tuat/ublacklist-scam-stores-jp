"""2026-10-21 報告の誤検知 9 件に対する回帰テスト。

対象: whitelist 追加 / 元リストからの削除 / スコア配分の見直し /
scam と cloaking の重複排除 / 単一企業ブランド TLD の risky_tld 除外。
"""

from pathlib import Path

import cloaking_publish
from features import PageFeatures, is_risky_tld
from scorer import Scorer
from whitelist import SEED, Whitelist
from whois_rdap import RdapInfo

ROOT = Path(__file__).resolve().parent.parent

REPORTED = {
    "chuko-pc-lab.com": "official_store",
    "gemini.google": "vendor_support",
    "tu-han.net": "official_store",
    "accessoires-asus.com": "official_store",
    "bandai-hobby.net": "official_store",
    "deepmind.google": "vendor_support",
    "dmm.co.jp": "aggregator",
    "facebook.com": "blog_platform",
    "k-tai-iosys.com": "used_store",
}


def feat(**kw):
    base = {"domain": "shop.example", "registrable": "shop.example", "tld": "example"}
    base.update(kw)
    return PageFeatures(**base)


def _list_entries(rel: str) -> set[str]:
    text = (ROOT / rel).read_text(encoding="utf-8")
    return set(publish_entries(text))


def publish_entries(text: str) -> list[str]:
    from publish import existing_entries

    return existing_entries(text)


# --- 1. ホワイトリスト ---
def test_all_reported_false_positives_are_in_seed():
    missing = [d for d in REPORTED if d not in SEED]
    assert not missing, missing


def test_whitelist_matches_reported_domains_and_subdomains():
    wl = Whitelist(SEED)
    for d in REPORTED:
        assert wl.match(d) == d, d
        assert wl.match(f"https://www.{d}/path") == d, d


def test_lookalike_of_reported_domain_is_not_whitelisted():
    wl = Whitelist(SEED)
    assert wl.match("gemini.google.evil.example") is None
    assert wl.match("notfacebook.com") is None


# --- 2. 元リストからの削除 ---
def test_reported_false_positives_are_absent_from_both_lists():
    scam = _list_entries("uBlacklist.txt")
    cloaking = _list_entries("cloaking_detected/uBlacklist.txt")
    leaked = [f"{d} in uBlacklist.txt" for d in REPORTED if f"*://*.{d}/*" in scam] + [
        f"{d} in cloaking_detected/uBlacklist.txt" for d in REPORTED if f"*://*.{d}/*" in cloaking
    ]
    assert not leaked, leaked


# --- 3. ブランド TLD ---
def test_single_company_brand_tld_is_not_risky():
    assert is_risky_tld("google") is False
    assert is_risky_tld("gmo") is False
    assert is_risky_tld("youtube") is False


def test_generic_risky_tld_still_fires():
    assert is_risky_tld("casa") is True
    assert is_risky_tld("shop") is True
    assert is_risky_tld("xyz") is True


def test_registrar_url_on_brand_tld_is_not_foreign():
    """実測: 中古 PC 店の RDAP は GMO (https://internet.gmo/) を指す。"""
    info = RdapInfo(domain="chuko-pc-lab.com", ok=True, registrar_url="https://internet.gmo/")
    tld_foreign, _, _ = info.flags("chuko-pc-lab.com")
    assert tld_foreign is False


def test_registrar_url_on_generic_foreign_tld_still_fires():
    info = RdapInfo(domain="x.example", ok=True, registrar_url="https://rdap.registry.click/")
    assert info.flags("x.example")[0] is True


# --- 4. スコア配分 ---
def test_single_heavy_signal_no_longer_auto_blocks():
    """誤検知の主因は「1 シグナルだけで auto_block に到達」していたこと。"""
    s = Scorer()
    cases = {
        "redirect_to_google": feat(redirect_to_google=True),
        "favicon_collision": feat(favicon_collision=True),
        "cloaking_promoted": feat(cloaking=True, status=403),
        "bot_only_body": feat(bot_only_body=True),
    }
    for name, f in cases.items():
        r = s.score(f)
        assert r.verdict == "hold", (name, r.total, r.reasons)
        assert r.total == 18.0, (name, r.total, r.reasons)


def test_combination_of_two_signals_still_auto_blocks():
    s = Scorer()
    assert s.score(feat(redirect_to_google=True, risky_tld=True)).verdict == "auto_block"
    assert s.score(feat(favicon_collision=True, shared_2ld=True)).verdict == "auto_block"
    assert s.score(feat(cloaking=True, status=403, deep_product_path=True)).verdict == "auto_block"


def test_generic_sale_words_alone_do_not_reach_auto_block():
    """tu-han.net 型 (stolen_image + 販促語 3 + deep path) は hold 帯に留まる。

    販促語の重みは 3/hit (cap 9) のまま据え置く。2/hit cap 6 に下げると 96 件
    コーパスの recall が 42 -> 29 に落ちたため、RDAP (registrar URL の brand TLD)
    と whitelist 側で解く。
    """
    s = Scorer()
    assert s.weights["dark_pattern_cap"] == 9
    r = s.score(feat(stolen_image=True, dark_hits=3, deep_product_path=True))
    assert r.total == 19.0 and r.verdict == "hold"


# --- 5. publish の重複排除 ---
def test_cloaking_merge_excludes_domains_published_as_scam():
    text = cloaking_publish.merge_cloaking_list(
        "", ["scam.example", "cloak.example"], exclude=["scam.example"]
    )
    entries = publish_entries(text)
    assert "*://*.cloak.example/*" in entries
    assert "*://*.scam.example/*" not in entries


def test_cloaking_merge_prunes_existing_duplicate_lines():
    existing = cloaking_publish.render_cloaking_list(["scam.example", "cloak.example"])
    text = cloaking_publish.merge_cloaking_list(
        existing, ["cloak.example"], exclude=["scam.example"]
    )
    entries = publish_entries(text)
    assert entries == ["*://*.cloak.example/*"], entries


def test_write_cloaking_list_honours_exclude(tmp_path):
    path = tmp_path / "uBlacklist.txt"
    text = cloaking_publish.write_cloaking_list(
        path, ["scam.example", "cloak.example"], exclude=["scam.example"]
    )
    assert "*://*.cloak.example/*" in text
    assert "*://*.scam.example/*" not in text
