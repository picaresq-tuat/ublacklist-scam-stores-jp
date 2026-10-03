"""P4: スコアラ (重み外部化 / 閾値境界) の RED テスト。"""
from pathlib import Path

import pytest

from features import PageFeatures
from scorer import DEFAULT_CONFIG, Score, Scorer, load_weights


def feat(**kw):
    base = dict(domain="shop.example", registrable="shop.example", tld="example")
    base.update(kw)
    return PageFeatures(**base)


def test_default_config_exists_and_loads():
    w = load_weights(DEFAULT_CONFIG)
    assert w["weights"]["redirect_to_google"] == 35
    assert w["thresholds"]["auto_block"] == 30
    assert w["thresholds"]["hold"] == 12
    assert w["pivot"]["max_queries"] >= 3


def test_weights_come_from_yaml_not_hardcoded(tmp_path):
    cfg = tmp_path / "w.yaml"
    cfg.write_text("version: 1\nweights:\n  risky_tld: 99\nthresholds:\n  auto_block: 5\n"
                   "  hold: 1\n  fast_track: 9\n  zencart_min_hits: 2\n  nights_required: 2\n"
                   "pivot:\n  max_queries: 3\n  hold_trigger: 1\n", encoding="utf-8")
    s = Scorer(config=cfg)
    assert s.score(feat(risky_tld=True)).total == 99


def test_clean_page_scores_zero():
    s = Scorer()
    r = s.score(feat())
    assert isinstance(r, Score)
    assert r.total == 0.0
    assert r.reasons == {}


def test_doorway_plus_favicon_plus_tld_matches_measured_combo():
    """実測スパイクの代表例 (35+30+8+6)。"""
    s = Scorer()
    r = s.score(feat(redirect_to_google=True, favicon_collision=True, risky_tld=True,
                     shared_2ld=True))
    assert r.total == 79.0
    assert "redirect_to_google" in r.reasons
    assert r.reasons["redirect_to_google"] == 35


def test_zencart_requires_min_hits():
    s = Scorer()
    assert s.score(feat(zencart_hits=1)).total == 0.0
    assert s.score(feat(zencart_hits=2)).total == 25.0


def test_zencart_min_hits_is_configurable(tmp_path):
    cfg = tmp_path / "w.yaml"
    cfg.write_text("version: 1\nweights:\n  zencart: 25\nthresholds:\n  auto_block: 30\n  hold: 12\n"
                   "  fast_track: 60\n  zencart_min_hits: 4\n  nights_required: 2\n"
                   "pivot:\n  max_queries: 3\n  hold_trigger: 12\n", encoding="utf-8")
    s = Scorer(config=cfg)
    assert s.score(feat(zencart_hits=3)).total == 0.0
    assert s.score(feat(zencart_hits=4)).total == 25.0


def test_cloaking_promoted_when_bot_only_body():
    s = Scorer()
    plain = s.score(feat(cloaking=True))
    assert plain.reasons["cloaking"] == 12
    assert plain.total == 12.0
    both = s.score(feat(cloaking=True, bot_only_body=True))
    assert both.reasons["cloaking"] == 20
    assert both.reasons_src["cloaking"] == "cloaking_promoted"


def test_bot_only_body_does_not_double_count_cloaking():
    s = Scorer()
    r = s.score(feat(cloaking=True, bot_only_body=True))
    assert r.total == 20.0, r


def test_offsite_redirect_is_subsumed_by_doorway():
    s = Scorer()
    assert s.score(feat(offsite_redirect=True)).total == 10.0
    assert s.score(feat(offsite_redirect=True, redirect_to_google=True)).total == 35.0


def test_dark_pattern_cap():
    s = Scorer()
    assert s.score(feat(dark_hits=1)).total == 3.0
    assert s.score(feat(dark_hits=3)).total == 9.0
    assert s.score(feat(dark_hits=10)).total == 9.0, "上限を超えて加点している"


def test_deep_product_path_and_shared_2ld_and_young_index():
    s = Scorer()
    assert s.score(feat(deep_product_path=True)).total == 2.0
    assert s.score(feat(shared_2ld=True)).total == 6.0
    assert s.score(feat(extra={"young_index": True})).total == 5.0


def test_verdict_exact_thresholds():
    """hold=12 / auto_block=30。allow <12 <= hold <30 <= auto_block。"""
    s = Scorer()
    assert s.score(feat(cloaking=True)).verdict == "hold"           # 12 == hold 下限
    assert s.score(feat(stolen_image=True)).verdict == "hold"       # 15
    assert s.score(feat(zencart_hits=2)).verdict == "hold"          # 25
    assert s.score(feat(favicon_collision=True)).verdict == "auto_block"  # 30 == auto 下限
    assert s.score(feat(redirect_to_google=True)).verdict == "auto_block"  # 35


def test_verdict_allow_below_hold():
    s = Scorer()
    assert s.score(feat()).verdict == "allow"                       # 0
    assert s.score(feat(deep_product_path=True)).verdict == "allow"  # 2
    assert s.score(feat(extra={"young_index": True})).verdict == "allow"  # 5
    assert s.score(feat(shared_2ld=True)).verdict == "allow"        # 6
    assert s.score(feat(risky_tld=True)).verdict == "allow"         # 8
    assert s.score(feat(dark_hits=3)).verdict == "allow"            # 9 (上限)
    assert s.score(feat(offsite_redirect=True)).verdict == "allow"  # 10


def test_fast_track_flag():
    s = Scorer()
    assert s.score(feat(redirect_to_google=True, favicon_collision=True,
                        risky_tld=True, shared_2ld=True)).fast_track is True
    assert s.score(feat(offsite_redirect=True)).fast_track is False


def test_explain_returns_sorted_reason_lines():
    s = Scorer()
    r = s.score(feat(redirect_to_google=True, dark_hits=2, risky_tld=True))
    text = r.explain()
    assert "redirect_to_google" in text and "+35" in text
    assert text.index("redirect_to_google") < text.index("dark_pattern")


def test_score_is_json_friendly():
    import json
    s = Scorer()
    r = s.score(feat(redirect_to_google=True))
    d = json.loads(json.dumps(r.to_dict()))
    assert d["total"] == 35.0 and d["verdict"] == "auto_block"


def test_domain_score_combines_occurrences_and_pivots():
    s = Scorer()
    a = s.score(feat(risky_tld=True))              # 8
    b = s.score(feat(dark_hits=3))                 # 9
    dom = s.domain_score("shop.example", [a, b], pivot_hits=3, general_hits=2)
    assert dom.total == 9 + 6 + 3, dom
    assert dom.verdict == "hold"


def test_domain_score_verdict_and_evidence():
    s = Scorer()
    a = s.score(feat(redirect_to_google=True))     # 35
    dom = s.domain_score("shop.example", [a], pivot_hits=0, general_hits=1)
    assert dom.total == 35 + 3
    assert dom.verdict == "auto_block"
    assert dom.evidence["pages_scored"] == 1
    assert dom.evidence["pivot_hits"] == 0


def test_multiple_pages_take_max_not_sum():
    s = Scorer()
    a = s.score(feat(risky_tld=True))              # 8
    b = s.score(feat(risky_tld=True))              # 8
    dom = s.domain_score("x.casa", [a, b], pivot_hits=0, general_hits=0)
    assert dom.total == 8.0, "同一ページスコアを合算している"
