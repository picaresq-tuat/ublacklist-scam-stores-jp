"""P4: ゴールデンセット回帰 (安全弁)。

2026-09-24 実測の 40 ドメイン (既知詐欺 20 / 型番検索でヒットした正規 20) に対する
ページスコアの再現率と偽陽性を固定する。ここが落ちたら重み変更は差し戻し。

実測結果:
  scam : auto_block 18/20 (残り2件は既にドメインが死んでいる/プレースホルダ)
  legit: auto_block 0/20, hold 3/20
"""

import pytest
from scorer import Scorer

RECALL_MIN = 18  # / 20
LEGIT_FP_MAX = 0  # auto_block に到達してはならない
LEGIT_HOLD_MAX = 3  # 保留域までは許容 (人手承認で弾く)


@pytest.fixture(scope="module")
def scored(golden):
    s = Scorer()
    scam = {d: s.score(golden.features[d]) for d in golden.scam() if d in golden.features}
    legit = {d: s.score(golden.features[d]) for d in golden.legit() if d in golden.features}
    return scam, legit


def test_golden_fixture_covers_recorded_domains(golden):
    assert golden.recorded_at, "ゴールデンセットの採取日時が空"
    assert len(golden.features) >= 35, golden.unscorable()
    assert len(golden.scam()) == 20
    assert len(golden.legit()) == 20


def test_three_legit_domains_are_unreachable_and_documented(golden):
    """到達不能だった 3 件は記憶ではなく記録として残す。"""
    assert set(golden.unscorable()) == {"biccamera.com", "heeeee.jp", "dospara.co.jp"}
    for domain, err in golden.probe_errors.items():
        assert domain in golden.unscorable()
        assert "FetchError" in err


def test_recall_on_known_scam_domains(scored):
    scam, _ = scored
    blocked = [d for d, r in scam.items() if r.verdict == "auto_block"]
    assert len(blocked) >= RECALL_MIN, (
        f"再現率低下: {len(blocked)}/{len(scam)} のみ auto_block; "
        f"未検出={sorted(set(scam) - set(blocked))}"
    )


def test_scam_median_score_is_high(scored):
    scam, _ = scored
    totals = sorted(r.total for r in scam.values())
    median = totals[len(totals) // 2]
    assert median >= 30, f"詐欺ドメインのスコア中央値が低すぎる: {median}"


def test_legit_domains_never_auto_block(scored):
    _, legit = scored
    fp = [d for d, r in legit.items() if r.verdict == "auto_block"]
    assert len(fp) <= LEGIT_FP_MAX, f"偽陽性: {[(d, legit[d].total) for d in fp]}"


def test_legit_hold_count_is_bounded(scored):
    _, legit = scored
    holds = [d for d, r in legit.items() if r.verdict == "hold"]
    assert len(holds) <= LEGIT_HOLD_MAX, f"保留域が多すぎる: {sorted(holds)}"


def test_legit_median_score_is_low(scored):
    _, legit = scored
    totals = sorted(r.total for r in legit.values())
    median = totals[len(totals) // 2]
    assert median <= 12, f"正規ドメインのスコア中央値が高すぎる: {median}"


def test_measured_cluster_is_fully_detected(scored):
    """実測の最大クラスタ (*.hika-jp.casa 17 件) は全件検出できること。"""
    scam, _ = scored
    cluster = [d for d in scam if d.endswith("hika-jp.casa")]
    assert len(cluster) == 17
    for d in cluster:
        assert scam[d].verdict == "auto_block", d
        assert "favicon_collision" in scam[d].reasons, d
        assert "zencart" in scam[d].reasons, d


def test_measured_quervia_detected_without_naive_cloaking(scored):
    """quervia.biz は bot 側が Cloudflare チャレンジ (WAF) なので cloaking では拾わない。

    それでも ZenCart 構造 + 盗用画像 + TLD で auto_block に到達することを固定する。
    """
    scam, _ = scored
    r = scam["abpvdb.quervia.biz"]
    assert r.verdict == "auto_block", r.reasons
    assert "cloaking" not in r.reasons, "WAF チャレンジを cloaking と誤認している"
    assert r.reasons["zencart"] == 10
    assert r.reasons["stolen_image"] == 8
    assert r.reasons["risky_tld"] == 8


def test_legit_stores_are_not_flagged_for_zencart(scored):
    """正規通販 (楽天系モール等) を ZenCart 判定で巻き込んでいないこと。"""
    _, legit = scored
    for d, r in legit.items():
        assert "zencart" not in r.reasons, (d, r.reasons)


def test_score_gap_between_classes(scored):
    scam, legit = scored
    scam_min_blocked = min(r.total for r in scam.values() if r.verdict == "auto_block")
    legit_max = max(r.total for r in legit.values())
    assert scam_min_blocked > legit_max, (scam_min_blocked, legit_max)


def test_all_reasons_are_known_weights(scored):
    from scorer import load_weights

    w = load_weights()
    scam, legit = scored
    known = set(w["weights"]) | {"dark_pattern", "page_max", "general_hits", "pivot_hits"}
    for r in list(scam.values()) + list(legit.values()):
        assert set(r.reasons) <= known, set(r.reasons) - known
