"""T4: S5 閾値再校正の回帰テスト。

実データ (tests/golden の生レスポンス + logs/spike_s4_signals.json) を
scripts/calib_s5_thresholds.py と同じ経路で採点し、adopt した閾値・重みで
precision (FP=0) と recall の下限を固定する。

数値は logs/calib_s5_sweep.tsv の実測値。ここが落ちたら閾値/重みの変更は差し戻し。
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from scorer import Scorer

ROOT = Path(__file__).resolve().parent.parent

# adopt 値 (script/scoring.yaml と一致させる。判定は実 yaml の閾値で行う)
ADOPTED_AUTO_BLOCK = 20
ADOPTED_STOLEN_IMAGE = 8
ADOPTED_HOLD = 12

# 実測 (2026-10, オフライン再採点, logs/calib_s5_sweep.tsv)
GOLDEN_RECALL_MIN = 18  # / 20 (残り 2 件は特徴量が risky_tld + deep_product_path のみ)
PARTIAL_RECALL_MIN = 45  # / 96 (部分特徴量のみの下限。favicon/cloaking 未計測)
MIN_HEADROOM = 9  # auto_block - max(legit score)。FP=0 が偶然でないための余白
MAX_LEGIT_SCORE = 11.0  # golden / spike_s4 とも 11 (dark 9 + deep 2)
HOLD_FP_MAX = 0  # hold 帯 (12 <= s < auto_block) に入る legit の上限


def _calib():
    spec = importlib.util.spec_from_file_location(
        "calib_s5_thresholds", ROOT / "scripts" / "calib_s5_thresholds.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def rows():
    calib = _calib()
    rdap = calib.load_rdap()
    corpus = calib.golden_corpus(rdap) + calib.partial_corpus(rdap)
    return calib.score_rows(corpus, Scorer())


def _auto_block() -> float:
    return Scorer().thresholds["auto_block"]


def _split(rows, corpus, label=None):
    return [r for r in rows if r["corpus"] == corpus and (label is None or r["label"] == label)]


def test_corpus_is_real_and_non_degenerate(rows):
    """採点対象が実データで、全件 0 点のような空回りでないこと。"""
    golden_scam = _split(rows, "golden", "scam")
    golden_legit = _split(rows, "golden", "legit")
    partial_scam = _split(rows, "spike_s4", "scam")
    partial_legit = _split(rows, "spike_s4", "legit")
    assert len(golden_scam) == 20
    assert len(golden_legit) >= 17, "golden legit の採点対象が少なすぎる"
    assert len(partial_scam) == 96, "scam 96 件コーパスが読めていない"
    assert len(partial_legit) == 25
    assert sum(1 for r in golden_scam if r["score"] > 0) == 20
    assert sum(1 for r in partial_scam if r["score"] > 0) >= 90


def test_golden_legit_never_reaches_auto_block(rows):
    """FP=0 は絶対条件。golden legit は 1 件も auto_block に到達しない。"""
    legit = _split(rows, "golden", "legit")
    blocked = [(r["domain"], r["score"]) for r in legit if r["score"] >= _auto_block()]
    assert blocked == [], f"golden legit の FP: {blocked}"


def test_partial_legit_never_reaches_auto_block(rows):
    """96 件コーパスの legit 25 件でも FP=0 を維持する。"""
    legit = _split(rows, "spike_s4", "legit")
    blocked = [(r["domain"], r["score"]) for r in legit if r["score"] >= _auto_block()]
    assert blocked == [], f"部分特徴量コーパスの FP: {blocked}"


def test_golden_recall(rows):
    scam = _split(rows, "golden", "scam")
    blocked = [r["domain"] for r in scam if r["score"] >= _auto_block()]
    assert len(blocked) >= GOLDEN_RECALL_MIN, f"recall 低下: {sorted(blocked)}"
    # 未検出 2 件は特徴量不足 (risky_tld 8 + deep 2 = 10) で、閾値では救えない。
    missed = sorted({r["domain"] for r in scam} - set(blocked))
    assert missed == ["uplast.bepark.shop", "yuguoyinxi.love"], missed


def test_partial_corpus_recall_lower_bound(rows):
    """96 件コーパスは favicon/cloaking 未計測のため recall は下限値。"""
    scam = _split(rows, "spike_s4", "scam")
    blocked = [r for r in scam if r["score"] >= _auto_block()]
    assert len(blocked) >= PARTIAL_RECALL_MIN, f"{len(blocked)}/96"


def test_class_separation_has_margin(rows):
    """境界が分布の谷にあり、FP=0 が 1 点差の偶然でないこと。"""
    legit_max = max(r["score"] for r in rows if r["label"] == "legit")
    assert _auto_block() - legit_max >= MIN_HEADROOM, (
        f"余白不足: auto_block={_auto_block()} legit_max={legit_max}"
    )
    assert legit_max == MAX_LEGIT_SCORE, f"legit 最大が移動した: {legit_max}"


def test_hold_band_has_no_legit(rows):
    """hold 帯 (hold <= score < auto_block) に正規店が入らないこと。"""
    hold = Scorer().thresholds["hold"]
    hold_fp = [
        (r["domain"], r["score"])
        for r in rows
        if r["label"] == "legit" and hold <= r["score"] < _auto_block()
    ]
    assert len(hold_fp) <= HOLD_FP_MAX, f"hold 帯 FP: {hold_fp}"


def test_scoring_yaml_matches_adopted_values():
    """校正結果が yaml に反映されていること (回帰ピン)。

    Scorer() だけを見るとキーを yaml から消しても _FALLBACK が同値を供給して通る。
    ここは yaml のテキストそのものを見る。
    """
    import re

    text = (ROOT / "script" / "scoring.yaml").read_text(encoding="utf-8")
    for key, expected in (
        ("auto_block", ADOPTED_AUTO_BLOCK),
        ("stolen_image", ADOPTED_STOLEN_IMAGE),
        ("hold", ADOPTED_HOLD),
    ):
        m = re.search(rf"^\s+{key}:\s*(\d+)", text, re.M)
        assert m, f"scoring.yaml に {key} の明示行がない"
        assert int(m.group(1)) == expected, f"{key}: yaml={m.group(1)} 期待={expected}"
    # 実効値も一致すること (yaml のパース経路の確認)
    s = Scorer()
    assert s.thresholds["auto_block"] == ADOPTED_AUTO_BLOCK
    assert s.weights["stolen_image"] == ADOPTED_STOLEN_IMAGE
    assert s.thresholds["hold"] == ADOPTED_HOLD


def test_fallback_matches_yaml_entirely():
    """scorer._FALLBACK が yaml と完全同値であること (二重管理のドリフト防止)。

    _FALLBACK は yaml を読めない場合のみ使う保険。yaml と食い違うと、
    yaml 破損時に黙って別の採点になる。
    """
    from scorer import _FALLBACK, load_weights

    cfg = load_weights(ROOT / "script" / "scoring.yaml")
    assert _FALLBACK["weights"] == cfg["weights"]
    assert _FALLBACK["thresholds"] == cfg["thresholds"]
