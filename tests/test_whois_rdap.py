"""T3: whois/RDAP 特徴量 (whois_rdap.py) の RED テスト。

ネットワークは使わない。実測データは tests/golden/rdap.json (spike S5 が生成) を
フィクスチャとして読み、golden legit が RDAP 特徴量で FP (hold 以上) にならないことを担保する。
"""

from __future__ import annotations

import itertools
import json
import time
import urllib.error
from pathlib import Path

import pytest
from features import extract_features
from fetch import FetchResult
from scorer import Scorer
from whois_rdap import (
    KNOWN_FOREIGN_MAKERS,
    RdapInfo,
    abuse_phone_cc,
    registrar_url_tld,
)

GOLDEN_RDAP = Path(__file__).resolve().parent / "golden" / "rdap.json"


def res(url="https://shop.example/item"):
    return FetchResult(
        url=url,
        status=200,
        final_url=url,
        chain=[(200, url)],
        body="<html><body>商品</body></html>",
    )


def rdap(
    ok=True,
    elapsed_ms=500,
    registrar_url="https://www.example-registrar.com/contact",
    abuse_phone="+81.312345678",
    error="",
):
    return RdapInfo(
        domain="example.com",
        ok=ok,
        elapsed_ms=elapsed_ms,
        registrar_name="Example Registrar",
        registrar_url=registrar_url,
        abuse_phone=abuse_phone,
        error=error,
    )


# --- パーサ ---


def test_registrar_url_tld():
    assert registrar_url_tld("https://nnid.asus.com/tw") == "com"
    assert registrar_url_tld("https://www.example.co.jp/") == "jp"
    assert registrar_url_tld("https://twnic.net.tw/x") == "tw"
    assert registrar_url_tld("") == ""
    assert registrar_url_tld("not-a-url") == ""


def test_abuse_phone_cc():
    assert abuse_phone_cc("+81.355551111") == "81"
    assert abuse_phone_cc("+886.21234567") == "886"
    assert abuse_phone_cc("+1.8005550199") == "1"
    assert abuse_phone_cc("") == ""


def test_rdap_info_first_value_rule():
    """同一項目が複数ある場合は 1 番目を採用する。"""
    info = RdapInfo.from_json(
        "example.com",
        {
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["fn", {}, "text", "First Registrar"],
                            ["fn", {}, "text", "Second Registrar"],
                            ["url", {}, "uri", "https://first.example.com"],
                            ["url", {}, "uri", "https://second.example.com"],
                        ],
                    ],
                },
                {
                    "roles": ["abuse"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["tel", {}, "text", "+886.100"],
                            ["tel", {}, "text", "+81.200"],
                        ],
                    ],
                },
            ]
        },
        elapsed_ms=100,
    )
    assert info.ok
    assert info.registrar_name == "First Registrar"
    assert info.registrar_url == "https://first.example.com"
    assert info.abuse_phone == "+886.100"


def test_rdap_terms_of_use_omitted():
    """Terms of use 相方フィールド (links / notices / port43) は特徴量に入れない。"""
    info = RdapInfo.from_json(
        "example.com",
        {"notices": [{"title": "Terms of Use"}], "links": [{"href": "https://x"}]},
        elapsed_ms=10,
    )
    assert info.registrar_name == ""
    assert "notices" not in info.raw_keys()
    assert "links" not in info.raw_keys()


# --- 特徴量フラグ ---


def test_elapsed_ms_kept_as_raw_value():
    """features は生 ms のみ保持。slow 判定 (rdap_slow_ms) は scorer 側で yaml 閾値を使用。"""
    f = extract_features("example.com", res(), rdap=rdap(elapsed_ms=3500))
    assert f.rdap_elapsed_ms == 3500
    assert f.rdap_ok is True
    f2 = extract_features("example.com", res(), rdap=rdap(elapsed_ms=1500))
    assert f2.rdap_elapsed_ms == 1500


def test_foreign_registrar_tld_and_phone_flags():
    f = extract_features(
        "example.com",
        res(),
        rdap=rdap(registrar_url="https://twnic.net.tw", abuse_phone="+886.21234567"),
    )
    assert f.rdap_registrar_tld_foreign is True
    assert f.rdap_phone_foreign is True


def test_jp_or_com_registrar_no_flag():
    f = extract_features(
        "example.com",
        res(),
        rdap=rdap(registrar_url="https://www.gonbei.co.jp", abuse_phone="+81.312345678"),
    )
    assert f.rdap_registrar_tld_foreign is False
    assert f.rdap_phone_foreign is False


def test_missing_fields_do_not_flag():
    """欠損 (URL なし / 電話なし) は foreign とみなさない (precision 優先)。"""
    f = extract_features("example.com", res(), rdap=rdap(registrar_url="", abuse_phone=""))
    assert f.rdap_registrar_tld_foreign is False
    assert f.rdap_phone_foreign is False


def test_network_failure_means_no_flags():
    """タイムアウト等で RDAP 取得に失敗した場合は特徴量 0 (= 加算しない)。"""
    f = extract_features("example.com", res(), rdap=rdap(ok=False, error="timeout"))
    assert f.rdap_ok is False
    assert f.rdap_registrar_tld_foreign is False
    assert f.rdap_phone_foreign is False


def test_no_rdap_data_means_no_flags():
    f = extract_features("example.com", res())
    assert f.rdap_ok is False
    assert f.rdap_registrar_tld_foreign is False
    assert f.rdap_phone_foreign is False


# --- 海外メーカー例外 ---


def test_known_foreign_makers_include_asus():
    assert "asus.com" in KNOWN_FOREIGN_MAKERS
    entry = KNOWN_FOREIGN_MAKERS["asus.com"]
    assert "tw" in entry["tlds"]
    assert "886" in entry["ccs"]


def test_asus_tw_registrar_not_flagged():
    f = extract_features(
        "asus.com",
        res(url="https://asus.com/tw"),
        rdap=rdap(registrar_url="https://nnid.asus.com", abuse_phone="+886.21234567"),
    )
    assert f.rdap_registrar_tld_foreign is False
    assert f.rdap_phone_foreign is False


def test_unknown_domain_with_tw_still_flagged():
    f = extract_features(
        "scam-shop.example",
        res(),
        rdap=rdap(registrar_url="https://twnic.net.tw", abuse_phone="+886.21234567"),
    )
    assert f.rdap_registrar_tld_foreign is True
    assert f.rdap_phone_foreign is True


def test_asus_other_country_phone_still_flagged():
    """例外は故意のマッピングのみ。asus.com が例えば +1 の電話なら旗は立つ。"""
    f = extract_features(
        "asus.com", res(url="https://asus.com"), rdap=rdap(abuse_phone="+1.8005550199")
    )
    assert f.rdap_phone_foreign is True


# --- スコアラ統合 ---


def test_scorer_has_rdap_weights_from_yaml():
    s = Scorer()
    for key in ("rdap_slow", "registrar_url_tld_foreign", "abuse_phone_foreign"):
        assert key in s.weights, f"scoring.yaml に {key} がない"


def test_scorer_adds_rdap_reasons():
    f = extract_features(
        "example.com",
        res(),
        rdap=rdap(
            elapsed_ms=3500,
            registrar_url="https://twnic.net.tw",
            abuse_phone="+886.21234567",
        ),
    )
    s = Scorer()
    sc = s.score(f)
    assert sc.reasons.get("registrar_url_tld_foreign") == s.weights["registrar_url_tld_foreign"]
    assert sc.reasons.get("abuse_phone_foreign") == s.weights["abuse_phone_foreign"]


def test_scorer_no_addition_on_rdap_failure():
    """RDAP 取得失敗時はスコアに一切影響しない (特徴量 0)。"""
    s = Scorer()
    base = s.score(extract_features("example.com", res())).total
    fail = s.score(
        extract_features(
            "example.com", res(), rdap=rdap(ok=False, error="timeout", elapsed_ms=12000)
        )
    )
    assert fail.total == base


def test_scorer_rdap_slow_weight_zero_no_reason():
    """rdap_slow は重み 0 (計測のみ) のため reasons に現れない。"""
    s = Scorer()
    assert s.weights["rdap_slow"] == 0
    sc = s.score(extract_features("example.com", res(), rdap=rdap(elapsed_ms=5000)))
    assert "rdap_slow" not in sc.reasons


def test_fallback_matches_yaml_rdap_weights():
    """scorer._FALLBACK の RDAP 重み/閾値は scoring.yaml と同値でなければならない。

    Scorer().weights は yaml で上書き済みなので比較に使うと恒真になる。_FALLBACK を直接見る。
    """
    import re

    from scorer import _FALLBACK

    text = (Path(__file__).resolve().parent.parent / "script" / "scoring.yaml").read_text(
        encoding="utf-8"
    )
    for key in ("rdap_slow", "registrar_url_tld_foreign", "abuse_phone_foreign"):
        m = re.search(rf"^\s+{key}:\s*(\d+)", text, re.M)
        assert m, f"scoring.yaml に {key} がない"
        assert int(m.group(1)) == _FALLBACK["weights"][key], f"{key} の _FALLBACK と yaml が不一致"
    m = re.search(r"^\s+rdap_slow_ms:\s*(\d+)", text, re.M)
    assert m, "scoring.yaml に rdap_slow_ms がない"
    assert int(m.group(1)) == _FALLBACK["thresholds"]["rdap_slow_ms"]


# --- 実データ (golden) を使う FP ガード ---


def _info_from_golden(rec: dict) -> RdapInfo:
    """golden レコード (flat 形式) から RdapInfo を構成する。"""
    return RdapInfo(
        domain=rec["domain"],
        ok=bool(rec.get("ok")),
        elapsed_ms=int(rec.get("elapsed_ms") or 0),
        registrar_name=rec.get("registrar_name", ""),
        registrar_url=rec.get("registrar_url", ""),
        abuse_phone=rec.get("abuse_phone", ""),
        error=rec.get("error", ""),
    )


def test_golden_rdap_parsing_is_not_vacuous():
    """golden の flat レコードが実際にフラグ計算へ届いていること (positive control)。"""
    data = json.loads(GOLDEN_RDAP.read_text(encoding="utf-8"))
    parsed = [_info_from_golden(r) for r in data["legit"] if r.get("ok")]
    assert parsed, "golden legit に ok=True のレコードがない (データ欠落)"
    with_url = [i for i in parsed if i.registrar_url]
    assert with_url, "golden legit に registrar_url 付きレコードがない (データ欠落)"
    tlds = {
        registrar_url_tld(i.registrar_url) for i in with_url if registrar_url_tld(i.registrar_url)
    }
    assert tlds, "registrar_url から TLD が取れない = パース経路が死んでいる"
    # 例外マップ外のドメインに同じ URL を当てれば foreign=True (判定経路が生きている)
    for info in with_url:
        tld = registrar_url_tld(info.registrar_url)
        if tld and tld not in {"com", "jp"}:
            probe = RdapInfo(domain="probe.invalid", ok=True, registrar_url=info.registrar_url)
            assert probe.registrar_tld_foreign("probe.invalid") is True
            break
    else:  # pragma: no cover - データ次第
        pytest.skip("golden legit に com/jp 以外の registrar URL がない")


def test_golden_legit_does_not_reach_hold_via_rdap():
    """実測 RDAP 結果を golden legit に適用しても hold 未満を維持する。"""
    data = json.loads(GOLDEN_RDAP.read_text(encoding="utf-8"))
    s = Scorer()
    for rec in data["legit"]:
        info = _info_from_golden(rec)
        sc = s.score(extract_features(rec["domain"], res(), rdap=info))
        assert sc.verdict != "auto_block", f"{rec['domain']}: RDAP で auto_block 到達"
        rdap_pts = sum(
            v
            for k, v in sc.reasons.items()
            if k in ("rdap_slow", "registrar_url_tld_foreign", "abuse_phone_foreign")
        )
        assert rdap_pts == 0, f"{rec['domain']}: 正規店が RDAP 特徴量で {rdap_pts} 加算"


# --- fetch_rdap の異常系・レート制限 (ネットワークはスタブ) ---


class _FakeResp:
    def __init__(self, payload: bytes):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, n: int = -1) -> bytes:
        return self._payload if n is None or n < 0 else self._payload[:n]


@pytest.fixture
def fast_rate(monkeypatch):
    """レート制限の待機を無効化し、直近要求時刻をリセットする。"""
    import whois_rdap as wr

    monkeypatch.setattr(wr, "MIN_REQUEST_INTERVAL", 0.0)
    monkeypatch.setattr(wr, "_last_request_monotonic", 0.0)
    return wr


def test_fetch_rdap_404_returns_ok_false(fast_rate, monkeypatch):
    def boom(*a, **kw):
        raise urllib.error.HTTPError("https://rdap.org/domain/x.jp", 404, "Not Found", {}, None)

    monkeypatch.setattr(fast_rate.urllib.request, "urlopen", boom)
    info = fast_rate.fetch_rdap("x.jp")
    assert info.ok is False
    assert "404" in info.error


def test_fetch_rdap_timeout_returns_ok_false(fast_rate, monkeypatch):
    def boom(*a, **kw):
        raise TimeoutError("timed out")

    monkeypatch.setattr(fast_rate.urllib.request, "urlopen", boom)
    info = fast_rate.fetch_rdap("x.jp")
    assert info.ok is False
    assert "Timeout" in info.error


def test_fetch_rdap_invalid_json_returns_ok_false(fast_rate, monkeypatch):
    monkeypatch.setattr(
        fast_rate.urllib.request, "urlopen", lambda *a, **kw: _FakeResp(b"{not json")
    )
    info = fast_rate.fetch_rdap("x.jp")
    assert info.ok is False
    assert "JSONDecodeError" in info.error


def test_fetch_rdap_error_object_is_not_ok(fast_rate, monkeypatch):
    payload = json.dumps({"errorCode": 404, "title": "Not Found"}).encode()
    monkeypatch.setattr(fast_rate.urllib.request, "urlopen", lambda *a, **kw: _FakeResp(payload))
    info = fast_rate.fetch_rdap("x.jp")
    assert info.ok is False
    assert "404" in info.error


def test_fetch_rdap_empty_domain_makes_no_request(fast_rate, monkeypatch):
    calls = []
    monkeypatch.setattr(
        fast_rate.urllib.request, "urlopen", lambda *a, **kw: calls.append(a) or _FakeResp(b"{}")
    )
    info = fast_rate.fetch_rdap("  ")
    assert info.ok is False and info.error == "empty_domain"
    assert calls == []


def test_fetch_rdap_elapsed_excludes_rate_limit_wait(monkeypatch):
    """レート制限の待機は elapsed_ms に含めない (取得遅延のみを測る)。"""
    import whois_rdap as wr

    monkeypatch.setattr(wr, "MIN_REQUEST_INTERVAL", 0.5)
    monkeypatch.setattr(wr, "_last_request_monotonic", time.monotonic())
    monkeypatch.setattr(wr.urllib.request, "urlopen", lambda *a, **kw: _FakeResp(b"{}"))
    info = wr.fetch_rdap("x.jp")
    assert info.ok is True
    assert info.elapsed_ms < 300, f"待機時間が elapsed に混入: {info.elapsed_ms}ms"


def test_rate_limit_serializes_threads(monkeypatch):
    """スレッド並列でも採用間隔が MIN_REQUEST_INTERVAL 以上になる。"""
    import threading as _threading

    import whois_rdap as wr

    interval = 0.2
    monkeypatch.setattr(wr, "MIN_REQUEST_INTERVAL", interval)
    monkeypatch.setattr(wr, "_last_request_monotonic", 0.0)
    stamps: list[float] = []
    lock = _threading.Lock()

    def fake_urlopen(*a, **kw):
        with lock:
            stamps.append(time.monotonic())
        return _FakeResp(b"{}")

    monkeypatch.setattr(wr.urllib.request, "urlopen", fake_urlopen)
    threads = [_threading.Thread(target=wr.fetch_rdap, args=("x.jp",)) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    stamps.sort()
    gaps = [b - a for a, b in itertools.pairwise(stamps)]
    assert len(stamps) == 3
    assert all(g >= interval * 0.9 for g in gaps), gaps


# --- 本番配線 (probe.Pipeline / cli._build_pipeline) ---


def test_rdap_supported_skips_jp():
    from whois_rdap import rdap_supported

    assert rdap_supported("shop.example.jp") is False
    assert rdap_supported("scam.amtlkg.click") is True
    assert rdap_supported("") is False
    assert rdap_supported("localhost") is False


def test_pipeline_wires_rdap_features_into_score(monkeypatch):
    """注入した rdap_fn の結果が特徴量 → スコア理由に載ること (デッドコードでないこと)。"""
    import probe

    def fake_fetch(url, **kw):
        from fetch import FetchResult

        r = FetchResult(
            url=url,
            status=200,
            final_url=url,
            headers={},
            body="<title>shop</title>",
            discarded=False,
        )
        r.html_sanitized = "<title>shop</title>"
        r.raw_bytes = 10
        return r

    monkeypatch.setattr(probe, "fetch", fake_fetch, raising=False)
    called = []

    def fake_rdap(dom):
        called.append(dom)
        return RdapInfo(
            domain=dom,
            ok=True,
            registrar_url="https://rdap.registry.click/x",
            abuse_phone="tel:+1.555",
        )

    p = probe.Pipeline(rdap_fn=fake_rdap)
    res = p.run_domain("shop.amtlkg.click")
    assert called == ["shop.amtlkg.click"]
    assert res.features["rdap_registrar_tld_foreign"] is True
    assert "registrar_url_tld_foreign" in res.reasons


def test_pipeline_skips_rdap_for_jp(monkeypatch):
    import probe

    def fake_fetch(url, **kw):
        from fetch import FetchResult

        r = FetchResult(
            url=url,
            status=200,
            final_url=url,
            headers={},
            body="<title>shop</title>",
            discarded=False,
        )
        r.html_sanitized = "<title>shop</title>"
        r.raw_bytes = 10
        return r

    monkeypatch.setattr(probe, "fetch", fake_fetch, raising=False)
    called = []
    p = probe.Pipeline(rdap_fn=lambda d: called.append(d))
    p.run_domain("shop.example.jp")
    assert called == []


def test_pipeline_survives_rdap_exception(monkeypatch):
    import probe

    def fake_fetch(url, **kw):
        from fetch import FetchResult

        r = FetchResult(
            url=url,
            status=200,
            final_url=url,
            headers={},
            body="<title>shop</title>",
            discarded=False,
        )
        r.html_sanitized = "<title>shop</title>"
        r.raw_bytes = 10
        return r

    monkeypatch.setattr(probe, "fetch", fake_fetch, raising=False)

    def boom(dom):
        raise RuntimeError("rdap down")

    res = probe.Pipeline(rdap_fn=boom).run_domain("shop.amtlkg.click")
    assert res.features.get("rdap_ok") is False


def test_build_pipeline_enables_rdap():
    import cli

    p = cli._build_pipeline(db_dir=".")
    assert p.rdap_fn is not None
