# S5 スパイク報告: whois/RDAP 特徴量 (T3) の実測

- 実施日: 2026-10-17 (JST)
- スクリプト: `scripts/spike_s5_rdap.py` (取得) / `scripts/spike_s5_rdap_summary.py` (集計)
- 生データ: `logs/spike_s5_rdap.json` (生 RDAP) / `tests/golden/rdap.json` (集計済みフィクスチャ)
- 方式: `https://rdap.org/domain/<domain>` (リダイレクト先レジストリ RDAP) を urllib で取得。
  whois python ライブラリ不使用。**1 req/sec 以上あける (MIN_REQUEST_INTERVAL=1.1s) を自前で厳守**。
- コーパス: golden legit 18 件 (tests/golden/domains.json legit) + sagidame scam 30 件。

## 実測結果

| 項目 | legit (n=18) | scam (n=30) |
|---|---|---|
| RDAP 取得成功 | 2/18 (16 件は 404: .jp は JPRS が rdap.org 経由の RDAP 未整備) | 12/30 (18 件は 404: thin registry / 新規 TLD の一部) |
| 取得時間 min/med/max | 645 / 1772 / 1772 ms | 770 / 808 / 1200 ms |
| (a) rdap_slow (>3s) | 0/2 | 0/12 |
| (b) Registrar URL TLD != com/jp | 1/2 (dynabook.com → 1api.net) — maker 例外適用後 **0/2** | 11/12 = 91.7% (全体の 36.7%) |
| (c) Abuse 電話国番号 != +81 | 1/2 (dynabook.com → +49) — maker 例外適用後 **0/2** | 4/12 = 33.3% (全体の 13.3%) |

- レジストラ内訳: legit = 1API GmbH ×1, GoDaddy ×1 / scam = Sav.com ×8, Spaceship ×1, West263 ×3。
- scam 側の (b) は registrar entity の `links rel=about` が `rdap.registry.click` 等
  (レジストラ公式サイトの URL が未公開で RDAP エンドポイントを指すケース) を拾ったもの。
  `.click` 系の格安 TLD に偏るため実務上は有効なシグナル。
- dynabook.com は日本メーカーだが正規登録者が海外レジストラ (1API GmbH, .net / +49) を使うため、
  `KNOWN_FOREIGN_MAKERS` に `dynabook.com` (tlds: com/net/jp, ccs: 81/49) を登録して FP を回避。
  ASUS 等の既知海外メーカー (SONY, Panasonic, Canon, Nikon, Lenovo, Samsung, Xiaomi ほか) も同マッピングで除外。

## 結論 → scoring.yaml への反映

- precision 優先:
  - `rdap_slow: 0` — 実測で両クラス 0 発火。判別力なしのため計測用のみ (重み 0)。
  - `registrar_url_tld_foreign: 6` — scam 91.7% / 正規店 0%。単独では hold(12) 未満の補助シグナル。
  - `abuse_phone_foreign: 4` — scam 33.3% / 正規店 0%。欠損 (難読化 tel) は加算しない。
- 正規店への RDAP による加算: **0/18 件 (FP 0%)**。scam への加算: 11/30 件 (中央値 +6)。

## 適用限界 (重要)

`.jp` は rdap.org 経由の RDAP が未整備 (JPRS 404) のため、正規店 corpus (大部分が `.jp`) では
**そもそも RDAP が取得できず、本特徴量は構造的に発火機会がない**。したがって legit 側の
FP 0/18 は「特徴量の判別力で FP を抑えた」結果ではなく「発火しなかった」結果であり、
legit 側の FP 検証は構造的に不可能である。本特徴量は実質、海外レジストラを用いる
scam (新規 TLD 中心) に対する補助シグナルとしてのみ機能する。`.jp` の whois を扱うには
JPRS の whois サーバ (port 43) 直接照会など別経路が必要 (未実装)。

## ネットワーク失敗の扱い

タイムアウト / 404 / レート制限等すべての取得失敗では `RdapInfo.ok=False` となり、
RDAP 由来の特徴量は **すべて 0 (加算しない)**。スコアは RDAP なしの base と完全に一致する
(`test_scorer_no_addition_on_rdap_failure` で担保)。

## RED → GREEN

- RED: `tests/test_whois_rdap.py` 実装前は ImportError で 17/17 失敗。
- GREEN: 実装後 20/20 passed。リポジトリ全体 428 passed / ruff clean。

## 品質レビュー対応 (REQUEST_CHANGES → 修正)

| 指摘 | 対応 |
| --- | --- |
| C1 golden FP ガードが空回り (flat レコードを `rec["rdap"]` で読んでいた) | `_info_from_golden()` で flat フィールドから `RdapInfo` を構成。`test_golden_rdap_parsing_is_not_vacuous` で positive control (実データがフラグ計算に到達すること) を追加し、`skipif` を撤去 (golden はコミット済みのため skip させない) |
| I1 レート制限がスレッド並列で 1 req/sec を守れない | `threading.Lock` で wait+記録を不可分化。ロック無効化時の実測 gaps `[200ms, 1ms]` → 修正後は全 gap ≥ interval を `test_rate_limit_serializes_threads` で担保。docstring に単一プロセス前提を明記 |
| I2 features が private `_maker_exception` を 3 回呼ぶ | 公開関数 `maker_exception()` と `RdapInfo.flags()` (1 ルックアップで 3 フラグ) を新設し、features は `flags()` を 1 回だけ呼ぶ |
| I3 `fetch_rdap` の異常系・elapsed 除外が未テスト | 404 / timeout / 不正 JSON / RDAP errorCode / 空ドメイン (要求なし) / レート待機が elapsed に入らないこと、の 6 本を追加 |
| I4 `_FALLBACK` 同値テストが恒真 | `scorer._FALLBACK` を直接 import して比較 (yaml の自己一致を見ない)。`thresholds.rdap_slow_ms` も比較対象に追加 |
| I5 本番経路に未配線 (デッドコード) | `probe.Pipeline(rdap_fn=...)` を追加し `cli._build_pipeline()` で `fetch_rdap` を注入。`.jp` は `rdap_supported()` で**要求自体を出さない** (404 既知)。RDAP 例外は握って特徴量 0。配線テスト 5 本 (RED 4 件確認済み) |
| I6 失敗理由が観測不能 | 未対応 (follow-up): `PageFeatures` に `rdap_error` を足すと DB スキーマと集計に波及するため別チケット |
| I7 シグナル名と実態のズレ | 改名はせず `scoring.yaml` に意味論の注意 (registrar entity のリンク先 TLD を測っている、scam 11 件中 10 件は `rdap.registry.click`) と allow-list の将来条件を明記 |

追加の堅牢化 (Minor): `_vcard_first` の長さガード、RDAP 応答サイズ上限 2MB、
`errorCode` 付き応答を成功扱いしないこと、空ドメインで待機しないこと。

最終検証: **441 passed** / ruff check + format clean (53 files)。
