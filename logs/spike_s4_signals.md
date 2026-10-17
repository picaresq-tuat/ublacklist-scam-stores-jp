# Spike S4: stolen_image / dark_pattern / affiliate 実測 (2026-10-17)

## 方法
- scam コーパス: sagidame.com 直近検知 (`/?page=1..5`) から 100 ドメイン収集、96 件実測
  (`scripts/spike_s4_signals.py` / 生データ `logs/spike_s4_signals.json`)。
- legit コーパス: 正規 EC / メディア / ブログ 33 ドメイン中 25 件実測 (8 件取得エラー)。

## ① stolen_image (境界一致への精緻化)
| コーパス | 旧 substring | 新境界一致 | 発火時ヒット数 |
|---|---|---|---|
| scam 96 | 37/96 (39%) | 37/96 (39%) | 16〜65 |
| legit 25 | 3/25 (12%) | 3/25 (12%) | 1, 20, 43 |

- 発火 legit 3 件は構造的 FP: `store.shopping.yahoo.co.jp` (自社資産 `s.yimg.jp`, 43),
  `www.rakuten.co.jp` (`r.r10s.jp`, 1), `netshop.impress.co.jp` (amazon 埋め込み, 20)。
  ヒット数では scam (16〜65) と分離できない。
- 境界一致化 (`host == h or host.endswith("." + h)`) により
  `evilrakuten.co.jp.attacker.example` 型の偽装ホスト誤一致を排除 (今回コーパスでは
  発火率は不変だが堅牢化)。`stolen_image_hits` を新設し計測可能に。
- **重み判断**: stolen_image=15 は単独で hold(12) のみ、auto_block(30) に届かない。
  合算例 (golden quervia.biz): stolen 15 + risky_tld 8 + zencart 10 = 33 → 維持。
  → **重み変更なし** (hit 数で閾値化すると scam 検知 39% が消えるため)。

## ② dark_pattern 文言棚卸し (ドメイン発火率)
| 用語 | scam (n=96) | legit (n=25) | 判定 |
|---|---|---|---|
| 送料無料 | 87 (91%) | 6 (24%) | 維持 (最大の recall 貢献、cap 9 で単独 hold 不可) |
| 数量限定 | 53 (55%) | 2 (8%) | 維持 |
| 激安 | 9 (9%) | 3 (12%) | 維持 |
| %OFF | 9 (9%) | 1 (4%) | 維持 |
| ％OFF | 6 (6%) | 2 (8%) | 維持 |
| 大幅値下げ | 7 (7%) | 1 (4%) | 維持 |
| タイムセール | 6 (6%) | 1 (4%) | 維持 |
| 限定販売 | 4 (4%) | 0 | 維持 |
| 訳あり | 1 (1%) | 3 (12%) | **除去** (legit 優勢) |
| 今すぐ | 2 (2%) | 2 (8%) | **除去** (legit 優勢) |
| 破格 | 1 (1%) | 0 | **除去** (非生産的) |
| 在庫限り | 0 (0%) | 1 (4%) | **除去** (scam 0%) |
| 在庫処分 | 0 (0%) | 1 (4%) | **除去** (scam 0%) |

dark_hits>0: scam 95% → 91% (−4pt)、legit 40% → 36% (−4pt)。
cap 9 < hold 12 のため dark_pattern 単独では判定に影響せず、合算時の 1-2 hit 分
の寄与から legit 優勢語を除くのが precision 上最適。

## ③ affiliate
- scam 96 / legit 25 のいずれでも **affiliate 広告リンク 0 件** (0%)。
  a8.net / afl.rakuten / linksynergy / valuecommerce / amazon-adsystem 等の
  ホストを `<a href>` から抽出 (`affiliate_hits` 新設、features.py)。
  正規 EC が affiliate を張らない実コーパスだったため判別力を確認できず、
  **重みは設定しない** (計測用特徴量として保持)。将来サンプルを増やす際は再計測。

## ④ scoring.yaml
重み変更なし (上記判断)。変更は features.py 側 (照合精緻化・用語整理・新特徴量) のみ。

## 検証
- pytest 408 件すべて成功 (test_features/test_scorer/test_golden 含む)。ruff check + format clean。
