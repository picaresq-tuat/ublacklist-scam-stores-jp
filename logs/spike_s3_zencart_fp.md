# Spike S3: ZenCart 構造指紋の正規店 FP 計測 (2026-10-17)

## 方法
- scam コーパス: sagidame.com 直近検知 (`/?page=1..5`) から 100 ドメイン収集し実取得
  (`scripts/spike_s3_zencart_fp.py` / 結果 `logs/spike_s3_zencart.json`)。
- legit コーパス: golden 20 件の実測値 (`tests/golden/domains.json`) + 正規 ZenCart 導入店
  (cms-server.ne.jp / shop.obitastar.co.jp / www.bigmouse.co.jp ほか、`logs/spike_s3_zencart_legit_extra.json`)。

## 結果
| コーパス | 計測 | hits 分布 | >=2 hits |
|---|---|---|---|
| sagidame scam | 96 | 0:6, 1:53, 2:16, 3:21 | 39% |
| legit (一般 EC/レビュー/ブログ) | 29 (17 golden + 12 spike) | すべて 0 | **0%** |
| legit 正規 ZenCart 店 | 3 実測 | 2, 3, 1 | **2/3** |

要点: `main_page=` + `products_id=` / `zenid=` の組み合わせは **正規 ZenCart 店でも 2-3 ヒットする**。
つまり `min_hits=2` かつ旧重み 25 では正規店が単独 auto_block (50 >= 30) される。
一方 min_hits=3 に上げても legit(obitastar=3) を排除できず、min_hits=4 は scam 新コーパスで recall 0 になる。

## 決定 (precision 優先)
- `zencart` 重み: **25 → 10**。単独では hold(12) / auto_block(30) に到達しない補助シグナルとする。
- `zencart_min_hits`: **2 を維持**。単独発火が allow に留まるため min_hits は recall 寄与のため緩めたまま。
- 検知は favicon_collision / stolen_image / risky_tld などとの合算でのみ判定に寄与する
  (例: zencart 10 + stolen_image 15 + risky_tld 8 = 33 → auto_block。golden quervia.biz は維持)。

## 検証
- pytest 404 件すべて成功 (test_golden / test_scorer を新重みに更新)。
