# ublacklist-scam-stores-jp

日本向けの Scam 商品ページを検索結果から排除するための **uBlacklist フィルターリスト** と、
それを夜間に生成する Python スクリプト群。

- 配布リスト: [`uBlacklist.txt`](uBlacklist.txt) (常設正規表現 3 本 + `## Hermes nightly` セクションの個別ドメイン)
- cloaking 検知のみで保留中のドメイン: [`cloaking_detected/uBlacklist.txt`](cloaking_detected/uBlacklist.txt)
- 設計: 型落ちノート PC の型番 × 用語で夜間検索 → ホワイトリストで除外 → 実ページ深掘り → スコア閾値判定 → PR

## 構成

```
.
├── uBlacklist.txt            # 配布リスト本体 (これが成果物)
├── cloaking_detected/        # cloaking 検知 + hold 判定の保留リスト
│   └── uBlacklist.txt
├── script/                   # 本体コード
│   ├── cli.py                # 夜間実行 CLI
│   ├── hunter.py             # 5 ステージのオーケストレータ
│   ├── features.py           # 特徴量抽出
│   ├── scorer.py             # スコアラ (重みは scoring.yaml)
│   ├── scoring.yaml
│   ├── fetch.py              # 実ページ取得 (SSRF ガード / 3 UA / 5 MiB 上限)
│   ├── probe.py, health.py   # 深掘り / P8 失効監視
│   ├── publish.py, cloaking_publish.py, gitops.py
│   ├── modeldb.py, queries.py, searchlog.py, scamstore.py, whitelist.py, searxng.py
│   └── data/models_seed.csv  # 型番シード (240 件)
├── tests/                    # pytest (golden セット回帰を含む)
├── scripts/                  # 運用補助 (init_db.py, gh_git.sh, ...)
├── db/                       # 実行時 DB (.gitignore 対象 / scripts/init_db.py で再生成)
└── logs/                     # nightly_scan.log* は uBlacklist.txt の更新履歴 (追跡対象)
```

## セットアップと実行

```bash
python3 scripts/init_db.py                      # db/ を seed から再生成
python3 -m pytest                               # テスト
python3 script/cli.py --night 2026-09-30 --dry-run --report logs/report.json
python3 script/cli.py --night 2026-09-30 --publish --ulist uBlacklist.txt     --cloaking-list cloaking_detected/uBlacklist.txt --repo picaresq-tuat/ublacklist-scam-stores-jp --pr
```

## 取り扱い

- **`db/` と生ログ (`logs/*.raw.log`) は `.gitignore` で除外**。リポジトリには含めない。
  DB は `scripts/init_db.py` で再生成できる。
- `logs/nightly_scan.log*` は **編集済み**の実行ログで、`uBlacklist.txt` の更新履歴にあたる。
- トークン・認証情報は環境変数 (`GITHUB_TOKEN`) からのみ読む。ソース・ログ・コミットに値を書かない。
- `uBlacklist.txt` の更新は feature branch (`nightly/YYYY-MM-DD`) → PR → **人手承認後に merge --no-ff**。

## ライセンス

MIT (see [LICENSE](LICENSE)).
