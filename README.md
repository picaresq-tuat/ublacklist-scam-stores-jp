# ublacklist-scam-stores-jp

日本向けのscam商品ページを検索結果から排除するuBlacklistフィルターと、その判定を手元で再現するPython実装。

配布しているリストは2本ある。

- [`uBlacklist.txt`](uBlacklist.txt) — 確定分25ドメインと常設正規表現3本。ブラウザに入れるのはこちら。
- [`cloaking_detected/uBlacklist.txt`](cloaking_detected/uBlacklist.txt) — cloakingを検知したが自動確定に届かない保留分91件。人手で確認してから本体へ移す。

## 判定の流れ

```
検索 (SearXNG) → トリアージ (whitelist) → 取得 (ブラウザ/bot/favicon/RDAP)
   → 特徴量 → スコア → 記録 (scam.db) → 出版 (uBlacklist.txt)
```

判定の単位はドメインである。1ドメインにつきスコアを1つ出し、閾値で`block` / `hold` / `dismissed`に振り分ける。

## セットアップ

```bash
git clone https://github.com/picaresq-tuat/ublacklist-scam-stores-jp.git
cd ublacklist-scam-stores-jp
python3 -m pytest -q            # 判定ロジックとゴールデンセットの回帰
```

DBはリポジトリに含めてあるため、clone直後から同じ判定を再現できる。手元で作り直す場合は次のとおり。

```bash
python3 scripts/init_db.py      # models.db (240件) とwhitelist.db (120件) をseedから再生成
```

## 実行するスクリプト

| コマンド | 実際に行うこと |
| --- | --- |
| `python3 script/nightly.py --repo OWNER/NAME` | 1晩分の探索からPR作成まで。cronの入口 |
| `python3 script/cli.py --dry-run --report logs/report.json` | 同じ処理を単発で回し、出版せずレポートだけ書く |
| `python3 scripts/rejudge_lists.py --dry-run --json logs/rejudge_lists.json` | 既存2リストを再取得して判定し直す |
| `python3 scripts/rejudge_lists.py --from-json logs/rejudge_lists.json --apply` | 監査結果をリストへ反映する (再取得なし) |
| `python3 script/cloaking_audit.py --dry-run --json logs/cloak_audit.json` | cloakingリストから非200の行を洗い出す |
| `python3 scripts/calib_s5_thresholds.py` | ゴールデンセットとスパイク結果で閾値を再校正する |
| `python3 scripts/record_golden.py` | ゴールデンセット (scam 20 / legit 20) を実取得して記録する |

### 1晩の処理 (`script/nightly.py`, `script/cli.py`)

1. `hunter.run_night`をpublishモードで1回実行する。
2. `logs/nightly_scan.log`に1ブロック追記する。月が変わると`.YYYYMM`へ退避する。
3. 2つのリストに変化があれば、`nightly/YYYY-MM-DD`ブランチへcommitしてpushし、PRを作る。
4. `db/manual_candidates.txt`があれば、その全件を同じパイプラインで再判定し、`block`かつ2xxのドメインだけを`uBlacklist.txt`へ昇格する。

`main`へのpushとmergeは行わない。トークンは環境変数`GITHUB_TOKEN`からのみ読み、引数・ログ・コミットには書かない。

### 探索から出版までの各段階

クエリ生成では、`db/models.db`の型番240件と用語を組み合わせて1晩のクエリを作る。ページ番号は履歴 (`db/searches.db`) を見て未消化の範囲から選ぶ。検索はSearXNG (`--searx-url`) 経由で行い、既定エンジンはGoogle CSEである。429が続く夜は指数バックオフし、失敗が上限に達したらその夜は中止する。1巡目で新規ドメインが取れなければ、クエリとページ番号を変えて最大3巡する。

トリアージでは、whitelist (120ドメイン) に載るホストを除外する。取得では`https://`を通常UAで開き、4xxか5xxなら`http://`も試す。続いてGooglebot、Bingbotの順に取得し、差が出るかを見る。faviconは`/favicon.ico`を画像バイトのまま取り、先頭バイトがICO/PNG/GIF/JPEG/BMP/WEBP/AVIF/SVGのいずれかで8バイト以上あるものだけをMD5化する (404のHTML等は捨てる)。RDAPは対応TLDのみ引く。応答が3秒を超えた場合は「遅い」として記録する。

特徴量は下の表の各項目を1ページから計算する。取れなかった項目は0として扱う。スコアは重みの合計で、`auto_block`以上なら`block`、`hold`以上なら`hold`、未満なら`dismissed`とする。

記録では`db/scam.db`に判定と特徴量を残す。`block`は連続2晩 (`nights_required`) の確認を経て`uBlacklist.txt`に入り、`hold`はcloakingリストへ回る。`dismissed`は記録だけを残す。失効監視では、登録から30日を超えたドメインの到達性を確認し、7晩連続で応答がなければリストから外す。

### 既存リストの再判定 (`scripts/rejudge_lists.py`)

cloakingリストと手動候補を並列に取得し、`block`かつ2xxのドメインを確定リストへ移す。cloakingリストからは`block`になった行だけを削除し、`hold`と取得失敗は残す。`--workers`で同時取得数を指定する。`--from-json`を付けると、保存済みの判定結果から反映だけを行う。

### 校正 (`scripts/calib_s5_thresholds.py`)

ネットワークを使わず、`tests/golden/`の生レスポンスと`logs/spike_s4_signals.json`から現行の特徴量を再計算する。`auto_block`を16から45まで動かし、recallと偽陽性を並べた`logs/calib_s5_sweep.tsv`を書き出す。採用値は`scoring.yaml`に置く。

## 特徴量と重み

重みの一次情報は`script/scoring.yaml`である。`scorer.py`はこのファイルだけを読み、値をハードコードしない。

| シグナル | 何を見るか | 重み | 実測メモ |
| --- | --- | ---: | --- |
| `redirect_to_google` | 検索エンジンへのドアウェイ転送 | 35 | 単独で`auto_block`に届く |
| `favicon_collision` | 判定履歴にある同じfavicon MD5 (2ドメイン以上) | 30 | `db/scam.db`から毎回corpusを構築 |
| `bot_only_body` | Googlebotにだけ本文を返す | 20 | 単独で`auto_block`に届く |
| `cloaking_promoted` | cloakingかつbot専用本文またはstatus差 | 20 | `cloaking`の昇格版 |
| `cloaking` | titleが異なり本文長比が0.3以上 | 12 | 実測15/15が乗っ取り型。正規0/116 |
| `offsite_redirect` | 外部ドメインへの転送 | 10 | `redirect_to_google`と排他 |
| `zencart` | ZenCartの構造マーカーが2個以上 | 10 | 正規ZenCart店が2〜3個返すため補助に留める |
| `stolen_image` | 商品画像が他社ストアの資産ホスト | 8 | 自社CDNを誤検知するため15から引き下げた |
| `risky_tld` | 安価な新規TLD | 8 | goldenのscam 20/20、正規0 |
| `dark_pattern` | 文言パターン1個につき3、上限9 | 3 / 9 | 90% 前後のscamで発火、正規も約40% |
| `shared_2ld` | 同一2LDの使い回し | 6 | 供給が未接続 (下記) |
| `favicon_cross_origin` | 他ドメインと同一favicon (同一registrable domainは除外) | 5 | `db/scam.db`から毎回corpusを構築 |
| `young_index` | 公開直後のインデックス | 5 | 供給が未接続 (下記) |
| `registrar_url_tld_foreign` | レジストラのリンク先TLDがcom/jp以外 | 4 | scam 7/15、正規13/116 |
| `deep_product_path` | 商品ページらしい深いパス | 2 | scam 2/15、正規35/116で判別力なし |
| `abuse_phone_foreign` | abuse電話の国番号が81以外 | 0 | scam 47%、正規60%。計測のみ |
| `rdap_slow` | RDAP応答が3秒超 | 0 | 両クラスで0件。計測のみ |

`favicon_collision`と`favicon_cross_origin`は、`script/favicon_corpus.py`が`db/scam.db`の判定履歴から`md5 -> distinctドメイン数`と代表ホストを組み立て、CLI・夜間ランナー・候補監視の各パイプラインに渡す。ネットワークは使わない。corpusに載るのは`favicon_source`が`raw`の行 (生の画像バイトからMD5を作った行) だけで、旧実装が本文テキスト先頭64文字から作った値は混ぜない。汎用favicon (`GENERIC_FAVICON_MD5S`) は両シグナルから除外する。

`shared_2ld`と`young_index`は定義と重みがあるが、実走査では値が供給されない。現状の判定に寄与するのは表の残りの項目である。

スコアは重みの単純合計である。`redirect_to_google`と`offsite_redirect`、`cloaking`と`bot_only_body`はそれぞれ排他で、片方だけを加算する。`dark_pattern`はヒット数に3を掛け、9で頭打ちにする。RDAP系は取得に成功した場合だけ加算する。

| 閾値 | 値 | 意味 |
| --- | ---: | --- |
| `auto_block` | 20 | この点数以上で`block` |
| `hold` | 12 | この点数以上で`hold`、cloakingリスト行き |
| `fast_track` | 60 | 連続2晩を待たずに登録 |
| `nights_required` | 2 | 確定に必要な連続確認の夜数 |
| `zencart_min_hits` | 2 | ZenCartと判定するマーカー数 |
| `rdap_slow_ms` | 3000 | RDAPの「遅い」閾値 |

校正の結果は`auto_block=20`、`hold=12`である。ゴールデンセットでscamの検出が18/20、偽陽性0/17、部分特徴量のコーパスで42/96、偽陽性0/25だった。どちらのコーパスでも正規の最大スコアは11で、閾値まで9点の余白がある。

## 出力形式

各エントリはuBlacklistの`*://*.example.com/*`形式で、ドメイン順に並べる。`publish.validate()`は常設正規表現3本とセクション見出しの存在、重複、常設ルールと同形の個別登録を検査し、問題があれば書き込まない。

## データベース

`db/`のDBは追跡対象である。cloneした時点の判定を再現するために置いてある。

| ファイル | 内容 |
| --- | --- |
| `db/models.db` | 型番240件 (クエリ生成の元データ) |
| `db/whitelist.db` | 除外する正規ドメイン120件 |
| `db/scam.db` | 判定履歴1,636件 (block 17 / hold 135 / dismissed 1,484) と特徴量、失効監視の状態 |
| `db/searches.db` | 検索履歴658件 (クエリの重複を避けるため) |

`models.db`と`whitelist.db`は`scripts/init_db.py`でseedから作り直せる。`scam.db`は判定の履歴そのものなので、消すと確定済みドメインの再確認と失効監視が振り出しに戻る。手動収集した容疑ドメインの`db/manual_candidates.txt`だけは、未検証の情報を含むため追跡しない。

## テスト

`python3 -m pytest -q`で469件を実行する。内訳は、ゴールデンセット40ドメインの回帰、閾値と重みの校正値、取得と出版の境界、リスト再判定と候補監視の単体テストである。テストはネットワークを使わず、記録済みのレスポンスとスタブで動く。

## 運用

変更は`nightly/YYYY-MM-DD`ブランチにcommitし、PRを経て人手でmergeする。トークンと認証情報は環境変数からのみ読み、ソース、ログ、コミットに値を書かない。生ログ (`logs/*.raw.log`) とレポートJSONは追跡しない。

## ライセンス

MIT (see [LICENSE](LICENSE)).
