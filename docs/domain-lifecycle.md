# ドメイン巡回ライフサイクル仕様

この文書は、scam リスト (`uBlacklist.txt`) と cloaking リスト
(`cloaking_detected/uBlacklist.txt`) に載るドメインを、どの順序で・どの頻度で巡回し、
どの条件でリストから外し、どこで巡回対象から完全に外すかを定義する。
実装は `script/lifecycle.py`（状態遷移）と `script/scamstore.py`（永続化）、
`script/hunter.py`（1 夜の実行）にある。

## 1. 状態

| 状態 | 意味 | リスト |
| --- | --- | --- |
| `active` | 現役。`base_decision` が `block` なら scam リスト、`hold` なら cloaking リスト | 掲載 |
| `pending_release` | スコア閾値を 3 晩連続で下回った観測待ち。scam から cloaking へ移す | cloaking のみ |
| `pending_expiration` | 3 晩連続で到達不能。スコア算出を停止し、到達性だけを見る | 掲載したまま |
| `released` | 観測ウィンドウで `hold` 未満のみだった。cloaking からも外す | なし |
| `expired` | `pending_expiration` のまま 5 回連続到達不能。リストから削除 | なし |
| `retired` | `expired` / `released` のまま 5 回連続で条件を満たした。巡回対象外 | なし |

`base_decision` は降格前の判定（`block` / `hold`）を保持する。到達可能に戻ったときは
この値へ復帰する。状態は `decisions.decision` に書き、履歴は `decision_history` に残す。
巡回対象から外れたドメインは whitelistへは追加しない。

## 2. 巡回スケジュール

巡回の間隔は壁時計の日数ではなく、**完了した nightly run の回数** (`nightly_runs.seq`)
で数える。全体が失敗した夜はrunを完了扱いにしないため、間隔も連続カウントも進まない。

| 状態 | 間隔 |
| --- | --- |
| `active` | 毎晩 |
| `pending_release` | 毎晩（3 晩の観測ウィンドウ） |
| `pending_expiration` | 3 run ごと |
| `released` | 7 run ごと |
| `expired` | 7 run ごと |
| `retired` | 巡回しない |

同じnightを再実行してもrunは1回として扱う（`nightly_runs.night`はUNIQUE）。
再実行時はその夜のライフサイクル巡回をやり直さない。

## 3. 到達不能ルート（スコア閾値より優先）

判定は `HealthChecker` の 3 値（到達可能 / 到達不能 / 不明）で行う。

1. `active` / `pending_release` / `released` で **3 回連続**到達不能 → `pending_expiration`。
   スコアの算出を一時停止する。リストからは削除しない（30 日経過の制限は撤廃）。
2. `pending_expiration` で、降格後 **5 回連続**到達不能 → `expired`。リストから削除する。
3. `expired` で、降格後 **5 回連続**到達不能 → `retired`。巡回対象から外す。
4. 途中で到達できた場合は `active` に戻し、`base_decision` を復元してスコア算出を再開する。
   `expired` から復帰したドメインは元のリストへ再掲載する。

到達不能の判定はスコア閾値の判定に優先する。同じ巡回で到達不能と判定された場合、
スコア側の連続カウントは増減させない。

**別ドメインへの転送は到達不能と扱わない。** 転送先が別ドメインでも、最終応答が
正常なら到達可能とする。転送先で失敗した場合は「不明」とし、到達不能には数えない。

## 4. スコア閾値ルート

1. `active` で **3 晩連続**で閾値未満（`block` 以外。`hold` は scam リストのドメインに
   とっては閾値未満と同じ扱い）→ `pending_release`。scam リストから削除し、
   cloaking リストへ移す。
2. `pending_release` は一時状態。毎晩観測し、
   - `block` が一度でも出れば scam リストで確定（`active` / `block`）
   - `hold` が出れば cloaking リストで確定（`active` / `hold`）
   - `hold` 未満のみが 3 回続けば `released`。cloaking リストからも削除する
3. `released` は 7 run ごとに観測する。
   - `block` → 即座に scam リストへ戻す（`active` / `block`）
   - 直近 5 回の観測で `hold` が 2 回以上 → cloaking リストへ戻す（`active` / `hold`）
   - `hold` 未満が **5 回連続** → `retired`（巡回対象外）

## 5. 1 回の nightly 全体が失敗した場合

次のいずれかに該当する夜は「失敗した夜」とし、ライフサイクル巡回そのものを実行しない。

- discovery が例外で落ちた
- 検索エンジンの失敗が上限に達して `aborted=True` になった

失敗した夜は `nightly_runs` に完了行を作らない。したがって

- 「閾値を下回った」回数は増えない
- 「到達不能」回数は増えない
- 3 run / 5 run / 7 run の間隔も進まない
- 状態遷移もリストの増減も起きない

個別ドメインの取得失敗（WAF・タイムアウト等）は `unknown` として扱い、同じく
どちらのカウントにも数えない。`unknown` の夜は `last_check_seq` を更新しないため、
次に成功した夜に再試行する。

## 6. 再発見

`retired`のドメインはdiscoveryの既知集合から除外する。nightly runで再度見つかった
場合はライフサイクル行を破棄し、新しいドメインと同じ経路（トリアージ → probe →
スコア → 2 晩確認）で扱う。`released` / `expired` は巡回対象に残るため、discovery では
従来どおり既知として扱う。

## 7. レポート

hunterのreportとnightlyログには次を出す。

- `lifecycle_checked` — その夜に巡回したドメイン数
- `lifecycle_skipped` — 全体失敗などで巡回しなかった理由
- `pending_release` / `pending_expiration` — その夜に降格したドメイン
- `reconfirmed` — `block` を再確認したドメイン
- `released` / `expired` / `retired` — その夜に降格したドメイン
- `restored` — 到達可能に戻って `active` へ復帰したドメイン
