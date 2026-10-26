"""夜間オーケストレータ (P7c)。

1 夜の流れ:
  discovery (searx) → triage (whitelist) → probe+score (pipeline.run_domain)
  → record (scamstore) → publish (uBlacklist.txt 更新)
  + P8: 監視対象 (登録後30日以上) の到達性チェックと失効スイープ。

R5: 1巡目で scam.db に新規が入らなければ、クエリ生成/pageno を変えて
    最大 3 回 discovery をやり直す。
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from publish import build_entries, merge_list
from scamstore import RECONFIRM_MISS_LIMIT, ScamStore
from searchlog import PageRangeExhausted, pick_pageno
from twold_corpus import count_2ld

MAX_ROUNDS = 3
MONITOR_AGE_DAYS = 30
EXPIRE_STREAK_DAYS = 7

# 実測 (2026-09-24): Google CSE を主引擎にすると 429 ("unusual traffic") で
# エンジンが suspension する。1 クエリの失敗で夜全体を落とさず、かつ
# 失敗が続く夜は叩き続けない (IP レピュテーション悪化の防止) ための上限。
MAX_ENGINE_FAILURES = 5

# 実測 (2026-09-24): 1.5 秒間隔の連投でも 30 クエリ程度で 429 になった。
# 失敗時は指数的バックオフ (10s, 20s, 40s, ... 上限 300s) で間隔を空ける。
DEFAULT_ENGINE_BACKOFF_SEC = 10.0
MAX_ENGINE_BACKOFF_SEC = 300.0

# 実測 (2026-09-24): Bing はページング非対応 (pageno>=2 で常に 0 件)。
# ランダム pageno を使う以上、上限はページング可能な Google CSE の実測上限に合わせる。
from searxng import PRIMARY_MAX_PAGENO as DEFAULT_MAX_PAGENO  # noqa: E402


def _today() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def term_of(query: str, model: str) -> str:
    """クエリ文字列から用語部分を取り出す (build_query の逆)。"""
    q = (query or "").strip()
    m = (model or "").strip()
    if m and q.startswith(m):
        return q[len(m) :].strip()
    return q


def _host_of(url: str) -> str:
    u = str(url or "")
    if "//" not in u:
        return ""
    try:
        return (urlsplit(u).hostname or "").lower()
    except ValueError:
        return ""


def run_night(
    *,
    night: str | None = None,
    searx,
    pipeline,
    store: ScamStore,
    db_dir: Path | str,
    ulist_path: Path | str | None = None,
    publish: bool = False,
    dry_run: bool = False,
    max_queries: int = 12,
    health=None,
    max_pageno_attempts: int = 3,
    max_pageno: int | None = None,
    max_engine_failures: int = MAX_ENGINE_FAILURES,
    engine_backoff_sec: float = DEFAULT_ENGINE_BACKOFF_SEC,
    engine_backoff_max_sec: float = MAX_ENGINE_BACKOFF_SEC,
    sleep=None,
    gen=None,
    models_db=None,
    cloaking_list_path: Path | str | None = None,
) -> dict:
    night = night or _today()
    _sleep = sleep if sleep is not None else time.sleep
    db_dir = Path(db_dir)
    db_dir.mkdir(parents=True, exist_ok=True)
    if max_pageno is None:
        max_pageno = DEFAULT_MAX_PAGENO

    from queries import QueryGen
    from searchlog import SearchLog
    from whitelist import SEED, Whitelist

    searchlog = SearchLog(db_dir / "searches.db")
    wl = Whitelist(SEED)
    if gen is None:
        gen = QueryGen(db=models_db, max_pageno=max_pageno)
    gen.rotate()  # 夜のはじめにサンプルを組み直す
    round_no = 0
    new_domains: int = 0
    seen_domains: set[str] = set()
    # shared_2ld 用: 同じ夜の検索結果に現れた *生のホスト名* を 1 本のリストに
    # 集める。下のループはこの後 registrable domain に畳んで重複排除するため、
    # 畳む前 (= ここ) で拾わないとサブドメインの本数が失われる。正規化 (大文字・
    # ポート・末尾ドット) とプラットフォーム除外は count_2ld 側で行う。
    observed_hosts: list[str] = []
    blocked: list[str] = []
    held: list[str] = []
    dismissed: list[str] = []
    whitelisted: list[str] = []
    already_known: list[str] = []
    empty_queries: int = 0
    engine_failures: int = 0
    aborted: bool = False

    from features import registrable_domain
    from searxng import EngineUnavailable

    known_before = {r["domain"] for r in store.all_decisions()}
    # 夜の開始時点で「block かつ連続 2 夜確認が未了」のドメインを控えておく。
    # known_before で discovery から除外されるため、ここで掬わないと nights_confirmed
    # が進まない (実バグ回帰)。
    pending_confirmation = store.reconfirm_targets()

    def _search(query: str, pageno: int):
        """検索 1 回。エンジン suspension は数え上げて None を返す (夜を落とさない)。"""
        nonlocal engine_failures, aborted
        try:
            return searx.search(query, pageno=pageno)
        except EngineUnavailable:
            engine_failures += 1
            if engine_failures >= max_engine_failures:
                aborted = True
            else:
                # 429 は連投が原因。指数的に間隔を空ける (上限で頭打ち)。
                delay = min(
                    engine_backoff_sec * (2 ** (engine_failures - 1)), engine_backoff_max_sec
                )
                _sleep(delay)
            return None

    while round_no < MAX_ROUNDS and not aborted:
        round_no += 1
        found_this_round: list[str] = []
        for query, model, pageno in gen.queries(limit=max_queries, searchlog=searchlog):
            if aborted:
                break
            # R3: pageno がエンジンの想定最大を超えると 0 件が返る。
            #     その場合は別 pageno で引き直す (上限 max_pageno_attempts 回)。
            results = _search(query, pageno)
            if results is None:
                if aborted:
                    break
                continue
            attempts = 1
            tried = {pageno}
            while not results and attempts < max_pageno_attempts:
                attempts += 1
                try:
                    alt = pick_pageno(
                        searchlog,
                        model,
                        term_of(query, model),
                        gen.rng,
                        max_pageno=max_pageno,
                        exclude=tried,
                    )
                except PageRangeExhausted:
                    break
                tried.add(alt)
                results = _search(query, alt)
                if results is None:
                    break
                if results:
                    pageno = alt
                    searchlog.record_result(
                        model, term_of(query, model), alt, result_count=len(results)
                    )
            if results is None:
                # pageno 引き直し中のエンジン失敗。engine_failures で計上済みなので
                # 空応答として二重計上せず、None を反復しない (実バグ回帰: 10-05/10-08 の
                # cron が `for item in results:` で TypeError になっていた)。
                if aborted:
                    break
                continue
            if not results:
                empty_queries += 1
                # P9c: 空応答 pageno を実結果数 0 として記録し、
                # pick_pageno の 30 日空応答プールで再利用を避ける。
                searchlog.record_result(model, term_of(query, model), pageno, result_count=0)
            else:
                searchlog.record_result(
                    model, term_of(query, model), pageno, result_count=len(results)
                )
            for item in results:
                host = _host_of(item.get("url", ""))
                if not host:
                    continue
                dom = registrable_domain(host)
                if not dom:
                    continue
                # 重複排除より前に数える: 2 件目以降のサブドメインも shared_2ld の
                # 本数には寄与する。ホワイトリストは数えない (公式サイトの
                # www/shop/support が 3 本あるだけで加点しないため)。
                if not wl.match(dom):
                    observed_hosts.append(host)
                if dom in seen_domains:
                    continue
                seen_domains.add(dom)
                if wl.match(dom):
                    whitelisted.append(dom)
                    continue
                if dom in known_before:
                    already_known.append(dom)
                    continue
                found_this_round.append(dom)

        # 同じ夜に観測した 2LD 別ホスト数を probe に渡す (>=3 で shared_2ld)。
        # 空の夜でも必ず差し替える: 前夜の counts が残ると古いホスト数で加点してしまう。
        setter = getattr(pipeline, "set_2ld_counts", None)
        if callable(setter):
            setter(count_2ld(observed_hosts))

        if not found_this_round:
            if round_no < MAX_ROUNDS and not aborted:
                gen.rotate()  # R5: クエリ生成と pageno の取り直し
                continue
            break

        for domain in found_this_round:
            res = pipeline.run_domain(domain)
            store.record(
                domain,
                score=res.score,
                decision=res.decision,
                features=res.features,
                evidence=[res.reasons] if isinstance(res.reasons, dict) else list(res.reasons),
                night=night,
            )
            if res.decision == "block":
                blocked.append(domain)
            elif res.decision == "hold":
                held.append(domain)
            else:
                dismissed.append(domain)

        new_domains += len(found_this_round)
        break

    # --- 再確認: block 判定の「連続 2 夜確認」を進める ---
    # 再評価して「今夜も block」だったときだけ記録する (nights_confirmed が進む)。
    # それ以外は既存の block 行をそのまま残す: 1 夜の観測で自動公開の判断を
    # 覆さないため、また一時的な取得失敗で誤って解除しないため。
    reconfirmed: list[str] = []
    released: list[str] = []
    for domain in pending_confirmation:
        res = pipeline.run_domain(domain)
        if res.decision == "block":
            store.record(
                domain,
                score=res.score,
                decision=res.decision,
                features=res.features,
                evidence=[res.reasons] if isinstance(res.reasons, dict) else list(res.reasons),
                night=night,
            )
            store.clear_reconfirm_miss(domain)
            reconfirmed.append(domain)
            continue
        # 今夜 block にならなかった。1 夜の観測で覆さないが、連続で確認できない
        # ドメインを block のまま放置すると limbo (掲載も解除もされない) になる。
        if store.note_reconfirm_miss(domain, night) < RECONFIRM_MISS_LIMIT:
            continue
        store.record(
            domain,
            score=res.score,
            decision=res.decision,
            features=res.features,
            evidence=[res.reasons] if isinstance(res.reasons, dict) else list(res.reasons),
            night=night,
        )
        store.clear_reconfirm_miss(domain)
        released.append(domain)

    # --- P8: 失効スイープ ---
    expired: list[str] = []
    health_probed: list[str] = []
    targets = store.monitor_targets(age_days=MONITOR_AGE_DAYS)
    if health is not None:
        for domain in targets:
            reachable = bool(health.check(domain))
            # checked_on に night を渡す: streak は「夜の観測」の連続数であって
            # 壁時計日ではない (同日に再実行しても 1 行に潰れない)。
            store.record_health(domain, reachable=reachable, checked_on=night)
            health_probed.append(domain)
    expired = store.expire_unreachable(streak_days=EXPIRE_STREAK_DAYS)

    # --- publish ---
    published: list[str] = []
    would_publish: list[str] = []
    published_total: list[str] = []
    already_listed: list[str] = []
    excluded_permanent_shape: list[str] = []
    ulist_removed: list[str] = []
    ulist_changed = False
    if ulist_path is not None:
        current = Path(ulist_path).read_text(encoding="utf-8") if Path(ulist_path).exists() else ""
        from publish import domains_to_remove, entries_to_domains, existing_entries

        # ホワイトリストは「誤検知/正規」の最終判断なので、decisions が block のままでも
        # 掲載しない。既存行に残っている分も publish のたびに取り除く (自己修復)。
        listed = entries_to_domains(existing_entries(current))
        retired = {d for d in listed if wl.match(d)}
        eligible = [d for d in store.eligible_domains() if not wl.match(d)]
        # 掲載されない理由を可視化する: 常設ルールが既に覆う形 (com.xx / .co / punycode)。
        from publish import is_permanent_shape as _is_permanent_shape

        excluded_permanent_shape = [d for d in eligible if _is_permanent_shape(d)]
        eligible = [d for d in eligible if not _is_permanent_shape(d)]
        wanted = build_entries(eligible)
        published_total = wanted
        before_entries = set(existing_entries(current))
        already_listed = [e for e in wanted if e in before_entries]
        if publish:
            text = merge_list(current, eligible)  # merge_list 側で entry 化する

            dropped = retired | set(expired)
            if dropped:
                text = domains_to_remove(text, dropped)
            Path(ulist_path).write_text(text, encoding="utf-8")
            # published は「今夜 新たに追記した entry」だけ。累積を返すとログ/commit
            # message が +23 と表示するのに差分 0 行、という誤報になる。
            before = before_entries
            after = set(existing_entries(text))
            published = sorted(after - before)
            ulist_removed = sorted(before - after)
            ulist_changed = text != current
            if dry_run:
                would_publish = wanted  # entry 形式で統一
        else:
            would_publish = wanted

    # --- P9b: cloaking-hold 専用リスト (cloaking_detected/uBlacklist.txt) ---
    cloaking_holds = [d for d in store.cloaking_holds() if not wl.match(d)]
    cloaking_would: list[str] = []
    cloaking_added: list[str] = []
    if cloaking_list_path is not None:
        from cloaking_publish import write_cloaking_list
        from publish import entries_to_domains, existing_entries

        path = Path(cloaking_list_path)
        before = existing_entries(path.read_text(encoding="utf-8")) if path.exists() else []
        # scam リスト (uBlacklist.txt) で公開済みのドメインは cloaking 側に載せない。
        # 両リストに同じドメインが出ると、どちらの判定が正かレビューで追えなくなる。
        scam_text = (
            Path(ulist_path).read_text(encoding="utf-8")
            if ulist_path is not None and Path(ulist_path).exists()
            else ""
        )
        cloak_before_domains = entries_to_domains(before)
        exclude = entries_to_domains(existing_entries(scam_text))
        # ホワイトリスト済み (= 誤検知) は cloaking 側の既存行からも落とす。
        exclude |= {d for d in cloak_before_domains if wl.match(d)}
        if dry_run:
            cloaking_would = build_entries([d for d in cloaking_holds if d not in exclude])
            cloaking_added = [e for e in cloaking_would if e not in before]
        else:
            text = write_cloaking_list(path, cloaking_holds, exclude=exclude)
            cloaking_added = [e for e in existing_entries(text) if e not in before]

    return {
        "night": night,
        "rounds": round_no,
        "empty_queries": empty_queries,
        "engine_failures": engine_failures,
        "aborted": aborted,
        "new_domains": new_domains,
        "domains_found": len(seen_domains),
        "blocked": blocked,
        "hold": held,
        "dismissed": dismissed,
        "whitelisted": whitelisted,
        "already_known": already_known,
        "expired": expired,
        "health_probed": health_probed,
        "published_entries": len(published),
        "published": published,
        "published_total": published_total,
        "already_listed": already_listed,
        "excluded_permanent_shape": excluded_permanent_shape,
        "pending_confirmation": pending_confirmation,
        "ulist_removed": ulist_removed,
        "ulist_changed": ulist_changed,
        "would_publish": would_publish,
        "reconfirmed": reconfirmed,
        "released": released,
        "cloaking_holds": cloaking_holds,
        "would_cloaking_holds": cloaking_would,
        "cloaking_added": cloaking_added,
        "dry_run": bool(dry_run),
    }
