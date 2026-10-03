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
from scamstore import ScamStore
from searchlog import PageRangeExhausted, pick_pageno

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
        return urlsplit(u).netloc.split(":")[0].lower()
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
                if not dom or dom in seen_domains:
                    continue
                seen_domains.add(dom)
                if wl.match(dom):
                    whitelisted.append(dom)
                    continue
                if dom in known_before:
                    already_known.append(dom)
                    continue
                found_this_round.append(dom)

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
    if ulist_path is not None:
        current = Path(ulist_path).read_text(encoding="utf-8") if Path(ulist_path).exists() else ""
        eligible = store.eligible_domains()
        wanted = build_entries(eligible)
        if publish:
            text = merge_list(current, eligible)  # merge_list 側で entry 化する
            from publish import domains_to_remove

            if expired:
                text = domains_to_remove(text, expired)
            Path(ulist_path).write_text(text, encoding="utf-8")
            published = wanted  # entry 形式 (*://*.d/*)
            if dry_run:
                would_publish = wanted  # entry 形式で統一
        else:
            would_publish = wanted

    # --- P9b: cloaking-hold 専用リスト (cloaking_detected/uBlacklist.txt) ---
    cloaking_holds = store.cloaking_holds()
    cloaking_would: list[str] = []
    if cloaking_list_path is not None:
        from cloaking_publish import write_cloaking_list

        if dry_run:
            cloaking_would = build_entries(cloaking_holds)
        else:
            write_cloaking_list(cloaking_list_path, cloaking_holds)

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
        "would_publish": would_publish,
        "cloaking_holds": cloaking_holds,
        "would_cloaking_holds": cloaking_would,
        "dry_run": bool(dry_run),
    }
