"""手動収集した容疑ドメインの継続監視 (P10)。

夜間ランナーから呼び、`db/manual_candidates.txt` (リポジトリ外・未検証リスト) を
毎晩同じパイプラインで再判定する。block かつ現役のものだけを uBlacklist.txt へ昇格。

- 候補リストは公開しない (誤検知を含む未検証データのため .gitignore 済み)
- 昇格判定は rejudge.select_promotions と同一ロジック (二重実装しない)
- probe は差し替え可能 (テストはネットワークを使わない)
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from pathlib import Path

import publish
from rejudge import Outcome, select_promotions

CANDIDATES_REL = Path("db") / "manual_candidates.txt"
ULIST_REL = Path("uBlacklist.txt")

_ENTRY = re.compile(r"^\*://\*\.([^/]+)/\*$")


def load_candidates(text: str) -> list[str]:
    """`*://*.example.com/*` 行からドメインを抽出 (重複除去・順序保持)。"""
    out: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        m = _ENTRY.match(line.strip())
        if not m:
            continue
        d = m.group(1).strip().lower()
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def promote(scam_text: str, outcomes: Iterable[Outcome]) -> tuple[str, list[str]]:
    """昇格対象を uBlacklist テキストへ反映し、(新テキスト, 昇格ドメイン) を返す。"""
    known = {m.group(1) for m in map(_ENTRY.match, publish.existing_entries(scam_text)) if m}
    promoted = select_promotions(outcomes, known)
    if not promoted:
        return scam_text, []
    new_text = publish.merge_list(scam_text, promoted)
    problems = publish.validate(new_text)
    if problems:
        raise ValueError(f"uBlacklist validation failed: {problems}")
    return new_text, promoted


def probe_domains(
    domains: list[str], workers: int = 6, db_path: Path | str | None = None
) -> list[Outcome]:
    """本番パイプラインでドメインを再判定する (実 I/O。テストからは使わない)。"""
    from concurrent.futures import ThreadPoolExecutor

    from favicon_corpus import build_corpus
    from probe import Pipeline
    from scamstore import DEFAULT_DB
    from whois_rdap import fetch_rdap

    # favicon corpus は判定履歴から組む。呼び出し側が DB を指定できる。
    favicon_counts, favicon_origins = build_corpus(db_path or DEFAULT_DB)
    pipe = Pipeline(
        rdap_fn=fetch_rdap,
        favicon_counts=favicon_counts,
        favicon_origins=favicon_origins,
    )

    def one(dom: str) -> Outcome:
        r = pipe.run_domain(dom)
        f = r.features or {}
        status = f.get("status")
        return Outcome(
            domain=dom,
            decision=r.decision,
            score=float(r.score or 0.0),
            status=status if isinstance(status, int) else None,
            cloaking=bool(f.get("cloaking")),
            reasons=dict(r.reasons or {}),
        )

    if workers <= 1:
        return [one(d) for d in domains]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(one, domains))


def monitor(
    repo_dir: Path | str,
    *,
    probe: Callable[[list[str]], list[Outcome]],
    dry_run: bool = False,
) -> dict:
    """候補リストを再判定し、必要なら uBlacklist.txt を更新する。

    dry_run=True でも判定は行い、`promoted` に結果を返す (書き込みだけしない)。
    """
    repo_dir = Path(repo_dir)
    cand_path = repo_dir / CANDIDATES_REL
    if not cand_path.exists():
        return {"candidates": 0, "promoted": [], "skipped": "no_candidates_file"}

    domains = load_candidates(cand_path.read_text(encoding="utf-8"))
    if not domains:
        return {"candidates": 0, "promoted": [], "skipped": "empty_candidates_file"}

    outcomes = probe(domains)
    ulist = repo_dir / ULIST_REL
    text = ulist.read_text(encoding="utf-8") if ulist.exists() else ""
    new_text, promoted = promote(text, outcomes)
    if promoted and not dry_run:
        ulist.write_text(new_text, encoding="utf-8")
    return {"candidates": len(domains), "promoted": promoted}
