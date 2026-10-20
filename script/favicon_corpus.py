"""favicon corpus の構築 (P11): 既存の判定履歴から md5 の共起を数える。

`favicon_collision` / `favicon_cross_origin` に供給する corpus を
`db/scam.db` の decisions から組み立てる。ネットワークは使わない。

汚染対策:
- `favicon_source == "raw"` の行だけを使う。旧実装は本文テキスト先頭 64 文字を
  MD5 化していたため、それらの md5 はアイコンの指紋ではない。
- 汎用 favicon (`GENERIC_FAVICON_MD5S`) と md5 形式でない値は除外する。
- 件数は「同一 md5 を持つ distinct ドメイン数」。同一ドメインの再判定は 1 と数える。
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from features import GENERIC_FAVICON_MD5S
from scamstore import DEFAULT_DB

_MD5_HEX = set("0123456789abcdef")


def _is_md5(value) -> bool:
    return isinstance(value, str) and len(value) == 32 and set(value.lower()) <= _MD5_HEX


def build_corpus(db_path: Path | str = DEFAULT_DB) -> tuple[dict[str, int], dict[str, str]]:
    """(md5 -> distinct ドメイン数, md5 -> 代表オリジン) を返す。

    DB が無い・読めない場合は空の corpus を返す (走査を止めない)。
    """
    path = Path(db_path)
    if not path.exists():
        return {}, {}
    domains: dict[str, set[str]] = {}
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error:
        return {}, {}
    try:
        rows = con.execute("SELECT domain, features_json FROM decisions")
        for domain, raw in rows:
            if not isinstance(domain, str) or not domain.strip():
                continue
            try:
                feats = json.loads(raw or "{}")
            except (TypeError, ValueError):
                continue
            if not isinstance(feats, dict):
                continue
            if feats.get("favicon_source") != "raw":
                continue
            md5 = feats.get("favicon_md5")
            if not _is_md5(md5):
                continue
            md5 = md5.lower()
            if md5 in GENERIC_FAVICON_MD5S:
                continue
            domains.setdefault(md5, set()).add(domain.strip().lower())
    except sqlite3.Error:
        return {}, {}
    finally:
        con.close()
    counts = {md5: len(seen) for md5, seen in domains.items()}
    origins = {md5: min(seen) for md5, seen in domains.items() if seen}
    return counts, origins
