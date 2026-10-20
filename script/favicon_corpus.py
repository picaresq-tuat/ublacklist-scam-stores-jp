"""favicon corpus の構築 (P11): 既存の判定履歴から md5 の共起を数える。

`favicon_collision` / `favicon_cross_origin` に供給する corpus を
`db/scam.db` の decisions から組み立てる。ネットワークは使わない。

汚染対策:
- `favicon_source == "raw"` の行だけを使う。旧実装は本文テキスト先頭 64 文字を
  MD5 化していたため、それらの md5 はアイコンの指紋ではない。
- 汎用 favicon (`GENERIC_FAVICON_MD5S`) と md5 形式でない値は除外する。
- 件数は host ではなく registrable domain で数える。同一サイトの
  www / shop サブドメインが別ドメインとして collision を立てないようにする。
- collision の母数は block / hold の行だけ (「既知の悪性との一致」)。
  cross_origin の代表は dismissed も含む全観測から出す。
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from urllib.parse import quote

from features import GENERIC_FAVICON_MD5S, registrable_domain
from scamstore import DEFAULT_DB

logger = logging.getLogger(__name__)

_MD5_HEX = set("0123456789abcdef")
_BAD_DECISIONS = ("block", "hold")


def _is_md5(value) -> bool:
    return isinstance(value, str) and len(value) == 32 and set(value.lower()) <= _MD5_HEX


def _connect_ro(path: Path) -> sqlite3.Connection:
    """パスを URI エスケープして読み取り専用で開く (#?% を含むパス対策)。"""
    return sqlite3.connect(f"file:{quote(str(path))}?mode=ro", uri=True)


def build_corpus(
    db_path: Path | str | None = DEFAULT_DB,
) -> tuple[dict[str, int], dict[str, list[str]]]:
    """(md5 -> 悪性ドメイン数, md5 -> 観測オリジン一覧) を返す。

    件数は registrable domain 単位。DB が無い・読めない場合は空の corpus を
    返す (走査を止めない) が、黙って無効化しないよう警告は残す。
    """
    if db_path is None:
        return {}, {}
    path = Path(db_path)
    if not path.exists():
        return {}, {}
    try:
        con = _connect_ro(path)
    except sqlite3.Error as exc:
        logger.warning("favicon corpus: cannot open %s: %s", path, exc)
        return {}, {}
    seen_all: dict[str, set[str]] = {}
    seen_bad: dict[str, set[str]] = {}
    try:
        try:
            rows = con.execute("SELECT domain, features_json, decision FROM decisions").fetchall()
        except sqlite3.OperationalError:
            # decision 列を持たない古い DB。判定不明なので collision 母数は全行とする。
            logger.warning("favicon corpus: %s に decision 列がありません", path)
            rows = [
                (d, f, "block")
                for d, f in con.execute("SELECT domain, features_json FROM decisions")
            ]
        for domain, raw, decision in rows:
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
            reg = registrable_domain(domain) or domain.strip().lower()
            seen_all.setdefault(md5, set()).add(reg)
            if decision in _BAD_DECISIONS:
                seen_bad.setdefault(md5, set()).add(reg)
    except sqlite3.Error as exc:
        logger.warning("favicon corpus: cannot read %s: %s", path, exc)
        return {}, {}
    finally:
        con.close()
    counts = {md5: len(seen) for md5, seen in seen_bad.items()}
    origins = {md5: sorted(seen) for md5, seen in seen_all.items() if seen}
    return counts, origins
