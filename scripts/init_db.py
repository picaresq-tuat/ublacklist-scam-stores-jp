#!/usr/bin/env python3
"""db/ を初期化する (gitignore 対象の実データを seed から再生成)。

  python3 scripts/init_db.py

生成物: db/models.db (models_seed.csv から 240 件), db/whitelist.db (seed 投入)。
scam.db / searches.db は実行時に自動生成される。
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "script"))

from modeldb import ModelDB, SEED_CSV  # noqa: E402
from whitelist import SEED, WhitelistDB  # noqa: E402


def main() -> int:
    db_dir = ROOT / "db"
    db_dir.mkdir(parents=True, exist_ok=True)
    n = ModelDB(db_dir / "models.db").load_csv(SEED_CSV)
    print(f"models.db: {n} models")
    wl = WhitelistDB(db_dir / "whitelist.db")
    wl.load_seed(SEED)
    print(f"whitelist.db: {wl.count()} domains")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
