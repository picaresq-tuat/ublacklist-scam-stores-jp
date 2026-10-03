"""型番 DB (P0)。

日本で 2011〜2021 年 (15〜5 年前) に発売された国内ノート PC の型番を保持する。
シードは data/models_seed.csv、実行時 DB は models.db (SQLite)。
"""
from __future__ import annotations

import csv
import random
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

YEAR_MIN = 2011
YEAR_MAX = 2021

PKG_ROOT = Path(__file__).resolve().parent.parent  # リポジトリルート
DB_DIR = PKG_ROOT / "db"
SEED_CSV = Path(__file__).resolve().parent / "data" / "models_seed.csv"
DEFAULT_DB = DB_DIR / "models.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS models (
    model         TEXT PRIMARY KEY,
    brand         TEXT NOT NULL,
    released_year INTEGER NOT NULL CHECK (released_year BETWEEN 2011 AND 2021),
    source_url    TEXT NOT NULL DEFAULT '',
    added_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_models_year ON models(released_year);
CREATE INDEX IF NOT EXISTS idx_models_brand ON models(brand);
"""


@dataclass(frozen=True)
class Model:
    brand: str
    model: str
    released_year: int
    source_url: str = ""


def load_seed(path: Path | str = SEED_CSV) -> list[Model]:
    """シード CSV を読み、範囲外の年を弾いて Model のリストを返す。"""
    out: list[Model] = []
    with Path(path).open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            year = int(row["released_year"])
            if not (YEAR_MIN <= year <= YEAR_MAX):
                continue
            model = row["model"].strip()
            if not model:
                continue
            out.append(Model(row["brand"].strip(), model, year, (row.get("source_url") or "").strip()))
    return out


class ModelDB:
    def __init__(self, path: Path | str = DEFAULT_DB):
        self.path = Path(path)
        self._con = sqlite3.connect(self.path)
        self._con.executescript(SCHEMA)
        self._con.commit()

    def close(self) -> None:
        self._con.close()

    def __enter__(self) -> "ModelDB":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def load_csv(self, path: Path | str = SEED_CSV) -> int:
        """CSV を投入し、投入後の総件数を返す (冪等)。"""
        rows = load_seed(path)
        self._con.executemany(
            "INSERT OR REPLACE INTO models(model, brand, released_year, source_url) VALUES (?,?,?,?)",
            [(m.model, m.brand, m.released_year, m.source_url) for m in rows],
        )
        self._con.commit()
        return self.count()

    def count(self) -> int:
        return int(self._con.execute("SELECT COUNT(*) FROM models").fetchone()[0])

    def all(self) -> list[Model]:
        cur = self._con.execute(
            "SELECT brand, model, released_year, source_url FROM models ORDER BY released_year, model"
        )
        return [Model(*row) for row in cur.fetchall()]

    def brands(self) -> list[str]:
        cur = self._con.execute("SELECT DISTINCT brand FROM models ORDER BY brand")
        return [r[0] for r in cur.fetchall()]

    def get(self, model: str) -> Optional[Model]:
        cur = self._con.execute(
            "SELECT brand, model, released_year, source_url FROM models WHERE model = ?", (model,)
        )
        row = cur.fetchone()
        return Model(*row) if row else None

    def sample(self, n: int, rng: random.Random | None = None) -> list[Model]:
        rng = rng or random.Random()
        pool = self.all()
        if n > len(pool):
            raise ValueError(f"requested {n} but only {len(pool)} models")
        return rng.sample(pool, n)

    def sample_by_year_range(self, year_from: int, year_to: int, n: int,
                             rng: random.Random | None = None) -> list[Model]:
        rng = rng or random.Random()
        cur = self._con.execute(
            "SELECT brand, model, released_year, source_url FROM models"
            " WHERE released_year BETWEEN ? AND ? ORDER BY model",
            (year_from, year_to),
        )
        pool = [Model(*row) for row in cur.fetchall()]
        if n > len(pool):
            raise ValueError(f"requested {n} but pool has {len(pool)} (years {year_from}-{year_to})")
        return rng.sample(pool, n)


def seed_iter(models: Iterable[Model]) -> list[str]:
    return [m.model for m in models]
