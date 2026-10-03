"""P0: 型番 DB (models.db) の RED テスト。"""

import csv
import sqlite3
from pathlib import Path

import pytest
from modeldb import SEED_CSV, YEAR_MAX, YEAR_MIN, Model, ModelDB, load_seed

EXPECTED_BRANDS = {
    "dynabook",
    "Lenovo ThinkPad",
    "Panasonic Let's note",
    "VAIO",
    "NEC LaVie",
    "Fujitsu",
    "HP",
    "Dell",
    "ASUS",
    "Acer",
}


@pytest.fixture()
def db(tmp_path):
    d = ModelDB(tmp_path / "models.db")
    d.load_csv(SEED_CSV)
    return d


def test_seed_csv_exists_and_is_large_enough():
    with Path(SEED_CSV).open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) >= 200, f"seed rows={len(rows)}"
    assert {"brand", "model", "released_year"} <= set(rows[0])


def test_seed_year_range_is_2011_to_2021(db):
    years = [m.released_year for m in db.all()]
    assert min(years) == 2011 and max(years) == 2021
    assert YEAR_MIN == 2011 and YEAR_MAX == 2021


def test_count_and_brands(db):
    assert db.count() >= 200
    assert set(db.brands()) == EXPECTED_BRANDS


def test_all_returns_models_with_unique_strings(db):
    ms = db.all()
    assert all(isinstance(m, Model) for m in ms)
    assert len({m.model for m in ms}) == len(ms)
    assert all(m.model.strip() == m.model and m.model for m in ms)


def test_sample_returns_unique_models(db):
    picked = db.sample(20)
    assert len(picked) == 20
    assert len({m.model for m in picked}) == 20


def test_sample_by_year_range_filters(db):
    picked = db.sample_by_year_range(2015, 2017, 25)
    assert picked, "no models in 2015-2017"
    assert all(2015 <= m.released_year <= 2017 for m in picked)
    assert len(picked) == 25


def test_sample_by_year_range_rejects_unavailable(db):
    with pytest.raises(ValueError):
        db.sample_by_year_range(2011, 2021, 10_000)


def test_sample_is_deterministic_with_seed(db):
    import random

    a = [m.model for m in db.sample(12, rng=random.Random(7))]
    b = [m.model for m in db.sample(12, rng=random.Random(7))]
    assert a == b


def test_load_csv_is_idempotent(tmp_path):
    d = ModelDB(tmp_path / "m.db")
    assert d.load_csv(SEED_CSV) == d.load_csv(SEED_CSV)
    assert d.count() == len(load_seed())


def test_schema_is_queryable_by_sql(db):
    con = sqlite3.connect(db.path)
    (n,) = con.execute("SELECT COUNT(*) FROM models").fetchone()
    assert n == db.count()


def test_get_model_roundtrip(db):
    first = db.all()[0]
    got = db.get(first.model)
    assert got == first
    assert db.get("no-such-model-zzz") is None
