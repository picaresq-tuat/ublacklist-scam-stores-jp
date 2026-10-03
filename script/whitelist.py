"""ホワイトリスト = triage ゲート。

「未知 = 詐欺」ではない (S4)。ここに落ちたドメインは以降のステージに進めない。
"""
from __future__ import annotations

import sqlite3
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

PKG_ROOT = Path(__file__).resolve().parent.parent  # リポジトリルート
DB_DIR = PKG_ROOT / "db"
DEFAULT_DB = DB_DIR / "whitelist.db"

CATEGORIES: tuple[str, ...] = (
    "vendor_support", "official_store", "used_store",
    "news_media", "blog_platform", "favicon_reference", "aggregator",
)

# 互換のための別名 (テスト/CLI から参照)
SEED: tuple[str, ...] = (
    # --- vendor_support (公式サポート) ---
    "panasonic.jp", "panasonic.co.jp", "panasonic.com", "vaio.com", "jp.vaio.com",
    "dynabook.com", "dynabook.co.jp", "vaio.jp", "toshiba.com", "nec.co.jp",
    "toshiba.co.jp", "lenovo.com", "dell.com", "hp.com", "support.hp.com",
    "epson.jp", "nec-lavie.jp", "fujitsu.com", "sharp.co.jp", "sony.jp",
    "asus.com", "acer.com", "msi.com", "apple.com", "support.microsoft.com",
    "buffalo.jp", "iodata.jp", "elecom.co.jp", "logitec.co.jp", "microsoft.com",
    # --- official_store (正規ストア) ---
    "apple.com", "store.google.com", "panasonicstore.jp", "vaio-direct.com",
    "jp.dynabook.com", "lenovo.co.jp", "dell.co.jp", "hpdirect.co.jp",
    "musashi-ec.jp", "dospara.co.jp", "tsukumo.co.jp", "ark-pc.co.jp",
    "pc-koubou.jp", "bicbic.com", "sofmap.com", "dynabook-direct.jp",
    "onlineshop.nec-lavie.jp", "fujitsu-webmart.com", "shop.sharp.co.jp",
    # --- used_store (中古・整備済み) ---
    "janpara.co.jp", "iosys.co.jp", "pcfree.co.jp", "usedpc.com",
    "re-plus.jp", "pc-doctor.jp", "sofmap.com", "geo-online.co.jp",
    "bookoff.co.jp", "netmall.hardoff.co.jp", "suruga-ya.jp",
    "akibasouba.com", "pcshop.kakaku.com", "mall.pc-supply.com",
    # 型番検索で実際にヒットした小規模正規店 (2026-09-24 ゴールデン採取)
    "pc-master.jp", "hyperlab.jp",
    # --- news_media (PC ニュース) ---
    "itmedia.co.jp", "pcwatch.impress.co.jp", "kakakumag.com", "internet.watch.impress.co.jp",
    "ascii.jp", "gigazine.net", "impress.co.jp", "impress.co.jp.cdn", "mynavi.jp",
    "nikkei.com", "ascii.jp", "weekly.ascii.jp", "news.mynavi.jp", "akiba-pc.watch.impress.co.jp",
    # --- blog_platform (ブログ/プラットフォーム) ---
    "hatenablog.com", "hatenablog.jp", "note.com", "ameblo.jp", "livedoor.jp",
    "seesaa.net", "blogspot.com", "blog.jp", "exblog.jp", "cocolog-nifty.com",
    "wordpress.com", "github.io", "qiita.com", "zenn.dev", "speakerdeck.com",
    "fc2.com", "blog.fc2.com", "goo.ne.jp", "biglobe.ne.jp", "so-net.ne.jp",
    # --- favicon_reference (favicon 照合の基準元) ---
    "komeri.com", "askul.co.jp", "suruga-ya.jp", "zencart.com", "rakuten.co.jp",
    "amazon.co.jp", "yahoo.co.jp", "mercari.com", "shopping.yahoo.co.jp",
    "google.co.jp",
    # --- aggregator (まとめ/EC モール) ---
    "kakaku.com", "aucfan.com", "rakuten.co.jp", "amazon.co.jp", "yahoo.co.jp",
    "mercari.com", "paypayfleamarket.yahoo.co.jp", "wikipedia.org", "ja.wikipedia.org",
    "nikkei.com", "biccamera.com", "yodobashi.com", "joshinweb.jp", "edion.com",
)

# 型番検索で「正規」と確認できた個人ブログ (2026-09-24 ゴールデン採取 / 8 件)
MEASURED_LEGIT_BLOGS: tuple[str, ...] = (
    "fuji-x-life.tokyo", "blog.htkyama.org", "limonenote.com",
    "gadgetken.com", "heeeee.jp", "websumaho.blog.fc2.com",
)

SEED = SEED + MEASURED_LEGIT_BLOGS


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalise_host(value: str) -> str:
    """URL / host[:port] / host のいずれからでも host を取り出す。"""
    v = (value or "").strip().lower()
    if not v:
        return ""
    if "//" in v:
        v = urllib.parse.urlsplit(v).netloc or v
    elif "/" in v:
        v = v.split("/", 1)[0]
    return v.rsplit("@", 1)[-1].split(":")[0].strip(".")


class Whitelist:
    """前方一致ではなく「末尾一致 (ラベル境界)」で照合する。"""

    def __init__(self, domains):
        self.domains: frozenset[str] = frozenset(normalise_host(d) for d in domains if d)
        self._cache: dict[str, Optional[str]] = {}

    def match(self, host_or_url: str) -> Optional[str]:
        host = normalise_host(host_or_url)
        if not host:
            return None
        labels = host.split(".")
        for i in range(len(labels)):
            cand = ".".join(labels[i:])
            if cand in self.domains:
                return cand
        return None


def is_whitelisted(host_or_url: str, domains) -> bool:
    return Whitelist(domains).match(host_or_url) is not None


class WhitelistDB:
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS whitelist (
        domain   TEXT PRIMARY KEY,
        category TEXT NOT NULL,
        source   TEXT NOT NULL DEFAULT '',
        added_at TEXT NOT NULL
    );
    """

    def __init__(self, path: Path | str = DEFAULT_DB):
        self.path = Path(path)
        self._con = sqlite3.connect(str(self.path))
        self._con.executescript(self.SCHEMA)
        self._con.commit()

    def close(self) -> None:
        self._con.close()

    def __enter__(self) -> "WhitelistDB":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def count(self) -> int:
        return int(self._con.execute("SELECT COUNT(*) FROM whitelist").fetchone()[0])

    def add(self, domain: str, category: str, *, source: str = "", added_at: Optional[str] = None) -> bool:
        if category not in CATEGORIES:
            raise ValueError(f"unknown category: {category!r}")
        host = normalise_host(domain)
        if not host:
            raise ValueError("empty domain")
        cur = self._con.execute(
            "INSERT OR IGNORE INTO whitelist(domain, category, source, added_at) VALUES(?,?,?,?)",
            (host, category, source, added_at or _now()),
        )
        self._con.commit()
        return bool(cur.rowcount)

    def remove(self, domain: str) -> bool:
        cur = self._con.execute("DELETE FROM whitelist WHERE domain=?", (normalise_host(domain),))
        self._con.commit()
        return bool(cur.rowcount)

    def load_seed(self, entries=SEED, category: str = "") -> int:
        added = 0
        for d in entries:
            cat = category or _guess_category(d)
            added += int(self.add(d, cat, source="seed"))
        return added

    def categories(self) -> dict:
        cur = self._con.execute("SELECT category, COUNT(*) FROM whitelist GROUP BY category")
        return {str(r[0]): int(r[1]) for r in cur.fetchall()}

    def all(self) -> list[str]:
        return [str(r[0]) for r in self._con.execute("SELECT domain FROM whitelist ORDER BY domain")]

    def matcher(self) -> Whitelist:
        return Whitelist(self.all())

    def match(self, host_or_url: str) -> Optional[str]:
        """命中した *カテゴリ* を返す (未収録は None)。"""
        host = normalise_host(host_or_url)
        labels = host.split(".")
        for i in range(len(labels)):
            cand = ".".join(labels[i:])
            row = self._con.execute("SELECT category FROM whitelist WHERE domain=?", (cand,)).fetchone()
            if row:
                return str(row[0])
        return None


def _guess_category(domain: str) -> str:
    d = domain.lower()
    if d in ("zencart.com", "komeri.com", "askul.co.jp", "suruga-ya.jp"):
        return "favicon_reference"
    if any(k in d for k in ("hatenablog", "note.com", "ameblo", "livedoor", "seesaa",
                            "blogspot", "blog.jp", "exblog", "cocolog", "wordpress.com",
                            "github.io", "qiita", "zenn.dev", "speakerdeck")):
        return "blog_platform"
    if any(k in d for k in ("itmedia", "impress", "kakaku.com", "gigazine", "ascii",
                            "mynavi", "nikkei", "watch")):
        return "news_media"
    if any(k in d for k in ("janpara", "iosys", "pcfree", "usedpc", "re-plus", "pc-doctor",
                            "geo-online", "bookoff", "hardoff", "suruga-ya", "akibasouba")):
        return "used_store"
    if any(k in d for k in ("kakaku.com", "aucfan", "rakuten", "amazon", "yahoo", "mercari",
                            "paypay", "wikipedia")):
        return "aggregator"
    if any(k in d for k in ("vaio", "dynabook", "toshiba", "lenovo", "dell", "hp.com",
                            "epson", "lavie", "fujitsu", "sharp", "sony", "asus", "acer",
                            "msi.com", "apple", "microsoft", "buffalo", "iodata", "elecom",
                            "logitec", "panasonic", "nec", "support.")):
        return "vendor_support"
    return "official_store"
