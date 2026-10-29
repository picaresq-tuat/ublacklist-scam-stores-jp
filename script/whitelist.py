"""ホワイトリスト = triage ゲート。

「未知 = 詐欺」ではない (S4)。ここに落ちたドメインは以降のステージに進めない。
"""

from __future__ import annotations

import sqlite3
import urllib.parse
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parent.parent  # リポジトリルート
DB_DIR = PKG_ROOT / "db"
DEFAULT_DB = DB_DIR / "whitelist.db"

CATEGORIES: tuple[str, ...] = (
    "vendor_support",
    "official_store",
    "used_store",
    "news_media",
    "blog_platform",
    "favicon_reference",
    "aggregator",
)

# 互換のための別名 (テスト/CLI から参照)
SEED: tuple[str, ...] = (
    # --- vendor_support (公式サポート) ---
    "panasonic.jp",
    "panasonic.co.jp",
    "panasonic.com",
    "vaio.com",
    "jp.vaio.com",
    "dynabook.com",
    "dynabook.co.jp",
    "vaio.jp",
    "toshiba.com",
    "nec.co.jp",
    "toshiba.co.jp",
    "lenovo.com",
    "dell.com",
    "hp.com",
    "support.hp.com",
    "epson.jp",
    "nec-lavie.jp",
    "fujitsu.com",
    "sharp.co.jp",
    "sony.jp",
    "asus.com",
    "acer.com",
    "msi.com",
    "apple.com",
    "support.microsoft.com",
    "buffalo.jp",
    "iodata.jp",
    "elecom.co.jp",
    "logitec.co.jp",
    "microsoft.com",
    # --- official_store (正規ストア) ---
    "apple.com",
    "store.google.com",
    "panasonicstore.jp",
    "vaio-direct.com",
    "jp.dynabook.com",
    "lenovo.co.jp",
    "dell.co.jp",
    "hpdirect.co.jp",
    "musashi-ec.jp",
    "dospara.co.jp",
    "tsukumo.co.jp",
    "ark-pc.co.jp",
    "pc-koubou.jp",
    "bicbic.com",
    "sofmap.com",
    "dynabook-direct.jp",
    "onlineshop.nec-lavie.jp",
    "fujitsu-webmart.com",
    "shop.sharp.co.jp",
    # --- used_store (中古・整備済み) ---
    "janpara.co.jp",
    "iosys.co.jp",
    "pcfree.co.jp",
    "usedpc.com",
    "re-plus.jp",
    "pc-doctor.jp",
    "sofmap.com",
    "geo-online.co.jp",
    "bookoff.co.jp",
    "netmall.hardoff.co.jp",
    "suruga-ya.jp",
    "akibasouba.com",
    "pcshop.kakaku.com",
    "mall.pc-supply.com",
    # 型番検索で実際にヒットした小規模正規店 (2026-09-24 ゴールデン採取)
    "pc-master.jp",
    "hyperlab.jp",
    # --- news_media (PC ニュース) ---
    "itmedia.co.jp",
    "pcwatch.impress.co.jp",
    "kakakumag.com",
    "internet.watch.impress.co.jp",
    "ascii.jp",
    "gigazine.net",
    "impress.co.jp",
    "impress.co.jp.cdn",
    "mynavi.jp",
    "nikkei.com",
    "ascii.jp",
    "weekly.ascii.jp",
    "news.mynavi.jp",
    "akiba-pc.watch.impress.co.jp",
    # --- blog_platform (ブログ/プラットフォーム) ---
    "hatenablog.com",
    "hatenablog.jp",
    "note.com",
    "ameblo.jp",
    "livedoor.jp",
    "seesaa.net",
    "blogspot.com",
    "blog.jp",
    "exblog.jp",
    "cocolog-nifty.com",
    "wordpress.com",
    "github.io",
    # Firebase Hosting (Google)。`project.web.app` 形式の全サブドメインが
    # 同一 2LD を共有する共有ホスティング基盤なので、ブログ基盤と同じ扱い。
    # ラベル境界の末尾一致なので `web.app` 1 件でサブドメイン全体を覆う。
    "web.app",
    "qiita.com",
    "zenn.dev",
    "speakerdeck.com",
    "fc2.com",
    "blog.fc2.com",
    "goo.ne.jp",
    "biglobe.ne.jp",
    "so-net.ne.jp",
    # --- favicon_reference (favicon 照合の基準元) ---
    "komeri.com",
    "askul.co.jp",
    "suruga-ya.jp",
    "zencart.com",
    "rakuten.co.jp",
    "amazon.co.jp",
    "yahoo.co.jp",
    "mercari.com",
    "shopping.yahoo.co.jp",
    "google.co.jp",
    # --- aggregator (まとめ/EC モール) ---
    "kakaku.com",
    "aucfan.com",
    "rakuten.co.jp",
    "amazon.co.jp",
    "yahoo.co.jp",
    "mercari.com",
    "paypayfleamarket.yahoo.co.jp",
    "wikipedia.org",
    "ja.wikipedia.org",
    "nikkei.com",
    "biccamera.com",
    "yodobashi.com",
    "joshinweb.jp",
    "edion.com",
)

# 型番検索で「正規」と確認できた個人ブログ (2026-09-24 ゴールデン採取 / 8 件)
MEASURED_LEGIT_BLOGS: tuple[str, ...] = (
    "fuji-x-life.tokyo",
    "blog.htkyama.org",
    "limonenote.com",
    "gadgetken.com",
    "heeeee.jp",
    "websumaho.blog.fc2.com",
)

# 実測で「cloaking ではない」と確認した大規模正規サイト (2026-10-12)。
# どちらも通常ブラウザ取得と bot 取得で内容が変わるが、差の向きが正規の挙動:
#   bandai-hobby.net — browser 200/194,898B「バンダイ ホビーサイト」に対し
#                      googlebot/bingbot は 200/13,157B「404 NOT FOUND｜バンダイホビーサイト」
#                      (クローラにエラーページを返す = 反スクレイピング側の挙動)
#   dmm.co.jp        — browser 200/30,403B「年齢認証 - FANZA」(年齢ゲート) に対し
#                      googlebot/bingbot は 200/731KB で www.fanza.jp/top/ へリダイレクト
#                      (人間に法定のゲートを出す挙動)
# PC UA とモバイル UA の差はそれぞれ jaccard=0.977 / ゲート同一で、レスポンシブ差ではない。
MEASURED_NON_CLOAKING: tuple[str, ...] = ("bandai-hobby.net", "dmm.co.jp")


# 2026-10-21 に運用者が報告した誤検知 9 件。いずれも実ページを確認して正規と判断した:
#   chuko-pc-lab.com / tu-han.net / accessoires-asus.com / k-tai-iosys.com — 正規の販売・情報サイト
#   gemini.google / deepmind.google — ブランド TLD (.google) 上の公式サービス
#   facebook.com — 通常取得が 400 を返しただけ (cloaking ではない)
#   bandai-hobby.net / dmm.co.jp — MEASURED_NON_CLOAKING (差分の向きが正規)
# triage ゲートで probe 対象から外す。個別リストからも削除済み。
MEASURED_FALSE_POSITIVES: tuple[str, ...] = (
    "chuko-pc-lab.com",
    "gemini.google",
    "tu-han.net",
    "accessoires-asus.com",
    "bandai-hobby.net",
    "deepmind.google",
    "dmm.co.jp",
    "facebook.com",
    "k-tai-iosys.com",
    # 2026-10-27 に運用者が誤検知として報告した 3 件 (scam 1 件 / cloaking 2 件)。
    "yahoo.jp",
    "dailymotion.com",
    "jsmjapan.com",
)

# 上記のうち `_guess_category` の部分一致では正しく分類できないものの明示カテゴリ。
_EXPLICIT_CATEGORIES: dict[str, str] = {
    "bandai-hobby.net": "official_store",
    "dmm.co.jp": "aggregator",
    "chuko-pc-lab.com": "blog_platform",
    "gemini.google": "vendor_support",
    "deepmind.google": "vendor_support",
    "tu-han.net": "official_store",
    "accessoires-asus.com": "official_store",
    "k-tai-iosys.com": "used_store",
    "facebook.com": "blog_platform",
    "web.app": "blog_platform",
    "yahoo.jp": "aggregator",
    "dailymotion.com": "blog_platform",
    "jsmjapan.com": "official_store",
}

# 2026-10-27: 200 ドメイン規模への拡充。カテゴリは実測ではなく運用者の判断で固定する
# (部分一致の推定に任せると "paypay" のような語で誤分類するため)。
EXPANSION: dict[str, tuple[str, ...]] = {
    "vendor_support": (
        "intel.com",
        "amd.com",
        "nvidia.com",
        "samsung.com",
        "lg.com",
        "huawei.com",
        "xiaomi.com",
        "oppo.com",
        "motorola.com",
        "brother.com",
        "brother.co.jp",
        "canon.com",
        "canon.jp",
        "ricoh.com",
        "ricoh.co.jp",
        "kyocera.com",
        "oki.com",
        "fujixerox.co.jp",
        "nikon.com",
        "casio.com",
        "casio.jp",
        "fujifilm.com",
    ),
    "official_store": (
        "nojima.co.jp",
        "yamada-denki.jp",
        "kdenki.com",
    ),
    "used_store": ("hardoff.co.jp",),
    "news_media": (
        "nhk.or.jp",
        "asahi.com",
        "yomiuri.co.jp",
        "mainichi.jp",
        "sankei.com",
        "tokyo-np.co.jp",
        "reuters.com",
        "bloomberg.co.jp",
        "toyokeizai.net",
        "diamond.jp",
        "businessinsider.jp",
        "wired.jp",
        "gizmodo.jp",
        "forbesjapan.com",
        "president.jp",
    ),
    "blog_platform": (
        # livedoor.blog は無料ブログ基盤で、配下に詐欺ページが同居しうるため除外する
        # (shared_2ld の検出対象でもある)。
        "hatena.ne.jp",
        "hatenadiary.jp",
        "hatenadiary.org",
        "jugem.jp",
        "nifty.com",
        "ocn.ne.jp",
        "plala.or.jp",
        "tumblr.com",
        "medium.com",
        "substack.com",
        "twitter.com",
        "x.com",
        "instagram.com",
        "tiktok.com",
        "youtube.com",
        "linkedin.com",
        "pinterest.com",
        "reddit.com",
        "github.com",
        "gitlab.com",
        "stackoverflow.com",
    ),
    "favicon_reference": (
        "aeon.com",
        "seiyu.co.jp",
        "donki.com",
        "uniqlo.com",
        "muji.com",
    ),
    "aggregator": (
        "qoo10.jp",
        "paypay.ne.jp",
        "ruten.co.jp",
    ),
}

# 大手サイトが自社で保有する別名。canonical は必ず SEED に存在する。
# whitelist 単体 (Whitelist(SEED)) でも DB でも同じように効くよう、両方で展開する。
ALIASES: dict[str, tuple[str, ...]] = {
    "yahoo.co.jp": ("yahoo.com",),
    "rakuten.co.jp": ("rakuten.com",),
    "amazon.co.jp": ("amazon.com", "amazon.jp"),
    "google.co.jp": ("google.com",),
    "apple.com": ("apple.co.jp",),
    "microsoft.com": ("microsoft.co.jp",),
    "dmm.co.jp": ("dmm.com",),
    "dailymotion.com": ("dai.ly",),
    "wikipedia.org": ("wikipedia.com",),
    "sony.jp": ("sony.co.jp", "sony.com"),
}

_EXPANDED_SEED: tuple[str, ...] = tuple(d for domains in EXPANSION.values() for d in domains)
_EXPLICIT_CATEGORIES.update(
    {d: category for category, domains in EXPANSION.items() for d in domains}
)

SEED = (
    SEED + MEASURED_LEGIT_BLOGS + MEASURED_NON_CLOAKING + MEASURED_FALSE_POSITIVES + _EXPANDED_SEED
)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def expand_aliases(domains: Iterable[str]) -> frozenset[str]:
    """登録ドメインを、そのサイトが自社で保有する別名まで広げる。

    `ALIASES` は canonical -> aliases の片方向だけを持つ。ここで双方向に展開するので、
    呼び出し側 (hunter など) は `Whitelist(SEED)` のままで別名をカバーできる。
    """
    hosts = {normalise_host(d) for d in domains if d}
    hosts.discard("")
    aliases: set[str] = set()
    for host in hosts:
        aliases.update(ALIASES.get(host, ()))
    for canonical, names in ALIASES.items():
        if canonical in hosts:
            aliases.update(names)
        elif any(name in hosts for name in names):
            aliases.add(canonical)
    return frozenset(hosts | aliases)


class Whitelist:
    """前方一致ではなく「末尾一致 (ラベル境界)」で照合する。"""

    def __init__(self, domains):
        self.domains: frozenset[str] = expand_aliases(domains)
        self._cache: dict[str, str | None] = {}

    def match(self, host_or_url: str) -> str | None:
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

    def __enter__(self) -> WhitelistDB:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def count(self) -> int:
        return int(self._con.execute("SELECT COUNT(*) FROM whitelist").fetchone()[0])

    def add(
        self, domain: str, category: str, *, source: str = "", added_at: str | None = None
    ) -> bool:
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
        """SEED と、その canonical に紐づく公式エイリアスを投入する。

        エイリアスも 1 行として持たせるので、`match()` / `matcher()` は追加の
        ルックアップなしに whitelist 単体で別名を判定できる。
        """
        added = 0
        for d in entries:
            host = normalise_host(d)
            if not host:
                continue
            cat = category or _EXPLICIT_CATEGORIES.get(host) or _guess_category(host)
            added += int(self.add(host, cat, source="seed"))
            for alias in ALIASES.get(host, ()):
                added += int(self.add(alias, cat, source=f"alias:{host}"))
        return added

    def categories(self) -> dict:
        cur = self._con.execute("SELECT category, COUNT(*) FROM whitelist GROUP BY category")
        return {str(r[0]): int(r[1]) for r in cur.fetchall()}

    def all(self) -> list[str]:
        return [
            str(r[0]) for r in self._con.execute("SELECT domain FROM whitelist ORDER BY domain")
        ]

    def matcher(self) -> Whitelist:
        return Whitelist(self.all())

    def match(self, host_or_url: str) -> str | None:
        """命中した *カテゴリ* を返す (未収録は None)。"""
        host = normalise_host(host_or_url)
        labels = host.split(".")
        for i in range(len(labels)):
            cand = ".".join(labels[i:])
            row = self._con.execute(
                "SELECT category FROM whitelist WHERE domain=?", (cand,)
            ).fetchone()
            if row:
                return str(row[0])
        return None


def _guess_category(domain: str) -> str:
    d = domain.lower()
    if d in ("zencart.com", "komeri.com", "askul.co.jp", "suruga-ya.jp"):
        return "favicon_reference"
    if any(
        k in d
        for k in (
            "hatenablog",
            "note.com",
            "ameblo",
            "livedoor",
            "seesaa",
            "blogspot",
            "blog.jp",
            "exblog",
            "cocolog",
            "wordpress.com",
            "github.io",
            "qiita",
            "zenn.dev",
            "speakerdeck",
        )
    ):
        return "blog_platform"
    if any(
        k in d
        for k in (
            "itmedia",
            "impress",
            "kakaku.com",
            "gigazine",
            "ascii",
            "mynavi",
            "nikkei",
            "watch",
        )
    ):
        return "news_media"
    if any(
        k in d
        for k in (
            "janpara",
            "iosys",
            "pcfree",
            "usedpc",
            "re-plus",
            "pc-doctor",
            "geo-online",
            "bookoff",
            "hardoff",
            "suruga-ya",
            "akibasouba",
        )
    ):
        return "used_store"
    if any(
        k in d
        for k in (
            "kakaku.com",
            "aucfan",
            "rakuten",
            "amazon",
            "yahoo",
            "mercari",
            "paypay",
            "wikipedia",
        )
    ):
        return "aggregator"
    if any(
        k in d
        for k in (
            "vaio",
            "dynabook",
            "toshiba",
            "lenovo",
            "dell",
            "hp.com",
            "epson",
            "lavie",
            "fujitsu",
            "sharp",
            "sony",
            "asus",
            "acer",
            "msi.com",
            "apple",
            "microsoft",
            "buffalo",
            "iodata",
            "elecom",
            "logitec",
            "panasonic",
            "nec",
            "support.",
        )
    ):
        return "vendor_support"
    return "official_store"
