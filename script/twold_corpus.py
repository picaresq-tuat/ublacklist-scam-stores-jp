"""同一 registrable domain の下に何個のホスト名が現れたかを数える。

`shared_2ld` (scoring.yaml: 6 点) の供給用。1 晩の検索結果に含まれる *生の
ホスト名* を registrable domain 単位で数え、3 ホスト以上なら「同一 2LD の
使い回し」とみなす (golden の scam は hika-jp.casa 配下の 17 サブドメイン)。

複数テナントを正当に抱えるブログ/ホスティング基盤は、無関係な利用者どうしが
同じ 2LD を共有するため数えない (`PLATFORM_2LDS`)。ネットワークは使わない。
"""

from __future__ import annotations

from collections.abc import Iterable

from features import registrable_domain

# 1 つの 2LD の下に多数の独立サイトが同居する基盤。ここを数えると
# 「fc2.com のブログが 3 つ検索に出た」だけで 6 点が乗ってしまう。
PLATFORM_2LDS: frozenset[str] = frozenset(
    {
        "fc2.com",
        "hatenablog.com",
        "blogspot.com",
        "wordpress.com",
        "ameblo.jp",
        "livedoor.blog",
        "github.io",
        "note.com",
    }
)

MAX_HOST_LEN = 253


def _normalise_host(value: object) -> str:
    """ホスト名を比較用に正規化する。不正なら空文字を返す。

    - 前後空白除去 → 末尾ドット 1 個除去 → 小文字化 → userinfo 除去
      (`user@host` の `user@` はホスト名ではない)
    - 非 ASCII ラベルは IDNA (punycode) に変換し、Unicode 表記と `xn--` 表記を
      同じホストに畳む (変換できないラベルは不正)
    - ポートは `:数字` のときだけ落とす (`example.com:8080` は host、
      `::1` のような IPv6 表記はそのまま残して不正扱いにする)
    - ドットを含まない (TLD なし) / 内部に空白 / 253 文字超 / 空ラベルは不正
    """
    if not isinstance(value, str):
        return ""
    host = value.strip()
    if host.endswith("."):
        host = host[:-1]
    host = host.lower()
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    if not host:
        return ""
    if any(ch.isspace() for ch in host):
        return ""
    base, sep, port = host.rpartition(":")
    if sep and port.isdigit() and base:
        host = base
    if "." not in host:
        return ""
    if not host.isascii():
        try:
            host = ".".join(
                label if label.isascii() else label.encode("idna").decode("ascii")
                for label in host.split(".")
            )
        except UnicodeError:
            return ""
    if len(host) > MAX_HOST_LEN:
        return ""
    labels = host.split(".")
    if any(not label for label in labels):
        return ""
    return host


def count_2ld(hosts: Iterable[str]) -> dict[str, int]:
    """registrable domain ごとの distinct ホスト名数を返す (2 以上のみ)。

    `hosts` は同じ夜の検索結果から集めた生ホスト名。表記ゆれ (大文字・ポート・
    末尾ドット) は同一ホストに畳む。`PLATFORM_2LDS` のグループは除外する。
    """
    groups: dict[str, set[str]] = {}
    for raw in hosts:
        host = _normalise_host(raw)
        if not host:
            continue
        reg = registrable_domain(host)
        if not reg or reg in PLATFORM_2LDS:
            continue
        groups.setdefault(reg, set()).add(host)
    return {reg: len(found) for reg, found in groups.items() if len(found) >= 2}
