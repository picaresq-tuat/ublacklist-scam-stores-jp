"""whois/RDAP 特徴量 (T3)。

rdap.org (https://rdap.org/domain/<domain> → 各レジストリの RDAP へリダイレクト) から
whois 相当情報を取得する。whois python ライブラリは使わない (urllib のみ)。

設計方針:
- 公開サービスのため 1 req/sec 以下を自前で厳守する (モジュール全体で直近要求時刻を記録)。
  レート制御は threading.Lock で wait+記録を不可分化しており、単一プロセス内のスレッド
  並列では守られる。プロセス並列 (fork / 別実行) では各プロセスが独立カウンタを持つため
  呼び出し側で間隔制御が必要 (現行の probe は逐次)。
- Terms of use 相当フィールド (notices / links の rel=self 以外のレジストリ案内 /
  port43 / redacted) は特徴量に入れない。同一項目が複数ある場合は 1 番目のみ採用。
- 取得失敗 (タイムアウト / 404 = 対応 RDAP なし / レート制限) の場合は ok=False とし、
  特徴量はすべて 0 (= 加算しない)。precision 優先。
- 海外メーカー例外: KNOWN_FOREIGN_MAKERS に登録したメーカー own domain / 正規登録者は
  .tw / +886 等を「海外の兆候」とみなさない (golden legit の FP 防止)。
"""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlsplit

RDAP_BASE = "https://rdap.org/domain/"
RDAP_TIMEOUT = 10.0
_MAX_BODY_BYTES = 2 * 1024 * 1024  # リダイレクト先は任意レジストリのため応答サイズ上限を設ける
MIN_REQUEST_INTERVAL = 1.1  # 秒。公開サービスのレート制限 (1 req/sec) を厳守
USER_AGENT = "scam-hunter-research/1.0"

# 「Registrar の URL」とみなす link の rel。self は RDAP レコード自身を指すため除外。
_REGISTRAR_URL_RELS = frozenset({"about", "related"})

# 海外メーカー例外マッピング。日本で正規販売される海外ブランド (own domain) は
# 本国のレジストラ URL TLD / abuse 電話国番号を使うため foreign 扱いにしない。
# 実測 (S5 スパイク, logs/spike_s5_rdap.md) に基づく追加:
#   dynabook.com — 日本メーカーだが正規登録者が海外レジストラ 1API GmbH
#   (.net / +49) を使う実測例があり、これを FP にしないため例外に登録。
KNOWN_FOREIGN_MAKERS: dict[str, dict] = {
    "asus.com": {"tlds": {"com", "tw", "jp"}, "ccs": {"81", "886"}},
    "sony.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "sony.co.jp": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "panasonic.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "panasonic.co.jp": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "canon.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "canon.co.jp": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "nikon.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "nikon-image.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "lenovo.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81", "86"}},
    "samsung.com": {"tlds": {"com", "jp", "kr"}, "ccs": {"1", "81", "82"}},
    "xiaomi.com": {"tlds": {"com", "jp", "cn"}, "ccs": {"1", "81", "86"}},
    "mi.com": {"tlds": {"com", "jp", "cn"}, "ccs": {"1", "81", "86"}},
    "apple.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "dyson.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81", "44"}},
    "dyson.co.jp": {"tlds": {"com", "jp"}, "ccs": {"1", "81", "44"}},
    "bose.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "gopro.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "anker.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "ankerjapan.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    "seagate.com": {"tlds": {"com", "jp"}, "ccs": {"1", "81", "65"}},
    "buffalo.jp": {"tlds": {"com", "jp"}, "ccs": {"1", "81"}},
    # 実測で foreign registrar が発火した正規店 (S5 スパイク参照)
    "dynabook.com": {"tlds": {"com", "net", "jp"}, "ccs": {"81", "49"}},
}

MULTI_LABEL_SUFFIXES = frozenset({"co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "gr.jp", "lg.jp"})

_last_request_monotonic = 0.0
_rate_lock = threading.Lock()


def _rate_limit_wait() -> None:
    """1 req/sec 以下を保証する。wait と記録をロック内で行い、スレッド並列でも直列化する。"""
    global _last_request_monotonic
    with _rate_lock:
        wait = MIN_REQUEST_INTERVAL - (time.monotonic() - _last_request_monotonic)
        if wait > 0:
            time.sleep(wait)
        _last_request_monotonic = time.monotonic()


def maker_exception(domain: str) -> dict | None:
    """ドメインが KNOWN_FOREIGN_MAKERS に該当すれば例外マップ、なければ None。"""
    return KNOWN_FOREIGN_MAKERS.get(_registrable(domain))


# rdap.org が RDAP を持たない TLD (JPRS は .jp を rdap.org 経由で公開していない)。
# 問い合わせても 404 になるだけなので、特徴量 0 として要求自体を省く。
UNSUPPORTED_TLDS = frozenset({"jp"})


def rdap_supported(domain: str) -> bool:
    """このドメインに RDAP を問い合わせる価値があるか (404 既知の TLD を除外)。"""
    dom = (domain or "").strip().lower().strip(".")
    if not dom or "." not in dom:
        return False
    return dom.rsplit(".", 1)[-1] not in UNSUPPORTED_TLDS


def registrar_url_tld(url: str) -> str:
    """Registrar URL から TLD (co.jp 等は 3 ラベル) を返す。URL がなければ空。"""
    host = urlsplit(url or "").netloc.lower().split(":")[0].strip(".")
    if not host:
        return ""
    if host.startswith("www."):
        host = host[4:]
    labels = host.split(".")
    if len(labels) < 2:
        return ""
    if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return "jp"
    return labels[-1]


def abuse_phone_cc(tel: str) -> str:
    """abuse 電話から国番号 (先頭の + 直後の数字列) を返す。欠損/難読化は空。"""
    t = (tel or "").replace("tel:", "").strip()
    m = re.match(r"\+(\d+)", t)
    return m.group(1) if m else ""


@dataclass
class RdapInfo:
    domain: str
    ok: bool = False
    elapsed_ms: int = 0
    registrar_name: str = ""
    registrar_url: str = ""
    abuse_phone: str = ""
    error: str = ""
    meta_keys: tuple = field(default=())

    @staticmethod
    def raw_keys_of(data: dict) -> tuple:
        """特徴量に使わないメタフィールドを除外したキー一覧 (監査用)。"""
        skip = {"notices", "links", "port43", "redacted", "rdapConformance"}
        return tuple(k for k in (data or {}) if k not in skip)

    @classmethod
    def from_json(cls, domain: str, data: dict, *, elapsed_ms: int = 0) -> RdapInfo:
        if not isinstance(data, dict):
            return cls(domain=domain, ok=False, elapsed_ms=elapsed_ms, error="invalid_rdap_shape")
        if data.get("errorCode"):
            # RDAP のエラーオブジェクト (例: 404 相当) は成功扱いしない
            return cls(
                domain=domain,
                ok=False,
                elapsed_ms=elapsed_ms,
                error=f"rdap_error_{data.get('errorCode')}",
            )
        info = cls(domain=domain, ok=True, elapsed_ms=elapsed_ms, meta_keys=cls.raw_keys_of(data))
        for ent in data.get("entities") or []:
            if not isinstance(ent, dict) or "registrar" not in (ent.get("roles") or []):
                continue
            info.registrar_name = _vcard_first(ent, "fn")
            info.registrar_url = _registrar_link(ent)
            info.abuse_phone = _abuse_phone(ent)
            break  # 同一項目が複数ある場合は 1 番目のみ
        if not info.abuse_phone:
            # registrar 配下に入れ子でない場合は兄弟エンティティの abuse を 1 番目のみ採用
            for ent in data.get("entities") or []:
                if not isinstance(ent, dict) or "abuse" not in (ent.get("roles") or []):
                    continue
                tel = _vcard_first(ent, "tel")
                if tel:
                    info.abuse_phone = tel
                    break
        return info

    # --- 特徴量フラグ ---
    def raw_keys(self) -> tuple:
        return self.meta_keys

    def _maker_exception(self, domain: str) -> dict | None:
        """後方互換。新規コードはモジュール関数 maker_exception() / flags() を使う。"""
        return maker_exception(domain)

    def flags(self, domain: str) -> tuple[bool, bool, bool]:
        """(registrar_tld_foreign, phone_foreign, exception) を 1 回の例外ルックアップで返す。"""
        exc = maker_exception(domain)
        tld = registrar_url_tld(self.registrar_url)
        tld_foreign = bool(tld) and not (exc and tld in exc["tlds"]) and tld not in {"com", "jp"}
        cc = abuse_phone_cc(self.abuse_phone)
        phone_foreign = bool(cc) and not (exc and cc in exc["ccs"]) and cc != "81"
        return tld_foreign, phone_foreign, exc is not None

    def registrar_tld_foreign(self, domain: str) -> bool:
        return self.flags(domain)[0]

    def phone_foreign(self, domain: str) -> bool:
        return self.flags(domain)[1]


def _registrable(domain: str) -> str:
    host = (domain or "").strip().lower().strip(".")
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host


def _vcard_first(ent: dict, kind: str) -> str:
    vcard = (ent.get("vcardArray") or [None, []])[1]
    for item in vcard if isinstance(vcard, list) else []:
        if isinstance(item, (list, tuple)) and len(item) >= 4 and item[0] == kind:
            return str(item[3] or "")
    return ""


def _registrar_link(ent: dict) -> str:
    """Registrar の URL。links (rel=about/related) を優先し、なければ vCard url を採用。"""
    for link in ent.get("links") or []:
        rel = str(link.get("rel") or "")
        href = str(link.get("href") or "")
        if rel in _REGISTRAR_URL_RELS and href.startswith(("http://", "https://")):
            return href
    url = _vcard_first(ent, "url")
    return url if url.startswith(("http://", "https://")) else ""


def _abuse_phone(registrar_ent: dict) -> str:
    for sub in registrar_ent.get("entities") or []:
        if "abuse" not in (sub.get("roles") or []):
            continue
        tel = _vcard_first(sub, "tel")
        if tel:
            return tel
    return _vcard_first(registrar_ent, "tel")


def fetch_rdap(domain: str, *, timeout: float = RDAP_TIMEOUT) -> RdapInfo:
    """rdap.org 経由で whois 相当情報を取得する。失敗時は ok=False (特徴量 0)。"""
    domain = (domain or "").strip().lower().strip(".")
    if not domain:
        return RdapInfo(domain="", ok=False, error="empty_domain")
    _rate_limit_wait()  # 待機は計測外 (elapsed は実リクエストの遅延のみ)
    t0 = time.monotonic()
    url = RDAP_BASE + domain
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(_MAX_BODY_BYTES + 1)
        if len(raw) > _MAX_BODY_BYTES:
            raise ValueError(f"response too large (> {_MAX_BODY_BYTES} bytes)")
        elapsed = int((time.monotonic() - t0) * 1000)
        return RdapInfo.from_json(
            domain, json.loads(raw.decode("utf-8", "replace")), elapsed_ms=elapsed
        )
    except Exception as exc:
        elapsed = int((time.monotonic() - t0) * 1000)
        return RdapInfo(
            domain=domain, ok=False, elapsed_ms=elapsed, error=f"{type(exc).__name__}: {exc}"
        )
