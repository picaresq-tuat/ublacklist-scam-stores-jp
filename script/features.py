"""特徴量抽出 (P3)。

fetch.py が返した FetchResult (ブラウザ UA / Googlebot UA / favicon バイト列) から
スコアリング用の特徴量を取り出す。閾値や重みはここでは持たない (scoring.yaml / scorer.py)。
生 HTML は保持せず、テキストとリンク・img src のみを扱う。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit

from fetch import FetchResult
from whois_rdap import BRAND_TLDS, RdapInfo

ZENCART_MARKERS: tuple[str, ...] = (
    "main_page=",
    "products_id=",
    "zenid=",
    "manufacturers_id",
    "template_default",
    "shopping_cart.php",
    "index.php?cPath",
    "includes/modules/",
    "zen_get",
    "E-Commerce Engine",
    "zc_install",
    "?currency=",
)

# 汎用 favicon (誰のサイトでも同じ画像になるもの) の実測 md5。
# これらは collision / cross-origin の両方から除外する。
# 値はすべて実ファイルを取得して md5sum で確認したもの (2026-10-20):
#   https://wordpress.org/favicon.ico        53a151ba1af3acdefe16fbbdad937ee4
#   https://www.xserver.ne.jp/favicon.ico    a1bfd92e9401d9f063eb3d56b49925fc
#   https://www.onamae.com/favicon.ico       69189948129989fa07b0d62db0f97b06
# 追加するときは必ず実ファイルから計算する (プレースホルダを入れない)。
GENERIC_FAVICON_MD5S: frozenset[str] = frozenset(
    {
        "53a151ba1af3acdefe16fbbdad937ee4",
        "a1bfd92e9401d9f063eb3d56b49925fc",
        "69189948129989fa07b0d62db0f97b06",
    }
)

# S4 スパイク (logs/spike_s4_signals.md) で実測し棚卸し済み。
# 除去: 在庫限り/在庫処分 (scam 0/96)、訳あり (scam 1% vs legit 12%)、
#       今すぐ (scam 2% vs legit 8%)、破格 (scam 1%, 非生産的)。
DARK_PATTERN_TERMS: tuple[str, ...] = (
    "タイムセール",
    "激安",
    "%OFF",
    "％OFF",
    "送料無料",
    "限定販売",
    "数量限定",
    "大幅値下げ",
)

# S4-③: affiliate 広告ネットワークのホスト/ドメイン (リンク先として出現したら計上)。
# 正規 EC も affiliate を張るため、重み設定は実測 (spike S4) の前にしない。
AFFILIATE_HOST_MARKERS: tuple[str, ...] = (
    "a8.net",
    "afl.rakuten.co.jp",
    "linksynergy.com",
    "valuecommerce.com",
    "amazon-adsystem.com",
    "rentracks.jp",
    "trafficgate.net",
    "adsistant.net",
    "affiliate",
)

STORE_ASSET_HOSTS: tuple[str, ...] = (
    "rakuten.co.jp",
    "r10s.jp",
    "yimg.jp",
    "amazon.co.jp",
    "media-amazon.com",
    "yahoo.co.jp",
    "yahoocdn.com",
    "mercari.com",
    "static.mercdn.net",
    "suruga-ya.jp",
    "askul.co.jp",
    "komeri.com",
    "shopping.yahoo.co.jp",
    "a-ads.com",
)

RISKY_TLDS: frozenset[str] = frozenset(
    {
        "casa",
        "shop",
        "biz",
        "love",
        "click",
        "top",
        "xyz",
        "online",
        "site",
        "store",
        "icu",
        "cyou",
        "news",
        "cam",
        "vin",
        "live",
        "wiki",
        "work",
        "rest",
        "bar",
    }
)


def is_risky_tld(tld: str) -> bool:
    """TLD が「詐欺サイトに多い」集合に属するか。

    単一企業が運営するブランド TLD (`BRAND_TLDS`) は、その企業自身しか登録できない
    ため詐欺の兆候にならない (例: `.google`, `.gmo`)。RISKY_TLDS に同名が入っていても
    除外する。
    """
    t = (tld or "").strip().lower().lstrip(".")
    return bool(t) and t in RISKY_TLDS and t not in BRAND_TLDS


MULTI_LABEL_SUFFIXES: tuple[str, ...] = (
    "co.jp",
    "ne.jp",
    "or.jp",
    "ac.jp",
    "ad.jp",
    "ed.jp",
    "go.jp",
    "gr.jp",
    "lg.jp",
    "com.au",
    "co.uk",
    "co.kr",
    "com.tw",
    "com.br",
    "co.in",
    "com.cn",
)

SEARCH_ENGINE_HOSTS: tuple[str, ...] = ("google.", "bing.com", "yahoo.co.jp", "search.")

# Measured domain ages: scam (n=24), <=30d: 16 and <=90d: 21;
# legitimate RDAP ages: 3114d and 10183d (n=2). Use 90 days as the cutoff.
YOUNG_DOMAIN_DAYS = 90

# 429 は「レート制限をかけられた」だけであり、クローキングの証拠ではない (実測: hatenablog)。
RATE_LIMIT_STATUSES: frozenset[int] = frozenset({429})

# --- (A) bot エラーページ・ガード ---
# bot へエラーページを返した差分は「内容の出し分け」ではない (実測 2026-10-12:
# bandai-hobby.net はブラウザ 194,898 B に対し Googlebot へ 200 で「404 NOT FOUND」13,157 B)。
ERROR_TITLE_MARKERS: tuple[str, ...] = (
    "404",
    "410",
    "not found",
    "page not found",
    "error",
    "forbidden",
    "access denied",
    "service unavailable",
    "bad gateway",
    "ページが見つかりません",
    "ページが存在しません",
    "お探しのページ",
    "見つかりませんでした",
    "エラー",
    "メンテナンス",
)
# title が無いエラーページ用。本文先頭 2048 B のみを対象にし、定型文に限定する
# (本文全体を走査すると「404」を含む通常ページを誤判定するため)。
ERROR_BODY_MARKERS: tuple[str, ...] = (
    "404 not found",
    "page not found",
    "the requested url was not found",
    "ページが見つかりません",
    "お探しのページは見つかりません",
)

# --- (B) 年齢認証ゲート・ガード ---
# 年齢認証 interstitial との差分も「内容の出し分け」ではない (実測 2026-10-12:
# dmm.co.jp はブラウザ「年齢認証 - FANZA」30,207 B に対し Googlebot へ 731 KB の実ページ)。
# 商品ページの文言 ("アダルト" 等) を拾わないよう、ゲート固有の言い回しだけを並べる。
AGE_GATE_MARKERS: tuple[str, ...] = (
    "年齢認証",
    "年齢確認",
    "18歳未満",
    "18歳以上",
    "are you over 18",
    "age verification",
    "age check",
    "成人向けコンテンツ",
    "18+",
)
# bot 側の本文がこれ未満なら「アクセス拒否ページ」とみなし、本文提示と数えない。
MIN_BOT_BODY_BYTES = 60
# WAF/チャレンジの interstitial は bot への「本文提示」ではない (実測: Cloudflare, quervia.biz)。
CHALLENGE_MARKERS: tuple[str, ...] = (
    "attention required! | cloudflare",
    "just a moment...",
    "checking your browser",
    "cf-browser-verification",
    "cf_chl_",
    "ddos protection by",
    "sucuri website firewall",
    "access denied |",
    "one more step",
)

_PRODUCT_PATH = re.compile(r"/(product|products|item|items|goods|shop|detail|dp)/", re.I)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_IMG_RE = re.compile(r"<img[^>]+src=[\"']([^\"']+)", re.I)
_A_HREF_RE = re.compile(r"<a[^>]+href=[\"']([^\"']+)", re.I)
_ICON_RE = re.compile(r"<link[^>]*rel=[\"']?[^\"'>]*icon[^>]*>", re.I)
_ICON_HREF_RE = re.compile(r"href=[\"']([^\"']+)", re.I)


@dataclass
class PageFeatures:
    domain: str
    registrable: str = ""
    tld: str = ""
    risky_tld: bool = False
    shared_2ld: bool = False
    young_index: bool = False
    status: int = 0
    bot_status: int = 0
    title: str = ""
    body_len: int = 0
    bot_body_len: int = 0
    len_ratio_gap: float = 0.0
    zencart_hits: int = 0
    dark_hits: int = 0
    n_img: int = 0
    stolen_image: bool = False
    stolen_image_hits: int = 0
    affiliate_hits: int = 0
    favicon_md5: str | None = None
    favicon_source: str = ""
    favicon_bytes_len: int = 0
    favicon_collision: bool = False
    favicon_cross_origin: bool = False
    favicon_cross_origin_of: str = ""
    offsite_redirect: bool = False
    redirect_to_google: bool = False
    redirect_hops: int = 0
    deep_product_path: bool = False
    cloaking: bool = False
    bot_only_body: bool = False
    # T3: RDAP (whois 相当) 特徴量。生値は監査用に保持し、フラグは maker 例外適用後の値。
    # 取得失敗/欠損時は ok=False でフラグなし (= 加算しない)。時間閾値 (rdap_slow_ms) は
    # scoring.yaml thresholds で管理し、判定は scorer 側で行う。
    rdap_ok: bool = False
    rdap_elapsed_ms: int = 0
    rdap_registrar_name: str = ""
    rdap_registrar_url: str = ""
    rdap_abuse_phone: str = ""
    rdap_registrar_tld_foreign: bool = False
    rdap_phone_foreign: bool = False
    rdap_exception: bool = False
    # (A)/(B) ガード: 差分が「出し分け」以外で説明できるときの記録 (監査用)
    bot_error_page: bool = False
    age_gate: bool = False
    age_gate_side: str = ""
    discarded: bool = False
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("extra", None)
        return d


def registrable_domain(host: str) -> str:
    """登録可能ドメイン (public suffix + 1 ラベル) を推定する。"""
    host = (host or "").strip().strip(".").lower()
    host = host.split(":")[0]
    if not host:
        return ""
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def _favicon_count(known_favicons, md5: str) -> int:
    """corpus の観測ドメイン数を安全に int 化する (型違いで落とさない)。"""
    if not isinstance(known_favicons, dict):
        return 0
    value = known_favicons.get(md5, 0)
    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _normalise_origin(value) -> str:
    """URL / ホスト名を registrable domain 比較用のホストへ正規化する。

    プロトコル相対 (//host/path)・大文字・末尾ドット・ポートを吸収し、
    不正 URL (壊れた IPv6 など) と 253 文字超は空文字に落とす。
    """
    if not isinstance(value, str):
        return ""
    text = value.strip().lower()
    if not text:
        return ""
    if text.startswith("//"):
        text = "https:" + text
    try:
        if "://" in text:
            host = urlsplit(text).hostname or ""
        else:
            host = urlsplit("//" + text).hostname or ""
    except ValueError:
        return ""
    host = (host or "").strip().strip(".")
    if host.startswith("www."):
        host = host[4:]
    if not host or len(host) > 253:
        return ""
    return host


def _favicon_origins(favicon_origin_map, md5: str) -> list[str]:
    """corpus のオリジン集合を正規化して返す。

    corpus は md5 ごとに観測ドメインのリストを持つ (旧形式の単一文字列も受け付ける)。
    """
    if not isinstance(favicon_origin_map, dict):
        return []
    value = favicon_origin_map.get(md5)
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (list, tuple, set, frozenset)):
        values = list(value)
    else:
        return []
    out: list[str] = []
    for item in values:
        host = _normalise_origin(item)
        if host and host not in out:
            out.append(host)
    return out


def _is_challenge(result: FetchResult | None) -> bool:
    """WAF のチャレンジ/拒否 interstitial か。"""
    if result is None:
        return False
    head = (result.body or "")[:2048].lower()
    return any(m in head for m in CHALLENGE_MARKERS)


def _is_foreign_store_asset(src: str, own_registrable: str) -> bool:
    """画像 src が「他社ドメインのストア資産」か。

    自ドメイン (cdn.askul.co.jp 等) の画像は盗用ではない。相対 URL も対象外。
    S4: 照合は substring でなくホスト境界一致 (host == h or host.endswith("." + h))。
    「evilrakuten.co.jp.attacker.example」のような偽装ホストを拾わない。
    """
    asset_reg = _store_asset_host(src)
    return bool(asset_reg) and asset_reg != (own_registrable or "")


def _store_asset_host(src: str) -> str:
    """画像 src のホストが STORE_ASSET_HOSTS に境界一致した場合のみその registrable を返す。"""
    if not src or any(c in src for c in ("\n", " ", "\t")):
        return ""
    host = urlsplit(src).netloc.lower().split(":")[0]
    if not host:
        return ""
    for h in STORE_ASSET_HOSTS:
        if host == h or host.endswith("." + h):
            return registrable_domain(h)
    return ""


def _affiliate_link_matches(href: str) -> bool:
    """リンク先が affiliate 広告ネットワークか (S4-③ 計測用)。"""
    if not href or any(c in href for c in ("\n", " ", "\t")):
        return False
    host = urlsplit(href).netloc.lower().split(":")[0]
    if not host:
        return False
    return any(m in host for m in AFFILIATE_HOST_MARKERS)


def _body_len(result: FetchResult | None) -> int:
    if result is None or result.body is None:
        return 0
    return len(result.body)


def _usable(result: FetchResult | None) -> bool:
    """本文が特徴量として使えるか (403/読み捨て/空 は使えない)。"""
    if result is None or result.discarded or result.body is None:
        return False
    return bool(result.body.strip())


def _title(result: FetchResult | None) -> str:
    if result is None or not result.body:
        return ""
    m = _TITLE_RE.search(result.body)
    return m.group(1).strip() if m else ""


def _matches_markers(result: FetchResult | None, markers: tuple[str, ...]) -> bool:
    """title に marker を含むか。title が無ければ本文先頭 2048 B を定型文として見る。"""
    if result is None:
        return False
    title = _title(result).lower()
    if title:
        return any(m in title for m in markers)
    head = (result.body or "")[:2048].lower()
    return any(m in head for m in markers)


def _is_error_page(result: FetchResult | None) -> bool:
    """(A) bot へ返されたのがエラーページか。

    status 200 でも「404 NOT FOUND」のようなエラーページを返すサイトがあり、
    ブラウザとの本文差は出し分けの証拠にならない (実測: bandai-hobby.net)。
    title が無い場合は本文先頭の定型文のみを見る (「404」を含む通常ページを拾わない)。
    """
    if result is None:
        return False
    title = _title(result).lower()
    if title:
        return any(m in title for m in ERROR_TITLE_MARKERS)
    head = (result.body or "")[:2048].lower()
    return any(m in head for m in ERROR_BODY_MARKERS)


def _is_age_gate(result: FetchResult | None) -> bool:
    """(B) 年齢認証 interstitial か (実測: dmm.co.jp の「年齢認証 - FANZA」)。"""
    return _matches_markers(result, AGE_GATE_MARKERS)


def young_domain(rdap: RdapInfo | None, now: datetime | None = None) -> bool:
    """RDAP 登録日が 90 日以内か (両端含む・秒単位)。判定不能は False。

    `extract_features` と校正スクリプトの `attach_rdap` で同じ規則を使うため
    公開ヘルパにしている。日付の切り捨て (`.days`) ではなく経過秒で比較する。
    """
    if rdap is None or not rdap.ok:
        return False
    try:
        registered = datetime.fromisoformat((rdap.registration_date or "").replace("Z", "+00:00"))
        current = now if now is not None else datetime.now(UTC)
        if registered.tzinfo is None:
            registered = registered.replace(tzinfo=UTC)
        if current.tzinfo is None:
            current = current.replace(tzinfo=UTC)
        elapsed = (current.astimezone(UTC) - registered.astimezone(UTC)).total_seconds()
        return 0 <= elapsed <= YOUNG_DOMAIN_DAYS * 86400
    except Exception:
        return False


def extract_features(
    domain: str,
    browser: FetchResult,
    bot: FetchResult | None = None,
    *,
    favicon_bytes: bytes | None = None,
    known_favicons: dict[str, int] | None = None,
    favicon_origin_map: dict[str, object] | None = None,
    domain_2ld_counts: dict[str, int] | None = None,
    rdap: RdapInfo | None = None,
    now: datetime | None = None,
) -> PageFeatures:
    dom = (domain or "").strip().lower()
    reg = registrable_domain(dom)
    f = PageFeatures(domain=dom, registrable=reg, tld=dom.rsplit(".", 1)[-1] if "." in dom else dom)
    f.risky_tld = is_risky_tld(f.tld)
    f.status = int(browser.status if browser else 0)
    f.discarded = bool(browser.discarded if browser else False)
    f.title = _title(browser)
    f.body_len = _body_len(browser)
    f.bot_body_len = _body_len(bot)
    f.bot_status = int(bot.status if bot else 0)

    # (A)/(B) ガードの判定結果は features_json に残す (監査用)。
    f.bot_error_page = bool(bot is not None and _is_error_page(bot))
    browser_gate = _is_age_gate(browser)
    bot_gate = bool(bot is not None and _is_age_gate(bot))
    f.age_gate = bool(browser_gate or bot_gate)
    f.age_gate_side = "browser" if browser_gate else ("bot" if bot_gate else "")

    text = (browser.html_sanitized or browser.body or "") if browser else ""
    low = text.lower()
    f.zencart_hits = sum(1 for m in ZENCART_MARKERS if m.lower() in low)
    f.dark_hits = sum(1 for t in DARK_PATTERN_TERMS if t in text)

    srcs = _IMG_RE.findall(text)
    f.n_img = len(srcs)
    stolen_srcs = [s for s in srcs if _is_foreign_store_asset(s, reg)]
    f.stolen_image_hits = len(stolen_srcs)
    f.stolen_image = bool(stolen_srcs)
    hrefs = _A_HREF_RE.findall(text)
    f.affiliate_hits = sum(1 for h in hrefs if _affiliate_link_matches(h))
    f.deep_product_path = bool(_PRODUCT_PATH.search(text))

    if favicon_bytes:
        f.favicon_md5 = hashlib.md5(favicon_bytes).hexdigest()
        # 生バイト由来であることを記録する。corpus 構築はこの印がある行だけを使い、
        # 旧実装 (本文テキスト先頭 64 文字を MD5 化) の汚染データを混ぜない。
        f.favicon_source = "raw"
        f.favicon_bytes_len = len(favicon_bytes)
    if f.favicon_md5 and f.favicon_md5 not in GENERIC_FAVICON_MD5S:
        # corpus は外部データなので型を信用しない (None/int/空文字で落とさない)。
        f.favicon_collision = _favicon_count(known_favicons, f.favicon_md5) > 1
        # 同一 registrable domain のサブドメインは除外する。
        # 代表を 1 つだけ見ると辞書順最小のドメインが必ず False になるため、
        # 観測された全オリジンを比較する。
        origins = _favicon_origins(favicon_origin_map, f.favicon_md5)
        if origins:
            f.favicon_cross_origin_of = origins[0]
            for origin in origins:
                if registrable_domain(origin) != reg:
                    f.favicon_cross_origin_of = origin
                    f.favicon_cross_origin = True
                    break
    if domain_2ld_counts:
        f.shared_2ld = domain_2ld_counts.get(reg, 0) >= 3

    if browser and browser.chain:
        f.redirect_hops = max(0, len(browser.chain) - 1)
        final_host = urlsplit(browser.final_url or "").netloc.lower().split(":")[0]
        final_host = final_host[4:] if final_host.startswith("www.") else final_host
        if (
            final_host
            and final_host != dom
            and not final_host.endswith("." + dom)
            and not dom.endswith("." + final_host)
        ):
            f.offsite_redirect = True
            f.redirect_to_google = any(h in final_host for h in SEARCH_ENGINE_HOSTS)

    # T3: RDAP (whois 相当) 特徴量。rdap が None / ok=False の場合は特徴量 0 (= 加算しない)。
    if rdap is not None:
        f.rdap_ok = bool(rdap.ok)
        f.rdap_elapsed_ms = int(rdap.elapsed_ms)
        f.rdap_registrar_name = rdap.registrar_name
        f.rdap_registrar_url = rdap.registrar_url
        f.rdap_abuse_phone = rdap.abuse_phone
        if rdap.ok:
            f.young_index = young_domain(rdap, now)
            tld_foreign, phone_foreign, is_maker = rdap.flags(dom)
            f.rdap_registrar_tld_foreign = tld_foreign
            f.rdap_phone_foreign = phone_foreign
            f.rdap_exception = is_maker

    # UA クローキング: title 差 かつ 本文長比 ≥0.3 を基本条件に、
    # ブラウザ拒否 (4xx) に対して bot に本文を返す場合は昇格して cloaking とする。
    if bot is not None:
        denom = max(f.body_len, f.bot_body_len, 1)
        f.len_ratio_gap = round(abs(f.body_len - f.bot_body_len) / denom, 3)
        # bot 側が「実コンテンツを返した」と言える条件 (拒否ページ・429・(A) エラーページ・
        # (B) 年齢認証ゲートの本文は数えない)
        bot_usable = bool(
            _usable(bot)
            and f.bot_status == 200
            and f.bot_body_len >= MIN_BOT_BODY_BYTES
            and not _is_challenge(bot)
            and not f.bot_error_page
            and not bot_gate
        )
        browser_denied = (
            browser is not None
            and not _usable(browser)
            and (f.discarded or f.status >= 400 or f.body_len == 0)
        )
        rate_limited = f.status in RATE_LIMIT_STATUSES
        f.bot_only_body = bool(bot_usable and browser_denied and not rate_limited)
        title_differs = _title(bot) != f.title and bool(_title(bot) or f.title)
        # 通常取得が HTTP 200 で応答していること。非 200 のエラーページ (例:
        # facebook.com の status=400/title="Error") は「内容を出し分けた」証拠にならない
        # (実バグ回帰)。200 で添付/空ボディを返した場合は従来どおり強い証拠として扱う。
        browser_ok = f.status == 200
        if rate_limited:
            # ブラウザ側が 429 = 「我々が throttled された」だけ。クローキングではない。
            f.cloaking = False
        else:
            # ブラウザ側の年齢認証ゲート (実測: dmm.co.jp「年齢認証 - FANZA」) との差は
            # 出し分けではないため cloaking としない。
            f.cloaking = bool(
                browser_ok
                and not browser_gate
                and bot_usable
                and ((title_differs and f.len_ratio_gap >= 0.3) or browser_denied)
            )
    return f
