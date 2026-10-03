"""P7a: uBlacklist リスト生成 (publish.py) の RED テスト。"""

from publish import (
    HEADER,
    PERMANENT_RULES,
    SECTION_MARKER,
    build_entries,
    merge_list,
    render_list,
    validate,
)

EXISTING = """# uBlacklist - scam stores JP
## Permanent rules (regex)
/https?:\\/\\/.*[\\.\\-](com|net|org)[\\.\\-][a-z]{2}\\/.*/

## Hermes nightly
*://*.old-scam.example/*
"""


def test_permanent_rules_are_three():
    assert len(PERMANENT_RULES) == 3
    assert any("com|net|org" in r for r in PERMANENT_RULES)
    assert any(r == "/https?:\\/\\/.*\\.co\\/.*/" for r in PERMANENT_RULES)
    assert any("xn--" in r for r in PERMANENT_RULES)


def test_shortened_co_rule_is_anchored_shape():
    rule = next(r for r in PERMANENT_RULES if "\\.co\\/" in r)
    assert rule.startswith("/") and rule.endswith("/")


def test_punycode_rule_is_valid_regex():
    import re

    rule = next(r for r in PERMANENT_RULES if "xn--" in r)
    pattern = rule[1:-1]
    re.compile(pattern)  # 例外が出ないこと
    assert re.search(pattern, "https://www.example.com/item/1") is None
    assert re.search(pattern, "https://shop.example.co.jp/item/1") is None
    assert re.search(pattern, "https://shop.xn--eckwd4c7c.example/item") is not None
    assert re.search(pattern, "https://www.xn--p1ai.example.com/item/1") is not None


def test_regex_payloads_actually_compile_after_unescaping():
    import re

    for rule in PERMANENT_RULES:
        re.compile(rule[1:-1].replace("\\/", "/"))


def test_build_entries_normalises_and_sorts():
    entries = build_entries(["B.example", "a.example", "a.example"])
    assert entries == ["*://*.a.example/*", "*://*.b.example/*"]


def test_build_entries_rejects_unsafe_input():
    assert build_entries(["", "  ", "http://x.example/path", "a.example/path"]) == []
    assert build_entries(["bad..example"]) == []
    assert build_entries(["a.example?x=1"]) == []


def test_build_entries_skips_permanent_rule_shapes():
    """.co 短縮形 / Punycode / .com.xx は個別登録しない (常設正規表現で足りる)。"""
    assert build_entries(["shop.co", "xn--p1ai.example.com", "x.com.xx"]) == []
    assert build_entries(["normal.example"]) == ["*://*.normal.example/*"]


def test_render_list_has_sections_and_permanent_rules():
    text = render_list(["b.example", "a.example"])
    assert HEADER.splitlines()[0] in text
    assert SECTION_MARKER in text
    for rule in PERMANENT_RULES:
        assert rule in text
    assert text.count("*://*.a.example/*") == 1
    assert text.index("a.example") < text.index("b.example")


def test_merge_appends_without_duplicating_existing_domains():
    out = merge_list(EXISTING, ["new.example", "old-scam.example"])
    assert out.count("old-scam.example") == 1
    assert "*://*.new.example/*" in out
    assert out.count("## Hermes nightly") == 1
    assert PERMANENT_RULES[0] in out


def test_merge_is_idempotent():
    once = merge_list(EXISTING, ["new.example"])
    twice = merge_list(once, ["new.example"])
    assert once == twice


def test_merge_creates_list_from_scratch():
    out = merge_list("", ["a.example"])
    assert "*://*.a.example/*" in out
    assert SECTION_MARKER in out
    assert PERMANENT_RULES[2] in out


def test_merge_preserves_pre_existing_sections():
    text = "# mine\n*://*.keep.example/*\n"
    out = merge_list(text, ["new.example"])
    assert "*://*.keep.example/*" in out
    assert out.startswith("# mine")


def test_validate_flags_problems():
    ok = render_list(["a.example"])
    assert validate(ok) == []
    problems = validate("*://*.a.example/*\n")
    assert any("permanent" in p for p in problems)
    assert validate("") != []


def test_newline_and_trailing_newline():
    out = render_list(["a.example"])
    assert out.endswith("\n")
    assert "\r" not in out
