"""P9b: cloaking-hold ドメイン専用リスト (`cloaking_detected/uBlacklist.txt`) の生成。

- 通常の uBlacklist.txt (publish.py) とは別パスに出力する。
- 生成ロジックは publish.py の render_list/merge_list/validate を再利用する。
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from publish import HEADER, SECTION_MARKER, build_entries, merge_list

CLOAKING_MARKER = "## cloaking-detected (hold)"


def render_cloaking_list(domains: Iterable[str]) -> str:
    """cloaking-hold ドメインだけで新規リストを生成。"""
    entries = build_entries(domains)
    lines = [
        HEADER.rstrip("\n").replace("scam stores JP", "cloaking-detected JP"),
        "",
        "# cloaking 検知かつ decision=hold のドメイン。人手確認後に通常リストへ昇格する。",
        "",
        "## Permanent rules (regex)",
    ]
    from publish import PERMANENT_RULES

    lines += list(PERMANENT_RULES)
    lines += ["", SECTION_MARKER]
    lines += entries
    return "\n".join(lines).rstrip("\n") + "\n"


def merge_cloaking_list(existing: str, domains: Iterable[str]) -> str:
    """既存 cloaking リストに追記する (冪等)。"""
    return merge_list(existing, domains)


def cloaking_pr_body(night: str, rows: list[dict]) -> str:
    """cloaking PR 本文。"""
    lines = [f"## cloaking-detected nightly {night}", ""]
    lines += [f"- 対象: {len(rows)} 件", ""]
    if rows:
        lines += ["| domain | score | reasons |", "| --- | ---: | --- |"]
        for r in rows:
            reasons = ", ".join(
                f"{k}:{v:g}"
                for k, v in sorted((r.get("reasons") or {}).items(), key=lambda kv: -kv[1])
            )
            lines.append(f"| `{r.get('domain', '')}` | {r.get('score', 0):g} | {reasons} |")
        lines.append("")
    lines += ["cloaking 検知 + hold 判定のドメイン。レビュー後に通常 uBlacklist.txt へ昇格。"]
    return "\n".join(lines) + "\n"


def write_cloaking_list(path: Path | str, domains: Iterable[str]) -> str:
    """既存ファイルがあれば追記、なければ新規生成して書き出す。"""
    path = Path(path)
    current = path.read_text(encoding="utf-8") if path.exists() else ""
    text = (
        merge_cloaking_list(current, domains) if current.strip() else render_cloaking_list(domains)
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return text
