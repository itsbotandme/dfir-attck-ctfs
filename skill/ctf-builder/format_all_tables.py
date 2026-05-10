#!/usr/bin/env python3
"""
format_all_tables.py — convert tab-separated tabular blocks inside a
lab HTML file into space-padded columns.

Forensic CLI tools (Volatility, fls, EvtxECmd, tshark -T fields) emit
output with tab field separators. When pasted into the lab's canned-output
template literal, the JS terminal renders it in a monospace font but
tabs stop at unpredictable visual positions — columns wobble and the
analyst's eye loses the row alignment.

This script walks every backtick-bounded string inside a lab HTML file,
detects tab-separated rows, and rewrites them as space-padded columns
where every column is wide enough for its widest value plus a 2-space
gutter.

Usage:
    python3 skill/ctf-builder/format_all_tables.py reports/<CaseName>-lab.html

Operates in-place. Run before publishing.

Critical regex: \\t with a NEGATIVE lookbehind for another \\, so the
backslash-t inside Windows paths (e.g. \\tcpsvcs.exe) is preserved as a
path character and is NOT treated as a column separator.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


# Match \t that is NOT preceded by another backslash. Paths like
# \\tcpsvcs.exe contain a literal backslash + t; the lookbehind keeps
# them intact.
TAB_SPLIT = re.compile(r"(?<!\\)\\t")


def split_row(row: str) -> list[str]:
    """Split a tab-separated row into fields, preserving \\t inside paths."""
    return TAB_SPLIT.split(row)


def is_tabular_block(lines: list[str]) -> bool:
    """A block is tabular if at least 3 consecutive non-blank lines contain \\t."""
    tab_lines = [l for l in lines if TAB_SPLIT.search(l)]
    return len(tab_lines) >= 3


def reformat_block(lines: list[str]) -> list[str]:
    """
    Reformat a list of lines so tab-separated rows become space-padded
    columns. Lines without \\t are preserved verbatim (they may be
    headers, separators, or [bracketed annotations]).
    """
    # Pass 1: identify which lines are tabular and split them
    rows: list[list[str] | None] = []
    for line in lines:
        if TAB_SPLIT.search(line):
            rows.append(split_row(line))
        else:
            rows.append(None)

    # Pass 2: compute per-column max widths across all tabular rows
    col_widths: dict[int, int] = {}
    for r in rows:
        if r is None:
            continue
        for i, cell in enumerate(r):
            col_widths[i] = max(col_widths.get(i, 0), len(cell))

    # Pass 3: rebuild output, padding tabular rows
    out: list[str] = []
    for orig, r in zip(lines, rows):
        if r is None:
            out.append(orig)
            continue
        padded = []
        for i, cell in enumerate(r):
            if i == len(r) - 1:
                padded.append(cell)  # last column — no trailing pad
            else:
                padded.append(cell.ljust(col_widths[i] + 2))
        out.append("".join(padded))
    return out


def reformat_template_literal(literal_body: str) -> str:
    """
    Reformat the body of one backtick-bounded JS template literal.
    If the body isn't tabular, return it unchanged.
    """
    lines = literal_body.split("\n")
    if not is_tabular_block(lines):
        return literal_body
    return "\n".join(reformat_block(lines))


def process_file(path: Path) -> tuple[int, int]:
    """
    Walk the file, reformat every backtick-literal in the JS body.
    Returns (literals_processed, literals_changed).
    """
    src = path.read_text()

    # Match a JS template literal — backtick, body (no nested backticks),
    # closing backtick. Forensic canned outputs in this repo never embed
    # ${...} expressions inside backtick strings (we use string concat or
    # pre-built constants), so a simple non-greedy match is enough.
    processed = 0
    changed = 0

    def _swap(m: re.Match) -> str:
        nonlocal processed, changed
        body = m.group(1)
        processed += 1
        new = reformat_template_literal(body)
        if new != body:
            changed += 1
        return f"`{new}`"

    new_src = re.sub(r"`([^`]*)`", _swap, src, flags=re.DOTALL)
    if new_src != src:
        path.write_text(new_src)
    return processed, changed


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Usage: format_all_tables.py <path/to/lab.html>", file=sys.stderr)
        return 2

    path = Path(argv[1])
    if not path.exists():
        print(f"Not found: {path}", file=sys.stderr)
        return 1

    processed, changed = process_file(path)
    print(f"{path}: {processed} template literals scanned, {changed} reformatted")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
