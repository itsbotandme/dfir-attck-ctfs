#!/usr/bin/env python3
"""
validate-lab.py — pre-publish checks for a ctf-builder lab triplet.

Usage:
    python3 skill/ctf-builder/validate-lab.py reports/<CaseName>-lab.html

Looks alongside the lab HTML for the matching DFIR-Report.md and
AnswerSheet.md (same <CaseName> stem). Exits 0 on success, 1 if any
check fails.

The check list is the contract from SKILL.md §14. Update both
sides if you add a new check.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fail(errors: list[str], msg: str) -> None:
    errors.append(msg)


def extract_block(src: str, opener: str) -> str | None:
    """
    Return the body of `const <opener> = { ... };` (or `[...]`).
    Anchors on the closing `};` or `];` at the start of a line — the
    canonical lab places those at column 0, which lets us skip the
    fragile balanced-bracket parsing.
    """
    pattern = rf"const {re.escape(opener)} = ([\[\{{].*?\n[\]\}}]);"
    m = re.search(pattern, src, flags=re.DOTALL)
    return m.group(1) if m else None


def parse_stages_array(src: str) -> list[dict]:
    """
    Best-effort parse of the STAGES array. We don't need full JS parsing —
    just enough to count stages, list field names, and read string/array
    values.

    Strategy: find STAGES = [ ... ]; split top-level objects by depth
    tracking, then for each object pull out the field names and the
    short scalar values.
    """
    block = extract_block(src, "STAGES")
    if block is None:
        return []
    # Strip JS line comments — they confuse the string/bracket trackers
    # below (a stray quote inside a comment would open a fake string mode).
    # Require // to be at start-of-line (optional indent) so URL paths like
    # http://example.com inside string literals stay intact.
    block = re.sub(r"^\s*//[^\n]*", "", block, flags=re.MULTILINE)
    body = block.strip()[1:-1]  # strip [ ... ]

    stages = []
    depth = 0
    in_str = None
    escape = False
    cur = []
    for ch in body:
        if in_str:
            cur.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_str:
                in_str = None
            continue
        if ch in ('"', "'", "`"):
            in_str = ch
            cur.append(ch)
            continue
        if ch == "{":
            depth += 1
            cur.append(ch)
            continue
        if ch == "}":
            depth -= 1
            cur.append(ch)
            if depth == 0:
                stages.append("".join(cur).strip())
                cur = []
            continue
        if depth > 0:
            cur.append(ch)
    return [parse_stage_obj(s) for s in stages if s.strip().startswith("{")]


def parse_stage_obj(obj_src: str) -> dict:
    """
    Pull top-level field names + simple scalar values out of a stage
    object. Doesn't try to parse nested objects fully — just enough to
    answer the validator's questions (which fields exist, hint count,
    plugin grade values, title shape).
    """
    out: dict = {"_raw": obj_src}

    # Top-level field names: name followed by colon at indent of 4
    # (the canonical lab indents stage fields at 4 spaces).
    for m in re.finditer(r"^\s{2,6}(\w+):\s", obj_src, flags=re.MULTILINE):
        field = m.group(1)
        if field not in out:
            out[field] = True

    # Specific scalars we care about
    for field in ("id", "title", "tactic", "technique", "answer"):
        m = re.search(
            rf'^\s+{field}:\s*("(?P<dq>[^"]*)"|\'(?P<sq>[^\']*)\'|`(?P<bq>[^`]*)`|(?P<num>\d+))',
            obj_src,
            flags=re.MULTILINE,
        )
        if m:
            out[field] = m.group("dq") or m.group("sq") or m.group("bq") or m.group("num")

    # noPicker / intro flags
    if re.search(r"^\s+intro:\s*true", obj_src, flags=re.MULTILINE):
        out["intro"] = True
    if re.search(r"^\s+noPicker:\s*true", obj_src, flags=re.MULTILINE):
        out["noPicker"] = True

    # Hints — count entries in the array
    m = re.search(r"hints:\s*\[(.*?)\]\s*\}?\s*$", obj_src, flags=re.DOTALL)
    if m:
        body = m.group(1).strip()
        if not body:
            out["hints"] = []
        else:
            # Count top-level entries in the hints array.
            # Each entry is bounded by a string delimiter; count delimiters / 2.
            entries = []
            depth = 0
            in_str = None
            escape = False
            cur = []
            for ch in body:
                if in_str:
                    cur.append(ch)
                    if escape:
                        escape = False
                    elif ch == "\\":
                        escape = True
                    elif ch == in_str:
                        in_str = None
                        if depth == 0:
                            entries.append("".join(cur))
                            cur = []
                    continue
                if ch in ('"', "'", "`"):
                    in_str = ch
                    cur.append(ch)
                    continue
            out["hints"] = entries

    # pluginGrades — collect grade values
    m = re.search(r"pluginGrades:\s*\{(.*?)\n\s*\},", obj_src, flags=re.DOTALL)
    if m:
        grades = re.findall(r'grade:\s*"([^"]+)"', m.group(1))
        out["pluginGrades_grades"] = grades

    # briefing body (just the string content, for ATT&CK leak check)
    m = re.search(r"briefing:\s*`([^`]*)`", obj_src, flags=re.DOTALL)
    if m:
        out["briefing_text"] = m.group(1)

    return out


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_lab(lab_path: Path) -> list[str]:
    errors: list[str] = []

    if not lab_path.exists():
        fail(errors, f"Missing file: {lab_path}")
        return errors

    if not re.match(r"^[A-Za-z0-9._-]+-(lab|CTF)\.html$", lab_path.name):
        fail(errors, f"Filename must match <CaseName>-lab.html (or legacy -CTF.html): {lab_path.name}")

    stem = lab_path.name.rsplit("-", 1)[0]
    base_dir = lab_path.parent
    report_path = base_dir / f"{stem}-DFIR-Report.md"
    answersheet_path = base_dir / f"{stem}-AnswerSheet.md"
    for p in (report_path, answersheet_path):
        if not p.exists():
            fail(errors, f"Missing companion file: {p}")

    src = lab_path.read_text()

    # --- Banned spoiler phrases ------------------------------------------
    # Scope to STAGES content only, so the validator's own anti-pattern docs
    # in JS comments don't trigger. Strip JS // line comments before matching.
    stages_block = extract_block(src, "STAGES") or ""
    stages_no_comments = re.sub(r"^\s*//[^\n]*", "", stages_block, flags=re.MULTILINE)
    spoilers = [
        "is your answer",
        "is the answer",
        "The plugin is windows.",
        "cmd.exe is the answer",
    ]
    for phrase in spoilers:
        if phrase in stages_no_comments:
            fail(errors, f"Banned hint phrase found in STAGES: {phrase!r}")

    # --- No flag-hunting language ---------------------------------------
    if re.search(r"find the flag|submit the flag|capture the flag|the flag is", src, flags=re.I):
        fail(errors, "Flag-hunting language detected — labs are investigation-driven, not flag-based")

    # --- No scoring -----------------------------------------------------
    if re.search(r"\b(score-pill .*\d+/\d+|/\s*\d{2,4}\s*points|leaderboard|state\.scores)\b", src):
        fail(errors, "Scoring construct detected — labs do not have points or scoreboards")

    # --- No difficulty labels -------------------------------------------
    if re.search(r"\b(diff-easy|diff-med|diff-hard|cur-difficulty|lab-difficulty)\b", src):
        fail(errors, "Difficulty-label CSS class detected — meta-spoiler, must be removed")

    # --- Local machine path leak ----------------------------------------
    if re.search(r"/home/[a-z][a-z0-9_-]+/|/Users/[A-Z]", src):
        fail(errors, "Local-machine path leak detected — run security sweep")

    # --- Personal email leak --------------------------------------------
    if re.search(r"[A-Za-z0-9._-]+@(gmail|outlook|yahoo|icloud|protonmail)\.com", src):
        fail(errors, "Personal email address detected — likely leaked from local config")

    # --- Tabs in canned-output blocks (must be space-padded) ------------
    # Lookbehind: only flag \t that's NOT preceded by another backslash, so
    # legitimate Windows paths like \\tcpsvcs.exe don't trigger.
    vol_block = extract_block(src, "VOL_OUTPUTS")
    if vol_block and re.search(r"(?<!\\)\\t", vol_block):
        fail(errors, "VOL_OUTPUTS contains \\t separators — re-run format_all_tables.py")

    # --- Per-stage checks -----------------------------------------------
    stages = parse_stages_array(src)
    if not stages:
        fail(errors, "No STAGES array parseable — file may be malformed")
        return errors

    # IDs as ints where present
    stage_ids = [int(s["id"]) for s in stages if str(s.get("id", "")).isdigit()]
    if not stage_ids:
        fail(errors, "No numeric stage ids found")
        return errors
    max_id = max(stage_ids)
    solvable = [s for s in stages if not s.get("intro")]

    if len(stages) < 6:
        fail(errors, f"STAGES has only {len(stages)} entries — needs >= 6 (intro + 5 investigative + synthesis)")

    required_all = ("title", "tactic", "technique", "whatsKnown", "briefing",
                    "question", "answer", "answerNote", "attReveal", "hints")
    # pluginGrades is required UNLESS the stage opts out via noPicker
    for s in solvable:
        for field in required_all:
            if field not in s:
                fail(errors, f"Stage {s.get('id', '?')} missing required field: {field}")
        if not s.get("noPicker") and "pluginGrades" not in s:
            fail(errors, f"Stage {s.get('id', '?')} missing required field: pluginGrades")
        hints = s.get("hints", [])
        if isinstance(hints, list) and len(hints) != 3:
            fail(errors, f"Stage {s.get('id', '?')} must have exactly 3 hints (got {len(hints)})")

        # Picker grades — synthesis stage exempt
        if not s.get("noPicker"):
            grades = s.get("pluginGrades_grades", [])
            if "best" not in grades:
                fail(errors, f"Stage {s.get('id', '?')} picker has no 'best' grade")
            if len(grades) < 5:
                fail(errors, f"Stage {s.get('id', '?')} picker has fewer than 5 plugins ({len(grades)})")

        # ATT&CK leak in briefing prose (synthesis stage exempt — it's about ATT&CK)
        if int(s.get("id", 0)) != max_id:
            briefing = s.get("briefing_text", "")
            if re.search(r"\bT\d{4}(\.\d{3})?\b|\bTA\d{4}\b", briefing):
                fail(errors, f"Stage {s.get('id', '?')} briefing contains ATT&CK reference — should be hidden until reveal")

        # Title shape — investigative stages should be question-framed
        title = s.get("title", "")
        if int(s.get("id", 0)) != max_id and not title.rstrip(".").endswith("?"):
            fail(errors, f"Stage {s.get('id', '?')} title should be question-framed: {title!r}")

    # --- Surviving placeholder markers ----------------------------------
    placeholder_count = len(re.findall(r"TEMPLATE[:_]", src))
    if placeholder_count:
        fail(errors, f"{placeholder_count} TEMPLATE markers still in lab — fill in the data before publishing")

    return errors


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Usage: validate-lab.py <path/to/CaseName-lab.html>", file=sys.stderr)
        return 2

    lab_path = Path(argv[1])
    errors = check_lab(lab_path)

    if errors:
        print(f"FAIL — {lab_path}: {len(errors)} issue(s)")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(f"OK — {lab_path}: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
