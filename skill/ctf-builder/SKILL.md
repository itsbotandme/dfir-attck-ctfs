---
name: ctf-builder
description: Convert any forensic artefact (memory image, disk image, pcap, log corpus) into a self-contained browser CTF organised by MITRE ATT&CK Enterprise tactics, with an interactive analyst terminal that returns realistic command output. Produces three deliverables — DFIR report, CTF HTML, junior-analyst answer sheet — sized for individual training or team exercises.
---

# Skill: CTF Builder — Forensic Artefacts → ATT&CK Kill-Chain CTF

## Overview

This skill turns a finished forensic investigation (or active case) into a teachable interactive CTF. The output mirrors how a real DFIR analyst works: stages map to ATT&CK Enterprise tactics in kill-chain order, each finding is tagged with a technique ID, and analysts type real commands (vol.py, strings, grep, sleuthkit binaries, etc.) into a sandboxed terminal that returns the actual output captured during the investigation.

**Use this skill when:**
- A finished case can be sanitised into a training exercise
- A team needs ATT&CK-mapped practice on real artefacts
- You want to stress-test a junior analyst's investigative reasoning, not just their tool knowledge

**Do not use this skill when:**
- The artefacts cannot be redacted (PII, classified, or attorney-client privileged)
- The audience needs a static report, not interactive practice
- You need a competitive/scored CTF platform (use CTFd / RingZer0 instead)

---

## Inputs

| Input | Purpose |
|-------|---------|
| Forensic artefact | Memory image, disk image (E01/dd/raw), pcap, EVTX corpus, log set |
| Case findings | The investigation conclusions (story you want the analyst to discover) |
| ATT&CK mapping | Per-finding technique IDs (this skill helps generate them) |
| Difficulty target | Junior / intermediate / senior |

---

## The Five-Phase Workflow

```
1. ANALYSE       Run forensic tools; capture raw outputs
       ↓
2. STORYLINE     Write the kill-chain narrative; assign ATT&CK
       ↓
3. STAGE        Decompose narrative into 6–10 tactic-aligned stages
       ↓
4. BUILD        Generate report + interactive HTML CTF + answer sheet
       ↓
5. VALIDATE     Run CTF end-to-end as if you were the student
```

### Phase 1 — Analyse (gather raw evidence)

Run the relevant forensic tooling against the artefact and **save every raw output verbatim**. Output goes to `./analysis/<domain>/`. Examples:

| Artefact type | Tooling | Skill reference |
|--------------|---------|----------------|
| Windows memory image | Volatility 3 (windows.* plugins) | `~/.claude/skills/memory-analysis/SKILL.md` |
| Disk image | Sleuth Kit (`fls`, `mactime`, `icat`), Plaso (`log2timeline`) | `~/.claude/skills/sleuthkit/SKILL.md`, `~/.claude/skills/plaso-timeline/SKILL.md` |
| Windows artefacts | EZ Tools (`MFTECmd`, `RECmd`, `EvtxECmd`, `LECmd`) | `~/.claude/skills/windows-artifacts/SKILL.md` |
| Network pcap | tshark, zeek, Suricata | (no dedicated skill yet) |
| YARA hunt | `yara`, `yarGen` | `~/.claude/skills/yara-hunting/SKILL.md` |

**Critical:** preserve the exact tool output strings — the CTF terminal will echo these verbatim back to the analyst.

### Phase 2 — Storyline (write the kill-chain narrative)

Walk the **MITRE ATT&CK Enterprise tactics in attacker order**:

```
TA0043 Reconnaissance
TA0042 Resource Development
TA0001 Initial Access            ← How did they get in?
TA0002 Execution                 ← What did they run?
TA0003 Persistence               ← How do they stay?
TA0004 Privilege Escalation      ← Did they elevate?
TA0005 Defense Evasion           ← How did they hide?
TA0006 Credential Access         ← What credentials did they steal?
TA0007 Discovery                 ← What did they enumerate?
TA0008 Lateral Movement          ← Did they pivot?
TA0009 Collection                ← What data did they gather?
TA0011 Command and Control       ← How did they communicate?
TA0010 Exfiltration              ← How did they exit data?
TA0040 Impact                    ← What harm did they cause?
```

Not every case will hit every tactic. **Skip the ones you have no evidence for** — but explicitly note them as negative findings in the report (e.g., "No persistence in Run keys; persistence mechanism unconfirmed").

For each tactic touched, fill in:
- **Confidence** (HIGH / MEDIUM / LOW) based on artefact strength
- **Severity** (CRITICAL / HIGH / MEDIUM / LOW) based on impact
- **Evidence source** — exact plugin output / file path
- **Sub-technique ID** — pull from https://attack.mitre.org/

### Phase 3 — Stage (decompose into CTF stages)

Aim for **6–10 stages**, each ~3–8 minutes for the target audience. Stage structure:

```
Stage N — <Title>
  Tactic:      TA00XX <Name>
  Technique:   T1XXX[.XXX] <Name>
  Difficulty:  easy | medium | hard
  Points:      30–80 (scaled to difficulty)

  Mission Briefing:
    - Why this stage matters in the kill chain
    - Suggested approach (3 bullet points: "first do X, then Y, then check Z")
    - Why this matters

  Expected Commands:
    - The actual commands the analyst should run
    - Multiple acceptable variants (different greps, different plugins)

  Question:
    - One specific factual question with a unique answer
    - Format hint included in question text (e.g., "PID number only", "T####.### format")

  Answer (+ alt answers):
    - Primary answer
    - Acceptable alternatives (path with / or \, with or without C:, etc.)

  Answer Note:
    - 2-3 sentence explanation revealing why the answer matters in ATT&CK terms

  Hints (2-3, progressively more direct):
    - Hint 1: nudge toward the right plugin
    - Hint 2: nudge toward the right column / pattern
    - Hint 3: near-direct answer
```

### Phase 4 — Build (generate the three deliverables)

#### 4a. The DFIR Report (Markdown)

Use the template structure: `./templates/report-template.md`. Sections:
1. Executive Summary (with severity/confidence table)
2. System Profile
3. **Attack Narrative — ATT&CK Kill Chain** (this is the centrepiece — one subsection per tactic)
4. Timeline of Events with ATT&CK overlay
5. Suspicious Process / File / Network Inventory
6. IOCs (file, process behavioural, host)
7. Full ATT&CK Mapping table
8. Remediation (Immediate / Short-term / Long-term)
9. Detection Engineering outputs (Sigma rule sketches)
10. Limitations & Caveats
11. Appendix — plugins/commands run

#### 4b. The CTF HTML (single self-contained file)

Use the template: `./templates/ctf-template.html`. Key elements:

- **Header** — title, badges, score pill
- **Sidebar** — stages list with ATT&CK tactic labels, progress bar, command quick-reference
- **Main area** — three vertical panels:
  1. Briefing (mission text + suggested approach)
  2. **Interactive Terminal** — the analyst types real commands, sees real output
  3. Question + answer form + ATT&CK mapping reveal

The terminal emulator must support:

| Command | Behaviour |
|---------|-----------|
| `vol -f <img> <plugin> [--pid N] [--key "..."]` | Returns canned output for the named plugin |
| `strings <file>` | Notes that strings would emit millions of lines; pipe to grep |
| `grep [-i] <pat>` | Filters stdin; supports pipes from vol/strings |
| `cat`, `head -n N`, `tail -n N`, `wc`, `sort`, `uniq` | Standard pipeline ops |
| `ls`, `pwd`, `file` | Filesystem orientation |
| `man <tool>`, `help`, `?` | Inline documentation |
| `tactics` | ATT&CK tactic reference card |
| `progress` | Show solved stages |
| `clear` | Clear terminal |
| ↑/↓ arrows | Command history |

**Pre-populate `VOL_OUTPUTS`** with every plugin output the analyst might run. **Pre-populate `STRINGS_HITS`** with key string hits (so `strings ... | grep <pattern>` returns the relevant lines).

For each stage, define:
- `expectedCommands` — array of "right" command strings (used in hints)
- `answer` + `altAnswers` — accepting case-insensitive, path-separator-flexible variants
- `attMap` — final reveal text after correct answer

#### 4c. The Answer Sheet (Markdown)

Use the template: `./templates/answersheet-template.md`. Structure:
1. **How a Real DFIR Analyst Approaches a Memory Image** (the universal mental model)
2. **Where to Start — The Triage Methodology** (which 3 commands always run first, why)
3. **Stage-by-Stage Walkthrough** — for each stage:
   - Hypothesis to test
   - Commands
   - Answer
   - **Why this answer matters** (analytical lesson)
   - **Decision tree** for the artefact category (e.g., "If you see X, then…")
   - Junior-analyst lesson
4. **Common Pitfalls** (5–8 numbered lessons)
5. **The Investigative Mindset — Final Notes**

The answer sheet is the **most important deliverable** for training value. It teaches *thinking*, not memorisation.

### Phase 5 — Validate

- Open the HTML file in a browser; complete the CTF without referring to the answer sheet
- Check every plugin command works in the terminal
- Verify no "not implemented" errors leak through
- Time the full run — junior should complete in ~60–90 minutes, senior in ~20–30
- Have one peer try it cold; capture their stuck-points and refine hints

---

## Output Layout

```
./reports/
  ├── <CaseID>-DFIR-Report.md
  ├── <CaseID>-CTF.html         ← MUST end in -CTF.html for the launcher
  └── <CaseID>-AnswerSheet.md

./analysis/
  └── memory|disk|network|...   ← raw tool outputs that feed the CTF
```

### Required filename convention — `<CaseID>-CTF.html`

All generated CTF HTML files MUST end with `-CTF.html`. This is enforced
because the system-wide `start` shell command launches CTFs by name:

```bash
start MemLabs-Lab1       # opens MemLabs-Lab1-CTF.html in browser
start memlabs            # case-insensitive partial match also works
start                    # no args → list all available CTFs
```

The `start` function (defined in `~/.bash_aliases`) searches these
directories, in order:

1. `<repo-root>/reports/`
2. `~/CTFs/`
3. `~/dfir-ctfs/`

Place generated CTFs in one of these locations (or any sub-directory under
them) and they are automatically launchable by name.

**Naming guidelines:**
- Use a stable, hyphenated case identifier (e.g. `MemLabs-Lab1`,
  `PhishCorp-2024-01`, `IRcase-AlphaBank`).
- Avoid spaces. Avoid generic names like `ctf` or `lab1` alone.
- Match the `<CaseID>` across all three deliverables (report,
  CTF, answer sheet) so they group naturally in `ls`.

---

## Stage Design Heuristics

| Audience | Stage count | Avg points | Difficulty mix |
|----------|-------------|-----------|----------------|
| Junior analysts | 6–8 | 30–60 each | 70% easy/medium, 30% hard |
| Intermediate | 8–10 | 40–80 each | 50% medium, 30% hard, 20% expert |
| Senior / red-team-aware blue | 10–12 | 50–100 each | minimal hand-holding; expert-level |

Always **include at least one negative-finding stage** (e.g., "Find the persistence mechanism" with answer "None observed in Run keys — pivot to scheduled tasks"). Real investigations involve null findings; analysts must learn to handle them.

---

## ATT&CK Mapping Quick Reference

| Tactic ID | Tactic Name | Common Techniques to Cover |
|-----------|-------------|---------------------------|
| TA0001 | Initial Access | T1078 Valid Accounts, T1133 External Remote Services, T1566 Phishing |
| TA0002 | Execution | T1059.001 PowerShell, T1059.003 cmd, T1053.005 Scheduled Task |
| TA0003 | Persistence | T1547.001 Run keys, T1053.005 Scheduled Task, T1543.003 Service |
| TA0004 | Privilege Escalation | T1548.002 UAC bypass, T1134 Token manipulation |
| TA0005 | Defense Evasion | T1036.005 Masquerading, T1027 Obfuscation, T1070 Indicator Removal |
| TA0006 | Credential Access | T1003.001 LSASS, T1003.002 SAM, T1552.001 Files, T1555 Password Stores |
| TA0007 | Discovery | T1082 System Info, T1083 File/Dir Discovery, T1018 Remote System |
| TA0008 | Lateral Movement | T1021.001 RDP, T1021.002 SMB/Admin Shares, T1550 Use Alternate Auth |
| TA0009 | Collection | T1005 Local Data, T1560.001 Archive via Utility, T1113 Screen Capture |
| TA0011 | Command and Control | T1071.001 HTTP/S, T1095 Non-Standard Port, T1572 Tunneling |
| TA0010 | Exfiltration | T1041 Over C2, T1048 Alternate Protocol, T1567 Web Service |
| TA0040 | Impact | T1486 Encrypt for Impact, T1485 Data Destruction, T1490 Inhibit Recovery |

---

## Templates

The skill ships with three templates in `./templates/`:

- `report-template.md` — DFIR report with placeholder sections
- `ctf-template.html` — interactive CTF with terminal emulator (copy from `MemLabs-Lab1-CTF.html` and replace `STAGES`, `VOL_OUTPUTS`, `STRINGS_HITS`)
- `answersheet-template.md` — junior analyst training guide

**To bootstrap a new CTF:** copy these three files into `<project>/reports/`, rename, and replace the data structures inside.

---

## Tips for High-Quality CTFs

1. **Make commands meaningful, not magic.** Every command in `expectedCommands` should be one a real analyst would actually run. Don't invent flags or plugins that don't exist.

2. **Question phrasing precision.** "How many sessions?" is bad — answer could be "2", "two", "2 sessions". "Number of distinct interactive user sessions (number only)" is good.

3. **Accept format flexibility.** Add `altAnswers` for: case variations, path separators (`/` vs `\`), with/without leading drive letter, with/without trailing extension.

4. **Hints should educate.** First hint = direction ("look at filescan output"). Second hint = method ("filter for .bat extension"). Third hint = direct ("the file is named St4G3$1.bat — note capitalisation").

5. **Answer notes carry the lesson.** Don't just confirm correctness — explain *why* this artefact maps to that ATT&CK technique. Two to three sentences. This is where learning happens.

6. **Negative findings are signal.** Include at least one stage where the right answer is "no Run key entries — persistence mechanism unconfirmed". Trains analysts not to over-claim.

7. **Show analysts the next pivot.** End each stage's answer note with what artefact you would fetch next. This builds investigative momentum.

---

## Limitations

- **Browser-based — no real tool execution.** The terminal is an emulator. Analysts who want hands-on tool fluency must run real commands on a SIFT/REMnux station after the CTF.
- **Pre-canned outputs only.** Free-form questions outside the predicted command set will return "command not found". Hint at correct commands in the briefing.
- **No multi-user scoreboard.** Single-player only. For team competition, pair with CTFd or similar.
- **Static once shipped.** Re-running the analyst's commands produces identical output every time — there's no random/dynamic content. This is a feature for training but a limitation for replayability.

---

## Example Invocations

```
"Build a CTF from /cases/MemLabs-Lab2/ — focus on credential access and lateral movement, junior level."

"Convert my completed pcap analysis at /cases/PhishCorp/ into a 6-stage CTF with focus on
 initial access (T1566) and command-and-control (T1071)."

"Take the EVTX corpus from /cases/2024-DC-compromise/ and build an intermediate CTF organised
 around the persistence and credential-access tactics observed."
```

When invoked, this skill will:
1. Survey the existing analysis outputs in the case folder
2. Identify which ATT&CK tactics have evidence
3. Propose a stage breakdown for user review
4. Generate the three deliverables (report, CTF, answer sheet)
5. Validate by running through the terminal emulator end-to-end
