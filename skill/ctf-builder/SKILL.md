---
name: ctf-builder
description: Convert any forensic artefact (memory image, disk image, pcap, log corpus) into a self-contained browser-based DFIR investigation lab. The lab presents one investigative question per stage and reveals MITRE ATT&CK technique mapping after each finding. Produces three deliverables — DFIR report, lab HTML, junior-analyst walkthrough. The skill directory keeps the historical "ctf-builder" stem; the labs it builds now follow an investigation-first pedagogy, not flag-hunting.
---

# Skill: ctf-builder — Forensic Artefacts → ATT&CK Investigation Labs

## 1. What this skill does

Turns a forensic artefact and an investigation into a teachable browser-playable lab. The lab walks an analyst through 6–10 stages, each opening with an investigative question, asking the analyst to commit to a tool/plugin pick, run commands in a sandboxed terminal that returns pre-recorded output, submit what they find, and then see the MITRE ATT&CK technique revealed as the language analysts use to brief other teams.

The canonical reference implementation is **The Black Window Case** (`reports/BlackWindow-CTF.html`). Every section below points back to it as the working example.

---

## 2. When to use / when not to use

**Use this skill when:**
- A finished or sanitisable case can be turned into a training exercise.
- The audience is junior-to-intermediate DFIR analysts who need analytical-reasoning practice, not just tool literacy.
- You want a self-contained, offline-capable, mobile-friendly lab that runs from a single HTML file.

**Do not use this skill when:**
- The artefact cannot be redacted (PII, classified, attorney-client privileged).
- The audience needs a static write-up, not interactive practice.
- You need a competitive/scored CTF platform — use CTFd / RingZer0 instead. This skill explicitly does **not** produce flag-hunting CTFs (see §17 Anti-patterns).
- You need a real Volatility/Plaso/etc. runtime — this skill produces canned-output labs (§19 Out of scope).

---

## 3. Pedagogical principles

These principles are non-negotiable. Every design decision below derives from them.

### ATT&CK as reveal, not signpost
Real DFIR investigates first, then maps findings to ATT&CK as the common vocabulary. Stages **do not** announce their ATT&CK technique upfront. The technique is shown only after the analyst answers correctly, in a dedicated reveal card that says "what you just identified maps to T1059.003 — Windows Command Shell". Trains analytical reasoning, not label-matching.

> **MITRE ATT&CK v19 (Apr 2026) — required reading for tactic IDs.** TA0005 was renamed *Defense Evasion → Stealth* (covers camouflage / blending-in techniques like T1036 Masquerading). The T1562 *Impair Defenses* family (actively disabling or degrading security controls) was promoted to its own tactic: **TA0112 Defense Impairment**. T1562 still exists as a technique — it now lives under TA0112. Every lab's `TACTICS_TEXT` block must include BOTH TA0005 and TA0112 rows so the analyst sees the v19 layout when they type `tactics`. Sub-techniques follow `Tnnnn.nnn`; always write the full ID (`T1078.002`, not `T1078`) where the lab maps to a sub-technique.

### Picker grades intentionality, not the final answer
Each stage shows the analyst a curated list of plugin options BEFORE they run anything. The picker grades the choice: ✓ best / ≈ plausible / ✗ off-base, with a one-line reason. The picker does NOT block submission — it grades the *thinking* (which tool fits the question), separately from the *finding* (what the artefact says). This is the cognitive core of the lab.

### No spoonfeeding
Briefings present the case state and the question. They do **not** name the plugin, the artefact, or the answer. Hints exist behind a button (3 escalating tiers) for analysts who genuinely need help.

### Soft-lock carry-forward context
Each stage's "what's known so far" recap carries forward findings from prior stages (which contain the answers to those stages). When the analyst clicks ahead to a stage they haven't unlocked yet, the recap is replaced with a one-line note: "🔒 Carry-forward context unlocks once you solve Stage N." The question, picker, and terminal stay accessible — soft, not hard.

### Absence of evidence is reportable
When the honest answer to a question is "we can't confirm from this data alone — pivot to disk/network/log review", THAT IS the answer. Stage 7 in The Black Window Case is the canonical example (channel available, transfer unconfirmed). Teach this pattern explicitly — it separates a defensible report from one that gets pulled apart on a bridge call.

### Forensic accuracy
Don't fabricate artefacts. Only use what's actually in the source. Where the lab needs setup-specific touches (e.g. a particular credential-tool default output location), call them out as setup-specific so the analyst doesn't learn a wrong heuristic. Do not invent attacker narratives the artefact can't support.

### No marketing copy
"Hypothesis-driven", "real X, real Y, real Z", "the why behind every finding", "the language analysts use to brief other teams" — all banned in user-facing prose. Describe what the lab IS, not how it makes the user feel. The design speaks; copy stays out of the way.

---

## 4. Artifact-type matrix

Each artefact class has a recommended tool family + sample plugin pool for the picker.

| Artefact class | Primary tools | Picker pool examples |
|---|---|---|
| Memory image (Windows) | Volatility 3 | `windows.info`, `windows.pslist`, `windows.pstree`, `windows.cmdline`, `windows.netscan`, `windows.filescan`, `windows.malfind`, `windows.handles`, `windows.envars`, `windows.registry.printkey` |
| Memory image (Linux) | Volatility 3 | `linux.psaux`, `linux.bash`, `linux.lsmod`, `linux.lsof`, `linux.netstat`, `linux.proc.Maps`, `linux.tty_check` |
| Disk image (NTFS) | Sleuth Kit + Plaso | `fls`, `icat`, `mactime`, `tsk_recover`, `log2timeline.py`, `psort.py`, `pinfo.py`, `EvtxECmd`, `RegistryExplorer`, `RECmd` |
| Disk image (ext4 / APFS) | Sleuth Kit + Plaso | `fls`, `icat`, `tsk_recover`, `log2timeline.py`, `bulk_extractor` |
| pcap | tshark / Zeek | `tshark -r`, `zeek -r`, `tcpdump -r`, `capinfos`, `mergecap`, `editcap` |
| EVTX log corpus | EZ Tools | `EvtxECmd`, `evtx_dump`, `EvtxECmd --csv`, `chainsaw`, `hayabusa` |
| Generic log corpus | Unix utilities | `grep`, `awk`, `jq`, `sort`, `uniq -c`, `tail`, `head`, `wc` |

For a new artefact class not listed above, identify the canonical analytical tool family for that artefact and follow the same picker pattern: 5–7 plugins/commands, mix of one or two "best" with several "off-base" so the analyst has a real choice to think through.

---

## 5. The three deliverables

Every lab ships as three files with the same `<CaseName>` stem:

| File | Audience | Purpose |
|---|---|---|
| `<CaseName>-lab.html` | Anyone | Interactive 60–90 min lab. Self-contained HTML+CSS+JS. Mobile-friendly. Plays offline. |
| `<CaseName>-DFIR-Report.md` | IR analysts, mgmt | Defensible kill-chain narrative + ATT&CK mapping + remediation + Sigma-rule sketches. Real IR write-up format. |
| `<CaseName>-AnswerSheet.md` | Junior analysts | Per-stage walkthrough: hypothesis, plugin, command, finding, why-it-matters, ATT&CK, lesson. Decision trees where useful. |

Filename suffix `-lab.html` is the current convention. Legacy `-CTF.html` is supported by the launcher (`scripts/start.sh`) for backward compatibility but not used for new work.

---

## 6. Lab data contract

### State object (in the lab HTML's `<script>`)

```js
let state = {
  current: 0,           // index into STAGES[] of the currently-displayed stage
  solved: new Set(),    // stageIds the analyst has answered correctly
  hintIdx: {},          // stageId -> next hint to reveal (0..3)
  cmdHistory: [],       // terminal command history (↑/↓ recall)
  cmdHistoryIdx: -1,    // current position in history when ↑/↓
  proMode: false,       // header toggle — hides plugin picker on every stage
  picks: {},            // stageId -> { plugin, grade } (latest pick per stage)
  pickerSkipped: {},    // stageId -> true if analyst submitted without picking
  promptAtTop: true     // true = empty/cleared terminal, prompt above output
};
```

`state.current` survives stage navigation. `state.solved` and `state.picks` persist across stage navigation but reset on page reload (no localStorage — labs are deliberately stateless across sessions). `state.promptAtTop` resets to `true` on `clear`.

### STAGES schema

```js
const STAGES = [
  {
    id: 0,
    intro: true,                  // true for the briefing stage; otherwise omit
    title: "Briefing & How It Works",
    tactic: "INTRO",              // sidebar label; ignored for intro
    briefing: `<HTML for the intro pane — see §7.1>`,
    hints: []
  },
  {
    id: 1,
    title: "Stage 1 — What am I looking at?",   // question-framed, NOT technique-named
    tactic: "TA0007 Discovery",                  // hidden until solved
    technique: "T1082 System Information Discovery",  // hidden until solved
    whatsKnown: `1-2 sentence carry-forward of relevant prior findings.`,
    briefing: `Short prose framing the analytical question. NO ATT&CK references.`,
    pluginGrades: {
      "windows.info":     { grade: "best",      reason: "..." },
      "windows.envars":   { grade: "plausible", reason: "..." },
      "windows.netscan":  { grade: "off-base",  reason: "..." },
      // 5-7 plugin options total
    },
    question: `Investigative question with required answer format.`,
    answer: "7601.17514",
    altAnswers: ["7601.17514.amd64fre"],   // optional; accepted variants
    answerNote: `Analyst-grade explanation of what the finding means.`,
    attReveal: {
      technique: "T1082 — System Information Discovery",
      fits: "One-line explanation of why this technique label fits the finding."
    },
    hints: [
      "Hint 1 — syntax shape with placeholders, NOT the answer.",
      "Hint 2 — property of the answer, NOT the answer.",
      "Hint 3 — literal command + answer location."
    ],
    noPicker: false              // true = skip the plugin picker (synthesis stage)
  },
  // ... more stages
];
```

Required fields per stage: `id`, `title`, `tactic`, `technique`, `whatsKnown`, `briefing`, `pluginGrades`, `question`, `answer`, `answerNote`, `attReveal`, `hints`. Optional: `altAnswers`, `noPicker`.

---

## 7. Stage authoring template

### 7.1 Stage 0 (Briefing) structure

Stage 0 is the special case. It has `intro: true` and renders a magazine-style pane (scoped CSS class `.intro-pane`) instead of the normal stage layout. No question, no terminal, no picker. Three sections:

1. **The Case.** Verbatim scenario from the source (in `<blockquote class="intro-quote">`). One sentence reframing the analyst's job — but no buzzwords (see §17).
2. **How this game works.** Plain-English explanation: single static HTML file, terminal looks up commands in an embedded table, no real Volatility runs. One-line note about the 💡 hint button.
3. **About [tool].** What the primary tool is (e.g. Volatility 3), version used, plugin syntax example, link to official docs (e.g. volatility3.readthedocs.io). A brief note on tool invocation conventions for the artefact class (e.g. `vol -f <image> <plugin>` shorthand vs `python3 vol.py -f ...` canonical).

CSS for `.intro-pane`, `.intro-section`, `.intro-quote`, `.intro-codeblock`, `.intro-cta` is scoped only to Stage 0 — uses sans-serif font (`-apple-system, "Segoe UI", "Inter", …`) for readability. Code samples remain monospace.

The Pro-mode toggle does NOT live in Stage 0 (header instead — see §9).

### 7.2 Per-stage authoring (Stages 1 through N)

For every solvable stage, fill the fields per these rules:

- **`title`** — investigative question, NOT a technique name. ✓ "What am I looking at?" ✗ "Initial System Triage". ✗ "TA0007 Discovery".
- **`tactic` / `technique`** — kept on the data for the post-answer reveal and the kill-chain panel. NEVER shown upfront in stages 1 to (N-1).
- **`whatsKnown`** — 1–2 sentences carrying forward relevant prior findings. Stage 1's whatsKnown is what's known from the case scenario alone (no prior stages).
- **`briefing`** — short prose (1–3 sentences) framing the analytical question. No ATT&CK references in stages 1 to (N-1). Stage N (synthesis) is the exception — it reframes as "you've earned 7 ATT&CK techniques across the previous stages" (see §7.4).
- **`pluginGrades`** — 5–7 plugin entries. 1–2 marked `"best"`, 1–2 `"plausible"`, the rest `"off-base"`. Grade-reasons CANNOT name the answer or the artefact. Off-base entries should be obviously wrong (wrong layer/wrong tool family) rather than trick questions.
- **`question`** — clear question with explicit answer format (e.g. "Format: NNNN.NNNNN — first two number groups only"). Avoid ambiguous phrasing.
- **`answer`** + **`altAnswers`** — exact match (case-insensitive after normalisation, slash-direction-tolerant). `altAnswers` covers variants the analyst might reasonably submit.
- **`answerNote`** — analyst-grade context: what the finding means, what carries forward, what to note for later stages.
- **`attReveal`** — `{ technique: "T_id — Name", fits: "One sentence on why this label fits the finding." }`. Two lines only — the deprecated "why this language matters" third line was preachy and is dropped.
- **`hints`** — exactly 3 strings, escalating per these rules:
  - **H1** — syntax shape with placeholders. E.g. `"Volatility 3 commands take the shape <code>vol -f &lt;memory image&gt; &lt;plugin&gt;</code>. There's a plugin that returns the basic system fingerprint — think about what it would be called."`
  - **H2** — property of the answer (NOT the answer). E.g. `"The plugin namespace is <code>windows.</code>; the suffix is the obvious word for 'basic info about the system'."`
  - **H3** — literal command + answer location. E.g. `"Run <code>vol -f MemoryDump_Lab1.raw windows.info</code>. Read the NTBuildLab field, first two number groups."`
  - Banned phrases anywhere: `"is your answer"`, `"is the answer"`, `"the plugin is X"` (flat name), `"X is the answer"`. These are spoonfeeding tells.
  - HTML-escape angle brackets in placeholders: `&lt;PID&gt;`, `&lt;memory image&gt;`. Browser parses raw `<PID>` as an unknown tag and silently strips it.
- **`noPicker`** — only `true` for the final synthesis stage (see §7.4).

### 7.3 The "absence of evidence is reportable" stage pattern

At least one stage per lab should test the analyst's ability to reach a defensible "I can't confirm from this data alone" conclusion. The Black Window Case Stage 7 is the canonical example: archive is staged, SMB is exposed, but no upload tool is running and no ESTABLISHED outbound connection exists — the answer is "channel available, transfer unconfirmed", and the lesson is that "I cannot confirm exfil from RAM alone — request firewall flow logs covering 14:30–14:38 UTC" is itself a valid analytical conclusion.

Author this stage with care: the `answerNote` and the `attReveal.fits` MUST acknowledge the limitation explicitly. Don't pretend the lab confirmed something it didn't.

### 7.4 The synthesis stage (final stage)

The final stage is the synthesis: the analyst proves they can map findings to ATT&CK themselves, without a reveal handing it over. Set `noPicker: true` (the analyst is mapping, not picking a plugin). The `briefing` reframes as "you've earned N techniques across the previous stages; do the mapping yourself." The terminal's `tactics` reference card is opt-in via the help command if the analyst genuinely needs it.

The synthesis stage is the ONLY stage where ATT&CK references appear in the briefing prose.

---

## 8. Terminal contract

These are the hard-won UI patterns. Replicate exactly — every deviation we tried produced regressions.

### 8.1 DOM structure

```html
<div class="terminal-wrapper">
  <div class="terminal-first-touch" id="terminal-first-touch"></div>  <!-- Stage 1 only -->
  <div class="terminal-label">
    <span>🖥️ ANALYST TERMINAL</span>
    <span class="hint-link" onclick="showHint()">💡 Need a hint?</span>
  </div>
  <div class="hint-popup" id="hint-popup"></div>
  <div class="term-input-row" id="term-input-row">     <!-- ABOVE terminal initially -->
    <input type="text" class="term-input-field" id="term-input"
           placeholder="Type a command or 'help'">
  </div>
  <div class="terminal" id="terminal"></div>            <!-- BELOW input row initially -->
</div>
```

### 8.2 Layout rules (CSS)

- **`.terminal`** — `max-height: 560px` (440 tablet, 360 phone), `overflow-y: auto`, `padding: 10px 14px`. **NO `min-height`.** A forced minimum produces "prompt jumps to the bottom of the page" feel on short error responses.
- **`.terminal:empty { padding: 0; border: none; box-shadow: none; }`** — fully collapses the box when there's no content. Required for clean initial state and after `clear`.
- **`.terminal` and `.term-input-row` both get** the green CRT-glow `box-shadow: 0 0 8px rgba(74,246,38,0.18), 0 0 24px rgba(74,246,38,0.12)`. Layered (inner sharper + outer halo) gives the lab its visual signature.
- **`.terminal-wrapper:focus-within .terminal` and `.term-input-row`** brighten the glow + tint the border green. Visual feedback when the analyst is interacting.
- **DO NOT** use `display: flex; flex-direction: column; justify-content: flex-end` on `.terminal` — it visually anchors content to the bottom but breaks internal scroll (browser locks scroll position when items overflow past the start of a flex-end container).

### 8.3 Prompt swap behaviour

Initial state: input row is ABOVE the terminal (`promptAtTop = true`). The analyst sees the prompt at the top, ready for typing.

On the FIRST command (and on first command after `clear`), JS swaps the DOM: `wrap.insertBefore(term, inputRow)` plus add class `cmd-entered`. Result: terminal above, input row below — like a real shell after the first command runs. CSS adjusts border-radii so the two boxes form one continuous frame.

On `clear`: `terminal.innerHTML = ''` AND swap back AND remove `cmd-entered` AND set `promptAtTop = true`. Next command re-triggers the swap.

### 8.4 Scroll-to-prompt-at-top

After a command runs, the terminal must show the LATEST PROMPT at the TOP of the visible area, not the END of the latest output. Pattern:

```js
const t = document.getElementById('terminal');
const promptStartOffset = t.scrollHeight;  // capture BEFORE termWritePrompt
termWritePrompt(line);
// ... output writes happen, each calling t.scrollTop = t.scrollHeight ...
requestAnimationFrame(() => { t.scrollTop = promptStartOffset; });
```

Without this, long outputs (e.g. windows.pslist with 35 rows) hide the analyst's command at the top, requiring manual scroll-up to see what they ran.

### 8.5 Terminal commands every lab must support

| Command | Returns |
|---|---|
| `help` / `?` | Brief command list (Volatility plugins / Unix utils / lab helpers) |
| `man <cmd>` | Man-page-style reference for a specific command (see §11) |
| `tactics` | ATT&CK Enterprise tactic reference card |
| `progress` | Stage-by-stage solved status |
| `clear` | Empty terminal + reset prompt to top |
| `pwd` | Print "current" working directory (e.g. `~/case` or `/cases`) |
| `ls` | List the canned files in the case directory (typically just the artefact) |
| `file <name>` | Identify file type — e.g. `MemoryDump_Lab1.raw: data` |
| `strings <file> [\| grep ...]` | ASCII strings with optional grep filter |
| `grep [-i] <pattern> [file]` | Filter lines (also works in pipes) |
| `head [-n N]`, `tail [-n N]`, `wc`, `sort`, `uniq` | Standard Unix utility behaviour |

The primary tool's invocation (`vol`, `fls`, `tshark`, etc.) is dispatched separately to the canned-output table.

### 8.6 Canned-output formatting

Tabular outputs MUST use space-padded fixed-width columns, NOT `\t` separators. Tabs render at unpredictable visual positions (browser default tab stop = 8 cols + variable column widths = misaligned headers vs data).

Use the `format_all_tables.py` helper script (see §14) to convert any `\t`-separated source rows into space-padded columns. Skip lines containing escaped backslash-t (e.g. `\\tcpsvcs.exe`) — the regex `(?<!\\)\\t` distinguishes field separators from path characters.

Each output should fit in ≤ 100 lines per command. If a tool naturally produces more, truncate with a `[--- N more rows truncated for readability ---]` marker.

### 8.7 Stage 1 first-touch hint

Stage 1 only — show a one-line orientation hint above the terminal:

```html
<div id="terminal-first-touch" class="show">
  👇 <b>Type your Volatility command in the terminal below</b> —
  e.g. <code>vol -f MemoryDump_Lab1.raw windows.info</code>.
  Press Enter to run. Then submit the answer above.
</div>
```

CSS: `color: var(--text)` (white body), `code` styling uses lilac (`var(--purple)`) on a faint purple background — distinct from both the question's blue accent border and the terminal's green prompt. JS in `renderCurrentStage` shows it for `s.id === 1` only, hides for stages 2+.

---

## 9. Visual design constants

### Colour palette and meaning

| Variable | Hex | Meaning |
|---|---|---|
| `--bg` | `#0a0e14` | Page background (dark) |
| `--panel` | `#11161d` | Card/sidebar background |
| `--panel-2` | `#161c25` | Question card background |
| `--border` | `#232a36` | Default borders |
| `--accent` | `#58a6ff` | Primary blue — question accent border, primary buttons, links |
| `--accent-2` | `#79c0ff` | Lighter blue — secondary accents, headings |
| `--green` | `#3fb950` | Correct answer feedback, picker "best", attribution |
| `--term-green` | `#4af626` | Terminal prompt, terminal text, CRT-glow shadow |
| `--yellow` | `#d29922` | Hint button + popup, picker "plausible", warnings |
| `--red` | `#f85149` | Wrong answer feedback, picker "off-base", errors |
| `--purple` | `#bc8cff` | ATT&CK reveal card border, Stage 1 first-touch inline code |
| `--text` | `#c9d1d9` | Default body text |
| `--muted` | `#7d8590` | Secondary text, labels |

Each colour carries one meaning. Don't reuse the green for non-correct/non-terminal contexts; don't reuse the purple for non-ATT&CK contexts; etc.

### Typography

- **Terminal area + most of the lab**: monospace stack — `'JetBrains Mono', 'Fira Code', 'Courier New', monospace`.
- **Stage 0 intro pane only**: humanist sans-serif — `-apple-system, BlinkMacSystemFont, "Segoe UI", "Inter", Helvetica, Arial, sans-serif`. Code samples inside the intro pane keep monospace.
- **Body text size**: 0.78–0.97rem range. Hints use 0.78rem.

### Component patterns

- **Question card** — `var(--panel-2)` background + `var(--accent)` 2px bottom border. Always above the terminal.
- **Plugin picker** — `var(--code-bg)` background + `var(--border)` 1px border. Between briefing and question.
- **Picker feedback** — green/yellow/red border based on grade.
- **Picker summary** (collapsed after solve) — one-line muted summary above the question.
- **Picker nudge** (when analyst submits without picking) — yellow bordered, brief.
- **ATT&CK reveal card** — `var(--purple)` border + faint purple background tint. Renders below the green ✓ Correct! finding card on solve.
- **Continue button** — primary blue, appears below ATT&CK reveal card when there's a next stage.
- **Hint button** — yellow pill (border + faint background) inside the terminal label.
- **Hint popup** — yellow accent, appears ABOVE the input row (not below the terminal).
- **Kill Chain Earned panel** — sidebar bottom, fills in as techniques are revealed.
- **Stage soft-lock note** — yellow accent, replaces `whatsKnown` for unsolved future stages.

---

## 10. OS-specific terminal skins

The terminal's prompt and accent colour can be skinned per the artefact's OS context. Default is `bash-ubuntu` (current Black Window Case lab).

| `terminalSkin` | Prompt | Prompt colour | Use when |
|---|---|---|---|
| `bash-ubuntu` | `analyst@host:~$` | `--term-green` (#4af626) | Linux memory/disk image, generic |
| `bash-dfir` | `analyst@dfir:/cases#` | `--term-green` | Memory image being analysed in a forensic workflow (current default) |
| `powershell-win` | `PS C:\Users\analyst>` | `--accent` (#58a6ff) | Windows memory/disk image — modern Windows context |
| `cmd-windows` | `C:\Users\analyst>` | `#fff` (white) | Windows artefact — older `cmd.exe` style |
| `zsh-macos` | `analyst@MacBook ~ %` | `#d4d4d4` (light grey) | macOS memory/disk image |

Implementation: `terminalSkin` field on the lab template. Maps to:
- A prompt-template-string (used in CSS `.term-input-row::before { content: ... }` and JS `termWritePrompt`).
- A prompt-colour CSS variable.
- The CRT-glow colour also adjusts to match — green for bash, blue for PowerShell, etc.

If you build a lab for a Windows artefact, prefer `powershell-win` or `cmd-windows` so the visual matches what an analyst would see in the captured environment.

---

## 11. Man-page mandate

Every tool a lab uses must have a `man <tool>` reference accessible from the terminal. The skill ships pre-built man-page snippets in `skill/ctf-builder/man-pages/` for the common forensic tools:

```
skill/ctf-builder/man-pages/
  vol.txt              # Volatility 3 — plugin list, common flags
  fls.txt              # Sleuth Kit — file listing
  icat.txt             # Sleuth Kit — extract by inode
  mactime.txt          # Sleuth Kit — mac timeline from body file
  log2timeline.txt     # Plaso — supertimeline generation
  psort.py.txt         # Plaso — supertimeline post-processing
  EvtxECmd.txt         # EZ Tools — EVTX parsing
  zeek.txt             # Zeek — pcap analysis
  tshark.txt           # Wireshark CLI — pcap analysis
  yara.txt             # YARA — IOC scanning
  bulk_extractor.txt   # bulk_extractor — string/feature extraction
  grep.txt             # grep — pattern matching
  strings.txt          # strings — printable string extraction
```

Each snippet is concise (10–25 lines) — purpose, common usage, key flags, one example. Not a full man page; just enough that an analyst stuck in the lab can `man vol` and remember how plugins work.

When you build a lab for a tool not in the list above, ADD a man-page snippet for that tool to the skill's `man-pages/` directory in the same commit. This grows the skill's coverage over time.

---

## 12. Naming conventions

- **Lab files (the triplet)** — `<CaseName>-lab.html`, `<CaseName>-DFIR-Report.md`, `<CaseName>-AnswerSheet.md`. Same `<CaseName>` stem across all three so they group naturally in `ls`.
- **Legacy `<CaseName>-CTF.html`** — supported by the launcher for backward compat. Don't use for new labs.
- **Case ID** — `<CASENAME>-001` format (e.g. `BLACKWINDOW-001`). Used in the DFIR report header table.
- **Display title** — short, human-readable (e.g. "The Black Window Case", "Operation Foxglove"). Used in the lab `<title>` and h1.
- **Sidebar stage titles** — investigative questions, NOT technique names. E.g. "Stage 2 — Who else is here?" not "Stage 2 — Identify Valid Accounts".
- **No spaces in directory/file names.** Use kebab-case or PascalCase, not "My Cool Lab.html".

---

## 13. Pre-flight security sweep

Run BEFORE publishing any new lab. The lab ships as a static file readable by anyone — leaking analyst-machine paths or PII is unacceptable.

```bash
# 1. No local-machine paths
grep -rEn 'sansforensics|/home/[a-zA-Z]|/Users/[a-zA-Z]|/opt/[a-z]+-[0-9]+' \
  reports/<CaseName>-*.{html,md} index.html

# 2. No personal contact info
grep -rEn '@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[A-Za-z0-9._-]+@[A-Za-z0-9.-]+' \
  reports/<CaseName>-*.{html,md}

# 3. No API keys / secrets / tokens
grep -rEn 'api[_-]?key|secret|token|password\s*=\s*["'\'']' \
  reports/<CaseName>-*.{html,md}

# 4. No tool install paths in canned outputs
grep -nE 'file:///opt/|file:///home/|/usr/local/[^/]*-[0-9]' \
  reports/<CaseName>-lab.html

# 5. No internal/proprietary org names from real cases
# (manual review — depends on the case; check hostnames, usernames, IPs)

# 6. All timestamps in UTC
grep -nE 'AEST|AEDT|EST|EDT|PST|PDT|BST|GMT[+-]' \
  reports/<CaseName>-*.{html,md}

# 7. Tabular outputs use space-padded columns (no \t separators)
grep -cn '\\t' reports/<CaseName>-lab.html
# Should be 0 in the canned-output blocks (the wc command's \t in JS template
# literals is the only legitimate \t that may remain)
```

For each finding, redact or replace. Common substitutions:
- `/opt/volatility3-2.20.0/symbols/...` → `<symbols>/...`
- `/home/<analyst>/Downloads/<case>/` → `~/case/`
- Real hostnames → fictional ones consistent with the lab's scenario
- Real user accounts in screenshots → kept as-is if from upstream public artefact (e.g. MemLabs); replaced with fictional if from a real case.

The DFIR Report and AnswerSheet share the same security sweep requirements as the lab HTML.

---

## 14. Validation script

Ship `skill/ctf-builder/validate-lab.py` — runs automated checks against a lab triplet before publishing. Mandatory checks:

```python
# Pseudocode of what validate-lab.py does:

def check_lab(lab_html_path, report_path, answersheet_path):
    errors = []

    # File presence
    for p in [lab_html_path, report_path, answersheet_path]:
        if not p.exists(): errors.append(f"Missing file: {p}")

    # Filename pattern
    if not re.match(r'^[A-Za-z0-9._-]+-(lab|CTF)\.html$', lab_html_path.name):
        errors.append("Filename must match <CaseName>-lab.html (or legacy -CTF.html)")

    lab_text = lab_html_path.read_text()

    # Banned spoilers in hints
    spoilers = [
        '"is your answer"', '"is the answer"',
        '"the plugin is windows.', '"cmd.exe is the answer"',
    ]
    for phrase in spoilers:
        if phrase in lab_text:
            errors.append(f"Banned hint phrase found: {phrase}")

    # No flag-hunting language
    if re.search(r'find the flag|submit the flag|capture the flag|flag is', lab_text, re.I):
        errors.append("Flag-hunting language detected — labs are investigation-driven, not flag-based")

    # No scoring
    if re.search(r'\b(score|points|/ ?\d{2,4} points|leaderboard)\b', lab_text):
        errors.append("Scoring language detected — labs do not have points or scoreboards")

    # No difficulty labels
    if re.search(r'\b(EASY|MEDIUM|HARD|difficulty-badge|diff-easy|diff-med|diff-hard)\b', lab_text):
        errors.append("Difficulty labels detected — meta-spoiler, must be removed")

    # Local machine paths
    if re.search(r'/home/[a-z]+/|/Users/[A-Z]', lab_text):
        errors.append("Local-machine path leak detected — run security sweep")

    # Tabs in tabular outputs
    canned_block = extract_vol_outputs_block(lab_text)
    if '\\t' in canned_block:
        errors.append("Canned-output blocks contain \\t separators — must be space-padded")

    # ATT&CK refs in stages 1 to (N-1) briefing prose
    stages = parse_stages_array(lab_text)
    for s in stages:
        if s.get('intro') or s.get('id') == max(stage_ids):  # skip intro + synthesis
            continue
        if re.search(r'T\d{4}|TA\d{4}', s.get('briefing', '')):
            errors.append(f"Stage {s['id']} briefing contains ATT&CK reference — should be hidden until reveal")

    # Per-stage required fields
    for s in stages:
        if s.get('intro'): continue
        for field in ['title', 'tactic', 'technique', 'whatsKnown', 'briefing',
                      'pluginGrades', 'question', 'answer', 'answerNote',
                      'attReveal', 'hints']:
            if field not in s:
                errors.append(f"Stage {s['id']} missing required field: {field}")
        if len(s.get('hints', [])) != 3:
            errors.append(f"Stage {s['id']} must have exactly 3 hints")
        # Picker grades
        grades = [p['grade'] for p in s.get('pluginGrades', {}).values()]
        if 'best' not in grades:
            errors.append(f"Stage {s['id']} picker has no 'best' grade")
        if len(grades) < 5:
            errors.append(f"Stage {s['id']} picker has fewer than 5 plugins")

    # Title is question-framed
    for s in stages:
        if s.get('intro'): continue
        if not s['title'].rstrip('?').endswith(('?')):
            # Stage 8 (synthesis) doesn't need to end in ?
            if s.get('id') != max(stage_ids):
                errors.append(f"Stage {s['id']} title should be question-framed")

    return errors
```

Run via `python3 skill/ctf-builder/validate-lab.py reports/<CaseName>-lab.html`. Exit code 1 + error list if any check fails.

---

## 15. Build process (step-by-step)

1. **Acquire the artefact.** Memory image / disk image / pcap / log corpus. Verify hash. Store under `/cases/<CaseName>/`.

2. **Decide artefact-type and tool family** (see §4 matrix). Default for memory: Volatility 3.

3. **Run forensic tools** against the artefact and capture all relevant outputs. For a memory image:
   ```bash
   for plugin in info pslist pstree cmdline netscan filescan malfind \
                 svcscan handles registry.printkey clipboard envars; do
     vol -f /cases/<CaseName>/<image>.raw windows.${plugin} \
       > analysis/memory/${plugin}.txt 2>&1
   done
   ```
   Save to `analysis/memory/` (gitignored — never committed).

4. **Author the case scenario.** If derivative (from MemLabs / publicly available), use the source's verbatim scenario quote. If original, write 1–3 sentences in the reporter's voice.

5. **Decompose into 6–10 stages** following the ATT&CK kill chain. Typical structure:
   - Stage 0 — Briefing (intro pane)
   - Stage 1 — Discovery / triage ("What am I looking at?")
   - Stage 2 — Initial Access ("Who else is here?")
   - Stage 3 — Execution ("What spawned…?")
   - Stage 4 — Stealth / Masquerading
   - Stage 5 — Credential Access
   - Stage 6 — Collection / Staging
   - Stage 7 — Exfiltration ("Could it have left?")
   - Stage 8 — Synthesis (analyst maps to ATT&CK themselves)

6. **Author per-stage content** per §7. Question-framed titles, picker grades, hints (3 escalating tiers), ATT&CK reveal text. Cross-check against §17 anti-patterns.

7. **Format canned outputs** as space-padded tables. Run the formatter:
   ```bash
   python3 skill/ctf-builder/format_all_tables.py reports/<CaseName>-lab.html
   ```

8. **Build the lab HTML** from `skill/ctf-builder/templates/lab-template.html`. Replace `STAGES`, `VOL_OUTPUTS` (or analogous), `STRINGS_HITS`, `FILES`, lab title, attribution.

9. **Apply the security sweep** (§13). Fix every finding before continuing.

10. **Run the validation script** (§14). Resolve every error.

11. **Test in browser** end-to-end:
    - Stage 0 loads first
    - Click Stage 1 — picker visible, terminal empty
    - Pick correct plugin → ✓ feedback. Pick wrong → ✗ feedback.
    - Type a wrong command → terminal shows error, prompt sits directly below
    - Type the right command → output appears, prompt at top of visible area
    - Submit correct answer → green ✓, ATT&CK reveal card, Continue button
    - Click Continue → stage 2 loads, sidebar advances
    - Repeat through all stages
    - Solving the last stage triggers fireworks + completion modal
    - Click `clear` in terminal → resets to top
    - Toggle Pro mode in header → picker hides
    - Mobile: hamburger menu opens sidebar; tap targets are reachable

12. **Write the DFIR Report** from the same stage data, using the report template. Follows real IR write-up format: Executive Summary → System Profile → Attack Narrative (kill chain) → Timeline → IOCs → ATT&CK Mapping → Network Posture → Remediation → Detection Engineering → Limitations → Appendix.

13. **Write the AnswerSheet** from the same stage data, using the answersheet template. Per-stage walkthrough: Hypothesis → Plugin → Command → Finding → Why it matters → ATT&CK → Lesson. Add decision trees where genuinely useful.

14. **Update `index.html`** landing-page card with the new lab's title, description, ATT&CK pills, and link.

15. **Commit with conventional-commit prefix** — `feat(labs): add <CaseName> lab — <one-line description>`.

16. **Push.** Pages rebuilds automatically.

---

## 16. Common gotchas

These cost hours of debugging during the BlackWindow rebuild. Don't repeat them.

- **`flex-direction: column; justify-content: flex-end`** on `.terminal` breaks internal scroll. Use normal block flow.
- **`min-height` on `.terminal`** creates "prompt jumps to bottom of page" feel on short error responses. Use `max-height` only.
- **Forgetting `:empty { padding: 0; border: none; box-shadow: none; }`** leaves an awkward 20px black strip when terminal is empty.
- **Forgetting `state.promptAtTop` reset in `clear`** leaves the input row stranded at the bottom of an invisible terminal box.
- **Not capturing `scrollHeight` BEFORE termWritePrompt** means scroll-to-prompt-at-top doesn't work — `termWrite`'s scroll-to-bottom default wins.
- **Raw `<placeholder>` text in JS string literals** that get assigned to `innerHTML` get parsed as HTML tags and silently stripped. ALWAYS HTML-escape: `&lt;PID&gt;`, `&lt;memory image&gt;`.
- **`\t` separators in canned tabular output** render at unpredictable visual positions. Use space-padded columns (`format_all_tables.py`).
- **Using `splitOn('\t')` in a Python helper** breaks paths like `\\tcpsvcs.exe` (path contains `\t`). Use `re.split(r'(?<!\\)\\t', line)` to skip escaped backslash-t.
- **Renaming `<CaseName>-lab.html` once shipped** breaks GitHub Pages bookmarks. Add a meta-refresh redirect shim at the old path.
- **Calling `renderCurrentStage()` in `checkAnswer`'s wrong-answer path** wipes the analyst's typed answer (because `ai.value = ''` for unsolved stages). Use direct DOM manipulation for non-blocking nudges instead.
- **Marketing buzzwords slip in over time.** Audit prose for "hypothesis-driven", "real X, real Y, real Z", "the why behind", "the language analysts use", etc. Strip on sight.

---

## 17. Anti-patterns — what NOT to do

These are deliberate design choices made and re-made through the BlackWindow rebuild. Do not "improve" them back.

| Don't | Why |
|---|---|
| Add scoring / points / leaderboards / progress percentages | The lab teaches analytical reasoning, not gamified flag-capture. Quiet "Stage N of M" tracker only. |
| Add difficulty labels (EASY / MEDIUM / HARD) | Meta-spoiler. The labels were author-arbitrary and primed analysts before they investigated. |
| Show ATT&CK technique upfront in stages 1 to (N-1) | Backwards pedagogy. ATT&CK is the translation layer for findings, not the framework you investigate by. |
| Use flag-hunting language ("find the flag", "submit the flag") | Wrong audience model. Analysts submit findings, not flags. |
| Hand the analyst the plugin to use | Picker grades intentionality; the analyst MUST commit to a pick (or skip via Pro mode) to learn the tool taxonomy. |
| Auto-suggest commands as tap-to-run pills | Spoonfeeding. Analysts type their own — that's the muscle memory that transfers to real cases. |
| Use `flex-end` on the terminal | Breaks internal scroll (browser locks scroll position when items overflow past start of flex-end container). |
| Use `min-height` on the terminal | Creates the "prompt shoots to the bottom of the page" feel on short error responses. |
| Use marketing buzzwords | "Hypothesis-driven", "the why behind every finding", "real X, real Y, real Z". The design speaks; copy stays out. |
| Fabricate artefacts the source doesn't contain | Forensic accuracy is non-negotiable. Don't invent attacker narratives the artefact can't support. |
| Add LLM-graded hypothesis text input | Without an LLM the grading is theatre; with an LLM the lab loses offline-capable + zero-dependency status. The picker grades intentionality without LLM. |
| Ship with localhost paths or PII | Pre-flight sweep is mandatory. Lab is publicly readable. |
| Add a hard-mode that hides ATT&CK | Pro-mode toggle hides the picker (real opt-out). Hiding ATT&CK defeats the lab's pedagogy. |

---

## 18. Attribution requirements

Every lab MUST credit upstream sources clearly. The skill's standard attribution structure:

**In the lab HTML (sidebar footer):**
```html
<div class="sb-h" style="margin-top:14px">🙏 Attribution</div>
<div style="...">
  Memory image and case scenario from
  <a href="<source-url>" style="...">stuxnet999/MemLabs Lab 1</a>.
  The interactive terminal, ATT&amp;CK mapping, stage decomposition, and
  analyst-training narration in this lab are original.
</div>
```

**In the DFIR Report (top of file):**
```markdown
> **Attribution:** The memory image and case scenario in this report are taken
> from **MemLabs Lab 1** by **stuxnet999** (<github-url>). The analytical
> write-up, ATT&CK mapping, kill-chain narrative, and detection-engineering
> content in this report are original, produced for analyst training.

> **Scenario (from the original):** *"<verbatim scenario text>"*
```

**In the AnswerSheet (top of file):**
```markdown
> **Attribution:** The memory image and case scenario for this lab are taken
> from **MemLabs Lab 1** by **stuxnet999** (<github-url>). The walkthrough,
> investigative methodology, and ATT&CK reasoning in this guide are original
> training content.

> **Scenario:** *"<verbatim scenario text>"*
```

Be specific about WHAT is derived (image + scenario) and WHAT is original (lab format, mapping, narration). Don't overclaim originality; don't underclaim either.

For original cases (no upstream source), credit the analyst(s) who did the investigation and any team or organisation involved.

---

## 19. Out of scope

Things the skill does NOT do, and labs built with it should NOT attempt:

- **Real Volatility / Plaso / Zeek runtime in the browser.** Would require a WASM port. Labs use canned output.
- **Server-side anything.** Labs are static HTML. No backend, no user accounts, no persistence across sessions.
- **Network calls at runtime.** Lab works fully offline. No CDN fonts, no analytics, no external resources.
- **Authentication / scoring / leaderboards / multiplayer.** Use CTFd or similar for those.
- **Real-time streaming output.** Canned outputs render synchronously when the analyst types the command.
- **Editing canned outputs at runtime.** Lab is read-only training material.
- **Localisation.** Labs are English-only. Translation is a separate concern not handled by this skill.
- **Real-time hint generation.** Hints are pre-authored per stage.

---

## 20. Reference: The Black Window Case

`reports/BlackWindow-CTF.html` is the canonical reference implementation. When in doubt about how a section should look, read the corresponding part of BlackWindow:

- Stage 0 (intro pane) → search for `intro: true` in `STAGES`
- Per-stage data — search for `id: 1` through `id: 8`
- Picker rendering — search for `function renderPickerHTML`
- Terminal logic — search for `function executeLine`
- Scroll-to-prompt-at-top — search for `scrollTerminalToPrompt`
- Pro-mode toggle — search for `pro-mode-toggle-header`
- Soft-lock carry-forward — search for `carryLocked`
- Continue button — search for `continue-btn`
- Picker nudge — search for `pickerSkipped`
- Fireworks — search for `runFireworks`

Companion files for cross-referencing:
- `reports/BlackWindow-DFIR-Report.md` — full IR write-up format
- `reports/BlackWindow-AnswerSheet.md` — per-stage walkthrough format
- `index.html` — landing-page card format
- `scripts/start.sh` — launcher with dual-glob support

When you build a new lab, work in parallel with these files open. Pattern-match for visual + structural consistency.

---

*Last revised after the BlackWindow rebuild — every section above derives from a specific design decision made and tested through that work. If you find a pattern that contradicts what's here, something's drifted: re-read §17 anti-patterns.*
