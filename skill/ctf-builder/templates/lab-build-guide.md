# Lab HTML — Data-Shape Reference

Concrete schema for the three data structures that drive a lab. The HTML/CSS/JS skeleton is in `lab-template.html` (or copy `reports/BlackWindow-CTF.html` as a working reference) — this guide explains what fills each placeholder.

> **Spec lives in [`../SKILL.md`](../SKILL.md).** Pedagogy, terminal contract, anti-patterns, build process, validation, attribution — all there. This guide covers only the data shapes.

---

## Bootstrap

```bash
# 1. Copy the scaffold
cp skill/ctf-builder/templates/lab-template.html \
   reports/<CaseName>-lab.html

# 2. In your editor, replace the four data structures (below) and the
#    header text. The terminal logic, picker, kill-chain panel, hint
#    popup, completion modal, and fireworks all stay as-is.

# 3. Validate locally
xdg-open reports/<CaseName>-lab.html
```

New labs use the `*-lab.html` suffix. The legacy `*-CTF.html` suffix is supported by `scripts/start.sh` for backward compatibility (see `BlackWindow-CTF.html`) but new work should not adopt it.

---

## Top-level lab state

```javascript
const state = {
  current: 0,                  // current stage id
  solved: new Set(),           // ids of solved stages
  hintIdx: {},                 // per-stage hint reveal index
  picks: {},                   // { [stageId]: { plugin, grade } }
  proMode: false,              // Stage 0 toggle — hides pickers
  promptAtTop: false           // terminal layout flag
};
```

`picks` and `proMode` are foundation-rebuild additions. Don't reintroduce a `scores` map — there is no scoring.

---

## 0.5 `TOOL_CONFIG` and `TERMINAL_SKIN` (set first, before STAGES)

Every user-facing tool reference in the lab — the plugin picker prompt, the Stage 1 first-touch hint above the terminal, the pro-mode tooltip, the `grep` no-input help — interpolates from `TOOL_CONFIG`. Without this, Vol-specific copy leaks into pcap / disk / EVTX / log labs.

```js
const TOOL_CONFIG = {
  name:        "tshark/Wireshark",                              // shown in picker prompt + tooltip
  cmd:         "tshark",                                        // command verb the analyst types
  invocation:  'tshark -r <pcap> [-Y "<filter>"] [-q -z <stat>]',
  pluginNoun:  "command",                                       // 'plugin' (Vol) / 'command' (tshark) / 'parser' (Plaso)
  exampleHelp: "tshark -r case.pcap -q -z io,phs"               // example shown in grep / help
};

const TERMINAL_SKIN = "bash-ubuntu";  // skin keys: bash-dfir | bash-ubuntu | powershell-win | cmd-windows | zsh-macos
```

See SKILL.md §10 for the per-artefact-class TOOL_CONFIG matrix and the TERMINAL_SKINS table. **Pick the skin from the analyst's environment, not the artefact's** — a Windows memory image analysed on a SANS SIFT box uses `bash-dfir`, not `powershell-win`.

The validator (`validate-lab.py`) rejects labs where `TOOL_CONFIG.cmd != 'vol'` but the user-facing Vol strings (picker prompt, first-touch hint, pro-mode tooltip) still appear — catches the leakage you'd otherwise miss in code review.

---

## 1. `STAGES` array

The single most important data structure. One entry per stage, including the Stage 0 intro. Schema below; per-field rules in §7 of SKILL.md.

### Stage 0 (intro)

```javascript
{
  id: 0,
  intro: true,                                 // flags as intro pane
  title: "Briefing & How This Works",
  tactic: "INTRO",                             // sidebar label only
  briefing: `<div class="intro-pane">
    <section class="intro-section">
      <h3>The Case</h3>
      <blockquote class="intro-quote">
        <!-- Verbatim source-of-truth scenario quote, if one exists.
             Cite the source. -->
      </blockquote>
      <p>Each stage opens with what's known so far and asks one
         investigative question. Pick a plugin, run commands, submit
         what you find. The ATT&CK technique is revealed after you
         answer.</p>
    </section>

    <section class="intro-section">
      <h3>How this game works</h3>
      <p>Static HTML. The terminal looks up your command in a table
         of pre-recorded outputs — it does not run the real tool.
         Commands not in the table say "no canned output". This is
         rails, not a sandbox.</p>
      <p>If you get stuck, the 💡 Need a hint? button gives
         progressive nudges.</p>
    </section>

    <section class="intro-section">
      <h3>About <Tool></h3>
      <p><One-paragraph what-it-is + which version + canonical
         invocation. Include the shorthand vs full form if relevant
         (e.g. <code>vol -f &lt;image&gt; &lt;plugin&gt;</code> vs
         <code>python3 vol.py -f &lt;image&gt; &lt;plugin&gt;</code>).</p>
      <pre class="codeblock">vol -f &lt;image&gt; &lt;plugin&gt;</pre>
    </section>

    <label class="pro-mode-toggle">
      <input type="checkbox" id="pro-mode-checkbox">
      <span>Pro mode — skip the plugin picker on each stage.</span>
    </label>
  </div>`,
  hints: []
}
```

### Stages 1 … N−1 (investigative)

```javascript
{
  id: 1,
  title: "Stage N — <one-line investigative question>",   // not a tactic name
  tactic: "TA#### Tactic Name",                           // hidden until solved
  technique: "T####.### Technique Name",                  // hidden until solved
  whatsKnown: `<one to two sentences carrying forward the
                relevant findings from prior stages.>`,
  briefing: `<one to two sentences framing the question and pointing
              at why a particular class of plugin is the right move —
              never name the plugin outright; the picker handles that.>`,
  pluginGrades: {
    "<tool>.<plugin-a>": { grade: "best",      reason: "<why this is the strongest first move>" },
    "<tool>.<plugin-b>": { grade: "plausible", reason: "<close cousin — useful but not the most direct>" },
    "<tool>.<plugin-c>": { grade: "off-base",  reason: "<wrong layer — explain briefly>" },
    // 6–7 plugins total. Mix grades so the analyst makes a real choice.
  },
  question: `<HTML question text — bold the answer-shaped noun, give
              the format spec parenthetically.>`,
  answer: "<canonical answer string>",
  altAnswers: [
    "<case variant>",
    "<path with / instead of \\>",
    "<short form>"
  ],
  answerNote: `<HTML reveal text. 2-3 sentences. State the finding,
                what it implies, and what to carry forward to the
                next stage. No ATT&CK reference here — that's the
                attReveal card's job.>`,
  attReveal: {
    technique: "T####.### — <Technique Name>",
    fits: "<one sentence linking the behavioural fingerprint just
            observed to the technique. Two if absolutely needed.>"
  },
  hints: [
    // H1 — syntax shape only. Names the command form, not the plugin.
    "<tool> commands take the shape <code>...</code>. There's a plugin that does X — think about what it would be called.",
    // H2 — narrows by property. Names a category or constraint without
    // naming the plugin or answer.
    "<a property of the plugin name, or the kind of pattern to grep for>",
    // H3 — literal command + where to read the answer in the output.
    // No "is your answer" filler.
    "Run <code><tool> ...</code>. Read the <field> column."
  ]
}
```

**Picker grade rules:**
- Each stage has exactly one `best` (the strongest first move). Two `plausible` is fine. The rest are `off-base`.
- `reason` strings must NOT name the answer. ("Filter for `.bat` in System32" is a spoiler — the analyst hasn't picked yet.)

**`whatsKnown` rules:**
- One sentence per prior fact, max two facts. The carry-forward, not a recap.
- Stage N's `whatsKnown` is the natural conclusion of Stage N−1's `answerNote`.

### Final synthesis stage (last entry)

```javascript
{
  id: 8,
  title: "Stage N — Map your findings to ATT&CK",
  noPicker: true,                              // hides the picker
  whatsKnown: `You've earned N−1 ATT&CK techniques across the
                previous stages. This stage is the synthesis — do
                the mapping yourself, no reveal handing it to you.`,
  // briefing, question, answer, answerNote, hints as normal
  attReveal: {
    technique: "<the technique they map to>",
    fits: "You earned this technique back at Stage X. Re-stating it
            here in formal ATT&CK is the writing-up muscle that turns
            an investigation into a defensible report."
  }
}
```

The synthesis stage asks the analyst to *produce* the mapping rather than receive a reveal. `noPicker: true` hides the picker UI. Hints are reasoning-shaped, not plugin-shaped.

---

## 2. `<TOOL>_OUTPUTS` — canned plugin output

The terminal looks up `<tool> -f <image> <plugin>` in this object and prints the matching string. Tab characters are encoded as `\t`. Newlines are real line breaks inside template literals.

```javascript
const VOL_OUTPUTS = {
  "windows.info": `Volatility 3 Framework 2.28.1
Variable\tValue
Kernel Base\t0xf800026...
NTBuildLab\t7601.17514.amd64fre.win7sp1_rtm.101119-1850
...`,

  // PID-specific plugins use the suffix -<PID>:
  "windows.handles-1512": `<output filtered to PID 1512>`,
  "windows.dlllist-1984":  `<output for PID 1984>`,

  // Plugins that take --key:
  "windows.registry.printkey-Microsoft\\\\Windows NT\\\\CurrentVersion": `...`,
};
```

Rename to `MFT_OUTPUTS`, `EVTX_OUTPUTS`, `TSHARK_OUTPUTS`, etc. for non-Volatility artefacts. The `cmdVol` handler in JS picks the right table based on the command verb — see §15 of SKILL.md for adding a new tool.

**Alignment matters.** Pre-format every table so columns line up under a monospace render. The repo ships `format_all_tables.py` — use it. Manually pasted output WILL drift on column widths.

---

## 3. `STRINGS_HITS` — pre-greppable corpus

Optional. Used when the lab needs `strings <image> | grep <pattern>` to return useful hits without storing a 1 GB strings dump.

```javascript
const STRINGS_HITS = {
  "St4G3":   `C:\\Users\\<user>\\Desktop\\St4G3$1.bat
C:\\Windows\\System32\\St4G3$1.bat`,
  "PASSWD":  `C:\\Windows\\debug\\PASSWD.LOG`,
};
```

Keys are exact patterns the analyst would grep for. Multiple hits per key as separate lines.

---

## 4. Header & chrome — the small surface area

| Where | What to change |
|-------|---------------|
| `<title>` | "<Case Name> — <Artefact Type>" |
| `<header>` h1 | Same case name |
| `<header>` badges | `[<Tool> <version>] [<OS / artefact descriptor>] [<image filename>] [Stage N / N]` |
| Footer attribution line | Per `SKILL.md` §18 — credit the artefact source if derivative |

The image-filename badge is load-bearing for analyst muscle memory — they should see the filename they'd type into the real `<tool> -f` command. On mobile, extra badges hide at the 768px breakpoint to fit; the filename is one of the badges that hides. Acceptable trade-off.

---

## Terminal — already implemented, don't break it

The shipped terminal supports these commands. New labs inherit them; only add a new handler if your artefact type genuinely needs one.

| Command | What it does |
|---------|-------------|
| `<tool> -f <img> <plugin> [--pid N] [--key "..."]` | Looks up `<TOOL>_OUTPUTS[plugin]` |
| `strings <file>` | Returns the `STRINGS_HITS` map for downstream grep |
| `grep [-i] <pattern>` | Filters stdin |
| `cat`, `head`, `tail`, `wc`, `sort`, `uniq` | Standard pipeline ops |
| `ls`, `pwd`, `file` | Filesystem orientation |
| `man <tool>`, `help`, `?` | Inline documentation (sourced from `man-pages/`) |
| `tactics`, `progress`, `clear` | Lab helpers |
| ↑ / ↓ / Enter | Command history & submission |

**Layout invariants.** The terminal is auto-sized (no `min-height`), has `max-height: 560px` for internal scroll, and uses `:empty` to fully collapse when there's no output. The wrapper carries the green CRT glow as a single `filter: drop-shadow()` so input row + output share one halo with no internal seam. Don't reintroduce `box-shadow` on the children — see the comment block above `.terminal` in the canonical lab.

---

## OS-specific terminal skin

If your artefact came from a different OS than the lab's default Linux/SIFT skin, set `terminalSkin` near the top of the script block:

```javascript
const terminalSkin = "powershell-win"; // bash-ubuntu | bash-dfir | powershell-win | cmd-windows | zsh-macos
```

The skin selector applies a CSS variable bundle (`--term-bg`, `--term-fg`, `--term-glow`) and a prompt-string template. Defaults to `bash-dfir` (`analyst@dfir:/cases#`). See `SKILL.md` §10 for the shipped palettes.

A Windows-host memory image looks more authentic with `powershell-win` (`PS C:\Users\analyst>`, blue chrome) — small detail, but it primes the analyst's mental model from the moment the lab opens.

---

## Adding a new tool handler

Most labs won't need to. If you do:

```javascript
// In runCommand() switch:
case 'tshark':
  return cmdTshark(tokens.slice(1));

function cmdTshark(args) {
  const key = args.join(' ');
  return { text: TSHARK_OUTPUTS[key] || "tshark: no canned output for this filter" };
}
```

Then populate `TSHARK_OUTPUTS` with keys matching the args strings the lab will actually use. The fallback message must say "no canned output" verbatim — the analyst is trained to recognise it as "this command isn't on the rails for this lab."

---

## Validation

Run `validate-lab.py` (in this skill directory) before shipping. It checks:

- Every plugin referenced in `pluginGrades` has an entry in `<TOOL>_OUTPUTS`
- Every command shown in a hint or briefing returns canned output (no "command not found")
- Every `answer` is reachable from at least one expected command shape
- `STAGES.length >= 6`
- Every stage has `whatsKnown`, `pluginGrades`, `attReveal` (except intro and synthesis stages, which can opt out)
- No `<placeholder>` markers survived
- No `sansforensics`, `/home/`, `/Users/`, real email addresses, API keys

Per `SKILL.md` §14.

---

## What this guide is NOT

- **Pedagogy or anti-patterns** — `SKILL.md` §3, §17.
- **Build process step-by-step** — `SKILL.md` §15.
- **Visual design / colour palette** — `SKILL.md` §9.
- **OS terminal-skin CSS bundles** — `SKILL.md` §10.
- **Pre-flight security sweep** — `SKILL.md` §13.

This file is just the data-shape contract. Everything else is the spec.
