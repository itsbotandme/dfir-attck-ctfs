# CTF HTML Template — Build Guide

The canonical, working CTF HTML implementation is at:
```
./reports/BlackWindow-CTF.html
```

**To bootstrap a new CTF:** copy that file, rename, and replace the three data structures listed below. The HTML/CSS/JS skeleton is reusable as-is.

---

## Data Structures to Replace

### 1. `VOL_OUTPUTS` (object)
Keys are plugin names, values are the plugin's output as a string. Tab characters are encoded as `\t`. Newlines as actual line breaks.

For PID-specific plugins (`windows.envars`, `windows.handles`, `windows.dlllist`), use the key format `<plugin>-<PID>`, e.g. `"windows.handles-1512"`.

```javascript
const VOL_OUTPUTS = {
  "windows.info": `Volatility 3 Framework 2.28.1
Variable\tValue
NTBuildLab\t...`,

  "windows.pslist": `...`,
  "windows.handles-1512": `...`,
  // ...
};
```

### 2. `STRINGS_HITS` (object)
Keys are search patterns, values are the lines from `strings <image> | grep <pattern>` that should appear when the analyst greps the strings output. Used to make `strings ... | grep` return useful results without storing the full 1GB strings table.

```javascript
const STRINGS_HITS = {
  "St4G3": `C:\\Users\\SmartNet\\Desktop\\St4G3$1.bat
C:\\Windows\\System32\\St4G3$1.bat`,

  "PASSWD": `C:\\Windows\\debug\\PASSWD.LOG`,
  // ...
};
```

### 3. `STAGES` (array)
The 6–10 CTF stages. Each stage has:

```javascript
{
  id: 1,                                    // 1-indexed
  title: "Stage N — <descriptive title>",
  tactic: "TA0001 Initial Access",          // ATT&CK tactic
  technique: "T1078 Valid Accounts",        // ATT&CK technique
  techniqueNote: "(parenthetical context)",
  difficulty: "easy" | "medium" | "hard",
  points: 30 | 40 | 50 | 60 | 70 | 80,

  briefing: `Multi-paragraph HTML.
              Use <code>...</code>, <b>...</b>, and the
              <ol class="approach-list">...</ol> CSS class
              for the suggested-approach bullet list.`,

  expectedCommands: [                       // canonical correct commands
    "vol -f <image> windows.<plugin>",
    "vol -f <image> windows.<plugin> | grep <pattern>"
  ],

  question: `<HTML question text with <b>highlighted</b> answer cues>`,

  answer: "primary answer string",

  altAnswers: [                             // optional alternates
    "case variant",
    "path with / instead of \\",
    "without C: prefix"
  ],

  answerNote: `<HTML reveal text — 2-3 sentences explaining the
               ATT&CK significance>`,

  attMap: "TA#### Tactic → T####.### Technique Name",

  hints: [                                  // 2-3 progressive hints
    "First hint: nudge toward the right plugin",
    "Second hint: nudge toward the right column/pattern",
    "Third hint: near-direct answer"
  ]
}
```

---

## Terminal Emulator — Already Implemented

The terminal supports these commands out of the box; you don't need to modify them:

| Command | Implementation |
|---------|---------------|
| `vol -f <img> <plugin> [--pid N] [--key "..."]` | `cmdVol()` — looks up plugin in `VOL_OUTPUTS` |
| `strings <file>` | `cmdStrings()` — returns the `STRINGS_HITS` map for downstream grep |
| `grep [-i] <pat>` | `cmdGrep()` — filters stdin or stdin's `raw` map |
| `cat`, `head`, `tail`, `wc`, `sort`, `uniq` | Standard pipeline ops |
| `ls`, `pwd`, `file` | Filesystem orientation |
| `man <tool>`, `help`, `?` | Inline documentation |
| `tactics`, `progress`, `clear` | Lab helpers |
| ↑/↓ arrows, Enter | Command history & submission |

---

## Style Customisations You Might Make

| What | Where to change |
|------|----------------|
| Colour theme | `:root { --bg: ... --accent: ... }` CSS variables |
| Header title / badges | `<header>` block in HTML body |
| Total points | Score pill text + `STAGES.points` sum |
| Completion modal text | `#completion-modal` block in HTML |
| Boot banner | `bootTerminal()` JS function |

---

## Validation Checklist

Before shipping a generated CTF, run through this:

- [ ] Every command in `expectedCommands` returns useful output (no "command not found")
- [ ] Every `answer` matches at least one acceptable variant in `altAnswers`
- [ ] Every stage's `attMap` text matches the actual tactic/technique
- [ ] Every `hints` array has 2–3 entries, progressively more direct
- [ ] Open in a browser — terminal scrolls correctly, hints display, completion modal triggers at 100%
- [ ] Total points (sum of `STAGES.points`) is reflected in the header score pill
- [ ] Time-to-complete with hints visible is appropriate for target audience

---

## Adding New Command Support

If your CTF needs commands beyond the built-in set (e.g., `tshark`, `MFTECmd`, `EvtxECmd`), add a handler:

```javascript
// In runCommand() switch:
case 'tshark':
  return cmdTshark(tokens.slice(1));

// Add the handler:
function cmdTshark(args) {
  // Parse args, look up canned output
  return { text: TSHARK_OUTPUTS[key] || "tshark: not implemented" };
}
```

Then populate the corresponding canned-data object (`TSHARK_OUTPUTS`).

---

## Quick Bootstrap Script (manual, for now)

```bash
# 1. Copy the canonical CTF HTML
cp ./reports/BlackWindow-CTF.html \
   ./reports/<NEW-CASE>-CTF.html

# 2. Open in editor and:
#    - Update title in <title> and <header>
#    - Replace VOL_OUTPUTS object
#    - Replace STRINGS_HITS object
#    - Replace STAGES array
#    - Adjust total-points value in header

# 3. Validate in browser
xdg-open ./reports/<NEW-CASE>-CTF.html
```

---

*The canonical implementation at `BlackWindow-CTF.html` is ~900 lines of HTML/CSS/JS. Reading through it once gives you everything you need to build derivatives.*
