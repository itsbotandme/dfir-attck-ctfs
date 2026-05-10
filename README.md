# DFIR ATT&CK Investigation Labs

Browser-playable, self-contained DFIR investigation labs that walk
the **MITRE ATT&CK** kill chain. One investigative question per
stage; the technique is revealed after the finding. Each lab ships
as three deliverables: an interactive analyst terminal, a full DFIR
investigation report, and a junior-analyst walkthrough.

## Currently Included

| Lab | Source | Format |
|-----|--------|--------|
| **The Black Window Case** | Memory image (1 GB raw) | 8-stage investigation |

---

## How to Play

### 🌐 Easiest — play online

**👉 https://itsbotandme.github.io/dfir-attck-ctfs/**

That URL is the live site. Pick a lab and play in your browser — works on desktop and mobile, no install needed.

### 💻 Or play locally (works fully offline)

```bash
# 1. Clone the repo
git clone https://github.com/itsbotandme/dfir-attck-ctfs.git
cd dfir-attck-ctfs

# 2. Open the landing page in your browser
xdg-open index.html         # Linux
open index.html             # macOS
start index.html            # Windows
```

That's it. **No installation, no Claude, no API keys, no internet** required at runtime. Each lab is a self-contained HTML file with a JavaScript terminal emulator and all Volatility outputs embedded.

### 📱 Play on Mobile (iOS / Android)

Each lab is **fully mobile-friendly** — no app store install needed.

1. Open **https://itsbotandme.github.io/dfir-attck-ctfs/** in Safari or Chrome on your phone
2. Tap a lab card → "Play Now"
3. Type Volatility commands directly into the terminal — analysts learn the muscle memory of the syntax this way, not by tapping pre-baked pills
4. Optional: **Add to Home Screen** (Safari → Share → Add to Home Screen / Chrome → Menu → Install app) for a fullscreen, native-feeling experience

Mobile features:
- ☰ **Hamburger menu** opens the stages drawer
- 💡 **Touch-friendly hints** with progressive guidance, large 44px tap targets throughout
- 🎆 Fireworks finale on completing all 8 stages (respects `prefers-reduced-motion`)

### Optional: `start <name>` shell launcher

For convenience, run any lab by name from the terminal:

```bash
# One-time setup (Linux/macOS)
source scripts/start.sh              # current shell only
echo "source $(pwd)/scripts/start.sh" >> ~/.bashrc   # permanent

# Then:
start                                # list available labs
start BlackWindow                    # exact match
start black                          # case-insensitive partial match
```

---

## How to Build Your Own Labs

The labs in this repo were built using a Claude Code skill called
**`ctf-builder`** that automates: forensic analysis → ATT&CK mapping →
stage decomposition → HTML generation. The directory name kept the
"ctf-builder" stem from earlier iterations; the labs it builds now
follow the same investigation-first pedagogy as The Black Window Case
— ATT&CK revealed after each finding, not signposted upfront (see
the SKILL.md for details).

To build new labs from your own forensic artefacts:

1. **Install [Claude Code](https://claude.com/claude-code)** (or use the Claude Agent SDK)
2. **Copy the skill into your Claude config:**
   ```bash
   cp -r skill/ctf-builder ~/.claude/skills/
   ```
3. **Invoke the skill** with your case data:
   > "Build an investigation lab from my memory image at `/cases/<name>/` using the ctf-builder skill"

Claude will read the artefact, run the relevant forensic tools (Volatility,
Sleuth Kit, Plaso, etc.), map findings to ATT&CK, and produce the three
deliverables (report, lab HTML, walkthrough).

> **Note:** Building new labs requires Claude Code or another LLM agent
> capable of running shell commands. Once built, the lab HTMLs themselves
> are completely standalone and can be played without any AI.

---

## Required External Download — Memory Image (The Black Window Case)

The Black Window Case is built on the memory image and case scenario from
**stuxnet999/MemLabs Lab 1**. The 1 GB image is **not committed to this
repo** for size and licensing reasons. Download it from the original source:

> **Source:** [stuxnet999/MemLabs — Lab 1](https://github.com/stuxnet999/MemLabs/tree/master/Lab%201)

```bash
# Manual: download MemLabs-Lab1.7z from the link above

# Extract:
mkdir -p cases/BlackWindow
7z x MemLabs-Lab1.7z -ocases/BlackWindow/
# → cases/BlackWindow/MemoryDump_Lab1.raw
```

**You do NOT need the memory image to play the lab.** The lab HTML has
all Volatility outputs pre-baked. The image is only needed if you want
to run your own commands against it on a real SIFT workstation, or to
validate the canned outputs.

---

## Repository Layout

```
.
├── README.md                       # this file
├── reports/
│   ├── BlackWindow-CTF.html        # play this
│   ├── BlackWindow-DFIR-Report.md  # full investigation write-up
│   └── BlackWindow-AnswerSheet.md  # junior-analyst walkthrough
├── skill/
│   └── ctf-builder/                # Claude Code skill to build more labs
│       ├── SKILL.md
│       └── templates/
├── scripts/
│   └── start.sh                    # portable lab launcher
└── .gitignore
```

> The `*-CTF.html` filename pattern is load-bearing — `scripts/start.sh`
> discovers labs by that glob. The "CTF" in the filename is historical
> (the project started as a CTF concept before the rebuild) and shouldn't
> be renamed unless the launcher is updated to match.

---

## What Each Deliverable Is For

| File | Audience | Purpose |
|------|----------|---------|
| `*-CTF.html` | Anyone | Interactive 60–90 min training session |
| `*-DFIR-Report.md` | IR analysts, mgmt | Defensible kill-chain narrative + ATT&CK mapping + remediation + Sigma rules |
| `*-AnswerSheet.md` | Junior analysts | Reasoning frameworks, decision trees, common pitfalls |

---

## Attribution

The lab format and analyst-training methodology in this repository
are derivative educational content. The underlying forensic challenges
are owned by their original authors:

| Lab | Original Author | Source |
|-----|----------------|--------|
| MemLabs Lab 1 | **stuxnet999** | [github.com/stuxnet999/MemLabs](https://github.com/stuxnet999/MemLabs) |

If you create new labs from other publicly-available challenges, please
credit the original author here.

---

## License

The wrapper content (lab HTML, DFIR report, walkthrough, ctf-builder skill,
launcher scripts) is released under **MIT License** for educational use.
Original challenge artefacts retain the licensing terms of their respective
upstream projects — see *Attribution* above.

---

## Contributing

PRs welcome — especially for:

- New labs built with the `ctf-builder` skill (must include attribution)
- Improvements to the terminal emulator (more commands, better grep)
- Detection rule contributions (Sigma, YARA) tied to specific ATT&CK techniques
- Translations of training material

When adding a new lab, please ensure:

- [ ] No personal/proprietary data (PII, internal hostnames, real org names)
- [ ] Clear attribution if derived from a public challenge
- [ ] All three deliverables (HTML, report, walkthrough) are present
- [ ] Filename pattern `<name>-CTF.html` so the launcher finds it
