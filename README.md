# DFIR ATT&CK CTF Lab Pack

Browser-playable, self-contained DFIR Capture-the-Flag challenges organised
by **MITRE ATT&CK Enterprise tactics**. Each CTF includes an interactive
analyst terminal, a full DFIR investigation report, and a junior-analyst
training guide that explains the *why* behind every finding.

## Currently Included

| Lab | Source | Format |
|-----|--------|--------|
| **MemLabs Lab 1** | Memory image (1 GB raw) | 8-stage ATT&CK kill-chain CTF |

---

## How to Play

```bash
# 1. Clone the repo
git clone <repo-url>
cd <repo-dir>

# 2. Open the CTF in your browser
xdg-open reports/MemLabs-Lab1-CTF.html      # Linux
open reports/MemLabs-Lab1-CTF.html          # macOS
start reports/MemLabs-Lab1-CTF.html         # Windows
```

That's it. **No installation, no Claude, no API keys, no internet.** The
CTF is a self-contained HTML file with a JavaScript terminal emulator and
all Volatility outputs embedded.

### Optional: `start <name>` shell launcher

For convenience, run any CTF by name from the terminal:

```bash
# One-time setup (Linux/macOS)
source scripts/start.sh              # current shell only
echo 'source ~/path/to/scripts/start.sh' >> ~/.bashrc   # permanent

# Then:
start                                # list available CTFs
start MemLabs-Lab1                   # exact match
start memlabs                        # case-insensitive partial match
```

---

## How to Build Your Own CTFs

The CTFs in this repo were built using a Claude Code skill called
**`ctf-builder`** that automates: forensic analysis → ATT&CK mapping →
stage decomposition → HTML generation.

To build new CTFs from your own forensic artefacts:

1. **Install [Claude Code](https://claude.com/claude-code)** (or use the Claude Agent SDK)
2. **Copy the skill into your Claude config:**
   ```bash
   cp -r skill/ctf-builder ~/.claude/skills/
   ```
3. **Invoke the skill** with your case data:
   > "Build a CTF from my memory image at `/cases/<name>/` using the ctf-builder skill"

Claude will read the artefact, run the relevant forensic tools (Volatility,
Sleuth Kit, Plaso, etc.), map findings to ATT&CK, and produce the three
deliverables (report, CTF HTML, answer sheet).

> **Note:** Building new CTFs requires Claude Code or another LLM agent
> capable of running shell commands. Once built, the CTF HTMLs themselves
> are completely standalone and can be played without any AI.

---

## Required External Download — MemLabs Lab 1 Memory Image

The 1 GB memory image is **not committed to this repo** for size and
licensing reasons. Download it from the original source:

> **Source:** [stuxnet999/MemLabs — Lab 1](https://github.com/stuxnet999/MemLabs/tree/master/Lab%201)

```bash
# Manual: download MemLabs-Lab1.7z from the link above

# Extract:
mkdir -p cases/MemLabs-Lab1
7z x MemLabs-Lab1.7z -ocases/MemLabs-Lab1/
# → cases/MemLabs-Lab1/MemoryDump_Lab1.raw
```

**You do NOT need the memory image to play the CTF.** The CTF HTML has
all Volatility outputs pre-baked. The image is only needed if you want
to run your own commands against it on a real SIFT workstation, or to
validate the canned outputs.

---

## Repository Layout

```
.
├── README.md                       # this file
├── reports/
│   ├── MemLabs-Lab1-CTF.html       # play this
│   ├── MemLabs-Lab1-DFIR-Report.md # full investigation write-up
│   └── MemLabs-Lab1-AnswerSheet.md # junior-analyst training guide
├── skill/
│   └── ctf-builder/                # Claude Code skill to build more CTFs
│       ├── SKILL.md
│       └── templates/
├── scripts/
│   └── start.sh                    # portable CTF launcher
└── .gitignore
```

---

## What Each Deliverable Is For

| File | Audience | Purpose |
|------|----------|---------|
| `*-CTF.html` | Anyone | Interactive 60–90 min training session |
| `*-DFIR-Report.md` | IR analysts, mgmt | Defensible kill-chain narrative + ATT&CK mapping + remediation + Sigma rules |
| `*-AnswerSheet.md` | Junior analysts | Reasoning frameworks, decision trees, common pitfalls |

---

## Attribution

The CTF concept and ATT&CK kill-chain training methodology in this
repository are derivative educational content. The underlying forensic
challenges are owned by their original authors:

| Lab | Original Author | Source |
|-----|----------------|--------|
| MemLabs Lab 1 | **stuxnet999** | [github.com/stuxnet999/MemLabs](https://github.com/stuxnet999/MemLabs) |

If you create new CTFs from other publicly-available challenges, please
credit the original author here.

---

## License

The wrapper content (CTF HTML, DFIR report, answer sheet, ctf-builder skill,
launcher scripts) is released under **MIT License** for educational use.
Original challenge artefacts retain the licensing terms of their respective
upstream projects — see *Attribution* above.

---

## Contributing

PRs welcome — especially for:

- New CTFs built with the `ctf-builder` skill (must include attribution)
- Improvements to the terminal emulator (more commands, better grep)
- Detection rule contributions (Sigma, YARA) tied to specific ATT&CK techniques
- Translations of training material

When adding a new CTF, please ensure:

- [ ] No personal/proprietary data (PII, internal hostnames, real org names)
- [ ] Clear attribution if derived from a public challenge
- [ ] All three deliverables (HTML, report, answer sheet) are present
- [ ] Filename pattern `<name>-CTF.html` so the launcher finds it

---

*Built with [Claude Code](https://claude.com/claude-code) and the
`ctf-builder` skill — see `skill/ctf-builder/SKILL.md` for the
methodology.*
