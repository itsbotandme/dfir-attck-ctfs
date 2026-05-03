# The Black Window Case — Junior Analyst Training Guide

> **Attribution:** The memory image and case scenario for this lab are taken from **MemLabs Lab 1** by **stuxnet999** ([github.com/stuxnet999/MemLabs/tree/master/Lab%201](https://github.com/stuxnet999/MemLabs/tree/master/Lab%201)). The walkthrough, hypothesis-driven methodology, and ATT&CK reasoning in this guide are original training content.

> **Scenario:** *"My sister's computer crashed. We were very fortunate to recover this memory dump. Your job is to get all her important files from the system. From what we remember, we suddenly saw a black window pop up with something being executed. When the crash happened, she was trying to draw something. That's all we remember from the time of crash…"*

**Audience:** Junior DFIR analysts learning memory forensics and the ATT&CK kill chain method.
**Purpose:** Teach analytical thinking, not just answers. Read the reasoning before peeking at the solution.

---

## How a Real DFIR Analyst Approaches a Memory Image

Before any specific commands, internalise this: **you are not looking for a flag, you are reconstructing a story.** The flag-style questions in the CTF are scaffolding — in real life, the deliverable is the kill chain narrative in §3 of the report.

A senior analyst's mental model when handed a fresh memory image:

```
1. WHAT AM I LOOKING AT?           (system characterisation)
        ↓
2. WHO ELSE IS HERE?               (users, sessions)
        ↓
3. WHAT ARE THEY DOING?            (processes, command lines)
        ↓
4. WHAT'S NEW OR ABNORMAL?         (anomaly detection)
        ↓
5. HOW DID IT GET HERE?            (parent chains, file origins)
        ↓
6. WHAT WAS TAKEN OR CHANGED?      (collection, persistence)
        ↓
7. CAN I PROVE IT?                 (artefact corroboration)
        ↓
8. CAN I MAP IT?                   (ATT&CK kill chain)
```

Each numbered step maps to one or more ATT&CK tactics. Rather than running every Volatility plugin in a fixed order, you **pivot** as evidence directs you.

---

## Where to Start — The Triage Methodology

### The First Three Commands (always)

For any new Windows memory image, the first three commands are reflexive:

```bash
vol -f <image> windows.info       # WHAT (OS, build, capture time)
vol -f <image> windows.pslist     # WHO (active processes)
vol -f <image> windows.cmdline    # WHAT-RUNNING (with arguments)
```

These three give you ~80% of the situational awareness you need to form initial hypotheses. The fourth command depends on those three:

- If you saw **suspicious processes** → `windows.pstree` to understand parent chains.
- If you saw **multiple users** → `windows.envars --pid <PID>` to confirm account context.
- If you saw **possible network activity** → `windows.netscan`.
- If processes look clean but something feels off → `windows.malfind` for code injection.

### Why This Order?

A junior analyst's instinct is often to "run everything and search for keywords." This works in CTFs but fails in real incidents because:

1. **Some plugins take 5+ minutes** on large images. Running all of them up-front wastes time before you've formed a hypothesis.
2. **Output volumes are huge.** `windows.filescan` returns thousands of entries. Without a hypothesis, you don't know what to look at.
3. **The plugin you need depends on the question.** If you don't know the question, you don't know the plugin.

**Form a hypothesis first, then choose the plugin that confirms or refutes it.**

---

# Stage-by-Stage Walkthrough

Each stage below shows: the ATT&CK tactic, a *why-am-I-here* hypothesis, the commands to run, and the analytical thinking framework.

---

## Stage 1 — TA0007 Discovery (analyst recon, T1082)

### Hypothesis to test
*"What system am I dealing with? Until I know the OS, build, and capture time, I cannot pick the right tooling or interpret timestamps."*

### Commands
```bash
vol -f MemoryDump_Lab1.raw windows.info
```

### Answer
**Build: `7601.17514`**

### Why this answer matters
- **7601** = Windows 7 SP1 → WDigest cleartext credentials are enabled by default → LSASS plaintext extraction is feasible.
- **17514** = baseline RTM revision → not yet patched → known elevation/credential-access primitives are available.
- **AMD64** = 64-bit → use 64-bit Volatility symbol set; LSASS structures differ from 32-bit.

### Junior-analyst lesson
The OS build determines what attacks are *possible* and what artefacts will *exist*. On Win10/11, WDigest is disabled by default and LSASS contents are different. On a Server SKU, you would expect domain controller artefacts (NTDS.dit references, Kerberos tickets in lsass). The first plugin output sets your investigative priors.

---

## Stage 2 — TA0001 Initial Access (T1078 Valid Accounts)

### Hypothesis to test
*"Is this a single-user workstation behaving normally, or are multiple accounts active in unusual ways?"*

### Commands
```bash
vol -f MemoryDump_Lab1.raw windows.pslist
vol -f MemoryDump_Lab1.raw windows.pstree | grep explorer.exe
```

### Answer
**Two interactive sessions.** Session 1 = SmartNet, Session 2 = Alissa Simpson.

### Why this answer matters
On a single-user workstation, **two simultaneous interactive sessions is anomalous**. The candidate explanations are:
1. **Fast User Switching** — legitimate but uncommon
2. **RDP / Remote Desktop** — rare on workstations; needs network proof
3. **Lateral movement** — attacker used another account's credentials to open a parallel session
4. **runas / Pass-the-Hash** — privileged operator deliberately switching context

### How to disambiguate
- Run `windows.envars --pid <explorer_PID>` to confirm `USERNAME` and `USERDOMAIN` for each session.
- Pull the Security event log (4624 LogonType): LogonType 2 = console, 7 = unlock, 10 = RDP, 11 = cached credentials.
- Check `windows.netscan` for inbound RDP (3389) connections.

### Junior-analyst lesson
**Session anomalies are entry-point evidence.** When you find them, freeze the timestamp range and pivot to logon log analysis. Always disambiguate the *mechanism* — not just "two users", but "two users via X mechanism".

---

## Stage 3 — TA0002 Execution (T1059.003 Cmd Shell)

### Hypothesis to test
*"Did someone deliberately spawn a shell? If so, that's the moment of hands-on activity — pivot from that timestamp."*

### Commands
```bash
vol -f MemoryDump_Lab1.raw windows.pstree
vol -f MemoryDump_Lab1.raw windows.cmdline | grep cmd.exe
```

### Answer
**PID 1984** — cmd.exe spawned from explorer.exe (PID 604) with conhost.exe (PID 2692) attached.

### Why this answer matters
A `cmd.exe` *with conhost* means **interactive console I/O** — someone was typing. Without conhost, cmd may be a non-interactive child of a script. The pairing is your hands-on-keyboard signal.

### Decision tree for cmd.exe findings
```
Found cmd.exe?
├── Parent = explorer.exe? → Manual launch by user (likely interactive)
│       ├── conhost.exe attached? → Confirmed hands-on-keyboard
│       └── No conhost? → Possibly /c /q invocation; check parent
├── Parent = svchost / services? → Possible suspicious automation
├── Parent = unusual binary? → Strong tooling indicator (ex: chrome.exe → cmd.exe = potential exploitation)
└── Parent missing/dead? → Process hollowing / orphaned process — high concern
```

### Junior-analyst lesson
Process *parentage* is more useful than process *name*. Anyone can rename a binary; nobody can fake the kernel-recorded parent PID at creation time.

---

## Stage 4 — TA0005 Stealth (T1036.005 Masquerading)

> **ATT&CK v19 note (Apr 2026):** TA0005 was renamed *Defense Evasion → Stealth*. The "actively disable / degrade controls" half of the old tactic (T1562) is now a separate tactic, **Impair Defenses**. T1036.005 Masquerading is a stealth behaviour (blending in, not breaking controls), so it stays under TA0005.

### Hypothesis to test
*"Is the attacker hiding tools in plain sight by using legitimate directory locations?"*

### Commands
```bash
vol -f MemoryDump_Lab1.raw windows.filescan | grep -i \.bat
vol -f MemoryDump_Lab1.raw windows.filescan | grep System32
```

### Answer
**`St4G3$1.bat`** in `C:\Windows\System32\` (and a copy on SmartNet's Desktop).

### Why this answer matters
- `C:\Windows\System32\` should contain only signed Microsoft binaries. A `.bat` file there is virtually never legitimate.
- The leet-speak naming (`St4G3$1` = `Stage$1`) is amateur tradecraft but signals deliberate masquerading.
- Cross-reference with **RecentDocs**: SmartNet opened both `St4g3$1.bat` AND `St4g3$1.txt`. The `.txt` extension means Notepad — the script was *edited*, not just executed.

### How to confirm it's malicious
1. **Recover the file from disk** (`fls`/`icat` from MFT) — read the actual script content
2. **Check signing** — System32 batch files are obviously unsigned, but you can grep for `signtool` style metadata
3. **Compare to baseline** — Memory Baseliner against a clean Win7 SP1 image will surface this immediately as a non-baseline artefact
4. **Pivot on filename** — search the rest of the network for the same filename

### Junior-analyst lesson
**File location alone is an IOC.** A junior analyst learns to be suspicious not just of unusual filenames but of *unusual filenames in unusual locations*. A real Word document in `C:\Windows\Temp` is suspicious. A cmd.exe outside of System32 is suspicious. Place + name + extension form a triad.

---

## Stage 5 — TA0006 Credential Access (T1003.001 LSASS Memory)

### Hypothesis to test
*"Is there evidence the attacker harvested credentials, either by dumping LSASS or by extracting saved credentials?"*

### Commands
```bash
vol -f MemoryDump_Lab1.raw windows.filescan | grep -i passwd
vol -f MemoryDump_Lab1.raw windows.filescan | grep -i credential
vol -f MemoryDump_Lab1.raw windows.filescan | grep debug
```

### Answer
**`C:\Windows\debug\PASSWD.LOG`**

### Why this maps to T1003.001 (as a working hypothesis)
LSASS contains plaintext credentials in memory on this OS (Win7 SP1 with WDigest on by default). The artefacts visible in the image — a `PASSWD.LOG` file in `\Windows\debug\` plus DPAPI credential blobs touched in both user profiles — establish *credential-stealing intent*, not yet confirmed extraction.

What you can defensibly say from RAM alone: **"Two converging artefacts indicate an attempt at credential collection on this host. The mechanism (LSASS dump, manual credential file generation, or other) requires disk-side carving of `PASSWD.LOG` to confirm."**

### How to confirm
1. Recover `PASSWD.LOG` from disk and read it. Cleartext credentials? Hashes? Netlogon-style error log?
2. Check the Netlogon `DbFlag` registry value — if it was never enabled, this file is not a legitimate Netlogon log
3. Re-examine LSASS process state in memory — has its handle/memory been touched anomalously?

### Junior-analyst lesson
**"Working hypothesis" is a real verdict.** A junior analyst's instinct is to escalate to "T1003.001 confirmed" when they see `PASSWD.LOG`. The mature read is "T1003.001 hypothesised; one more step needed to confirm." That extra step is what separates a defensible report from a report that gets pulled apart in court / on a bridge call.

---

## Stage 6 — TA0009 Collection (T1560.001 Archive via Utility)

### Hypothesis to test
*"Has the attacker staged data for exfiltration? Archives are the classic vehicle."*

### Commands
```bash
vol -f MemoryDump_Lab1.raw windows.cmdline | grep -i rar
vol -f MemoryDump_Lab1.raw windows.handles --pid 1512
```

### Answer
**`Important.rar`** at `C:\Users\Alissa Simpson\Documents\Important.rar`.

### Why the path matters more than the name
The archive is named "Important.rar" — clearly suspicious naming. But the **truly damning** part is *whose* documents are being archived. WinRAR runs in **Alissa Simpson's session** (PID 2504 explorer parent), accessing **Alissa Simpson's** files.

If the SmartNet operator was performing legitimate work on their own files, this would be unremarkable. But:
- SmartNet was already logged in (Session 1)
- A second session (Session 2) appeared as Alissa Simpson 4 minutes after SmartNet's cmd.exe and credential-touching activity
- The same workstation now has WinRAR running in the second session

The most parsimonious explanation: SmartNet (or whoever controls SmartNet) opened a session as Alissa Simpson — likely with credentials extracted from earlier — to access Alissa's files specifically.

### Junior-analyst lesson
**Cross-account access patterns are powerful evidence of lateral access.** Always note the *acting account* vs. the *file owner*. They should usually match. When they don't, ask why.

---

## Stage 7 — TA0010 Exfiltration (channel hypothesis)

### Hypothesis to test
*"Important.rar is staged in another user's Documents. What carrier could have taken it off the host, and is there evidence the carrier was actually used?"*

### Commands
```bash
vol -f MemoryDump_Lab1.raw windows.netscan
vol -f MemoryDump_Lab1.raw windows.cmdline | grep -iE "ftp|curl|wget|bitsadmin|powershell"
```

### Answer
**TCP 445 (SMB)** is LISTENING on this host. There is no upload tool (`curl`, `bitsadmin`, PowerShell `Invoke-WebRequest`, etc.) running in `cmdline`.

### Why "channel available, transfer unconfirmed" is the right verdict
This is one of the most important lessons of memory forensics: **memory tells you what was running at the moment of capture, not what happened five minutes ago.** If exfiltration occurred and finished before the capture, you may see no trace of it in netscan.

What you CAN say from this image:
- A staged archive existed in Alissa Simpson's Documents (Stage 6)
- SMB (445) was exposed and could plausibly have been the carrier
- No active upload tool was running at capture time
- No ESTABLISHED outbound connection was present at capture time

What you CANNOT say from this image:
- Whether `Important.rar` actually left the host
- Whether the SMB channel was actually used
- Whether a removable USB or different vector was used

### Decision tree for "did the data leave?"
```
Important.rar exists on host
├── netscan shows ESTABLISHED outbound during the staging window? → likely yes, identify peer
├── netscan shows nothing but SMB exposed? → carrier available, pivot to firewall flow logs
├── prefetch / shellbags show USB attached? → consider removable media
└── nothing matches?  → state "exfiltration not confirmed from RAM; recommend disk + network log review"
```

### Junior-analyst lesson
**Absence of evidence is not evidence of absence — but it is reportable.** Saying *"I cannot confirm exfil from RAM alone — request firewall flow logs covering 14:30–14:38 UTC"* is a defensible analytical conclusion. Saying *"the data was exfiltrated"* with no transfer evidence is not.

---

## Stage 8 — Synthesis: ATT&CK Mapping

### Hypothesis to test
*"Can I express the attack story in ATT&CK terms that any other analyst will immediately understand?"*

### Final mapping (the deliverable)

```
TA0001 Initial Access      → T1078         Two simultaneous sessions
TA0002 Execution           → T1059.003     cmd.exe (the "black window") + St4G3$1.bat
TA0005 Stealth             → T1036.005     Bat file in System32
TA0006 Credential Access   → T1003.001     PASSWD.LOG + DPAPI blobs (intent; extraction unconfirmed)
TA0009 Collection          → T1560.001     WinRAR + Important.rar
TA0010 Exfiltration        → T1048         SMB exposed (channel available; transfer unconfirmed)
```

### Why ATT&CK matters in your career

When you write a report saying "the attacker dumped LSASS", that's correct but vague. When you write "T1003.001 OS Credential Dumping: LSASS Memory", every blue-teamer worldwide understands:
- The exact technique
- The standard detection rules (Sysmon EID 10 with `lsass.exe` target, `GrantedAccess` 0x1010, etc.)
- The mitigations (Credential Guard, Protected Process Light)
- The threat-intel context (which APT groups use this)

ATT&CK IDs are **the lingua franca of threat detection.** Get fluent.

---

## Common Pitfalls Junior Analysts Hit

1. **Running every plugin before forming a hypothesis.** Wastes hours. Form the question first.
2. **Trusting the file name.** `lsass.exe` in `\Users\Public\` is not lsass. Check the parent + path.
3. **Ignoring negative findings.** "No persistence in Run keys" is itself a finding — it tells you the attacker uses *other* persistence (scheduled tasks, services, WMI subscriptions, COM hijacks).
4. **Confusing acquisition timestamp with attack timestamp.** The image was captured at 14:38:00. The cmd.exe was created at 14:34:54. Different events, different windows.
5. **Reporting "found malware" without explaining harm.** A senior analyst always answers: *what could the attacker do with what they got?* Here: with the .raw file offsite, they get cleartext credentials → full domain compromise potential.
6. **Forgetting the kill chain.** Reporting T1003.001 alone is incomplete. The story needs Initial Access → Execution → Credential Access → Collection. Each stage has different mitigations.

---

## The Investigative Mindset — Final Notes

A great DFIR analyst is part historian, part detective, part scientist:

- **Historian:** reconstructs the sequence of events with citations to artefacts.
- **Detective:** notices the small inconsistencies, follows where they lead.
- **Scientist:** generates hypotheses, designs tests (queries, plugin runs), updates priors based on evidence.

For every observation, ask:
1. **What did I see?** (the raw artefact)
2. **What could it mean?** (multiple hypotheses, ranked by prior likelihood)
3. **What's most likely?** (the leading hypothesis given context)
4. **What would prove or disprove it?** (the next plugin/query/disk artefact to fetch)

Run that loop for every anomaly until you have a coherent story. Then map it to ATT&CK, write it down, and brief the team.

---

*This guide is grounded in real Volatility 3 output from `MemoryDump_Lab1.raw`. The reasoning patterns transfer to any Windows memory investigation.*
