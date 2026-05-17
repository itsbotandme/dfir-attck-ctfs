# The Black Window Case — Junior Analyst Walkthrough

> **Attribution:** The memory image and case scenario for this lab are taken from **MemLabs Lab 1** by **stuxnet999** ([github.com/stuxnet999/MemLabs/tree/master/Lab%201](https://github.com/stuxnet999/MemLabs/tree/master/Lab%201)). The walkthrough, hypothesis-driven methodology, and ATT&CK reasoning in this guide are original training content.

> **Scenario:** *"My sister's computer crashed. We were very fortunate to recover this memory dump. Your job is to get all her important files from the system. From what we remember, we suddenly saw a black window pop up with something being executed. When the crash happened, she was trying to draw something. That's all we remember from the time of crash…"*

---

# Stage-by-Stage Walkthrough

## Stage 1 — What am I looking at?

**Hypothesis.** *What system am I dealing with? OS, build, and capture time set every other interpretation.*

**Plugin.** `windows.info` — returns OS, kernel, build, and capture timestamp in one call.

**Command.**
```bash
vol -f MemoryDump_Lab1.raw windows.info
```

**Finding.** Build `7601.17514` = Windows 7 SP1 x64, captured 2019-12-11 14:38:00 UTC.

**Why it matters.**
- 7601 = Win7 SP1 → WDigest enabled by default → LSASS plaintext extraction is feasible.
- 17514 = baseline RTM revision → not yet patched.
- AMD64 → use the 64-bit Volatility symbol set; LSASS structures differ from 32-bit.

**ATT&CK.** T1082 System Information Discovery — querying basic OS metadata is exactly what T1082 names.

**Lesson.** The OS build determines what attacks are *possible* and what artefacts will *exist*. The first plugin output sets the priors for everything that follows.

---

## Stage 2 — Who else is here?

**Hypothesis.** *Is this a single-user workstation behaving normally, or are multiple accounts active in unusual ways?*

**Plugin.** `windows.pslist` (and `windows.pstree` for hierarchy) — every interactive Windows session has its own `explorer.exe` with a distinct SessionId.

**Command.**
```bash
vol -f MemoryDump_Lab1.raw windows.pslist
vol -f MemoryDump_Lab1.raw windows.pstree | grep explorer.exe
```

**Finding.** Two interactive sessions: Session 1 = `SmartNet` (explorer PID 604, 14:32:25 UTC), Session 2 = `Alissa Simpson` (explorer PID 2504, 14:37:14 UTC). Five-minute gap.

**Why it matters.** On a single-user workstation, two simultaneous interactive sessions is anomalous. Candidate explanations:

1. **Fast User Switching** — legitimate but uncommon.
2. **RDP** — rare on workstations; needs network proof.
3. **Lateral movement** — credentials stolen and used to open a parallel session.
4. **runas / Pass-the-Hash** — privileged operator switching context.

**Disambiguating.**
- `windows.envars --pid <explorer_PID>` confirms `USERNAME` per session.
- Security event log 4624 LogonType: 2 = console, 7 = unlock, 10 = RDP, 11 = cached credentials.
- `windows.netscan` for inbound RDP (3389) connections.

**ATT&CK.** T1078 Valid Accounts (Local) — accessing the system using a legitimate account rather than exploiting a vulnerability.

**Lesson.** Session anomalies are entry-point evidence. Always disambiguate the *mechanism* — not just "two users", but "two users via X mechanism".

---

## Stage 3 — What spawned from the desktop?

**Hypothesis.** *Did someone deliberately spawn a shell? If so, that's the moment of hands-on activity — pivot from that timestamp.*

**Plugin.** `windows.pstree` shows parent-child relationships; `windows.cmdline` shows what was typed at each process's launch.

**Command.**
```bash
vol -f MemoryDump_Lab1.raw windows.pstree
vol -f MemoryDump_Lab1.raw windows.cmdline | grep cmd.exe
```

**Finding.** PID 1984 — `cmd.exe` spawned from `explorer.exe` (PID 604) with `conhost.exe` (PID 2692) attached at the same second. Created 2019-12-11 14:34:54 UTC.

**Why it matters.** A `cmd.exe` *with conhost* means interactive console I/O — someone was typing. Without conhost, cmd may be a non-interactive child of a script. The pairing is your hands-on-keyboard signal.

**Decision tree for cmd.exe findings.**
```
Found cmd.exe?
├── Parent = explorer.exe? → Manual launch by user (likely interactive)
│       ├── conhost.exe attached? → Confirmed hands-on-keyboard
│       └── No conhost? → Possibly /c /q invocation; check parent
├── Parent = svchost / services? → Possible suspicious automation
├── Parent = unusual binary? → Strong tooling indicator (e.g. chrome.exe → cmd.exe = potential exploitation)
└── Parent missing/dead? → Process hollowing / orphaned process — high concern
```

**ATT&CK.** T1059.003 Windows Command Shell — interactive cmd.exe spawned from explorer.exe with paired conhost.exe is the textbook fingerprint.

**Lesson.** Process *parentage* is more useful than process *name*. Anyone can rename a binary; nobody can fake the kernel-recorded parent PID at creation time.

---

## Stage 4 — A file where it doesn't belong?

> **ATT&CK v19 note (Apr 2026):** TA0005 was renamed *Defense Evasion → Stealth*. The T1562 *Impair Defenses* family (actively disabling or degrading security controls) was promoted to its own tactic, **TA0112 Defense Impairment**. T1562 still exists as a technique — it now lives under TA0112. T1036.005 Masquerading is a stealth behaviour (blending in, not breaking controls), so it stays under TA0005.

**Hypothesis.** *Is the attacker hiding tools in plain sight by using legitimate directory locations?*

**Plugin.** `windows.filescan` — walks the file object pool. Pipe to `grep` to filter by extension or path.

**Command.**
```bash
vol -f MemoryDump_Lab1.raw windows.filescan | grep -i \.bat
vol -f MemoryDump_Lab1.raw windows.filescan | grep System32
```

**Finding.** `St4G3$1.bat` in `C:\Windows\System32\` (and a copy on SmartNet's Desktop).

**Why it matters.**
- `C:\Windows\System32\` should contain only signed Microsoft binaries. A `.bat` file there is virtually never legitimate.
- Leet-speak naming (`St4G3$1` = `Stage$1`) is amateur tradecraft but signals deliberate masquerading.
- Cross-reference with **RecentDocs**: SmartNet opened both `St4g3$1.bat` AND `St4g3$1.txt`. The `.txt` extension means Notepad — the script was *edited*, not just executed.

**Confirming.** Recover the file from disk (Sleuth Kit `icat` from MFT) — read the actual script body. Compare against a clean Win7 SP1 baseline (Memory Baseliner). Pivot on the filename across the network.

**ATT&CK.** T1036.005 Masquerading: Match Legitimate Name or Location — naming or placing a file to blend with legitimate OS components.

**Lesson.** File *location* is itself an IOC. Be suspicious of unusual filenames in unusual locations. Place + name + extension form a triad — any one of them out of pattern warrants a second look.

---

## Stage 5 — Were credentials at risk?

**Hypothesis.** *Is there evidence the attacker harvested credentials, either by dumping LSASS or by extracting saved credentials?*

**Plugin.** `windows.filescan` — pipe to `grep` for credential-related filename patterns.

**Command.**
```bash
vol -f MemoryDump_Lab1.raw windows.filescan | grep -i passwd
vol -f MemoryDump_Lab1.raw windows.filescan | grep -i credential
```

**Finding.** `C:\Windows\debug\PASSWD.LOG`. DPAPI credential blob paths in both user profiles are page-resident.

**Why "working hypothesis" not "confirmed".** LSASS contains plaintext credentials in memory on this OS (Win7 SP1 with WDigest on by default). The PASSWD.LOG + DPAPI blob access establish *credential-stealing intent* — not yet confirmed extraction. What you can defensibly say from RAM alone:

> "Two converging artefacts indicate an attempt at credential collection on this host. The mechanism (LSASS dump, manual credential file generation, or other) requires disk-side carving of `PASSWD.LOG` to confirm."

**Confirming.**
1. Recover `PASSWD.LOG` from disk and read it (cleartext credentials? hashes? Netlogon-style error log?).
2. Check the Netlogon `DbFlag` registry value — if it was never enabled, the file is not a legitimate Netlogon log.
3. Re-examine LSASS process state in memory — has its handle/memory been touched anomalously?

**ATT&CK.** T1003.001 OS Credential Dumping: LSASS Memory — credential log + DPAPI blob access in user profiles is the behavioural signature T1003.001 covers; on Win7 SP1 with WDigest on by default, it's the technique attackers reach for.

**Lesson.** "Working hypothesis" is a real verdict. The mature read of `PASSWD.LOG` is "T1003.001 hypothesised; one more step needed to confirm." That extra step separates a defensible report from one that gets pulled apart on a bridge call.

---

## Stage 6 — Was data being staged?

**Hypothesis.** *Has the attacker staged data for exfiltration? Archives are the classic vehicle.*

**Plugin.** `windows.cmdline` filtered for archive-tool patterns; `windows.handles --pid <archiver>` to confirm the file is open and see the user-context.

**Command.**
```bash
vol -f MemoryDump_Lab1.raw windows.cmdline | grep -i rar
vol -f MemoryDump_Lab1.raw windows.handles --pid 1512
```

**Finding.** `Important.rar` at `C:\Users\Alissa Simpson\Documents\`. WinRAR (PID 1512) launched in Alissa's session, opening her own Documents folder.

**Why the path matters more than the name.** "Important.rar" is suspicious naming, but the damning part is *whose* documents are being archived. WinRAR runs in **Alissa Simpson's session** (parent explorer PID 2504), accessing **Alissa Simpson's** files — while SmartNet is also logged in (Session 1) and was the one who triggered cmd.exe and credential-touching activity 4 minutes earlier. Most parsimonious explanation: SmartNet (or whoever controls SmartNet) opened a session as Alissa to access her files specifically.

**ATT&CK.** T1560.001 Archive Collected Data: Archive via Utility — using a third-party archiver (WinRAR / 7-zip / tar) to bundle data for exfil.

**Lesson.** Cross-account access patterns are powerful evidence of lateral access. Always note the *acting account* vs. the *file owner*. They should usually match. When they don't, ask why.

---

## Stage 7 — Could it have left the host?

**Hypothesis.** *`Important.rar` is staged. What carrier could have taken it off the host, and is there evidence the carrier was actually used?*

**Plugin.** `windows.netscan` for active connections + listening sockets; `windows.cmdline` for upload tools.

**Command.**
```bash
vol -f MemoryDump_Lab1.raw windows.netscan
vol -f MemoryDump_Lab1.raw windows.cmdline | grep -iE "ftp|curl|wget|bitsadmin|powershell"
```

**Finding.** TCP 445 (SMB) is LISTENING. No upload tool (curl, bitsadmin, PowerShell `Invoke-WebRequest`) running in `cmdline`. No ESTABLISHED outbound connection at capture time.

**Why "channel available, transfer unconfirmed".** Memory tells you what was running at the moment of capture, not what happened five minutes ago. If exfil happened and finished before the capture, no trace appears in `netscan`.

What you CAN say:
- A staged archive existed in Alissa Simpson's Documents (Stage 6).
- SMB (445) was exposed and could plausibly be the carrier.
- No active upload tool was running at capture time.
- No ESTABLISHED outbound connection at capture time.

What you CANNOT say:
- Whether `Important.rar` actually left the host.
- Whether the SMB channel was actually used.
- Whether removable media or another vector was used.

**Decision tree for "did the data leave?".**
```
Important.rar exists on host
├── netscan shows ESTABLISHED outbound during the staging window? → likely yes, identify peer
├── netscan shows nothing but SMB exposed? → carrier available, pivot to firewall flow logs
├── prefetch / shellbags show USB attached? → consider removable media
└── nothing matches? → state "exfiltration not confirmed from RAM; recommend disk + network log review"
```

**ATT&CK.** T1048 Exfiltration Over Alternative Protocol — covers exfil over non-C2 channels (SMB, FTP, DNS); SMB on 445 is one such channel. Mapping this stage to T1048 documents *channel availability*, not confirmed transfer — and that distinction is the finding.

**Lesson.** Absence of evidence is not evidence of absence — but it IS reportable. *"I cannot confirm exfil from RAM alone — request firewall flow logs covering 14:30–14:38 UTC"* is a defensible analytical conclusion. Saying *"the data was exfiltrated"* with no transfer evidence is not.

---

## Stage 8 — Map your findings to ATT&CK

**Hypothesis.** *Can I express the attack story in ATT&CK terms that any other analyst will immediately understand?*

**Synthesis (the deliverable):**
```
TA0001 Initial Access      → T1078         Two simultaneous sessions
TA0002 Execution           → T1059.003     cmd.exe ("the black window") + St4G3$1.bat
TA0005 Stealth             → T1036.005     Bat file in System32
TA0006 Credential Access   → T1003.001     PASSWD.LOG + DPAPI blobs (intent; extraction unconfirmed)
TA0009 Collection          → T1560.001     WinRAR + Important.rar
TA0010 Exfiltration        → T1048         SMB exposed (channel; transfer unconfirmed)
```

**Why ATT&CK matters in your career.** When you write "the attacker dumped LSASS", that's correct but vague. When you write "T1003.001 OS Credential Dumping: LSASS Memory", every blue-teamer worldwide understands the technique, the standard detection rules (Sysmon EID 10 with `lsass.exe` target, `GrantedAccess` 0x1010), the mitigations (Credential Guard, Protected Process Light), and the threat-intel context.

**Lesson.** ATT&CK IDs are the lingua franca of threat detection. Get fluent.

---

## Common Pitfalls Junior Analysts Hit

1. **Running every plugin before forming a hypothesis.** Wastes hours. Form the question first.
2. **Trusting the file name.** `lsass.exe` in `\Users\Public\` is not lsass. Check the parent + path.
3. **Ignoring negative findings.** "No persistence in Run keys" is itself a finding — it tells you the attacker uses *other* persistence (scheduled tasks, services, WMI subscriptions, COM hijacks).
4. **Confusing capture time with attack time.** The image was captured at 14:38:00. The cmd.exe was created at 14:34:54. Different events, different windows.
5. **Reporting "found malware" without explaining harm.** A senior analyst answers: *what could the attacker do with what they got?* Here: with the .raw file offsite, they get cleartext credentials → full domain compromise potential.
6. **Forgetting the kill chain.** Reporting T1003.001 alone is incomplete. The story needs Initial Access → Execution → Credential Access → Collection. Each stage has different mitigations.

---

## The Investigative Mindset

For every observation, run the loop:

1. **What did I see?** (the raw artefact)
2. **What could it mean?** (multiple hypotheses, ranked by prior likelihood)
3. **What's most likely?** (the leading hypothesis given context)
4. **What would prove or disprove it?** (the next plugin / query / disk artefact to fetch)

Repeat for every anomaly until you have a coherent story. Then map it to ATT&CK, write it down, and brief the team.
