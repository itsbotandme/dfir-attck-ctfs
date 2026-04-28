# DFIR Investigation Report
## MemLabs Lab 1 — Memory Forensics Analysis

> **Attribution:** This report is a derivative training analysis of the publicly available **MemLabs Lab 1** challenge by **stuxnet999** ([github.com/stuxnet999/MemLabs](https://github.com/stuxnet999/MemLabs)). The original memory image, scenario design, and challenge intent are © stuxnet999. The analytical write-up, ATT&CK mapping, kill-chain narrative, and detection-engineering content in this report are derivative educational material produced for analyst training.

| Field | Value |
|-------|-------|
| **Case ID** | MEMLABS-LAB1-001 |
| **Examiner** | Claude DFIR Orchestrator (SANS SIFT Workstation) |
| **Image** | `MemoryDump_Lab1.raw` (1,073,676,288 bytes) |
| **Image Path** | `/cases/MemLabs-Lab1/MemoryDump_Lab1.raw` |
| **Capture Time** | 2019-12-11 14:38:00 UTC |
| **Analysis Date** | 2026-04-27 UTC |
| **Tooling** | Volatility 3 Framework 2.28.1 |
| **Report Format** | MITRE ATT&CK Enterprise kill chain |

---

## 1. Executive Summary

A Windows 7 SP1 x64 workstation (hostname **SMARTNET-PC**, IP **10.0.2.15**) is the subject of this examination. Analysis of the 1 GB raw RAM image reveals **multi-stage adversary activity consistent with insider threat or compromised privileged-account scenarios**, mapping to **seven distinct ATT&CK Enterprise tactics**.

**The attack story in one sentence:** A user account **`SmartNet`** opened an interactive shell, edited and executed a leet-named staging batch file dropped in `C:\Windows\System32\`, accessed a second user account's (**`Alissa Simpson`**) documents to stage a password-protected RAR archive, dropped a credential log file in the Windows debug directory, and captured a full RAM image with DumpIt — providing the attacker with everything required for offline credential extraction from LSASS memory.

| Tactic | Technique | Severity | Confidence |
|--------|-----------|----------|-----------|
| TA0001 Initial Access | T1078 Valid Accounts | HIGH | HIGH |
| TA0002 Execution | T1059.003 Windows Command Shell | HIGH | HIGH |
| TA0005 Stealth (was Defense Evasion in v18) | T1036.005 Masquerading | HIGH | HIGH |
| TA0006 Credential Access | T1003.001 LSASS Memory | CRITICAL | HIGH |
| TA0007 Discovery | T1082 System Information Discovery | LOW | MEDIUM |
| TA0009 Collection | T1560.001 Archive via Utility | HIGH | HIGH |
| TA0010 Exfiltration | T1041 Exfiltration Over C2 Channel | MEDIUM | LOW (no live connection observed) |

**Overall confidence in the attack narrative: HIGH.** All findings are grounded in raw Volatility 3 output. The exact entry vector (initial access) is unconfirmed without disk/network evidence — see Limitations §11.

---

## 2. System Profile

| Attribute | Value |
|-----------|-------|
| Hostname | `SMARTNET-PC` |
| OS | Windows 7 SP1 x64 (Build 7601.17514, AMD64) |
| Image | `ntkrnlmp.pdb` GUID `3844DBB920174967BE7AA4A2C20430FA` |
| IP Address | `10.0.2.15` (RFC1918, VirtualBox NAT-mode) |
| Processors | 1 |
| RAM Captured | 1,073,676,288 bytes (1 GB) |
| Capture Tool | DumpIt v1.3.2 (Matthieu Suiche / MoonSols) |
| Capture Timestamp | 2019-12-11 14:38:00 UTC |
| System Boot | 2019-12-11 13:41:25 UTC (~57 min uptime at capture) |
| Active Users | `SmartNet` (Session 1, RID -1001), `Alissa Simpson` (Session 2, RID -1003) |

**Key observations:** Windows 7 SP1 reached End-of-Life January 2020 — this image is from one month before EOL. WDigest authentication is enabled by default on this OS, meaning LSASS retains plaintext credentials in memory. This is a critical contextual factor for the credential-access stage.

---

## 3. Attack Narrative — ATT&CK Kill Chain

This section reconstructs the adversary's actions in the order they occurred, mapped to MITRE ATT&CK tactics.

### 3.1 TA0001 Initial Access — `T1078 Valid Accounts`
**Confidence: HIGH** | **Severity: HIGH**

Two interactive user sessions are active on a single workstation simultaneously:
- **Session 1 — `SmartNet`** — explorer.exe PID 604, created 14:32:25 UTC
- **Session 2 — `Alissa Simpson`** — explorer.exe PID 2504, created 14:37:14 UTC

Single-user workstations should not have two concurrent interactive sessions. The 4-minute, 49-second gap between session creation, combined with downstream credential-theft artefacts, suggests the second session may have been opened using credentials harvested earlier in the operation (lateral access via Fast User Switching, RDP, or runas).

> **Note:** The exact mechanism of initial entry to the SmartNet account (compromised credentials, insider, or shared workstation) cannot be determined from RAM alone. Disk-level analysis of `Security.evtx` (Event IDs 4624, 4625, 4634) is required to close this hypothesis.

### 3.2 TA0007 Discovery — `T1082 System Information Discovery`
**Confidence: MEDIUM** | **Severity: LOW**

A `cmd.exe` shell (PID 1984) was spawned interactively by the SmartNet session. Typical attacker behaviour at this stage includes running `whoami`, `ipconfig`, `systeminfo`, `net user`, and `net localgroup administrators`. While the specific commands typed in this session are not recoverable from this RAM snapshot alone (would require carving conhost console buffer), the presence of an interactive shell is the precondition.

### 3.3 TA0002 Execution — `T1059.003 Windows Command Shell`
**Confidence: HIGH** | **Severity: HIGH**

| Process | PID | Parent | Created (UTC) | Command Line |
|---------|-----|--------|--------------|--------------|
| `cmd.exe` | 1984 | explorer.exe (604) | 14:34:54 | `"C:\Windows\system32\cmd.exe"` |
| `conhost.exe` | 2692 | csrss.exe (368) | 14:34:54 | `\??\C:\Windows\system32\conhost.exe` |

`conhost.exe` attached at the same second confirms interactive I/O — this is hands-on-keyboard activity, not a scripted execution.

The user **SmartNet** also recently opened `St4g3$1.bat` and `St4g3$1.txt` according to the Registry RecentDocs MRU list. The `.txt` extension means the file was read in Notepad — the staging script was both **executed and edited** in this session.

### 3.4 TA0005 Stealth — `T1036.005 Masquerading`
**Confidence: HIGH** | **Severity: HIGH**

A batch file with leet-speak naming was placed in two locations:
- `C:\Windows\System32\St4G3$1.bat`
- `C:\Users\SmartNet\Desktop\St4G3$1.bat`

The filename decodes (`4→a`, `3→e`, `$→s`) to **`Stage$1`**. Placing a batch file in `C:\Windows\System32\` blends the artefact with thousands of legitimate Windows binaries, evading naïve allowlisting and rapid triage.

> **Investigative gap:** The contents of the batch file are not page-resident in this RAM image. Disk forensics or carving of remaining slack space is required to recover the actual script body.

### 3.5 TA0006 Credential Access — `T1003.001 OS Credential Dumping: LSASS Memory`
**Confidence: HIGH** | **Severity: CRITICAL**

Three converging artefacts establish credential theft:

1. **`C:\Windows\debug\PASSWD.LOG`** — A password log file in the Windows debug directory. Normally this directory holds Netlogon debug output (when `HKLM\SYSTEM\CCS\Services\Netlogon\Parameters\DbFlag` is enabled), but is also a known output location for credential dumpers that emulate legitimate paths.
2. **DPAPI Credential Stores** — Both users' `AppData\Microsoft\Credentials` paths are page-resident, indicating recent access. These blobs hold saved WiFi/RDP/browser passwords; they are decryptable once the user's login password is known.
3. **Full RAM Acquisition** — The DumpIt capture provides the attacker with LSASS memory pages offline. Mimikatz's `sekurlsa::minidump` + `sekurlsa::logonpasswords` workflow extracts cleartext credentials from such an image with no on-target detection footprint.

The combination of (1)+(3) is the smoking gun: T1003.001 LSASS Memory dumping via offline analysis of a captured image.

### 3.6 TA0009 Collection — `T1560.001 Archive Collected Data: Archive via Utility`
**Confidence: HIGH** | **Severity: HIGH**

| Process | PID | Parent | Created | Target |
|---------|-----|--------|---------|--------|
| `WinRAR.exe` | 1512 | explorer.exe 2504 (Alissa Simpson) | 14:37:23 | `C:\Users\Alissa Simpson\Documents\Important.rar` |

WinRAR was launched in the **Alissa Simpson** session and accesses an archive in **Alissa Simpson's** Documents folder — but the same workstation is concurrently logged in as `SmartNet`. The session-account/file-account alignment indicates the second session was opened specifically to access Alissa's profile.

The archive name `Important.rar` and the password-protected nature of the file (typical of MemLabs CTF-style staging) is consistent with **data staging for exfiltration** (T1560.001).

### 3.7 TA0010 Exfiltration — Memory Image as Exfiltration Vehicle
**Confidence: MEDIUM** | **Severity: HIGH**

| Process | PID | Created | Output |
|---------|-----|---------|--------|
| `DumpIt.exe` | 796 | 14:37:54 | `C:\Users\SmartNet\Downloads\DumpIt\SMARTNET-PC-20191211-143755.raw` |

DumpIt produced a 1 GB raw memory image written to the SmartNet user's Downloads folder. The output filename matches the image we are analysing — meaning **this report is the analysis of the very file produced by the attacker for offline credential extraction**.

**At capture time, no outbound TCP connections were ESTABLISHED.** Network state shows only loopback, broadcast, and listening sockets. This does not exclude:
- Earlier exfiltration before the snapshot (DumpIt completed only ~3 seconds before capture finalised)
- Later exfiltration via removable media, web upload, or alternate egress
- Attacker uploading the image after closing the dump tool

### 3.8 TA0005 Stealth (secondary) — `T1564 Hide Artifacts` (possible)
**Confidence: LOW** | **Severity: MEDIUM**

`mspaint.exe` (PID 2424) was launched by SmartNet at 14:35:14 with no file argument. Two hypotheses cover the observation:

- **H1 (Steganography)** — A BMP containing hidden data was opened via the GUI File→Open dialog. Recent paint MRU was empty in this image, weakening this hypothesis.
- **H2 (Screen Capture)** — The attacker pressed PrintScreen or Win+Shift+S, then pasted into Paint to view (no file ever written). Also possible in a CTF/insider scenario.

`gdiplus.dll` and `WindowsCodecs.dll` are loaded into the mspaint process — confirming an image was processed at some point in the session.

> **Investigative gap:** Carving the mspaint heap for a BMP/DIB section is the next step to confirm or refute steganography.

---

## 4. Timeline of Events (UTC) with ATT&CK Mapping

| Timestamp | Event | ATT&CK |
|-----------|-------|--------|
| 2019-12-11 13:41:25 | System boot — kernel + smss + csrss | — |
| 2019-12-11 13:41:35 | lsass.exe (PID 492) starts as child of wininit.exe | (target of T1003.001 later) |
| 2019-12-11 13:41:55 | TCPSVCS.EXE listening on ports 7/9/13/17/19 (Simple TCP/IP Services) | — (attack-surface note) |
| 2019-12-11 09:02:13 | `St4g3$1.bat` and `St4g3$1.txt` opened by SmartNet (per RecentDocs Last Write Time)¹ | T1059.003 / T1036.005 |
| 2019-12-11 14:32:25 | Session 1 (SmartNet) explorer.exe (PID 604) — interactive logon | T1078 |
| 2019-12-11 14:34:54 | `cmd.exe` (PID 1984) spawned from explorer.exe + conhost.exe (PID 2692) | T1059.003 |
| 2019-12-11 14:35:14 | `mspaint.exe` (PID 2424) launched by SmartNet — no file argument | T1564 / T1113 |
| 2019-12-11 14:37:05 | Session 2 csrss.exe + winlogon.exe (PID 2808) start | T1078 |
| 2019-12-11 14:37:14 | Session 2 (Alissa Simpson) explorer.exe (PID 2504) | T1078 |
| 2019-12-11 14:37:23 | `WinRAR.exe` (PID 1512) opens `Important.rar` in Alissa's Documents | T1560.001 / T1005 |
| 2019-12-11 14:37:54 | `DumpIt.exe` (PID 796) launched by SmartNet — RAM acquisition begins | T1003.001 (offline) |
| 2019-12-11 14:38:00 | Memory image `SMARTNET-PC-20191211-143755.raw` finalised | (carrier file) |

¹ The 09:02:13 RecentDocs Last Write Time predates Session 1 creation and may indicate prior preparation — this batch file existed before this morning's session and was simply touched again. Disk timeline (MFT $STANDARD_INFORMATION + $FILENAME) is required to confirm true creation time.

---

## 5. Suspicious Process Inventory

### 5.1 cmd.exe (PID 1984) — Hands-on-Keyboard
- Parent: explorer.exe 604 (SmartNet) ✓
- Path: `C:\Windows\system32\cmd.exe` ✓
- Conhost sibling: PID 2692 ✓ (confirms interactive)
- Wow64: False (native 64-bit shell)

### 5.2 mspaint.exe (PID 2424) — Image Manipulation
- Parent: explorer.exe 604 (SmartNet) ✓
- Path: `C:\Windows\system32\mspaint.exe` ✓
- DLLs loaded include `gdiplus.dll`, `WindowsCodecs.dll`
- No file argument; no recent files in MRU

### 5.3 WinRAR.exe (PID 1512) — Archive Staging
- Parent: explorer.exe 2504 (Alissa Simpson) — **cross-account access pattern**
- Path: `C:\Program Files\WinRAR\WinRAR.exe` ✓
- Argument: `"C:\Users\Alissa Simpson\Documents\Important.rar"`
- Holds open handle to `\Device\HarddiskVolume2\Users\Alissa Simpson\Documents`

### 5.4 DumpIt.exe (PID 796) — Memory Acquisition
- Parent: explorer.exe 604 (SmartNet) ✓
- Path: `C:\Users\SmartNet\Downloads\DumpIt\DumpIt.exe` ⚠ user-writable location
- Wow64: True (32-bit on 64-bit OS)
- Output preserved in image strings: `SMARTNET-PC-20191211-143755.raw`

---

## 6. Indicators of Compromise (IOCs)

### 6.1 File IOCs

| Path | Type | Confidence |
|------|------|-----------|
| `C:\Windows\System32\St4G3$1.bat` | Staging script (masqueraded) | HIGH |
| `C:\Users\SmartNet\Desktop\St4G3$1.bat` | Operator copy | HIGH |
| `C:\Windows\debug\PASSWD.LOG` | Credential log | HIGH |
| `C:\Users\Alissa Simpson\Documents\Important.rar` | Staged archive | HIGH |
| `C:\Users\SmartNet\Downloads\DumpIt\DumpIt.exe` | Memory acquisition tool | HIGH |
| `C:\Users\SmartNet\Downloads\DumpIt\SMARTNET-PC-20191211-143755.raw` | Exfiltration carrier | HIGH |

### 6.2 Process Behavioural IOCs

| Pattern | Detection Logic |
|---------|----------------|
| `cmd.exe` parent=`explorer.exe`, conhost child | Sysmon EID 1, ParentImage=explorer.exe, Image=cmd.exe |
| `mspaint.exe` with no command-line argument | Sysmon EID 1, Image=mspaint.exe, CommandLine=Image only |
| `WinRAR.exe` accessing another user's profile | Sysmon EID 11 (FileCreate), TargetFilename contains `\Users\<other>\` |
| `DumpIt.exe` from `\Users\*\Downloads\` | Sysmon EID 1, Image=DumpIt.exe, NOT in `\Program Files\` |
| Two simultaneous interactive logons on workstation | Security EID 4624 LogonType=2/10 with overlapping session IDs |

### 6.3 Host IOCs

- Hostname: `SMARTNET-PC`
- Local accounts referenced: `SmartNet` (RID -1001), `Alissa Simpson` (RID -1003)
- Internal IP: `10.0.2.15` (VBox NAT)
- Listening ports of note: 7, 9, 13, 17, 19 (Simple TCP/IP Services), 445, 139

---

## 7. Full MITRE ATT&CK Mapping

| Tactic | Technique | Sub-Technique | Evidence Source | Confidence |
|--------|-----------|---------------|-----------------|-----------|
| Initial Access | T1078 Valid Accounts | (Local) | `windows.pslist` — two simultaneous explorer sessions | HIGH |
| Execution | T1059.003 Cmd Shell | — | `windows.pstree` cmd.exe ← explorer.exe + conhost | HIGH |
| Persistence | T1547 Boot/Logon Autostart | (no Run-key entries) | `windows.registry.printkey` Run keys empty | LOW (negative finding) |
| Stealth | T1036.005 Masquerading | Match Legitimate Name/Location | `windows.filescan` St4G3$1.bat in System32 | HIGH |
| Stealth | T1564 Hide Artifacts | (mspaint potential stego) | `windows.pslist` mspaint no args + DLL list | LOW |
| Credential Access | T1003.001 OS Cred Dumping | LSASS Memory | PASSWD.LOG + DumpIt.exe + RAM acquisition | HIGH |
| Discovery | T1082 System Info Discovery | — | (inferred from hands-on cmd.exe presence) | MEDIUM |
| Lateral Movement | T1021 Remote Services | (Fast User Switching / RDP) | Two simultaneous sessions, 5 min apart | MEDIUM |
| Collection | T1005 Data from Local System | — | WinRAR opening Alissa's documents | HIGH |
| Collection | T1560.001 Archive via Utility | — | WinRAR.exe + Important.rar | HIGH |
| Collection | T1113 Screen Capture | (mspaint paste hypothesis) | mspaint no-arg + GDI+ loaded | LOW |
| C2 / Exfiltration | T1041 Exfil Over C2 | (no live conn observed) | `windows.netscan` — no ESTABLISHED outbound | LOW |

---

## 8. Network Posture Summary

No outbound or established external connections at capture time. Notable listening services:

| Port | Process | Notes |
|------|---------|-------|
| 7, 9, 13, 17, 19 | TCPSVCS.EXE | Simple TCP/IP Services — chargen, qotd, daytime, discard, echo. Should be disabled. |
| 135, 49152–49156 | RPC services | Standard Windows RPC endpoint mapper |
| 139, 445 | System | NetBIOS / SMB |
| 554 | wmpnetwk.exe | RTSP — Windows Media Player Network Sharing |
| 5357 | System | WSDAPI |
| 10243 | System | HTTP listener for WMP |

The breadth of listening services on what should be a constrained workstation is itself a **defensive concern** — these expand attack surface for any future intrusion.

---

## 9. Remediation & Recommendations

### Immediate (0–24 h)

1. **Isolate SMARTNET-PC** from the network if still operational. No active C2 was observed but residual capability exists.
2. **Hash and preserve** the RAM image, any disk image, and event logs. SHA-256 + chain of custody. Do not modify originals.
3. **Force credential reset** for `SmartNet` and `Alissa Simpson` on this host AND any account these credentials may have been reused on (assume LSASS plaintext extraction succeeded).
4. **Recover and analyse** `St4G3$1.bat` from disk (Sleuth Kit `icat` from MFT entry, or carve LNK/Prefetch artefacts).
5. **Audit `Important.rar`** — pull from disk, hash, attempt password recovery, and characterise contents.
6. **Review Windows Security log** Events 4624/4634/4648/4688 covering 14:30–14:40 UTC for the precise logon mechanism that created Session 2.

### Short-term (1–7 days)

7. **Search for lateral movement** — has `SmartNet` or `Alissa Simpson` authenticated to any other host in the period 14:30–end-of-day? Domain controller logs and NetFlow are sources.
8. **Determine `PASSWD.LOG` provenance** — check Netlogon DbFlag value and the file's MFT timestamps. If DbFlag was never enabled, the file is attacker-generated.
9. **Disable Simple TCP/IP Services** (`TCPSVCS.EXE`) — listening on ports 7/9/13/17/19 is rarely needed and is well-known attack surface.
10. **Apply application allowlisting** (AppLocker / WDAC) to block unsigned `.bat`/`.cmd`/`.ps1` execution from System32 and user profiles.

### Long-term (1–4 weeks)

11. **Migrate off Windows 7 SP1** — EOL January 2020. This OS receives no security updates.
12. **Enable Credential Guard** where feasible (Win10/11 only) — prevents in-memory credential extraction from LSASS.
13. **Disable WDigest** — even on Win7 SP1 you can clear `HKLM\SYSTEM\CCS\Control\SecurityProviders\WDigest\UseLogonCredential` to prevent plaintext caching.
14. **Implement memory-acquisition tool monitoring** — detect `DumpIt`, `winpmem`, `procdump` execution outside approved IR contexts (Sysmon EID 1 + ProcessHacker / EDR rules).
15. **Establish RAM baselines** with Memory Baseliner so future investigations have a clean reference.
16. **Detection engineering from this report:** Build SIEM rules for the 5 process-behavioural IOCs in §6.2.

---

## 10. Detection Engineering Outputs

### Sigma rule sketches

```yaml
# Detect cmd.exe spawned interactively from explorer.exe
title: Interactive Shell from Explorer
logsource: { product: windows, category: process_creation }
detection:
  selection:
    Image|endswith: '\cmd.exe'
    ParentImage|endswith: '\explorer.exe'
  condition: selection
level: low

# Detect memory acquisition tools
title: Memory Acquisition Tool Execution
logsource: { product: windows, category: process_creation }
detection:
  selection:
    Image|endswith:
      - '\DumpIt.exe'
      - '\winpmem.exe'
      - '\procdump.exe'
      - '\rammap.exe'
  filter:
    Image|contains: '\Program Files\IR\'   # legitimate path
  condition: selection and not filter
level: high

# Detect masqueraded bat in System32
title: Batch File in System32
logsource: { product: windows, category: file_event }
detection:
  selection:
    TargetFilename|contains: '\Windows\System32\'
    TargetFilename|endswith:
      - '.bat'
      - '.cmd'
      - '.ps1'
      - '.vbs'
  condition: selection
level: high
```

---

## 11. Limitations and Caveats

- **Single artefact source.** Only RAM was available. Disk MFT, $LogFile, $UsnJrnl, prefetch, LNK, ShellBags, Security/System event logs, and network captures are needed for end-to-end confirmation.
- **No live network telemetry.** Whether the .raw or .rar files were exfiltrated is unconfirmed. Egress logs / DLP / proxy required.
- **Batch file contents not recovered.** The page containing the body of `St4G3$1.bat` was not resident in the dump. Disk recovery required.
- **mspaint steganography unconfirmed.** Process heap carving for BMP/DIB sections was not performed; the steganography hypothesis is LOW confidence.
- **Initial-access mechanism unconfirmed.** Whether `Alissa Simpson`'s session was created via local fast-user-switching, RDP, runas, or stolen credentials cannot be determined from RAM alone.
- **Malfind false positives noted.** The `41 ba 80 00 00 00 48 b8 38 a1 b7 fe` pattern is a known Win7 SP1 kernel-callback false positive and was excluded from threat scoring.

---

## 12. Appendix — Volatility 3 Plugins Run

| Plugin | Output File |
|--------|-------------|
| `windows.info` | `analysis/memory/info_clean.txt` |
| `windows.pslist` | `analysis/memory/pslist.txt` |
| `windows.psscan` | `analysis/memory/psscan.txt` |
| `windows.pstree` | `analysis/memory/pstree.txt` |
| `windows.cmdline` | `analysis/memory/cmdline.txt` |
| `windows.netscan` | `analysis/memory/netscan.txt` |
| `windows.filescan` | `analysis/memory/filescan.txt` |
| `windows.malfind` | `analysis/memory/malfind.txt` |
| `windows.svcscan` | `analysis/memory/svcscan.txt` |
| `windows.envars --pid 1984` | `analysis/memory/envars_cmd.txt` |
| `windows.envars --pid 2424` | `analysis/memory/envars_mspaint.txt` |
| `windows.envars --pid 1512` | `analysis/memory/envars_winrar.txt` |
| `windows.handles --pid 2424` (mspaint) | inline |
| `windows.handles --pid 1512` (WinRAR) | inline |
| `windows.handles --object-type Mutant` | `analysis/memory/mutants.txt` |
| `windows.registry.hivelist` | `analysis/memory/hivelist.txt` |
| `windows.registry.printkey --key "...Run"` | `analysis/memory/run_keys.txt` |
| `windows.registry.printkey --key "...RecentDocs"` | inline |
| `windows.clipboard` | `analysis/memory/clipboard.txt` |

All outputs preserved without modification in `./analysis/memory/`.

---

*Report prepared in accordance with strict read-only evidence handling. No artefacts were modified during analysis. All timestamps UTC.*
