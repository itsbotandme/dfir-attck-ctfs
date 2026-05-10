# DFIR Investigation Report
## <CASE TITLE> — <Artefact Type> Analysis

> **Attribution:** <One paragraph crediting the artefact source if derivative. Mark the analytical write-up, ATT&CK mapping, kill-chain narrative, and detection-engineering content as original. Per SKILL.md §18.>

> **Scenario (from the original):** *"<verbatim source-of-truth quote, if one exists. Drop the parenthetical if there's no original to cite.>"*

| Field | Value |
|-------|-------|
| **Case ID** | <CASEID-NNN> |
| **Image** | `<filename>` (<size in bytes>) |
| **Capture Time** | <UTC timestamp> |
| **Analysis Date** | <UTC timestamp> |
| **Tooling** | <tool + version> |
| **Report Format** | MITRE ATT&CK Enterprise kill chain |

---

## 1. Executive Summary

<One paragraph: who/what/when/how, in plain English. Name the host, OS, IP if relevant. State the headline behaviour and the number of distinct ATT&CK tactics observed.>

**Headline finding.** <One paragraph stating the kill chain in narrative form. Name the actor account(s), the artefact(s) of interest, and the channel(s) used. Be honest about what's confirmed vs. inferred — flag any "viable but unconfirmed" channels explicitly.>

| Tactic | Technique | Severity | Confidence |
|--------|-----------|----------|-----------|
| TA####  Name | T####.### Name | CRIT/HIGH/MED/LOW | HIGH/MED/LOW |
| ... | ... | ... | ... |

**Overall confidence in the attack narrative: <HIGH/MED/LOW>.** <One sentence on what would raise or lower confidence.>

---

## 2. System Profile

<Table of identifying characteristics — hostname, OS build, architecture, capture timestamp, primary IP(s), notable services, time since last boot. Cite the plugin/file each value came from.>

| Attribute | Value | Source |
|-----------|-------|--------|
| Hostname | <name> | `<plugin / artefact>` |
| OS | <build> | `<plugin>` |
| ... | ... | ... |

---

## 3. Attack Narrative — ATT&CK Kill Chain

> Walk the chain in execution order, not tactic-numeric order. Skip tactics with no evidence, but explicitly note negative findings (`§3.X — TA0011 Command & Control: no evidence of beaconing or scheduled callback`). Negative findings ARE findings.

### 3.1 TA#### <Tactic Name> — `T####.### <Technique>`
**Confidence:** <HIGH/MED/LOW> · **Severity:** <CRIT/HIGH/MED/LOW>

<Evidence + reasoning. Cite the exact plugin output / file path / row number. Quote the relevant fields verbatim where it strengthens the case.>

<Optional follow-up paragraph if the technique has alternative interpretations the reader should consider.>

### 3.2 TA#### <Tactic Name> — `T####.### <Technique>`
...

### 3.3 TA0005 Stealth — `T####.### <Technique>`
<!-- v19 rename: TA0005 is "Stealth" (was "Defense Evasion" pre-v19).
     For active disabling/degrading of controls, use the "Impair
     Defenses" technique tree. -->
...

---

## 4. Timeline of Events (UTC) with ATT&CK Mapping

| Timestamp (UTC) | Event | Source | ATT&CK |
|-----------------|-------|--------|--------|
| YYYY-MM-DD HH:MM:SS | <Event description, factual> | `<plugin / file>` | T####.### |
| ... | ... | ... | ... |

> Reconstruct minute-by-minute from process creation times, file MAC times, and event log entries. Mark inferred timestamps as such (`~14:33:00 (inferred from PID gap)`).

---

## 5. Suspicious <Process / File / Network> Inventory

<One table per category that has hits. Drop tables that have no evidence rather than padding with N/A rows.>

| <Field> | <Value> | <Source> | <Why suspicious> |
|---------|---------|----------|------------------|

---

## 6. Indicators of Compromise (IOCs)

### 6.1 File IOCs
| Path | Hash (if available) | Type |
|------|---------------------|------|

### 6.2 Process Behavioural IOCs
| Behaviour | Plugin signal |
|-----------|--------------|

### 6.3 Host IOCs
| Indicator | Value |
|-----------|-------|

> Drop subsections that have no entries.

---

## 7. Full MITRE ATT&CK Mapping

| Tactic | Technique | Sub-Technique | Evidence | Confidence |
|--------|-----------|---------------|----------|-----------|
| TA####  | T####  | .### | <one-line citation pointing at §3.X> | HIGH/MED/LOW |

> One row per technique. Cite the §3 subsection that establishes the evidence so the reader can pivot back.

---

## 8. Network Posture Summary

<Listening sockets, established connections, DNS queries observable in the artefact. State explicitly when the artefact type doesn't capture some category (e.g. "Memory image cannot show DNS resolver cache history beyond what's resident at capture time").>

| Port | Process | State | Direction |
|------|---------|-------|-----------|

---

## 9. Remediation & Recommendations

> Keep tight. ~10 items total. Junior analysts read these first; bury them in detail and they don't act.

### Immediate (0–24 h)
1. <Action — concrete verb, named target>
2. ...

### Short-term (1–7 days)
1. ...

### Long-term (1–4 weeks)
1. ...

---

## 10. Detection Engineering Outputs

### Sigma rule sketches

```yaml
title: <Detection Name — short and behavioural>
id: <UUID4>
status: experimental
description: <one-line detection intent>
references:
  - <upstream attack reference>
author: <case ID>
date: YYYY/MM/DD
logsource:
  product: <windows | linux | macos | network>
  category: <process_creation | file_event | network_connection | ...>
detection:
  selection:
    Image|endswith: '\<binary>.exe'
    ParentImage|endswith: '\<parent>.exe'
  condition: selection
falsepositives:
  - <legitimate scenario this rule will fire on>
level: <high | medium | low>
tags:
  - attack.t####
  - attack.t####.###
```

> One Sigma per technique that left a behavioural fingerprint in the artefact. Don't write a Sigma for techniques you only inferred.

### YARA rule sketches *(optional — file-IOC stages only)*

```yara
rule <CaseID_Stage_Description> {
  meta:
    author = "<case ID>"
    description = "<what this catches>"
  strings:
    $a = "<distinctive string>"
  condition:
    $a
}
```

---

## 11. Limitations and Caveats

- <Be honest about what the artefact set could and couldn't tell you. Memory captures don't show pre-boot activity. Pcaps don't show host-side process context. Disk images miss volatile state.>
- <Call out specific evidence you'd want next to raise confidence on the lower-confidence techniques.>
- <Note any pivots the analyst tried but couldn't complete because of artefact limits — this is what makes a report defensible.>

---

## 12. Appendix — <Tool> Plugins Run

| Plugin | Purpose | Output File |
|--------|---------|-------------|
| `<tool>.<plugin>` | <one-line purpose> | `analysis/<case>/<plugin>.txt` |

> Lists only the plugins whose output drove a finding. Plugins run for orientation that returned nothing actionable can be omitted.

---

*Report prepared in accordance with strict read-only evidence handling. Source artefact accessed via mount-with-noexec / SHA-256 verified before and after analysis.*
