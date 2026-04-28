# DFIR Investigation Report
## <CASE TITLE>

| Field | Value |
|-------|-------|
| **Case ID** | <ID> |
| **Examiner** | <name> |
| **Image / Artefact** | <path + size + hash> |
| **Capture Time** | <UTC timestamp> |
| **Analysis Date** | <UTC timestamp> |
| **Tooling** | <tool versions> |
| **Report Format** | MITRE ATT&CK Enterprise kill chain |

---

## 1. Executive Summary

<One paragraph: who/what/when/how, in plain English.>

<One sentence summary of the attack story.>

| Tactic | Technique | Severity | Confidence |
|--------|-----------|----------|-----------|
| TA####  Name | T####.### Name | CRIT/HIGH/MED/LOW | HIGH/MED/LOW |
| ... | ... | ... | ... |

**Overall confidence in the attack narrative: <HIGH/MED/LOW>.**

---

## 2. System Profile

<Build a table with the system's identifying characteristics.>

---

## 3. Attack Narrative — ATT&CK Kill Chain

### 3.1 TA0001 Initial Access — `T<technique>`
**Confidence:** | **Severity:**

<Evidence + reasoning. Cite the exact plugin output / file path.>

### 3.2 TA0002 Execution — `T<technique>`
...

### 3.3 TA0005 Stealth — `T<technique>`
<!-- For active disabling/degrading of controls, use the v19 "Impair Defenses" tactic instead. -->
...

(Skip tactics with no evidence; explicitly note negative findings.)

---

## 4. Timeline of Events (UTC) with ATT&CK Mapping

| Timestamp | Event | ATT&CK |
|-----------|-------|--------|
| ... | ... | T#### |

---

## 5. Suspicious Process / File / Network Inventory

<Tables for each.>

---

## 6. Indicators of Compromise (IOCs)

### 6.1 File IOCs
### 6.2 Process Behavioural IOCs
### 6.3 Host IOCs

---

## 7. Full MITRE ATT&CK Mapping

| Tactic | Technique | Sub-Technique | Evidence | Confidence |

---

## 8. Network Posture Summary

---

## 9. Remediation & Recommendations

### Immediate (0–24 h)
### Short-term (1–7 days)
### Long-term (1–4 weeks)

---

## 10. Detection Engineering Outputs

### Sigma rule sketches

```yaml
title: <Detection Name>
logsource: { product: windows, category: process_creation }
detection:
  selection:
    Image|endswith: '\<binary>.exe'
    ParentImage|endswith: '\<parent>.exe'
  condition: selection
level: <high|medium|low>
```

---

## 11. Limitations and Caveats

- <Be honest about what the artefact set could and couldn't tell you.>

---

## 12. Appendix — Tools Run

| Tool / Plugin | Output File |
|---------------|-------------|

---

*Report prepared in accordance with strict read-only evidence handling.*
