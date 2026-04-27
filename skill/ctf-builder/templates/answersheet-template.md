# <CASE TITLE> — Junior Analyst Training Guide

**Audience:** <Junior / Intermediate / Senior> DFIR analysts.
**Purpose:** Teach analytical thinking, not just answers. Read the reasoning before peeking at the solution.

---

## How a Real DFIR Analyst Approaches a <Memory Image | Disk Image | Pcap | Log Corpus>

<Insert the universal mental model for this artefact type. Example for memory:>

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

---

## Where to Start — The Triage Methodology

### The First Three Commands (always)

<List the three reflexive commands for this artefact type and why.>

### Why This Order?

<Explain why hypothesis-driven analysis beats running every plugin up-front.>

---

# Stage-by-Stage Walkthrough

## Stage N — TA#### <Tactic Name> (T#### <Technique>)

### Hypothesis to test
*"<The question the analyst is testing at this stage>"*

### Commands
```bash
<exact commands>
```

### Answer
**<answer>**

### Why this answer matters
<2-4 paragraphs of analytical reasoning. This is the most important section.>

### Decision tree (when applicable)
```
Found <artefact>?
├── Condition A → Hypothesis 1
├── Condition B → Hypothesis 2
└── Condition C → Hypothesis 3
```

### Junior-analyst lesson
<One sentence the analyst should remember forever.>

---

## Common Pitfalls Junior Analysts Hit

1. <Concrete trap with example>
2. <...>

---

## The Investigative Mindset — Final Notes

A great DFIR analyst is part historian, part detective, part scientist:

- **Historian:** reconstructs the sequence with citations.
- **Detective:** notices small inconsistencies, follows them.
- **Scientist:** generates hypotheses, designs tests, updates priors.

For every observation, ask:
1. What did I see? (raw artefact)
2. What could it mean? (multiple hypotheses)
3. What's most likely? (leading hypothesis given context)
4. What would prove or disprove it? (next plugin/query/file)

---

*This guide is grounded in real <tool> output from `<artefact>`. The reasoning patterns transfer to any <domain> investigation.*
