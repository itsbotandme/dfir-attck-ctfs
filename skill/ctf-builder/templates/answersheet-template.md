# <CASE TITLE> — Junior Analyst Walkthrough

> **Attribution:** <one paragraph crediting the artefact source if derivative; mark walkthrough + ATT&CK reasoning as original training content. Per SKILL.md §18.>

> **Scenario:** *"<verbatim source-of-truth quote, if one exists>"*

---

# Stage-by-Stage Walkthrough

> Each stage uses the same seven-block template: Hypothesis → Plugin → Command → Finding → Why it matters → ATT&CK → Lesson. Read in order; each block answers a different reader's question (the planner, the operator, the reviewer, the trainee).

## Stage 1 — <one-line investigative question>

**Hypothesis.** *<one sentence framing what the analyst is testing — written from the analyst's voice, not as instruction>*

**Plugin.** `<tool>.<plugin>` — <one short clause on why this plugin answers the hypothesis>.

**Command.**
```bash
<tool> -f <image> <plugin>
```

**Finding.** <one or two sentences stating the concrete observation. Cite the field / row that carries the answer.>

**Why it matters.**
- <2–4 short bullets explaining the analytical implications of the finding>
- <link to what it constrains or unlocks for the next stage>
- <call out any caveats or assumptions the finding rests on>

**ATT&CK.** T####.### <Technique Name> — <one-clause behavioural fingerprint that maps the finding to the technique>.

**Lesson.** <One sentence the analyst should remember forever. The transferable rule, not the case-specific fact.>

---

## Stage 2 — <next investigative question>

**Hypothesis.** *...*

**Plugin.** `...`

**Command.**
```bash
...
```

**Finding.** ...

**Why it matters.** ...

**Disambiguating.** *(optional block — include when the finding has multiple plausible explanations the analyst should rule in or out)*
- `<command>` — <what it would prove>
- `<event ID / log source>` — <what it would prove>

**ATT&CK.** T####.### ...

**Lesson.** ...

---

<!-- Repeat for stages 3 … N−1 -->

---

## Stage N — Map your findings to ATT&CK

**(Synthesis stage — no picker, no fresh investigative move. The analyst writes up what they've already earned.)**

**Question.** Re-state the synthesis question (e.g. "What ATT&CK technique does the placement of `<artefact>` map to?")

**Reasoning.** <Three to five sentences walking through the mapping. The analyst is the producer of the mapping here, not the consumer of a reveal — frame the reasoning as "if I were briefing this to detection engineering, I'd say…".>

**Answer.** <The technique they map to.>

**Lesson.** <The one-sentence insight about *the act of mapping* — why naming behaviour in shared vocabulary is the writing-up muscle that turns an investigation into a defensible report.>

---

## Common Pitfalls Junior Analysts Hit

1. **<Pitfall name>.** <One-sentence trap with a concrete example from this case.>
2. **<Pitfall name>.** <...>
3. **<Pitfall name>.** <...>

(4–6 pitfalls is the right band. More than 8 reads as a wall and gets skipped.)

---

## The Investigative Mindset

A great DFIR analyst is part **historian**, part **detective**, part **scientist**:

- **Historian** — reconstructs the sequence with citations. Every claim ties back to a plugin output or file path.
- **Detective** — notices the small inconsistencies (a five-minute gap, a script in the wrong directory) and follows them.
- **Scientist** — generates a hypothesis, picks the test that would falsify it fastest, updates priors when the test comes back.

For every observation, ask:

1. **What did I see?** (raw artefact)
2. **What could it mean?** (multiple hypotheses — name at least two)
3. **What's most likely given the prior context?** (leading hypothesis)
4. **What would prove or disprove it?** (the next plugin / query / file)

The plugin picker on each stage of the lab trains step 4. This walkthrough trains steps 1–3.

---

*This guide is grounded in real <tool> output from `<artefact filename>`. The reasoning patterns transfer to any <domain> investigation; the case-specific findings are illustrative, not universal.*
