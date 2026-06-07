# ADR-3: Independent labeled corpora + data-first prose-gap closure (v1.4)

**Status:** Accepted (2026-06-07). Implemented in v1.4 (HYBRID 2+3), all local.
**Context plan:** `.omc/plans/v1.4-independent-corpus-and-prose-gap.md` (ralplan DELIBERATE
consensus: Planner → Architect SOUND → Critic APPROVE).
**Supersedes for measurement:** the anecdotal FinBot "2/6" live-run PoC (never persisted).

## Decision

Close the natural-language agentic-attack detection gap with a **HYBRID 2+3**:

1. **Grow the measurement substrate** with two *independent*, externally-authored corpora:
   - **AgentDojo** (ethz-spylab, MIT) — committed at `tests/corpus/agentdojo/`
     (35 injection-task GOALs, per-item provenance + best-effort AGT/ASI labels).
   - **AgentHarm** (ai-safety-institute, MIT **+ eval-only/no-redistribution + canary**) —
     **eval-only**: data stays in the gitignored `eval/` tree; only a numbers/IDs-only,
     schema-validated report (`tests/corpus/agentharm-report.json`) is committed.
2. **Author data-only detection rules** attacking the four confirmed root causes:
   - (a) morphological variants the conditional-`\b` matcher misses (`SSNs`,
     `passport_number`, plurals) → added as explicit variant signals on `AGT-PII-001`.
   - (b) missing finance/PII vocabulary (`tax_id`, `EIN`, `routing number`, `W-9`, …)
     → added as signals on `AGT-PII-001`.
   - (c) prose phrasing with no technical keyword (bulk email exfil, web exfil, prose
     money movement / structuring) → new rules `AGT-EXF-004`, `AGT-EXF-005`,
     `AGT-FIN-003`, each gated by `require_context` (an exfil recipient / URL /
     account-amount) so the verb alone never fires.
   - (d) source-kind gating (scoped `EXF`/`MIS` rules exclude chat actions) → the new
     rules use **broad/empty `source_kinds`** (matches any source) so they see
     `session:<tool>.input`.

The synthetic CI gate (`precision_recall.rs`, floor 0.85) is untouched and stays
**1.0000 / 1.0000 / FP=0**. The independent corpora drive a **separate `#[ignore]`,
non-gating** harness (`crates/scanner/tests/independent_corpus.rs`).

## Drivers

1. **Measurability** — replace the anecdotal 2/6 with a reproducible per-category number
   over corpora the project did not write. Result: AgentDojo **1/35 → 23/35**.
2. **Non-regression + completeness** — preserve the synthetic gate (1.0000/1.0000/FP=0),
   no dead rules (each new rule has a proof-of-life test), no recall regression.
3. **Legal / provenance + honesty** — zero AgentHarm examples or canary committed; the
   delta is labeled as coverage, not detection.

## Alternatives considered

- **(a) word-boundary fix.** Chosen: **A1** (data variant signals). Recorded as
  considered-and-deferred: **A3** — normalize the *haystack* (strip a closed set of
  token-final morphology in `relevant_input`, low fan-in, FROZEN DSL untouched,
  `deny_context` still runs so it does not reopen the `truncate`→`truncated` FP class) —
  the preferred engine escalation **if** variant enumeration ever proves unbounded.
  Rejected as default: **A2** (relax `\b` in `compile_signal`, the highest-fan-in symbol;
  reopens the US-F0-2 FP class; needs a new DSL field) — last resort only. **No engine
  change was needed: A1 (data) closed (a) for the finance/PII set; A3/A2 were not
  invoked.**
- **AgentDojo representation.** Chosen: **B1** (each GOAL as a synthetic chat-tool action
  input). Rejected: **B2** (a new `kind:"session-chat"` in the *gating* harness) — would
  touch the gate/schema.
- **AgentHarm.** Chosen: eval-only / numbers-only. Rejected: committing examples —
  forbidden by license + canary.
- **Widen existing scoped EXF/MIS rules to see chat sources.** Rejected — would risk
  their precision; instead added **new** broad rules with their own `require_context`.

## Consequences

- `detection-rules.yaml` gains 3 rules (`AGT-EXF-004/005`, `AGT-FIN-003`) + PII vocabulary
  (16 → 20 total rules); the FROZEN 3-modifier context DSL is unchanged.
- `tests/corpus/expected.json` gains 10 nearest-benign FP-traps (the only sanctioned gate
  edit). The size/drift guard provides **no** trap-coverage protection (its `assert_eq!`
  checks the pinned `MIN_FP_TRAPS=30` against the JSON field, not the actual count, which
  has slack); the real safeguard is the per-rule "zero unexpected fires vs the full trap
  set" discipline + the new matching.rs unit tests.
- **Category mismatch stated plainly (the central honesty consequence):** AgentDojo/
  AgentHarm attack strings are untrusted DATA the agent *reads*; B1 represents them as the
  agent's own tool *argument*. So v1.4 measures **bait-keyword surface coverage — NOT
  injection-consequence detection.** The tuned engine still applies `\b` + `source_kinds`
  + `require_context`/`deny_context`, so the baseline→tuned coverage is a real
  vocabulary+gating metric, but it is **not** a real-world detection-accuracy claim.
  BENCHMARK.md carries this caveat verbatim and grep-asserts the scoping string.
- The scanner stays offline/deterministic: all dataset I/O is Python in the gitignored
  `eval/.venv`; `crates/scanner/Cargo.toml` is unchanged; the dep-graph guard stays green.

## Follow-ups

- **Model AgentDojo trajectories** (the agent's post-injection tool calls scanned as
  `session:Bash`/tool actions) — the right vehicle for injection-**consequence**
  detection (the proper fix for the category mismatch).
- **Spanish-language gap**: documented, not closed (English-only for benchmark
  comparability).
- Unauthorized-autonomous-action and single-item destructive prose remain out of reach
  without trajectory context or precision-eroding overreach.
- If variant enumeration ever proves unbounded for a category, open the **A3** engine
  escalation (haystack normalization) with `gitnexus_impact(relevant_input)` evidence.
