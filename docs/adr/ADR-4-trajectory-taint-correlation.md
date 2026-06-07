# ADR-4: Deterministic Trajectory Taint-Correlation (injection→consequence candidates)

**Status:** DRAFT (v2.0 in progress — finalized in Phase 6 with the measured triple). ralplan
DELIBERATE consensus APPROVE (main plan + Amendment A rev 2). Plan:
`.omc/plans/v2.0-trajectory-taint-detection.md`. Base = v1.4 (HEAD d61db7b). All LOCAL.

## Decision

Add a NEW opt-in `taint:` rule block (sibling to ADR-2's `sequence:`), handled by a new
self-contained `crates/scanner/src/taint.rs` pass appended **after** the sequence pass in
`match_actions_with_suppress`. It correlates a **tainted source** — an action on the new
`tool-result:` channel (untrusted-data origin, emitted by `parse_session` from `type:"user"`
tool_result blocks) carrying **injection markers** and NOT in a quote/comment/doc window — with a
**genuine sensitive real-action sink** (exfil/destructive/financial) appearing LATER in the same
session. The sink MUST be a real-action tool_use (`source_kinds` ∈ {session:Bash, session:Write,
session:Edit}, **NEVER chat**) AND specifically sensitive (`require_context`). New rules
AGT-TRJ-001/002/003. The single-action matcher and the FROZEN 3-modifier DSL (ADR-1) are
byte-identically unchanged; AGT-MEM-001 (ADR-2) untouched.

## Impact analysis (Phase 0, gitnexus, mandated)

`match_actions_with_suppress` = **CRITICAL** (23 upstream, 10 direct callers, 9 processes — the
highest-fan-in symbol). **Mitigation (why this is safe):** the only edit to it is ONE append-only
trailing `match_taints(...)` call after `match_sequences`; the single-action loop is untouched. A
"byte-identical passthrough when no taint rule is loaded" test guards it. The CRITICAL rating is
fan-in count, not a semantic regression — additive output only. Surfaced to Pablo in Phase 0; he
approved the append-only design.

## Honest claim ceiling (the load-bearing honesty section — Amendment A)

- The engine detects the **injection→consequence PATTERN** as a CANDIDATE (marked-untrusted
  tool_result → genuine sensitive action), materially stronger than v1.4 bait-keyword coverage.
- It is **NOT** field-level semantic dataflow over real values (no value tracking, no LLM, offline).
- **Accepted limitation (laundering-order):** first-matching-sink fires + break; a benign early sink
  can mask a later genuine sink. Acceptable for a CANDIDATE detector; recorded, not silent.
- **Real-world result framing (Phase 5A, AgentDojo+MiniMax):** what is measured is **post-hoc
  recognizability** of AgentDojo `important_instructions` injection→action traces — NOT efficacy,
  NOT recall, NOT prevention. apohara is a post-hoc scanner, not an inline guardrail. The number is
  partly tautological on this suite (the attack plants a fixed marker; the sink is present by
  design) so it is reported scoped to the template, conditional on marker/sink vocab overlap, with
  the **generalization gap** (marker-overlap misses) reported. The headline always carries the
  TRIPLE: (a) MiniMax attack-success-rate, (b) k-of-N post-hoc detection on successes, (c)
  failed-injection FP (must be 0). If MiniMax yields zero successful injections, the claim stays
  **UNPROVEN on real traces; mechanism proven on the committed synthetic positive.** Never
  over-claimed as "detects real exploits."

## To finalize in Phase 6
- The measured triple + the prereg git SHA + the generalization-gap count.
- Alternatives considered (1B/1C/2B/2C, OQ1/OQ2 — see plan §5).
- Consequences + follow-ups (F-window decay accumulation; F-gate trajectory gate enrichment;
  F-real-corpus; F-dataflow as a future separate ADR).
