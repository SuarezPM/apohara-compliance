# ADR-4: Deterministic Trajectory Taint-Correlation (injection→consequence candidates)

**Status:** ACCEPTED (v2.0, 2026-06-07). ralplan DELIBERATE consensus APPROVE (main plan +
Amendment A rev 2). Plan: `.omc/plans/v2.0-trajectory-taint-detection.md`. Base = v1.4 (HEAD
d61db7b). All LOCAL.

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

## Measured real-world result (Phase 5A — AgentDojo+MiniMax, pre-reg SHA `3bdc5c8`)

Bounded, pre-registered run: AgentDojo v1.2.1 banking, `important_instructions_no_model_name`,
MiniMax-M3, 10 attacked + 2 benign. **Bound triple:** (a) MiniMax attack-success-rate **0/10**
(the model refused every indirect injection); (b) apohara post-hoc detection **0/0** (no
successes); (c) failed-injection FP **0/10**, benign FP **0/2**. Real usage: **28 calls /
65,550 tokens** (PROOF-v2-minimax.md).

**Honest verdict: real-world efficacy UNPROVEN.** Two measured reasons: (1) the target refused
all injections → no real positive; (2) **representation/vocab gap (verified)** — AgentDojo's
marker (`<INFORMATION>… important message…`) and STRUCTURED tool-call sinks (`send_money(…)`)
do not overlap apohara's frozen `taint_source`/`taint_sink` text vocab, so even a successful
trace would very likely not fire. The engine MECHANISM is proven on the committed synthetic
positive (F3); generalization to a different agent-representation is the open gap. Per the
pre-registration the rules were NOT retro-fitted to AgentDojo (that would be a fit, not a
measurement). The honest claim ceiling holds: "deterministic injection→consequence CANDIDATE
detection over the action stream (mechanism proven on synthetic positives)", NEVER "detects
real exploits".

## Alternatives considered & follow-ups
- Alternatives: 1B/1C (source channel), 2B/2C (engine shape), OQ1 (self-contained taint.rs),
  OQ2 (gate byte-identical) — see plan §5 / Decision sections (all rejected with rationale).
- Follow-ups: **F-generalize** — a SEPARATE future pre-registration with either
  AgentDojo-representation-aware rules OR a coding/shell-agent benchmark whose representation
  matches apohara's domain (NOT a retro-fit of this measurement). F-window (decay accumulation
  vs first-sink-fires). F-gate (trajectory gate enrichment). F-dataflow (field-level / tree-sitter
  = a future separate ADR).
