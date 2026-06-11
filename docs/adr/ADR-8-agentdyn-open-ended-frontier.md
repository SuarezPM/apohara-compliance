# ADR-8: AgentDyn Open-Ended Frontier — capability probe + Pablo-gated run

**Status:** PROPOSED (v2.4, 2026-06-11). Base = v2.3 (ADR-7) on `main` @ 9c574f4.
Plan: `.omc/plans/v2.4-argument-value-provenance-followups.md` (Rev 2,
consensus). All LOCAL until Pablo approves B-1.
Honesty lineage: v2.0/ADR-4 (synthetic positives) → v2.1/ADR-5 (representation
gap closed) → v2.2/ADR-6 (real-trajectory measurement, 169/236 on TEST
post-hoc, 0/80 on current-frontier workspace suite — UNMEASURED on
open-ended) → v2.3/ADR-7 (causal proxy, 52.1% headline on TEST, post-hoc
not preventive) → **v2.4/ADR-8 (closes the "open-ended frontier UNMEASURED"
gap honestly, OR documents why it can't be closed).**

## Context

v2.2's live run (PR #10, 9a8bf64) used `suite=workspace` because current-
frontier OpenRouter ids are not in AgentDyn's `model_registry.py`. The
result was 0/80 — every model resisted every attack on the AgentDojo
standard suite. ADR-6's follow-up notes this gap: the harder AgentDyn
open-ended suites (`shopping`, `github`, `dailylife`) are UNMEASURED on
current frontier. Last-gen models reached 14–22% ASR on those suites, so
the 0/80 workspace number may not generalize.

The naive v2.3 plan assumed the gap was a "model registry" issue requiring
a JSON override or a monkey-patch. Reading `scripts/eval/run_openrouter_e2e.py:124-134`
shows the v2.2 runner already instantiates `OpenAILLM(client, model)`
directly with the OpenRouter id and bypasses AgentDyn's registry
entirely. The `--suite` CLI flag is already wired to `get_suites(BENCH)[args.suite]`
(line 166). The real B-0 question is whether the open-ended suites are
registered in AgentDyn 5353cf7 and whether the v2.2 OpenRouter ids are
accepted unchanged.

## Decision

**B-0 (capability probe) runs unconditionally; B-1 (the live run) is
Pablo-gated.** Three sequential phases, each independently releasable
(deferring any phase is honest, not failure):

- **B-0.1 — Capability probe.** Verify `--suite {shopping,github,dailylife}`
  resolves via `get_suites(BENCH)` on AgentDyn 5353cf7. Verify v2.2's
  OpenRouter ids are accepted unchanged. Add a per-(model, suite) token
  cap on top of the existing global `--cap` (line 141 is a single
  cumulative cap, not per-pair).
- **B-0.2 — Budget table.** Per-model and per-suite token estimates for
  5 frontier models × 3 suites. ~5M tokens estimated (v2.2 workspace
  used ~700k for 4×20; open-ended has ~7× longer trajectories).
- **B-0.3 — Pablo gate.** Surface the B-0.1 + B-0.2 results. Pablo
  chooses: (a) approve the run with the cap, (b) reduce to a subset of
  (model, suite) pairs, or (c) defer B-1.

**B-1 — Live run, only on Pablo go.** 5 models × 3 suites (or
Pablo-approved subset). Per-(model, suite) hard cap, exceeded = stop
and report `cap_hit=true`. Smoke test (1 model × 1 suite × 5
trajectories, ≤ 100k tokens) before the full grid. Key never logged.
FROZEN `wrap_agentdojo_trace.py` (same as v2.2 + v2.3). Scan with the
SAME release binary as v2.2 + v2.3 (the engine is unchanged; only the
harness and corpus are new). Per-(model, suite) bound triple
(attack-success-rate, post-hoc detection on successes, FP on resisted +
benign). PROOF-v2.4-open-ended.md.

**B-2 — -P measure on open-ended (conditional on B-1 + v2.3).** Scan
the open-ended traces with the v2.3 AGT-TRJ-*-P variants enabled.
Report per-(model, suite) bound triple with -P, side-by-side with the
v2.3-equivalent AGT-TRJ-* numbers. Honest report even if -P detection
is much lower than v2.3's TEST headline (different distribution).

## Drivers

- **D1 — Honesty:** close the "open-ended frontier UNMEASURED" gap
  honestly, or document why it can't be closed. 0/N is a valid
  measurement.
- **D2 — No retro-fit:** if B-1 yields a number, that number is the
  number, including 0/N. Do NOT tune to match the v2.2 169/236
  headline.
- **D3 — Zero production regression:** B is a harness extension only;
  the FROZEN v2.3 release binary and the v2.2 download corpus scan
  must remain byte-identical. R10 regression check:
  `cargo run --release -- scan_repo tests/corpus/v22_minimal --rules rules/agt_trj_*.yaml`
  with the FROZEN v2.3 binary, run both before and after the B harness
  patch. Numbers must be byte-identical.
- **D4 — Bounded cost:** per-(model, suite) hard cap. Smoke test
  always first. Key never logged.

## Alternatives considered

- **A1 (chosen):** Capability probe + per-pair cap. Trivially additive
  (the harness already does the hard work). The only real code change
  is the per-pair cap.
- **A2:** Defer B-1 indefinitely; only ship B-0. Cheapest. Keeps the
  open-ended frontier gap open. Documented honestly. The honest
  fallback if A1.1 returns "suite not registered on AgentDyn 5353cf7."

### Rejected

- **JSON override file + monkey-patch via sitecustomize:** the v2.2
  harness does not import AgentDyn's `model_registry.py`; the override
  is dead weight.
- **Fork AgentDyn:** disproportionate to "run 3 harder suites." High
  rebase cost. Rejected.

## Consequences

- **If B-0.1 passes (suites registered) + B-1 runs:** the gap closes
  with measured numbers. If post-hoc detection is much lower than the
  v2.3 52.1% headline, the v2.3 causal proxy is overfit to the
  download corpus's distribution. This is a v2.5 design conversation
  (R4 CRITICAL), not a v2.5 "tidy up."
- **If B-0.1 fails (suites not registered):** the gap is documented
  as "AgentDyn 5353cf7 does not register the open-ended suites for
  our harness; revisit when upstream adds the registration or the
  harness is upstreamed to accept a custom suite." B-1 is DEFERRED.
- **If B-0.1 passes but B-1 reveals a large detection gap:** R4 fires
  (CRITICAL). The plan's mitigation is honest report + queue v2.5
  design conversation, do NOT retro-fit v2.3.
- **Cost ceiling:** ~5M tokens estimated; per-(model, suite) cap is
  the safety net. Smoke test before the full grid. Hard stop on
  cap-hit.

## Follow-ups

- **v2.5 (deferred):** if B-1 reveals the engine misses the harder
  14–22% ASR distribution, design a v2.5 model that handles
  multi-app trajectories and helpful-but-injected instructions. This
  is a separate workstream, not a v2.4 deliverable.
- **Open-questions.md update:** post-consensus, the B gate entry
  becomes "B-0.1 capability probed (2026-06-XX); see ADR-8."
- **README roadmap:** if B-1 ships, the "What we measured" table
  gets a new row for open-ended (frontier). If B-1 is deferred, the
  roadmap gets a "frontier open-ended: DEFERRED" line with the
  reason.

## References

- `scripts/eval/run_openrouter_e2e.py:124-134, 140, 141, 166, 226-233` —
  the v2.2 harness shape that the plan is grounded in.
- `docs/adr/ADR-6-real-trajectory-efficacy.md` — the v2.2 follow-up
  that names this gap explicitly.
- `.omc/plans/v2.4-argument-value-provenance-followups.md` Rev 2 —
  the consensus plan.
- `docs/open-questions.md` § "v2.3 follow-up B" — the gate entry.
