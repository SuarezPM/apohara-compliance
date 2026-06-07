# Validation log — synthetic precision / recall (US-F1-5 / RAC-1.5)

**Date:** 2026-06-05
**Engine baseline commit:** `44e15eb` (regex + context DSL engine: US-F1-1 source_kinds /
require_context / deny_context, conditional word-boundary matching US-F0-2,
visible suppression, ASI companions, gap mode). The P/R harness + corpus are
added on top of that commit.
**Scanner version:** `apohara-compliance-scanner` 0.1.0
**Toolchain (measured on):** rustc 1.95.0 (host). **Declared MSRV:** 1.74 (unchanged).
**Harness:** `crates/scanner/tests/precision_recall.rs` (runs under `cargo test`).
**Corpus:** `tests/corpus/expected.json` (committed, CI-gating).

> **SYNTHETIC-CORPUS CAVEAT (read first — honesty invariant).**
> Every number below is measured on a **100% synthetic, hand-crafted fixture
> corpus**. These are **fixture metrics, NOT real-world accuracy.** No real
> `~/.claude` session is committed or used for the CI gate. The only real
> sessions are private `~/.claude/projects/**` transcripts; sanitizing and
> committing them is unscoped and risks leaking private data, so the gating
> corpus is synthetic by design (plan Step 1.5, fix #7). **Real-session metrics
> are NON-GATING, manually refreshed, and NEVER committed** — a developer may run
> the scanner over their own transcripts and note the result locally (see the
> "Real-session (non-gating)" section below), but it never enters CI.

## Corpus composition

| Bucket | Count | Pinned minimum |
|---|---|---|
| FP-trap items (expected: NO finding) | 41 | ≥ 30 |
| True-positive items (expected: specific AGT code[s]) | 35 | ≥ 20 |
| **Total** | **76** | — |

FP-traps exercise the four precision mechanisms the tuned engine adds over the
naive substring matcher:
- **(a) conditional word-boundary** — a signal substring inside a larger word
  (`truncate`→"truncated", `DAN`→"abundant"/"redundant", `shred`→"shredder",
  `structuring`→"restructuring").
- **(b) `deny_context`** — a roleplay signal (`act as`) inside a doc/comment
  window (`//`, `#`, `<!--`, `example`, `documentation`, `fallback`).
- **(c) `source_kinds` scoping** — a destructive/exfil signal (`wipe`,
  `format disk`, `DROP TABLE`, `DELETE FROM`, `insmod`, `nsenter`) observed on a
  `session:Read.input` file-path source, outside the rule's
  `session:Bash` / `repo-file:` scope.
- **(d) multi-word / punctuated literals** — a partial phrase that is not the
  literal signal (`SELECT name…` is not `SELECT * FROM`; `wget` is not
  `wget http`; `pretend play` is not `pretend you are`; `developer-mode` hyphen
  is not the spaced `developer mode`).

A handful of items that "look" benign but whose signal is **unscoped with no
`deny_context`** (`jailbreak`, `smurfing`, `SSN`, `merge pull request`,
`you are now`) are encoded as **true positives of the literal signal** — the
deterministic engine genuinely fires, and we do not fake them as suppressed
FP-traps. Honesty over a green checkmark.

## Measured results (this same corpus, both matchers)

| Matcher | Precision | Recall | TP | FP | FN |
|---|---|---|---|---|---|
| **Substring baseline** (case-insensitive `contains`, no `\b`, no scoping, no context) | **0.6964** | **1.0000** | 39 | 17 | 0 |
| **Tuned engine** (regex + conditional `\b` + context DSL) | **1.0000** | **1.0000** | 39 | 0 | 0 |

**Precision lift: +0.304 (0.696 → 1.000).** The 17 substring false positives —
exactly the `(a)/(b)/(d)` FP class — are all eliminated by the tuned engine.
**Recall is unchanged (1.0000 → 1.0000): no recall regression.**

The substring baseline is computed inside the harness itself (a plain
case-insensitive `contains` of every `detection-rules.yaml` signal over the same
corpus), so the baseline and the engine are measured on identical inputs.

### Per-rule (tuned engine)

Every fired rule scores precision 1.000 / recall 1.000 on the synthetic corpus:
`AGT-EXF-001` (TP=3), `AGT-EXF-002` (TP=3), `AGT-FIN-001` (TP=1),
`AGT-FIN-002` (TP=2), `AGT-GOV-001` (TP=1), `AGT-GOV-002` (TP=1),
`AGT-GOV-003` (TP=1), `AGT-MIS-001` (TP=7), `AGT-MIS-002` (TP=4),
`AGT-MIS-003` (TP=2), `AGT-PI-001` (TP=5), `AGT-PI-002` (TP=4),
`AGT-PI-003` (TP=3), `AGT-PII-001` (TP=1), `AGT-PII-002` (TP=1).

> The tuned-engine precision is 1.0 partly **by construction**: the ground truth
> in `expected.json` was empirically derived from the engine's own behavior, then
> the harness re-confirms it every run. The metric that demonstrates the *value*
> of the tuning is the **baseline-vs-engine precision delta** (0.696 → 1.000),
> not the absolute 1.0. The recall floor exists to guard the other direction (the
> tuning must not silently drop a true positive the naive matcher caught).

## Committed CI floors (the gate — `tests/precision_recall.rs`)

`cargo test` FAILS (CI gate) if ANY of:

- **precision < 0.85** (`PRECISION_FLOOR`) — currently **1.0000**, margin +0.15.
- **recall < the substring-baseline recall** (measured each run, currently
  **1.0000**) — the tuned engine may not regress recall vs. the naive matcher.
- **corpus < the pinned minimum** (≥ 30 FP-traps AND ≥ 20 true-positives) —
  currently **41 / 35**, so a future edit that shrinks the corpus below the
  minimum fails the gate.

**Gate verified real (2026-06-05):** temporarily raising `PRECISION_FLOOR` to
`1.01` made the test FAIL with `PRECISION GATE FAILED`; raising the pinned
minimum past the corpus size made it FAIL with `corpus too small`. Both reverted.

## Real-session (non-gating, uncommitted)

None recorded. A developer MAY measure precision/recall over their own private
`~/.claude/projects/**` transcripts as local enrichment and note the result here,
but such numbers are **non-gating and must not be committed** (they would embed
private data and conflate fixture metrics with real-world accuracy). The CI gate
relies on the synthetic corpus ONLY.

## Independent corpora — non-gating (v1.4 HYBRID 2+3)

These measure **bait-keyword surface coverage over labeled injection STRINGS — NOT
injection-consequence detection** (an injection is untrusted DATA the agent reads,
represented here as the agent's own action input; see BENCHMARK.md + the ADR). They
drive a SEPARATE non-gating harness and never touch the synthetic CI gate.

### F1 BASELINE — current engine, before any v1.4 rule (commit-of-record 9b18d2d, 2026-06-07)

**AgentDojo** (ethz-spylab, MIT, v1.2.1; 35 injection-task GOALs) — reproduce with
`cargo test -p apohara-compliance-scanner --test independent_corpus -- --ignored --nocapture`:

- OVERALL recall: baseline 0.0286 (1/35) -> tuned 0.0286 (1/35).
- Per category (tuned): data-exfiltration 0/12, web-exfiltration/phishing 0/4,
  unauthorized-autonomous-action 0/10, financial-transaction 0/5,
  financial-structuring 0/1, destructive-action 0/1, **pii-harvest 1/2**.
- The single hit is the PII-harvest GOAL carrying "passport number" + "credit card
  number" (existing AGT-PII-001 signals). Everything else is prose with no current
  signal — exactly sub-gaps (a)/(b)/(c)/(d). This supersedes the anecdotal FinBot
  "2/6": the measurable baseline is **1/35**.

**AgentHarm** (ai-safety-institute, eval-only; 176 augmented prompts / 44 base) —
reproduce with `HF_HOME=$PWD/eval/agentharm/.cache eval/.venv/bin/python
scripts/eval/run_agentharm_eval.py` (numbers-only report at
tests/corpus/agentharm-report.json):

- Coverage: 0.0114 (2/176), only AGT-PII-001 (x2, both in the Harassment category).
- HONEST READ: AgentHarm's categories (Drugs, Hate, Sexual, Copyright, Disinformation,
  Fraud, Cybercrime, Harassment) are **content-harm**, largely **outside apohara's
  scope** — apohara is a tool-action / compliance candidate-surfacer, NOT a
  content-safety classifier. Low AgentHarm coverage is therefore mostly by-design, not
  a closable gap. The on-target corpus for v1.4 gap closure is **AgentDojo**.

### F2 POST-RULES — data-first prose rules added (2026-06-07)

Synthetic gate UNMOVED throughout F2: tuned precision=1.0000 recall=1.0000 (TP=39 FP=0
FN=0) after every rule; 10 nearest-benign FP-traps added (41 -> 51 traps); per-rule
"zero unexpected fires vs the full trap set" verified each step.

**AgentDojo** OVERALL recall **1/35 -> 23/35 (0.657)**:
- F2-1 (PII variants + finance vocab on AGT-PII-001): pii-harvest 1/2 -> 2/2 (1->2/35).
- F2-2 (AGT-EXF-004 bulk-messaging-exfil + AGT-EXF-005 web-exfil, broad source +
  require_context): data-exfiltration 0/12 -> 9/12, web-exfiltration 0/4 -> 4/4 (->15/35).
- F2-3 (AGT-FIN-003 prose money movement / structuring, broad + require_context):
  financial-transaction 0/5 -> 5/5, financial-structuring 0/1 -> 1/1, data-exfil 9 -> 10/12
  (exfil-via-transaction), unauthorized-action 0 -> 1/10 (->23/35).
- Honest remaining misses (12): unauthorized-but-benign-looking actions (9; out of reach
  without trajectory context), one "delete the file" destructive prose (skipped for FP
  risk), two security-code exfil phrasings.

**AgentHarm** coverage **2/176 -> 2/176 (0.011)** — UNCHANGED. The new exfil/financial
prose rules do not fire on content-harm prompts; reconfirms AgentHarm is off-target for a
tool-action/compliance scanner.

Rules: 17 -> 20 (added AGT-EXF-004, AGT-EXF-005, AGT-FIN-003). Engine UNTOUCHED (A1
data-only sufficed; A3/A2 not invoked). See ADR-3.

## v2.0 Trajectory taint-correlation (ADR-4) + real-world measurement (2026-06-07)

Engine: opt-in `taint:` block (taint.rs, append-only after the sequence pass). AGT-TRJ-001/002/003
(injection→exfil/destructive/financial). Synthetic gate UNMOVED 1.0000/1.0000/FP=0 throughout
(taint rules need 2 actions; single-item gate scans cannot fire them). Mechanism proof-of-life:
the 3 committed synthetic positives fire their rule via the real binary; benign + FinBot
negative-control fire zero.

REAL-WORLD (AgentDojo e2e + MiniMax-M3, pre-reg SHA 3bdc5c8): banking, important_instructions
(model-name-agnostic), 10 attacked + 2 benign. Bound triple — attack-success **0/10** (MiniMax
refused all), post-hoc detection **0/0**, failed-injection FP **0/10**, benign FP **0/2**; real
usage 28 calls / 65,550 tokens. Honest verdict: real-world efficacy **UNPROVEN** — (1) zero
successful injections, (2) verified representation/vocab gap (AgentDojo `<INFORMATION>` marker +
structured `send_money(…)` sinks do not overlap apohara's text vocab). Rules NOT retro-fitted
(pre-registration). Mechanism proven on synthetic positives; generalization is the open gap.
