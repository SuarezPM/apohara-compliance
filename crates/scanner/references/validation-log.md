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
