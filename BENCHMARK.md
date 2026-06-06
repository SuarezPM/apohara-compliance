# Benchmark — synthetic precision/recall

**What this measures:** how much the tuned detection engine (regex + word-boundary +
context) reduces false positives over a naive substring matcher, on a committed synthetic
corpus, gated on every `cargo test`.

> [!IMPORTANT]
> These are **fixture metrics on a 100% synthetic, hand-crafted corpus** — they are **not**
> a claim of real-world accuracy. The headline result is the **false-positive reduction
> (precision 0.70 → 1.00 at unchanged recall)**, not the absolute 1.00. See
> [Limitations](#limitations) — the 1.00 is partly true *by construction*.

## Headline: false positives removed without losing recall

The tuning eliminates the substring matcher's false positives — **precision rises
0.6964 → 1.0000 while recall stays 1.0000** — on the corpus below.

## Methodology

The gate ([`crates/scanner/tests/precision_recall.rs`](crates/scanner/tests/precision_recall.rs))
drives the **real compiled binary** (via `CARGO_BIN_EXE_apohara-compliance-scanner`) over
every item in the corpus
([`tests/corpus/expected.json`](tests/corpus/expected.json)) and compares emitted findings
to the labeled ground truth. It enforces two CI floors:

- **Precision floor 0.85** — the build fails below it.
- **Recall non-regression** — tuning must not drop recall below the substring baseline.

The "substring baseline" is a deliberately naive matcher (raw substring containment) used
as the control to isolate what the tuned engine's word-boundary + context logic buys.

**Corpus:** 76 items — 41 false-positive traps + 35 true-positives.

## Overall results

| Matcher (same synthetic corpus)                | Precision | Recall | TP | FP | FN |
|------------------------------------------------|-----------|--------|----|----|----|
| Naive substring baseline                       | 0.6964    | 1.0000 | 39 | 17 | 0  |
| Tuned engine (regex + word-boundary + context) | 1.0000    | 1.0000 | 39 | 0  | 0  |

The tuned engine removes all 17 substring false positives without dropping a single true
positive.

## Per-rule (tuned engine)

**15 of 16 defined rules are exercised by the corpus.** `AGT-EXF-003` has no corpus item,
so it is not listed below — its absence is a corpus-coverage gap, not a passing result.

| Rule        | Precision | Recall | TP |
|-------------|-----------|--------|----|
| AGT-EXF-001 | 1.000     | 1.000  | 3  |
| AGT-EXF-002 | 1.000     | 1.000  | 3  |
| AGT-FIN-001 | 1.000     | 1.000  | 1  |
| AGT-FIN-002 | 1.000     | 1.000  | 2  |
| AGT-GOV-001 | 1.000     | 1.000  | 1  |
| AGT-GOV-002 | 1.000     | 1.000  | 1  |
| AGT-GOV-003 | 1.000     | 1.000  | 1  |
| AGT-MIS-001 | 1.000     | 1.000  | 7  |
| AGT-MIS-002 | 1.000     | 1.000  | 4  |
| AGT-MIS-003 | 1.000     | 1.000  | 2  |
| AGT-PI-001  | 1.000     | 1.000  | 5  |
| AGT-PI-002  | 1.000     | 1.000  | 4  |
| AGT-PI-003  | 1.000     | 1.000  | 3  |
| AGT-PII-001 | 1.000     | 1.000  | 1  |
| AGT-PII-002 | 1.000     | 1.000  | 1  |

## Reproduce

```bash
cargo test -p apohara-compliance-scanner --test precision_recall -- --nocapture
```

The printed block is the source of every number above. A historical record of measured
runs lives in
[`crates/scanner/references/validation-log.md`](crates/scanner/references/validation-log.md).

## Limitations

Read these before quoting any number:

- **100% synthetic, hand-crafted corpus.** Every item was written for the test. These are
  fixture metrics, **not** real-world accuracy on real agent sessions or real repositories.
- **Candidate-only framing.** The scanner emits `CANDIDATE` findings (`note`/`warning`) for
  human review — "precision" here means "of the candidates flagged, how many match the
  labeled trap", not "how many real compliance violations exist".
- **No ground truth beyond `expected.json`.** There is no independent, third-party labeled
  dataset; the ground truth is the committed fixture.
- **The tuned 1.00 is partly true by construction.** The corpus and the engine's context
  rules co-evolved, so a perfect tuned score is expected on *this* corpus. The metric that
  carries real signal is the **baseline → tuned delta** (0.6964 → 1.0000), which shows the
  context logic removes false positives a naive matcher produces.
- **Coverage gap.** One defined rule (`AGT-EXF-003`) has no corpus item; full rule coverage
  is future work (see the README roadmap: *expanded synthetic corpus*).
