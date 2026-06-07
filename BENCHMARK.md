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

## Independent corpora (v1.4) — non-gating

The synthetic gate above is engine-derived (corpus and rules co-evolved). v1.4 adds two
**independent**, externally-authored corpora to measure coverage against attacks the
project did not write, and to drive the data-first prose-rule work.

> **What this measures (read first).** An injected attack is untrusted DATA the agent
> *reads* (the bait), not the agent's own action; apohara scans the agent's actions. To
> run the rule engine over this content we represent each attack string as an action
> input. The result is therefore (kept on one line for the grep-checkable scoping AC):
>
> **bait-keyword surface coverage over labeled injection STRINGS — NOT injection-consequence detection**
>
> It shows whether apohara's
> vocabulary + word-boundary + source/context machinery surfaces the attack *class*; it
> does **not** show whether apohara detects the *consequence* of a successful injection.
> Modeling attack *trajectories* (the agent's post-injection tool calls) is the right
> vehicle for consequence detection and is recorded as future work (ADR-3 follow-up).

**AgentDojo** (ethz-spylab, MIT; 35 injection-task GOALs across workspace/travel/banking/
slack) — committed at `tests/corpus/agentdojo/`, run with
`cargo test -p apohara-compliance-scanner --test independent_corpus -- --ignored --nocapture`:

| stage | overall recall | notes |
|---|---|---|
| v1.4 F1 baseline (pre-rule) | **1 / 35 (0.029)** | only a passport+credit-card PII GOAL fired; supersedes the anecdotal FinBot "2/6" |
| v1.4 F2 (data-first rules)  | **23 / 35 (0.657)** | data-exfil 10/12, web-exfil 4/4, financial 5/5, structuring 1/1, PII 2/2, unauthorized-action 1/10, destructive 0/1 |

The 12 remaining misses are **honestly out of reach for prose detection**: 9 are
unauthorized-but-benign-looking actions (create a calendar event, send an arbitrary
email) whose maliciousness is injection context the scanner cannot see from the action
text; 1 is a single "delete the file" destructive phrasing left unhandled to avoid
false positives; 2 are security-code exfiltration phrasings. Closing these would require
trajectory modeling or precision-eroding overreach — neither is in scope for v1.4.

**AgentHarm** (ai-safety-institute; 176 augmented prompts / 44 base behaviors) —
**eval-only / no-redistribution**, so no examples are committed; only a numbers/IDs-only
report at `tests/corpus/agentharm-report.json` (schema-validated). Coverage:
**2 / 176 (0.011)**, unchanged baseline→F2. This is expected and **by design**:
AgentHarm's categories (Drugs, Hate, Sexual, Copyright, Disinformation, Fraud,
Cybercrime, Harassment) are **content-harm**, largely outside apohara's scope — apohara
is a tool-action / compliance candidate-surfacer, **not a content-safety classifier**.
AgentDojo is the on-target corpus for this work.

## Trajectory taint-correlation (v2.0) — injection→consequence, post-hoc

v2.0 adds a deterministic taint engine (ADR-4): an injection marker in untrusted data the
agent READ (a `tool-result:` action) followed by a genuine sensitive real-action sink =
a CANDIDATE injection→consequence correlation. The engine MECHANISM is proven on committed
synthetic positive fixtures (AGT-TRJ-001/002/003 fire via the real binary; benign trajectories
and the FinBot direct-injection fixture — a negative control — fire zero).

**Real-world measurement (AgentDojo end-to-end + MiniMax-M3, pre-registered SHA `3bdc5c8`).**
Bounded run: banking suite, `important_instructions` (model-name-agnostic variant), 10 attacked
pairs + 2 benign. The bound triple (post-hoc, never "efficacy"):

| | result |
|---|---|
| MiniMax attack-success-rate | **0 / 10** (the model refused every indirect injection) |
| apohara post-hoc detection on successes | **0 / 0** (no successes) |
| failed-injection FP / benign FP | **0 / 10** · **0 / 2** |
| real MiniMax usage | 28 calls, 65,550 tokens |

> **Real-world efficacy is UNPROVEN — stated plainly.** Two measured reasons: (1) MiniMax-M3
> resisted all 10 injections, so no real positive trace exists; (2) a verified
> **representation/vocab gap** — AgentDojo's `<INFORMATION>…` marker and structured tool-call
> sinks (`send_money(…)`) do not overlap apohara's text-pattern `taint_source`/`taint_sink`
> vocabulary, so even a successful trace would very likely not fire. apohara is a **post-hoc**
> transcript scanner (recognizable-in-log ≠ would-have-prevented), and its rules are vocab-scoped
> to shell/coding agents. Per the pre-registration the rules were NOT retro-fitted to AgentDojo.
> The honest ceiling: **the mechanism is proven on synthetic positives; real-world generalization
> is an open, measured gap** — never "detects real exploits". See ADR-4 + PROOF-v2-minimax.md.

## Limitations

Read these before quoting any number:

- **100% synthetic, hand-crafted corpus.** Every item was written for the test. These are
  fixture metrics, **not** real-world accuracy on real agent sessions or real repositories.
- **Candidate-only framing.** The scanner emits `CANDIDATE` findings (`note`/`warning`) for
  human review — "precision" here means "of the candidates flagged, how many match the
  labeled trap", not "how many real compliance violations exist".
- **The synthetic gate has no third-party ground truth.** Its ground truth is the committed
  fixture. v1.4 adds the *independent* AgentDojo/AgentHarm corpora above as a non-gating
  cross-check, but those measure bait-keyword surface coverage (not consequence detection)
  and AgentDojo's labeling is best-effort (see `tests/corpus/agentdojo/SOURCE.md`).
- **English only.** Both the synthetic gate and the independent corpora are English; the
  Spanish-language detection gap is **documented but not closed** (out of scope for v1.4).
- **The tuned 1.00 is partly true by construction.** The corpus and the engine's context
  rules co-evolved, so a perfect tuned score is expected on *this* corpus. The metric that
  carries real signal is the **baseline → tuned delta** (0.6964 → 1.0000), which shows the
  context logic removes false positives a naive matcher produces.
- **Coverage gap.** One defined rule (`AGT-EXF-003`) has no corpus item; full rule coverage
  is future work (see the README roadmap: *expanded synthetic corpus*).
