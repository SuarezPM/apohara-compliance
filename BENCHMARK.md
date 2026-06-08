# Benchmark — synthetic precision/recall

**What this measures:** how much the tuned detection engine (regex + word-boundary +
context) reduces false positives over a naive substring matcher, on a committed synthetic
corpus, gated on every `cargo test`.

> [!IMPORTANT]
> These are **fixture metrics on a 100% synthetic, hand-crafted corpus** — they are **not**
> a claim of real-world accuracy. The headline result is the **false-positive reduction
> (precision 0.64 → 1.00, recall 0.92 → 1.00)**, not the absolute 1.00. See
> [Limitations](#limitations) — the 1.00 is partly true *by construction*.

## Headline: false positives removed without losing recall

The tuning eliminates the substring matcher's false positives — **precision rises
0.6389 → 1.0000, and tuned recall (1.0000) exceeds the naive baseline (0.9200)** — on the
corpus below.

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

**Corpus:** 101 items — 59 false-positive traps + 42 true-positives.

## Overall results

| Matcher (same synthetic corpus)                | Precision | Recall | TP code-matches | FP | FN |
|------------------------------------------------|-----------|--------|-----------------|----|----|
| Naive substring baseline                       | 0.6389    | 0.9200 | 46              | 26 | 4  |
| Tuned engine (regex + word-boundary + context) | 1.0000    | 1.0000 | 50              | 0  | 0  |

The tuned engine removes all 26 substring false positives **and** recovers the 4 true positives
the naive matcher misses — the structural `shlex` shell pass (v2.1) catches flag-reordered
destructive commands a substring scan cannot, so tuned recall 1.0000 > baseline 0.9200.
("TP code-matches" counts AGT-code hits, not corpus items — the per-rule table below sums to it.)

## Per-rule (tuned engine)

**17 rules are exercised by the corpus** (16 single-action-family + the `AGT-MIS-004` structural
shell rule, which fires via the shlex pass on session-bash items). (`AGT-MEM-001` sequence +
`AGT-TRJ-001/002/003` taint rules remain gate-exempt by design — the gate harness drives
single-action + the appended shell pass, not the trajectory/sequence passes.)

| Rule        | Precision | Recall | TP code-matches |
|-------------|-----------|--------|-----------------|
| AGT-EXF-001 | 1.000     | 1.000  | 3  |
| AGT-EXF-002 | 1.000     | 1.000  | 3  |
| AGT-EXF-003 | 1.000     | 1.000  | 1  |
| AGT-FIN-001 | 1.000     | 1.000  | 1  |
| AGT-FIN-002 | 1.000     | 1.000  | 2  |
| AGT-GOV-001 | 1.000     | 1.000  | 1  |
| AGT-GOV-002 | 1.000     | 1.000  | 1  |
| AGT-GOV-003 | 1.000     | 1.000  | 1  |
| AGT-MIS-001 | 1.000     | 1.000  | 13 |
| AGT-MIS-002 | 1.000     | 1.000  | 4  |
| AGT-MIS-003 | 1.000     | 1.000  | 2  |
| AGT-MIS-004 | 1.000     | 1.000  | 4  |
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

## Representation-aware taint (v2.1) — structured sinks + generic markers, post-hoc

v2.1 closes the v2.0 **representation** gap (ADR-5): the parser now emits a reserved `sink:`
action carrying a deterministic canonical role string (`recipient=`/`amount=`/`url=`/`command=`,
authority-role fields only — `const SINK_GRAMMAR`), and the AGT-TRJ taint rules gained a
taxonomy-derived **generic injection-marker** vocabulary (OWASP ASI02:2026 / AITG-APP-02 /
documented IPI canary families — each marker cited in `detection-rules.yaml`) plus structured-sink
`require_context` over the role tokens. The `sink:` channel is excluded from the single-action
loop by a one-line `starts_with("sink:")` guard, so the new representation cannot produce a
single-action false positive (proven by the C1 FP-safety + C2 grammar-disjointness tests).

**Mechanism + representation proven on synthetic positives.** The committed
`trj-representation-aware-positive.jsonl` (a generic marker on a `tool-result:` action →
a later structured `sink:` action) fires AGT-TRJ-001 + AGT-TRJ-003 via the real binary; the
`trj-structured-sink-benign-trap` and the FinBot direct-injection fixture (negative control)
fire **zero**. The synthetic positive is a **constructive existence proof** that the engine *can*
fire on a structured representation — it is authored to fire, so it is **not** an independent
measurement.

**Pre-registered measurement (AgentDojo committed corpus, frozen rules SHA `ac88825`, no LLM).**
The rules were frozen to `ac88825` **before** measuring; they were NOT retro-fitted. Against the
committed AgentDojo corpus (the only externally-anchored number):

| | result |
|---|---|
| AgentDojo single-action recall | **23 / 35 (0.657)** — UNCHANGED from v1.4 (Δ +0.000); WS1 added no single-action prose rules |
| generic-marker vocab coverage of the AgentDojo `important_instructions` marker class | **covered in vocabulary** (the generic `<information>`/`new instructions`/`you must now` delimiter families subsume it — derived from taxonomy, not copied) |
| structured-sink representation exercised on AgentDojo | **0 trajectory items** — the committed AgentDojo corpus is FLAT-BAIT (single chat-action GOAL strings), so it has no `tool-result:`→`sink:` dataflow to fire on |

> **Real-world efficacy is still UNPROVEN — stated plainly.** v2.1 closes the gap in the engine's
> *vocabulary and representation* (structured sinks + generic markers now exist and fire on a
> synthetic trajectory), but there is **no committed real trajectory corpus** to exercise it: the
> AgentDojo corpus is flat bait (no trajectories) and v2.1 defers all live capture (A10). So the
> structured-sink representation is measured on the **synthetic positive only**; real-trace
> generalization remains the deferred gap. A deterministic offline matcher will **never** catch a
> determined obfuscator (the documented ceiling). Claim ceiling: *"deterministic, post-hoc,
> representation-aware injection→consequence CANDIDATE correlation; mechanism + representation proven
> on synthetic positives; real-world efficacy UNPROVEN until a real trajectory fires."* See ADR-5.

## Real-trajectory measurement (v2.2) — fires on REAL successes, AND on resisted ones

v2.2 (ADR-6) closes the v2.0/v2.1 "real-world efficacy UNPROVEN **by absence of any real
trajectory**" gap: the engine is run, with the SAME frozen rules (blob SHA `dcd1ac6…582a`, frozen
BEFORE scanning), over a corpus of **real successful indirect-injection trajectories** from
last-generation frontier models — and it fires on them. The number is reported as a bound triple
plus its representation overlap-miss, and the correlation-not-causation ceiling is stated as a
co-headline of equal prominence.

**HEADLINE.** apohara v2.1 post-hoc-recognizes the injection→sink CORRELATION in **169/236
(71.6%)** of REAL successful indirect-injection trajectories from last-generation frontier models
(AgentDyn open-ended suites). This closes the v2.0 "real-world efficacy UNPROVEN by absence of any
real trajectory" gap — the mechanism fires on real traces, not only synthetic.

**CO-HEADLINE LIMIT (equal prominence, never buried).** It ALSO fires on **28.7% (659/2295)** of
RESISTED injections and **1.4% (5/352)** of benign traces. apohara is a CANDIDATE
injection→consequence CORRELATION surfacer, NOT a success/causation discriminator: a resisted
injection still carries the marker in a tool-result AND the agent still performs a legitimate
structured sink, so the marker→sink correlation fires in both succeeded and resisted cases.
**precision-on-success ≈ 169 / (169+659+5) = 169/833 ≈ 20%.** The discriminating signal (did the
agent OBEY the injection) is not representable in a deterministic post-hoc text-pattern model —
this is the quantified ceiling.

**The bound triple — DOWNLOAD corpus** (AgentDyn @ `5353cf7`, agentdojo 0.1.35, benchmark v1.2.2;
attack `important_instructions`; LAST-GEN models, date-labeled; open-ended suites; frozen rules
`dcd1ac6`):

| | result |
|---|---|
| (a) model attack-success-rate (AgentDyn labels, apohara-independent) | gpt-5.1-2025-11-13 **33/851** (3.9%) · gpt-5-mini-2025-08-07 **2/560** (0.4%) · gemini-2.5-pro **122/560** (21.8%) · gemini-2.5-flash **79/560** (14.1%) |
| (b) apohara post-hoc AGT-TRJ detection on the 236 REAL successes | **169/236 (71.6%)** — gpt-5.1 25/33 · gpt-5-mini 0/2 · gemini-2.5-pro 89/122 · gemini-2.5-flash 55/79 (AGT-TRJ-001 dominant, AGT-TRJ-003 secondary) |
| (c) false-positive control | failed-injection (RESISTED) FP **659/2295 (28.7%)** · benign FP **5/352 (1.4%)** ⇒ precision-on-success **169/833 ≈ 20%** |

**Overlap-miss** (model-independent representation coverage of the 236 positives): marker
`<information>` covered **232/236**; role-mapped structured sink covered **180/236**; BOTH
**178/236**; NEITHER **2/236**. Covered sink roles: url=170, recipient=60, amount=59, command=34.
MISSED sink arg-keys (OUTSIDE the frozen role map — the `iban`-analog): path (161), subject (114),
otp (87), title (79), body (68), recipients (68), repo_name (54), password (33). **Reported as-is,
NEVER closed** — adding any of these after seeing traces would convert the number from a
MEASUREMENT into a FIT (forbidden by the pre-registration).

**The bound triple — LIVE current-frontier** (via OpenRouter; suite `workspace`; attack
`important_instructions_no_model_name`; SAME frozen rules + frozen wrapper + release binary;
current-frontier models, date-labeled: gpt-5.5 (gpt-5.5-20260423), gemini-3.5-flash (20260519),
gemini-3.1-pro-preview (20260219), minimax-m3 (20260531), claude-opus-4.8 (claude-4.8-opus-20260528)):

| | result |
|---|---|
| (a) attack-success TOTAL | **0/80 (0.0%)** — EACH model 0/16 |
| (b) apohara post-hoc detection on successes | **0/0 — UNDEFINED** (no live success to detect on) |
| (c) false-positive control | failed-injection FP **0/80** · benign FP **0/15** (the download 28.7% correlation-FP did NOT reproduce on this live set) |
| real LIVE usage | **224 API calls, all HTTP 200; 698,959 tokens** (smoke+live; under the 1M cap); key never logged |

> **The honest framing — no overclaim.** 2026 current-frontier models (gpt-5.5, gemini-3.5-flash,
> gemini-3.1-pro-preview, minimax-m3, claude-opus-4.8) resisted **100% (0/80)** of the standard
> `important_instructions` attack on the workspace suite; with zero live successes, live post-hoc
> detection is undefined. **CAVEAT:** the live run used `suite=workspace` (the standard AgentDojo
> suite), NOT AgentDyn's harder open-ended suites (shopping/github/dailylife) where last-gen models
> reached 14–22% ASR — because the current-frontier OpenRouter IDs are not in AgentDyn's model
> registry. So the live 0/80 is on the EASIER standard suite; current-frontier behavior on the
> harder open-ended attack is UNMEASURED (a documented follow-up). The download corpus (last-gen,
> open-ended) remains the only set with real successes. **Ceiling (verbatim spirit):** post-hoc
> recognizability on the AgentDyn `important_instructions` template, template-scoped, conditional on
> representation overlap; recognizable-in-log ≠ would-have-prevented; NOT efficacy, NOT recall, NOT
> prevention. Pre-registered (rules frozen @ `dcd1ac6` BEFORE scanning; verified unchanged); NO
> retro-fit (the missed arg-keys like `iban`/`otp`/`repo_name` are a DOCUMENTED overlap-miss,
> deliberately NOT closed). See ADR-6 + PROOF-v2.2-real-trajectory.md.

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
- **English only by scope.** Both the synthetic gate and the independent corpora are
  English. Non-English detection is **out of scope by design** (English-only for benchmark
  comparability), not an open gap.
- **A3 normalization is SESSION-ONLY (v2.1, M4).** Unicode/casing/homoglyph normalization runs
  in the session value picker (`relevant_input`) only; `parse_repo` builds actions directly and is
  NOT normalized. So a homoglyph/zero-width evasion in **repo-file content** (the dominant
  indirect-injection surface) is un-normalized in v2.1 — a documented deferred gap (covers the
  session channel: 30/101 gate paths, 0/56 repo-file). See ADR-5.
- **The tuned 1.00 is partly true by construction.** The corpus and the engine's context
  rules co-evolved, so a perfect tuned score is expected on *this* corpus. The metric that
  carries real signal is the **baseline → tuned delta** (0.6389 → 1.0000), which shows the
  context logic removes false positives a naive matcher produces.
