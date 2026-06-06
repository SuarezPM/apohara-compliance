# ADR-2 — Multi-action (sequence/taint) matching for ASI06

**Status:** Accepted — design, Rev 2 (amendments A–E folded from architect design review) ·
**Date:** 2026-06-06 · **Supersedes:** none
**Extends:** ADR-1 (the CLOSED 3-field context DSL — `source_kinds` / `require_context` /
`deny_context`, frozen in `rules.rs:139-144`). ADR-1 explicitly says richer matching
(taint/dataflow) "is a separate ADR, not a quiet 4th field." **This is that ADR.**

## Context

ASI06 (OWASP Top 10 for Agentic Applications 2026 — *Memory & Context Poisoning*) is
intrinsically a **two-action correlation**: a tool result / retrieved content carrying
injection markers, **followed by** a write of that content into a memory / RAG / persist
sink, where it lies dormant and biases a later session. The current engine cannot express
this:

- `match_actions_with_suppress` (`matching.rs:275`) loops **one action at a time** over the
  compiled single-action signals; `context_verdict` inspects only `action.value` (a single
  action's text). There is **no sequence / ordering / "followed-by" primitive**.
- The context DSL is FROZEN to 3 single-action modifiers (`rules.rs:139-144`).
- A "memory/RAG sink" is **not currently an observable source kind** — `parse_session.rs`
  / `parse_otlp.rs` label actions `session:{Tool}.input`; nothing distinguishes a persist.

So AGT-PI-003 (Indirect Prompt Injection) already xrefs ASI06 (`detection-rules.yaml:87`)
as the closest single-action approximation, but there is no rule that captures the
*persist-then-trigger* mechanism that makes ASI06 distinct (and time-decoupled) from ASI01.

**Impact analysis (mandatory, `gitnexus_impact match_actions_with_suppress` upstream):
CRITICAL — 23 impacted, 10 direct callers, 9 processes, 6 modules.** Every scan path
(session/repo/otlp/action/gap) and the precision gate route through the matcher. This is
the dominant design constraint: **the existing single-action path must not change.**

## Decision

Add multi-action **sequence** matching as an **additive, opt-in second pass** — never a
modification of the single-action loop.

### 1. Rule schema — a new optional `sequence` block (no 4th *context* field)

`DetectionRule` gains one `#[serde(default)] pub sequence: Option<SequenceRule>`. The frozen
3-field context DSL is untouched; `sequence` is a **rule-shape** discriminator, not a 4th
context modifier:

```yaml
# detection-rules.yaml — a sequence rule (single-action rules omit `sequence`)
- agt_code: AGT-MEM-001
  name: Unsanitized content persisted to memory/RAG (candidate poisoning vector)
  asi_xref: ["ASI06"]
  sequence:
    source_step:                 # the marker-bearing action
      signals: ['(?i)\[\[SYSTEM\]\]', '(?i)ignore (all )?previous instructions', ...]
      source_kinds: []           # any source (tool result, retrieved doc)
    sink_step:                    # the persist/memory write that follows
      signals: ['(?i)\b(memor(y|ize)|persist|upsert|embed|rag|vector ?store)\b', ...]
      source_kinds: ["session:Bash", "otlp:"]   # observable-today (amendment B); NOT session:Memory/Write
    # ordering: a source_step action at index i, a sink_step action at index j>i.
```

`SequenceRule { source_step: Step, sink_step: Step }`, `Step { signals: Vec<String>,
source_kinds: Vec<String> }`. Steps reuse the EXISTING regex + `source_kinds` prefix
semantics (no new matching primitive beyond ordered pairing).

### 2. Engine — a separate second pass, compiled separately

- `compile_rules` partitions rules: single-action rules (no `sequence`) compile into
  `engine.signals` **exactly as today**; sequence rules compile into a new
  `engine.sequences`. A rule is in exactly one partition.
- `match_actions_with_suppress` runs the existing per-action loop **unchanged**, then calls
  a new `match_sequences(actions, &engine.sequences, rules, suppress)` and appends its
  findings/suppressed. The new pass scans the **full `actions` slice** for an ordered
  (source_step → sink_step) pair and fires **one candidate per rule** (deduped like the
  single-action path; allowlist + suppress channel reused).
- Determinism preserved: same ordered scan, same dedup. Candidate-only framing identical
  (SARIF note/warning, `CANDIDATE —`, `is_candidate=true`).

### 3. Source vocabulary — recognize a memory sink, honestly bounded

`parse_session.rs` / `parse_otlp.rs` already emit `session:{Tool}.input`. The sink_step
matches memory writes by (a) `source_kinds` prefix on known memory/RAG tool labels and (b)
`signals` regex on persist verbs. **Coverage limit (honest):** this sees only what the
transcript/telemetry names — if a memory write is performed by an unrecognized tool with no
persist-verb in its args, it is invisible. AGT-MEM-001 is therefore a **candidate that
content *could* poison memory**, never a detection of activated cross-session poisoning.

## Rev 2 amendments (binding — from the architect design review)

These supersede the prose above where they conflict; they are binding ACs for the
implementation.

- **A (CRITICAL) — filter, never renumber.** `compile_rules` MUST keep `agt_index` a
  positional index into the FULL `rules.detection.rules[]` (`matching.rs:161,290,296` rely
  on `engine.contexts[i]` ↔ `rules.detection.rules[i]` 1:1). Sequence rules contribute ZERO
  `CompiledSignal`s to `engine.signals` (so the single-action loop never sees them) but are
  NOT renumbered out: iterate the full vec with `.enumerate()`, push a context for every
  rule, and route by `match &rule.sequence { None => signal, Some(_) => sequence }`. The
  word "partition" in §2 means *filter*, not *re-index*.

- **B (HIGH) — sink vocabulary = observable-today (B-narrow chosen).** `parse_session.rs:
  169-172` surfaces only `file_path` for Write/Edit (NOT the written content), and no
  `Memory` tool exists, so `session:Memory`/`session:Write` sinks are near-unfireable.
  CHOSEN: scope `AGT-MEM-001`'s sink_step to what IS observable — a **`session:Bash`
  persist command** (e.g. writing to a vector store / memory file: `psql … INSERT INTO
  embeddings`, redis/`SET`, `>> ~/.../memory`, `chroma`/`qdrant`/`faiss` CLIs) and **generic
  `otlp:` records** whose body carries a persist verb. DROP `session:Memory`/`session:Write`
  from the sink vocabulary. (Future: a separate parser ADR could surface Write/Edit content
  under a NEW source namespace — e.g. `content:Write` — that existing rules do not match;
  that is out of scope here.) The coverage limit is documented honestly: AGT-MEM-001 fires
  on a marker-bearing action followed by a Bash/OTLP persist — it does not see memory writes
  performed by tools whose content the parser does not surface.

- **C (process).** B is a prerequisite of AGT-MEM-001's corpus ACs — the non-duplicate
  discriminator (below) is only honestly satisfiable once the sink is observable.

- **D (CRITICAL) — guards the precision gate does NOT provide.** Add, before merge:
  1. a **byte-identical-output test**: a captured fixture run through the engine with the
     existing 16 rules (no sequence rule) serialized identically before/after the
     `compile_rules` change (the precision gate is set-membership and can mask an index bug);
  2. a **`matching.rs` alignment unit test**: with a sequence rule loaded, assert for every
     `CompiledSignal` that `rules.detection.rules[cs.agt_index].agt_code` equals the agt_code
     it was compiled from, and `engine.contexts.len() == rules.detection.rules.len()`.

- **E (HIGH leverage) — minimize the diff to the CRITICAL module.** The ordered-pair scan
  lives in a NEW module `crates/scanner/src/sequence.rs`. The behavioral delta to
  `matching.rs` is exactly: (1) the agt_index-preserving filter in `compile_rules` (+ an
  `engine.sequences` field), and (2) ONE trailing `sequence::match_sequences(...)` call in
  `match_actions_with_suppress` before it returns `MatchOutcome`. `build_finding` becomes
  `pub(crate)` (visibility only) so `sequence.rs` reuses it. When no sequence rule is loaded
  the trailing call is a no-op, so the byte-identical path (D.1) is trivially green.

- **Corpus/harness note.** `precision_recall.rs` feeds ONE action per corpus item; a sequence
  needs TWO ordered actions, which the synthetic-gate item shape does not express. Therefore
  AGT-MEM-001's positive behavior is covered by a DEDICATED multi-action integration test
  (≥1 marker→persist sequence firing AGT-MEM-001 but NOT AGT-PI-003), while the synthetic
  gate asserts the NEGATIVE half of the discriminator: AGT-MEM-001 fires on ZERO of the 76
  single-action corpus items (per-rule count `AGT-MEM-001` == 0). This keeps the synthetic
  gate's numbers byte-unchanged (Principle 3) while still proving the rule is non-duplicate.

## Alternatives considered

- **A. Thread sequence-state into the existing per-action loop.** Rejected — it would
  rewrite the CRITICAL single-action path (10 direct callers, 9 processes) and risk
  regressing every existing rule. The whole point of the second pass is to leave it alone.
- **B. A single-action AGT-MEM-001 keying on injection markers.** Rejected — it duplicates
  AGT-PI-003 (`detection-rules.yaml:82` already keys on "tool output contains command") and
  cannot express persist-then-trigger; it would be a near-duplicate or near-unfireable rule
  (the consensus's central objection).
- **C. Full taint/dataflow (tree-sitter/AST).** Deferred — far larger; the ordered-pair
  second pass is the minimum that expresses ASI06 honestly. A future ADR can extend it.

## Consequences

- **+** ASI06 becomes a real, non-duplicate capability; the frozen 3-field DSL and all 16
  existing single-action rules are byte-identically unaffected (they have no `sequence`).
- **+** OTLP/session/repo inputs all feed the same second pass for free.
- **−** New engine surface (`engine.sequences`, `match_sequences`) on the highest-fan-in
  module — guarded by the non-regression gate below.
- **−** Sink recognition is exporter/transcript-bounded (documented limit, candidate-only).

## Verification (binding ACs for the implementation)

1. **No-regression on the single-action path:** the full synthetic precision/recall gate
   (`precision_recall.rs`, global precision ≥ 0.85, recall non-regression) stays green with
   ALL existing rules after the engine change. Byte-identical output for any input with no
   sequence rules active.
2. **AGT-MEM-001 is novel, not a duplicate:** ≥1 synthetic corpus item fires AGT-MEM-001 but
   **NOT** AGT-PI-003, and AGT-MEM-001 fires on **ZERO** pre-existing corpus items (checked
   via the per-rule counts at `precision_recall.rs:231-253`).
3. **Corpus:** ≥3 true-positive sequence items + ≥3 FP-trap items (e.g. a documented example
   of memory APIs with no injection marker; an injection marker with no subsequent persist).
4. **Honesty:** docs + rule description say "content that could poison memory" / candidate,
   never "detects memory poisoning" or any runtime/cross-session guarantee; `NEGATIVE_GUARD`
   (verify.sh) clean.
5. **Determinism + tolerance:** unchanged; sequence pass never panics on degenerate input.
