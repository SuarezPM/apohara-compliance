# PRE-REGISTRATION — v2.3 Argument-Value Provenance (Causal Proxy, post-hoc)

**This file is committed BEFORE any rule edit, BEFORE any re-measurement scan.**
The rule schema, the new flag, the normalization, the length floor, and the dev/test
split are FROZEN at the SHA recorded below. **No edit after this point is "fitting" the
result** — any post-SHA change to those fields invalidates the number as a measurement
(it becomes a fit) and the report MUST be labeled "post-prereg-modified (fit, not
measurement)".

This is the third pre-registration in the project (preceded by `PREREG-v2-agentdojo.md`
and `PREREG-v2.2-real-trajectory.md`); the discipline is the same.

## Frozen schema fields (FROZEN at the SHA below — record BEFORE any code change)

The v2.3 change is **ADDITIVE, OPT-IN, DECLARATIVE**. The CLOSED 3-field context DSL
(ADR-1) is untouched; the `taint` discriminator (ADR-4) is extended by ONE field. The
schema change ships in two commits but is the SAME conceptual addition:

- **File A** (engine): `crates/scanner/src/rules.rs` — `TaintRule` gains:
  ```rust
  #[serde(default)]
  pub require_value_from_source: Vec<String>,
  ```
  Absent (the default) ⇒ ordinary AGT-TRJ behavior, byte-identically unchanged. This
  is `#[serde(default)]` ⇒ existing YAML rules (AGT-TRJ-001/002/003) deserialize
  unchanged, and their behavior is preserved (no value-provenance check is performed).
- **File B** (engine): `crates/scanner/src/taint.rs` — `match_taints` gains value-latch
  + provenance check, gated on `rule.require_value_from_source.is_empty() == false`.
  When the flag is empty, the function executes the v2.2 path BYTE-IDENTICALLY (the
  exact same `taint_step_match` calls, in the same order, with the same return values).
- **File C** (rules): `crates/scanner/references/detection-rules.yaml` (and the
  byte-identical `references/detection-rules.yaml`) gains THREE new entries
  AGT-TRJ-001-P / -002-P / -003-P (mirrors of the originals with the new flag
  non-empty). The originals are NOT modified.
- **File D** (compile-time): `crates/scanner/build.rs` and `references/detection-rules.yaml`
  `total:` field and `verified_on:` date.

## Frozen semantics of `require_value_from_source` (NOT to be tuned post-scan)

When the flag is non-empty for a given rule and the rule's `taint_sink` step matches an
action at index `i`, apohara does the following BEFORE firing the candidate:

1. **Latch the source value** of the most recent `taint_source` match (a `&str` slice
   of the prior `action.value`). The latch is the same `tainted: Option<&str>` slot
   used by the v2.2 forward-correlated taint pass — no new state, no extra scan.
2. **Extract authority-role values** from the matched sink action's canonical string
   via the FROZEN field-name map (the same one the v2.2 `sink:` grammar uses, recorded
   in PREREG-v2.2-real-trajectory.md): `recipient ← {recipient, to, dest, destination,
   account, payee, email}`, `amount ← {amount, value, sum, total}`, `url ← {url, link,
   href, uri}`, `command ← {command, cmd, shell, exec, run}`. The value is the
   whitespace-split token(s) following the matched field name in the sink canonical
   string. Multiple matches per role are unioned.
3. **Normalize** each candidate value: ASCII-lowercase (Unicode case folding deferred
   to a future prereg). No whitespace stripping, no punctuation removal — these
   were explicitly considered and REJECTED in DD-2 of the v2.3 plan (lowest
   coincidental-match risk; documented as a future separate prereg).
4. **Length floor**: each candidate value MUST be `>= 6` characters (post-normalization).
   This is the anti-coincidence guard from R3 of the v2.3 plan.
5. **Provenance check**: each role's unioned values (after length floor + normalization)
   must contain a value that is a **substring** of the latched source value. If NO role
   finds a substring match, the candidate is SUPPRESSED (no finding fires). If at least
   one role finds a substring match, the candidate fires AND the `signal` string
   includes the role tag (audit trail without echoing raw values).

The frozen values are: `Vec<String>` content (role name list — e.g. `["recipient",
"amount"]`), normalization = ASCII-lowercase, length floor = 6, comparison = substring
of latched source. **No threshold, no weight, no semantic similarity** — this is a
pure exact-substring check on ASCII-lowercased authority-role values. Future extensions
(Unicode case folding, weighted role scores, semantic similarity) are EXPLICITLY
deferred to a separate prereg and are NOT in v2.3.

## Frozen tooling (apohara-agnostic — same as v2.2)

- **1:1 wrapper** — `scripts/eval/wrap_agentdojo_trace.py` (FROZEN at the v2.2
  faithfulness self-test; consumed unchanged).
- **Bucket extractor** — `scripts/eval/extract_agentdyn_positives.py` (FROZEN).
- **Polarity gate** — `scripts/eval/assert_polarity.py` (FROZEN).
- **Counter** — `scripts/eval/count_agentdyn_positives.py` (FROZEN).
- **NEW for v2.3**: `scripts/eval/split_v23_devtest.py` — stratified 20/80 dev/test split
  of the 236 positives (deterministic seed: SHA256("v2.3-argument-value-provenance")
  = `<recorded below>`); records `eval/v23/split.json` with the dev/test file lists +
  per-model+suite counts.

## Frozen corpus (the same v2.2 AgentDyn runs)

- **Upstream:** SaFo-Lab/AgentDyn (MIT), commit
  `5353cf7615b135cace8d07c8f12dac53a16b6db3` (2026-05-19).
- **`agentdojo_package_version` 0.1.35; `benchmark_version` v1.2.2.**
- **Committed suites** (already in `eval/agentdyn/runs/`): shopping, github, dailylife.
  (AgentDojo 4 baseline suites are gitignored as in v2.2.)
- **Models** (last-gen, date-labeled): `gpt-5.1-2025-11-13`, `gpt-5-mini-2025-08-07`,
  `google_gemini-2.5-pro`, `google_gemini-2.5-flash`. Distribution of 236 positives
  by (model, suite):
  - `google_gemini-2.5-pro × dailylife`: 63
  - `google_gemini-2.5-flash × dailylife`: 55
  - `google_gemini-2.5-pro × shopping`: 30
  - `google_gemini-2.5-pro × github`: 29
  - `gpt-5.1-2025-11-13 × dailylife`: 22
  - `google_gemini-2.5-flash × github`: 18
  - `gpt-5.1-2025-11-13 × github`: 7
  - `google_gemini-2.5-flash × shopping`: 6
  - `gpt-5.1-2025-11-13 × shopping`: 4
  - `gpt-5-mini-2025-08-07 × github`: 2

## Frozen dev/test split (stratified 20/80 by model × suite, deterministic)

For each (model, suite) bucket above, 20% of the positives are assigned to DEV and
80% to TEST, using a deterministic pseudo-random shuffle keyed by the bucket's
SHA-256 of the file path (no global RNG). The split script `split_v23_devtest.py`
records the assignment + a per-bucket count manifest at `eval/v23/split.json`.
**Normalization sanity check** (verify the 6-char floor + ASCII-lowercase do not
match coincidentally on common boilerplate) runs ONLY on DEV. The headline
v2.3 numbers are computed on TEST. **No re-shuffle, no re-balance after this
point** — that would be a fit.

## Metric definitions (the bound triple, same as v2.2 + new column)

For each row of the v2.3 report:
- (a) **model attack-success-rate** — same as v2.2 (AgentDyn's own `security` label).
- (b) **apohara correlation post-hoc** — k-of-N AGT-TRJ-* candidate fires on the
  236 positives (the v2.2 number, restated for context; this DOES NOT change in
  v2.3 because the originals are byte-identical).
- (c) **apohara provenance-gated post-hoc (NEW, v2.3)** — k'-of-N AGT-TRJ-*-P
  candidate fires on the same 236 positives. Reported side-by-side with (b).
- (d) **failed-injection + benign FP** — of the 2295 FAILED and 352 BENIGN, how
  many fire AGT-TRJ-*-P (must be ~0). The provenance gate should REDUCE (b)'s
  28.7% correlation FP. The honest number, whatever it is, is reported.

## Frozen SHA (record AFTER this commit; recorded BEFORE any source change)

- **PREREG-v2.3.md blob SHA** (to be filled in by the post-commit hook in the
  implementation step): `<SHA-after-commit>`.
- **Last commit that touched `crates/scanner/references/detection-rules.yaml` BEFORE
  the v2.3 edit**: `9a0385f` — "feat(scanner): structural shell tokenizer for
  flag-reorder evasions (v2.1 WS2-b / AC3.3, ADR-5 S1)".
- **Current `detection-rules.yaml` blob SHA** (BEFORE any v2.3 edit):
  `dcd1ac6e1d7ed8dce4b5b516296e8ce5a3e0582a` (verified via
  `git hash-object crates/scanner/references/detection-rules.yaml`; the project-root
  copy is byte-identical, `cmp` verified).

## MUST NOT (anti-fit guards)

- NO `iban` (or any other) field added to the `sink:` role map after seeing traces.
- NO threshold tuning, no weight adjustments, no semantic similarity scoring.
- NO Unicode case folding in v2.3 (deferred to a future prereg).
- NO deviation from the substring-of-source-value check.
- NO re-shuffle or re-balance of the dev/test split.
- NO claim of causation: v2.3 is a *proxy* (post-hoc substring-match on the source
  value), not a proof that the sink action was caused by the injection.

## Honest ceiling (the v2.3 claim)

v2.3 reports: "of the 236 successful-injection trajectories, AGT-TRJ-*-P fires on
k' of N. This is a post-hoc substring match between the authority-role values in
the sink and the source value. It is a *necessary-but-not-sufficient* proxy for
injection→consequence causation: it eliminates the FP class where the same sink
fires on a clean trajectory, but it does not prove the value was LIFTED from the
injection versus COINCIDENTALLY present in the injection text. Verbatim-flow
constraint only; no cross-step laundering (PACT does that, apohara does not)."
