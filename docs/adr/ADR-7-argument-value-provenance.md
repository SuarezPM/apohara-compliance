# ADR-7: Argument-Value Provenance — a causal proxy (post-hoc, verbatim-flow, opt-in)

**Status:** ACCEPTED (v2.3, 2026-06-09). Base = v2.2 (ADR-6). All LOCAL.
Pre-registration: `tests/corpus/PREREG-v2.3.md` (rules frozen at blob SHA
`dcd1ac6e1d7ed8dce4b5b516296e8ce5a3e0582a` BEFORE any source edit; verified
UNCHANGED at the time of re-measure; SHA `5e62e9e2c4cfdf2a2e13c0005ae384c2f4a42eeb`).
Honesty lineage: v2.0/ADR-4 (mechanism proven on synthetic positives; real-world
efficacy UNPROVEN) → v2.1/ADR-5 (representation gap closed; structured sinks
fire) → v2.2/ADR-6 (mechanism MEASURED on real successful trajectories;
correlation-not-causation ceiling quantified at 28.7% on FAILED + 5/352 on
BENIGN) → **v2.3/ADR-7 (the correlation-FP is mechanically killed by an
argument-value-provenance gate, BENIGN FP zeroed, FAILED FP halved, but the
52.1% headline is a post-hoc proxy — not causation).**

## Context

v2.2 quantified a correlation-not-causation ceiling: 138/192 (71.9%) of
TEST-positive trajectories fire an AGT-TRJ-* candidate, but the same binary
also fires on 28.7% of FAILED-injection trajectories and 5/352 of BENIGN
trajectories. The 28.7% FAILED rate is the biggest concern — apohara's
post-hoc candidates are surfacing genuine correlations between injection
markers and structured sinks on trajectories the agent ultimately resisted,
plus a small set of cases where the agent's legit action happens to be
matched by the AGT-TRJ candidate without the value being injection-derived.
The 5/352 BENIGN is the canary: the candidate fires on a clean (no-injection)
trajectory, which is a clear false positive.

The v2.3 plan (`.omc/plans/v2.3-followups.md`, RALPLAN Rev 1, 2026-06-08)
identified the mechanism: when the same AGT-TRJ candidate fires on a clean
trajectory, the sink's authority-role values (recipient, amount, url,
command) do NOT appear in the (absent or clean) source value. A provenance
check — "at least one authority-role value from the sink is a substring of
the latched source value" — kills the FP class.

PACT (arxiv 2605.11039), ARM (arxiv 2604.04035), and NeuroTaint (arxiv
2604.23374) all implement argument-provenance in the RUNTIME/PREVENTIVE
layer (block before the sink). apohara stays POST-HOC; v2.3 takes the
deterministic exact-structural-matching subset (PACT Layer-1, ARM Layer-3
string-match) and applies it to historical transcripts instead of live
enforcement. This is the established first line; verbatim-flow only; no
cross-step laundering.

## Decision

Add a single, OPT-IN, ADDITIVE field to `TaintRule` (`crates/scanner/src/rules.rs`):

```rust
#[serde(default)]
pub require_value_from_source: Vec<String>,
```

The flag is empty by default. The original AGT-TRJ-001/002/003 rules
deserialize unchanged (the field's default is an empty `Vec`), and
`match_taints` runs the v2.2 path byte-identically when the flag is empty
(verified by 13 existing taint tests + a new explicit v2.2-vs-v2.3
side-by-side test). The new AGT-TRJ-001-P / -002-P / -003-P variants
mirror the originals, with the flag non-empty (the OPT-IN).

When the flag is non-empty for a rule AND the rule's `taint_sink` step
matches an action at index `i`, the engine runs the v2.3 PROVENANCE CHECK
before firing the candidate:

1. **Latch the source value** (already done for the v2.2 forward-correlated
   pass; the latch slot is extended from `&str` to `(&str, &str)` so the
   action's value persists alongside the matched signal).
2. **Extract authority-role values** from the matched sink's canonical
   string via the FROZEN `sink_role_field_map` (recipient ←
   {recipient, to, dest, destination, account, payee, email}; amount ←
   {amount, value, sum, total}; url ← {url, link, href, uri}; command ←
   {command, cmd, shell, exec, run}). Whitespace tokens are split on `=`
   or `:`, the value is taken as everything after, ASCII-lowercased.
3. **Length floor 6**: each candidate value MUST be `>= 6` characters
   (anti-coincidence guard from R3 of the v2.3 plan; values like "go",
   "ok", "the" are excluded).
4. **Substring check**: at least one candidate value (per role) must be a
   **substring** of the latched source value (ASCII case-sensitive after
   both sides have been lowercased).
5. If no candidate value is a substring of the source value, the candidate
   is SUPPRESSED (logged as `provenance-gate: <code> (no value-flow)`,
   NOT counted as a finding NOR as an allowlist suppression — it's the
   v2.3 post-hoc filter).

The frozen values are: role-set content (a list of role names like
`["recipient", "url"]`), normalization = ASCII-lowercase, length floor = 6,
comparison = substring-of-source. **No threshold, no weight, no semantic
similarity** — this is a pure exact-substring check. Future extensions
(Unicode case folding, weighted role scores, semantic similarity) are
EXPLICITLY deferred to a separate prereg and are NOT in v2.3.

## What v2.3 measured

Test split: 192 positives (deterministic 20/80 split, 44 dev / 192 test,
SHA-256 of `salt + path` < 20% → DEV). Corpus: AgentDyn commit 5353cf7
(MIT), 4 last-gen models (gpt-5.1/5-mini 2025 dated tags, gemini-2.5-pro/flash),
3 open-ended suites (shopping, github, dailylife). 236 positives total,
2295 FAILED, 352 BENIGN. Frozen at v2.2 scan; re-scanned with the v2.3
binary.

```
(b) v2.2 correlation post-hoc AGT-TRJ-* on the 192 TEST positives
    TOTAL                                  138  192 (71.9%)

(c) v2.3 -P provenance-gated AGT-TRJ-*-P on the 192 TEST positives
    TOTAL                                100  192 (52.1%)

(d) FP controls:
    FAILED-injection: corr=659/2295 (28.7%)   -P=319/2295 (13.9%)
    BENIGN:           corr=5/352   (1.4%)     -P=0/352   (0.0%)
```

- The -P gate **zeroed the BENIGN FP** (5 → 0): the v2.2 corr made 5
  spurious AGT-TRJ fires on clean (no-injection) trajectories; the v2.3 -P
  gate eliminated all of them because the legit recipient/command never
  appears in a source value that lacks an injection marker. This is the
  FP-killer demo, **100% on the BENIGN bucket**.
- The -P gate **halved the FAILED-injection FP** (28.7% → 13.9%): the
  remaining 319 are trajectories where the agent received a marker but did
  NOT exfiltrate/destruct/send-money; the v2.2 corr fires on the
  marker+structured-sink combination regardless, the v2.3 -P suppresses when
  the sink values aren't in the source.
- The -P gate dropped 38 candidates on TEST positives (138 → 100, 52.1%).
  The drop is concentrated in `AGT-TRJ-003-P` (financial) — 48 → 20
  (58% drop on this code) — because the legit IBAN is not in the injection
  source. `AGT-TRJ-001-P` (exfil) dropped from 135 → 80 (40% drop on this
  code) for the same reason. `AGT-TRJ-002-P` (destructive) fired 0/192 —
  this is the honest v2.3-plan prediction: a destructive command (`rm -rf`,
  `DROP TABLE`) is rarely a verbatim substring of a generic injection.

## What v2.3 is NOT

- **NOT causation.** The 52.1% headline is a **post-hoc substring-match
  proxy**, not proof the value was LIFTED from the injection versus
  COINCIDENTALLY present in the injection text. Verbatim-flow only; no
  cross-step laundering (PACT does that, apohara does not). The honest
  ceiling: "necessary-but-not-sufficient proxy for injection→consequence
  causation: it eliminates the FP class where the same sink fires on a clean
  trajectory, but it does not prove the value was lifted from the
  injection."
- **NOT runtime/preventive.** Post-hoc over transcripts, never inline
  enforcement. PACT/AuthGraph/NeuroTaint operate at runtime; apohara scans
  transcripts. The two are complementary; apohara does not claim to be a
  PACT substitute.
- **NOT Unicode-aware.** v2.3 is ASCII-only case folding. Non-ASCII
  characters in authority-role values are passed through as-is and will
  not match a non-ASCII source value. Deferred to a future prereg.
- **NOT semantic.** v2.3 is exact-substring only. `evil@attacker.test` is
  a substring of the source; `evil(at)attacker(dot)test` is not. No fuzzy
  match, no Levenshtein, no embedding similarity. Deferred.
- **NOT retroactive.** The v2.2 numbers (138/192, 28.7%, 5/352) are
  PERMANENT and UNCHANGED. The v2.3 -P numbers are an additional column,
  not a replacement.

## Consequences

- **Schema delta**: `TaintRule` gains one `#[serde(default)]` field. The
  schema version stays at 1 (backward-compatible). Existing YAML rules
  deserialize unchanged.
- **Engine delta**: `CompiledTaint` gains the same field; `match_taints`
  latches `(source_sig, source_value)` instead of just `source_sig`. The
  v2.2 path is byte-identical (same `taint_step_match` calls, same order,
  same return values; only the latch slot is extended to a tuple). Verified
  by 13 existing taint tests + the explicit `v23_g_empty_flag_byte_identical_to_v22`
  side-by-side test.
- **Rule delta**: 3 new AGT-TRJ-001/002/003-P variants. Total rules:
  24 → 27. The originals are NOT modified.
- **Test delta**: 9 new tests (7 unit per plan §0 a-g + 2 integration FP-
  killer demos). 180 → 189 tests, all green.
- **CLI delta**: NONE. The v2.3 -P variants are regular rules, scanned by
  the same `scan-session` command. No new flag, no new subcommand.
- **crates.io / GH Release delta**: NONE per the rule's byte-identical
  fallback. The next release (v2.3.0) bumps the version and the README
  version line; everything else stays the same.

## Anti-fit guards (PREREG-frozen)

- NO `iban` (or any other) field added to the `sink:` role map after seeing
  traces.
- NO threshold tuning, no weight adjustments, no semantic similarity
  scoring.
- NO Unicode case folding in v2.3.
- NO deviation from the substring-of-source-value check.
- NO re-shuffle or re-balance of the dev/test split.
- The PREREG blob SHA is unchanged post-scan (verified
  `git hash-object`).
- The rules SHA changed ONLY because the three PREREG-specified -P rules
  were appended; the per-rule structure of the originals is byte-identical.
