# ADR-5: Representation-Aware Taint + Evasion-Robust Matching

**Status:** ACCEPTED (v2.1, 2026-06-07). ralplan DELIBERATE consensus APPROVE (Planner → Architect
SOUND-WITH-CHANGES[11] → Critic ITERATE[C1/C2 + M1–M4] → Rev 2 → Architect re-review[N1] → Critic
ACCEPT → Rev 3). Plan: `.omc/plans/v2.1-representation-aware-taint-and-evasion-robustness.md`.
Base = v2.0 (HEAD `9e1a78a`). All LOCAL.

## Context

v2.0 (ADR-4) shipped the trajectory taint engine but its real-world efficacy was measured UNPROVEN
for two reasons: (1) MiniMax-M3 refused all 10 AgentDojo injections, so no real positive trace
existed; (2) a VERIFIED **representation gap** — AgentDojo's `<INFORMATION>…` marker and structured
tool-call sinks (`send_money(recipient, amount)`) did not overlap apohara's text-pattern
`taint_source`/`taint_sink` vocabulary, so even a successful trace would very likely not have fired.
ADR-5 closes that representation gap and hardens the matcher against cheap evasions — additively,
deterministically, offline — without graduating the honest claim ceiling.

## Decision

Extend the deterministic engine to be REPRESENTATION-AWARE and EVASION-ROBUST:

1. **Structured-sink channel (`sink:` reserved prefix).** `parse_session` ADDITIVELY emits a NEW
   `sink:{name}` action whose value is a deterministic canonical role string
   (`const SINK_GRAMMAR = "tool-call:{name}[ recipient={v}][ amount={v}][ url={v}][ command={v}]"`),
   built by a small field-name→role map (recipient/amount/url/command — **authority-role fields
   ONLY, never free-text body/note**). The existing flat `session:{name}.input` action is
   byte-identical. The AGT-TRJ taint rules gained `source_kinds: ["sink:"]` on their sink side plus
   structured `require_context` over the role tokens, so a structured tool-call now counts as a
   sensitive sink (the existing `session:Bash/Write/Edit` sinks are kept — additive).

2. **`sink:` single-action isolation (C1-a / C2).** The new action is excluded from the
   single-action loop by a one-line guard `if action.source.starts_with("sink:") { continue; }` at
   the top of `match_actions_with_suppress`. The reserved **PREFIX** (not a `.sink` suffix) is
   collision-proof: no existing source starts with `sink:` (the five producers emit
   `session:{name}.input`, `tool-result:{id}`, `repo-path:{path}`, `repo-file:{path}`, OTLP
   `session:{tool}.input`) — so the guard is byte-identical for the existing corpus AND all real
   repos. (The Rev-2 `ends_with(".sink")` suffix form was REJECTED — it collided with a repo file
   named `foo.sink` → `repo-path:foo.sink`/`repo-file:foo.sink`, a gate-invisible false NEGATIVE;
   bug N1.) The canonical grammar is frozen as a code-level `const` + asserted; a guard test
   iterates the LIVE compiled single-action signal set and fails if any signal is a substring of the
   role-key vocab (`recipient=`/`amount=`/`url=`/`command=`).

3. **Generic injection markers (pre-registered).** The AGT-TRJ `taint_source` vocab gained a
   TAXONOMY-DERIVED generic marker set (OWASP ASI02:2026 / AITG-APP-02 / documented IPI canary
   families — each marker carries a `# source:` citation in `detection-rules.yaml`): a generic
   fake-delimiter tag family (`<system>`/`<important>`/`<instruction>`/`<information>` …) plus
   "new instructions", "additional instructions", "you must now", "the user actually/really wants".
   This is a GENERIC family that happens to subsume AgentDojo's `<INFORMATION>` — NOT a verbatim
   retro-fit. Rules were frozen to git SHA `ac88825` BEFORE measuring (pre-registration).

4. **A3 SESSION-ONLY haystack normalization.** `relevant_input` (the session value picker, risk
   LOW) normalizes its picked value before it becomes an `ObservedAction`: zero-width strip
   (ZWSP/ZWNJ/ZWJ/BOM/soft-hyphen) → frozen confusable/homoglyph fold (Cyrillic/Greek ASCII
   lookalikes, **Unicode confusables.txt 15.1.0**, a small in-file frozen table) → Unicode **NFKC**
   (via the pure-Rust `unicode-normalization` crate) → whitespace canonicalization. Hand-authored
   token-final morphology stays EMPTY/frozen (the US-F0-2 `truncate`→`truncated` hazard); in-scope =
   Unicode-DEFINED equivalences only.

5. **F1 pattern families.** Anchored family regexes (one per sub-family, non-combinatorial) extend
   AGT-MIS-001's destructive-command coverage: `rm -fr`, `rm -r -f`, `rm --recursive --force`,
   `dd if=`, `mkfs`, `TRUNCATE TABLE` — each shipped with its nearest benign FP-trap in the same
   commit. No `compile_signal` change (A2 invalidated); families are just more `signals`.

6. **S1 structural shell matching (`shell:` opt-in construct).** A NEW opt-in `shell:` rule block
   (sibling to `sequence:`/`taint:`), handled by a self-contained `crates/scanner/src/shell.rs`
   pass appended AFTER `match_taints` (additive, no-op when empty → byte-identical). It tokenizes
   `session:Bash` actions with the zero-dep pure-Rust `shlex` (≥1.3.0, post-RUSTSEC-2024-0006),
   extracts argv[0] basename + a normalized flag SET (bundled `-rf`→{r,f}; `--recursive`↔`r`,
   `--force`↔`f`), and fires when `binary == rule.binary` AND every `all_flags` entry is present —
   defeating flag REORDERING/spacing/bundling that the regex families miss. New rule AGT-MIS-004
   "Destructive Command (structural)" (`rm` + {r,f}); rule count 23 → 24.

The single-action matcher and the FROZEN 3-modifier context DSL (ADR-1) are byte-identically
unchanged; AGT-MEM-001 (ADR-2) and the existing AGT-TRJ taint pass (ADR-4) are untouched
semantically. New capability = a new parser source-kind + opt-in rule blocks, never a 4th DSL field.

## Impact analysis (Phase 0, gitnexus, mandated)

- `relevant_input` (A3 + the `sink:` emission) = **LOW** (1 caller `extract_assistant_actions`, 0
  processes).
- `match_actions_with_suppress` / `match_taints` = **CRITICAL** (fan-in: ~28 upstream, 13
  processes). **Mitigation:** the only edits are the one-line `starts_with("sink:")` guard and ONE
  append-only `match_shell(...)` trailing call; the single-action loop body is otherwise untouched.
  Byte-identical-passthrough + the A-NEW-1 two-case `repo-path:`/`repo-file:` `.sink`-filename
  regression tests guard it. CRITICAL = fan-in count, not a semantic regression. Surfaced to Pablo;
  he approved the design.

## Precision is the moat — now ENFORCED

`precision_recall.rs` gained `assert_eq!(eng.fp, 0)` (A5/M1): the FP=0 invariant is now CI-enforced,
not merely observed (the prior sole floor was precision ≥ 0.85). NOTE (M2): the precision_recall
gate is STRUCTURALLY BLIND to `sink:`/taint/shell actions (its corpus is single-action session/repo
only). `sink:` FP-safety is enforced by the C1 FP-safety + C2 disjointness unit tests + the
integration `sink:` benign trap, which are the de-facto gate for the new representation.

## Honest claim ceiling (carries from ADR-4, amended)

v2.1 closes the gap in the engine's **vocabulary and representation** (structured sinks + generic
markers now exist and fire on a synthetic trajectory; the matcher resists Unicode/casing/flag-order
evasions). It does NOT add value-level dataflow, causation proof, or runtime prevention. The
committed `trj-representation-aware-positive.jsonl` fires AGT-TRJ-001 + AGT-TRJ-003 via the real
binary — a **constructive existence proof** of the mechanism, authored to fire, NOT an independent
measurement. The only externally-anchored number is the AgentDojo marker-overlap finding.

**Real-world efficacy remains UNPROVEN — stated plainly.** Pre-registered (frozen SHA `ac88825`,
not retro-fitted): AgentDojo single-action recall = 23/35 UNCHANGED (WS1 added no single-action
prose rules); the generic-marker vocab covers AgentDojo's `important_instructions` marker class in
VOCABULARY, but the committed AgentDojo corpus is flat-bait (single chat-action GOAL strings) with
**0 trajectory items**, so the structured-sink representation has no AgentDojo trajectory corpus to
fire on — it is measured on the synthetic positive only. A deterministic offline matcher will NEVER
catch a determined obfuscator. Claim ceiling: *"deterministic, post-hoc, representation-aware
injection→consequence CANDIDATE correlation; mechanism + representation proven on synthetic
positives; real-world efficacy UNPROVEN until a real trajectory fires."*

## Limitations (deferred gaps, documented not buried)

- **A3 is SESSION-ONLY (M4).** `parse_repo` builds `ObservedAction` directly and is NOT normalized:
  repo-file content (the dominant indirect-injection evasion surface) is un-normalized in v2.1.
  Covers 30/86 (now 30/101) gate paths, 0/56 repo-file. Repo-file normalization (at the
  `ObservedAction` boundary) is deferred.
- **No real trajectory corpus.** Live capture is fully deferred (A10); a real positive needs a
  reproducibly-jailbreakable, in-domain target that does not yet exist in-hand.

## Alternatives considered (rejected, with rationale)

- **`ends_with(".sink")` source SUFFIX** (Rev-2 form) — REJECTED: collides with
  `repo-path:`/`repo-file:` filenames (N1, gate-invisible false negative); the `sink:` reserved
  PREFIX + `starts_with` is the collision-proof replacement.
- **1B rule-vocab-only** (regex the flat joined string) — re-creates the v1.4 bait-keyword weakness
  the representation gap condemned; documented degrade-path only.
- **1C provenance struct field on `ObservedAction`** — re-litigates ADR-4's settled 1C rejection;
  CRITICAL-path blast radius.
- **C1-b content-discipline as the PRIMARY `sink:` guard** — relies on format/value discipline; an
  adversarial role VALUE can still leak; kept as defense-in-depth, C1-a structural exclusion is
  primary.
- **2B copy AgentDojo's exact markers** — textbook retro-fit; measures nothing.
- **A2 relax `\b` in `compile_signal`** — reopens the US-F0-2 FP class on the highest-fan-in symbol;
  last resort, NOT chosen.
- **A1(a) normalize at the `ObservedAction` boundary** — larger CRITICAL-path blast radius;
  session-only (A1-b) chosen for v2.1's incremental posture (repo-file deferred).
- **S2 full shell AST (`brush-parser`/`flash`)** — the dep-graph disqualifier is `tokio` (on the
  verify.sh denylist), NOT `fancy-regex`. `conch-parser` (pure-Rust, no runtime) is DEFERRED, not
  rejected — a future escalation gated on a green `cargo tree -e no-dev` + `cargo audit` if `shlex`
  proves insufficient.

## Follow-ups

- Real-positive-trace capture once a reproducibly-jailbreakable, in-domain target+corpus exists.
- Repo-file normalization (A1-a `ObservedAction`-boundary, the deferred M4 gap).
- S2 escalation to `conch-parser` full AST if `shlex` tokenization proves insufficient.
- F-window (decay accumulation vs first-sink-fires, carried from ADR-4).
- The v2.1 version-badge bump (Pablo-gated, on the tag v2.1 eventually cuts).

## Consequences

A second `sink:` action per structured tool-call; a small deterministic field-name→role table; the
`sink:` canonical-role string is an UNSTABLE internal format (NO back-compat guarantee, NOT a public
format) until a real positive corpus exists, pinned by `const SINK_GRAMMAR` + the C2 disjointness
guard. Two new pure-Rust offline deps (`unicode-normalization` → tinyvec; `shlex` zero-dep), both
dep-graph-clean and `cargo audit` RUSTSEC-clean (artifact `cargo-audit-v2.1.txt`). A frozen
confusables table (Unicode 15.1.0) that must stay frozen. A new opt-in `shell:` construct. The FP=0
moat is now CI-enforced (`assert_eq!(eng.fp, 0)`). The honest ceiling and bound-triple /
pre-registration discipline carry forward verbatim.
