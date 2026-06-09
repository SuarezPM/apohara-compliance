# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.0] - 2026-06-09

"Argument-Value Provenance" (ADR-7). Additive, opt-in, byte-identical passthrough
when the new flag is empty. The v2.3 PROVENANCE GATE mechanically kills most of
the v2.2 correlation-FP on the FAILED bucket, zeroed the BENIGN FP, and dropped
the TEST-positives headline from 71.9% to 52.1% — a post-hoc substring-match
PROXY for injection→consequence causation (necessary-but-not-sufficient; verbatim-
flow only; no cross-step laundering). Pre-registered (`tests/corpus/PREREG-v2.3.md`;
rules frozen at blob SHA `dcd1ac6` BEFORE any source edit; PREREG SHA UNCHANGED
post-scan). All LOCAL. See `docs/adr/ADR-7-argument-value-provenance.md` +
`tests/corpus/PROOF-v2.3-argument-value-provenance.md` + the bound triple
on the v2.3 TEST split in `BENCHMARK.md`.

### Added

- `TaintRule.require_value_from_source: Vec<String>` (ADR-7). Empty by default;
  the v2.2 path runs byte-identically when the flag is empty (verified by 13
  existing taint tests + the new explicit `v23_g_empty_flag_byte_identical_to_v22`
  side-by-side test). The flag, when non-empty, triggers the v2.3 PROVENANCE
  CHECK: at least one authority-role value (recipient, amount, url, command)
  extracted from the sink must be a substring of the latched source value,
  after ASCII-lowercasing and a 6-character length floor. If no value flows,
  the candidate is suppressed.
- 3 new AGT-TRJ-001/002/003-P rule variants (mirrors of the originals with
  the new flag non-empty; gates: exfil=[recipient,url], destructive=[command],
  financial=[recipient,amount]). Total rules: 24 → 27.
- `scripts/eval/scan_v23_devtest.py` — apohara-AGNOSTIC scanner over the v2.2
  AgentDyn corpus, reporting AGT-TRJ-* (v2.2 corr) vs AGT-TRJ-*-P (v2.3 -P)
  side-by-side per model on the FROZEN dev/test split (44 dev / 192 test,
  deterministic SHA-256 seed per `PREREG-v2.3.md`).
- `scripts/eval/validate_v23_report.py` — strict numbers/IDs-only schema
  validator for the v2.3 report (mirrors `validate_v22_report.py`).
- 7 new unit tests (per plan §0 a-g) + 2 integration FP-killer demos. 180 → 189
  tests, all green.

### Headline (v2.3 TEST split, 192 positives)

| Metric | v2.2 corr (b) | v2.3 -P (c) | Delta |
|---|---|---|---|
| TEST positives (192) | 138 / 192 = 71.9% | 100 / 192 = 52.1% | -38 |
| FAILED (2295) | 659 = 28.7% | 319 = 13.9% | -340 (FP halved) |
| BENIGN (352) | 5 = 1.4% | **0 = 0.0%** | -5 (all FP killed) |

### Honest ceiling

v2.3 reports: 100/192 (52.1%) on the TEST split, vs v2.2's 138/192 (71.9%).
The 38-candidate drop is the FP-killer result. The 52.1% is a **post-hoc
substring-match proxy** for injection→consequence causation: a candidate
fires when an authority-role value in the sink is a substring of the latched
source value. This is necessary-but-not-sufficient: it kills the FP class
where the same sink fires on a clean trajectory, but it does NOT prove the
value was lifted from the injection versus coincidentally present in the
injection text. Verbatim-flow only; no cross-step laundering (PACT does
that, apohara does not). v2.2 numbers are PERMANENT and UNCHANGED; the v2.3
-P numbers are an additional column, not a replacement. See ADR-7 §"What
v2.3 is NOT" for the full ceiling.

## [2.2.0] - 2026-06-09

"Real-Trajectory Efficacy" (ADR-6). Additive — no scanner change; the engine is run
with the **same frozen rules** (blob SHA `dcd1ac6`, frozen BEFORE scanning) over a
corpus of real successful indirect-injection trajectories from last-generation
frontier models, and a live current-frontier cross-check. The number is reported
as a **bound triple** + its representation overlap-miss, and the
correlation-not-causation ceiling is stated as a co-headline of equal prominence.

### Added

- Eval harness (`scripts/eval/wrap_agentdojo_trace.py` + friends) that
  transcribes AgentDyn traces via an apohara-agnostic wrapper to the REAL
  release binary — never the scanner crate, never the rules, never the wrapper
  (the measurement is BY construction, not a fit).
- Download bound triple on AgentDyn (`5353cf7`, agentdojo 0.1.35, benchmark
  v1.2.2; attack `important_instructions`; **last-gen** models, date-labeled;
  open-ended suites): post-hoc AGT-TRJ detection on 236 real successes
  **169 / 236 (71.6 %)**; failed-injection (RESISTED) FP **659 / 2295
  (28.7 %)**; benign FP **5 / 352 (1.4 %)** ⇒ precision-on-success
  **169/833 ≈ 20 %**.
- Live current-frontier cross-check via OpenRouter (suite `workspace`, attack
  `important_instructions_no_model_name`; same frozen rules + wrapper + binary;
  current-frontier models, date-labeled: gpt-5.5, gemini-3.5-flash,
  gemini-3.1-pro-preview, MiniMax-M3, claude-opus-4.8): attack-success TOTAL
  **0 / 80 (0.0 %)** — each model 0 / 16; live post-hoc detection **0 / 0 —
  UNDEFINED**; failed-injection FP **0 / 80**; benign FP **0 / 15**. Real
  usage: **224 API calls, all HTTP 200; 698,959 tokens** (under the 1 M cap);
  key never logged.
- Overlap-miss (model-independent, 236 positives): marker `<information>`
  covered 232/236; role-mapped structured sink covered 180/236; BOTH
  178/236; NEITHER 2/236. Covered sink roles: `url=170, recipient=60,
  amount=59, command=34`. MISSED arg-keys (OUTSIDE the frozen role map — the
  `iban`-analog): `path (161), subject (114), otp (87), title (79), body (68),
  recipients (68), repo_name (54), password (33)`. **Reported as-is, NEVER
  closed** — a retro-fit converts the measurement into a fit.
- Reports (strict-schema-validated, numbers/IDs-only — no example text):
  - `tests/corpus/v2.2-real-trajectory-report.json` (the bound triple +
    live usage, validated by `scripts/eval/validate_v22_report.py` and wired
    into `scripts/verify.sh`).
- PREREG + PROOF (committed):
  - `tests/corpus/PREREG-v2.2-real-trajectory.md` (rules frozen at
    `dcd1ac6e1d7ed8dce4b5b516296e8ce5a3e0582a` **BEFORE** any scan; verified
    unchanged post-scan).
  - `tests/corpus/PROOF-v2.2-real-trajectory.md`.
- CAVEAT (stated): the live run used `suite=workspace` (the standard
  AgentDojo suite), NOT AgentDyn's harder open-ended suites (shopping /
  github / dailylife) where last-gen models reached 14–22 % ASR — because
  the current-frontier OpenRouter IDs are not in AgentDyn's model registry.
  So the live 0/80 is on the **easier standard suite**; current-frontier
  behaviour on the harder open-ended attack is **UNMEASURED** (a documented
  follow-up).

### Notes

- Honesty invariants unchanged: every finding is `is_candidate: true`, every
  formatter line is `CANDIDATE — ` prefixed, SARIF `level` is never `error`.
- The single-action engine is byte-identical to v2.1; the additive trajectory
  pass is unchanged. The synthetic precision/recall gate still
  **1.0000 / 1.0000 / FP = 0**; the AgentDojo prose-rule recall still
  **23 / 35 (0.657)**; the AGT-TRJ rules fire on the synthetic positive and
  zero on the FinBot negative control.

### Claim ceiling (verbatim, ADR-6)

*"deterministic, post-hoc, representation-aware injection → consequence
CANDIDATE CORRELATION surfacer; mechanism + representation proven on
synthetic positives; post-hoc recognition MEASURED on real successful
trajectories (169/236, last-gen open-ended) with an explicit model-independent
overlap-miss; ALSO fires on resisted (28.7 %) + benign (1.4 %) — a correlation
surfacer, NOT a success / causation discriminator (precision-on-success ≈
20 %); NOT efficacy / recall / prevention; recognisable-in-log ≠
would-have-prevented."*

## [2.1.0] - 2026-06-09

"Representation-Aware Taint + Evasion Robustness + Cleanups" (ADR-5). Additive
— the v2.0 trajectory pass is unchanged; representation + vocabulary + a
structural shell pass are added; the single-action engine is byte-identical to
v1.4 (AgentDojo recall 23 / 35 UNCHANGED). The gap closed: the v2.0
representation/vocab gap (AgentDojo's structured tool-call sinks did not
overlap the v2.0 `taint_source` / `taint_sink` vocab).

### Added

- Representation-aware taint (ADR-5): the parser now emits a reserved
  `sink:` action carrying a deterministic canonical role string
  (`recipient=` / `amount=` / `url=` / `command=`, with `const SINK_GRAMMAR`
  enforcing an authority boundary). The `sink:` channel is excluded from the
  single-action loop by a one-line `starts_with("sink:")` guard, so the new
  representation **cannot** produce a single-action false positive (proven by
  the C1 FP-safety + C2 grammar-disjointness tests).
- Taxonomy-derived **generic injection-marker** vocabulary for AGT-TRJ (OWASP
  ASI02:2026 / AITG-APP-02 / documented IPI canary families — each marker
  cited in `detection-rules.yaml`).
- Structural `shlex` shell pass → AGT-MIS-004 catches flag-reordered
  destructive commands a substring scan cannot (e.g. `rm -r -f` / `rm -fr` /
  quoted-arg variants); folded into `AGT-MIS-004`.
- A3 session-only normalization (Unicode / casing / homoglyph) in the session
  value picker (`relevant_input`). Documented deferred gap: `parse_repo`
  builds actions directly and is NOT normalized — covers the session channel
  (30/101 gate paths, 0/56 repo-file). Repo-file normalization is a documented
  follow-up (ADR-5 M4).
- Synthetic positive (`trj-representation-aware-positive.jsonl`) fires
  AGT-TRJ-001 + AGT-TRJ-003 via the real binary; the
  `trj-structured-sink-benign-trap` and the FinBot direct-injection fixture
  (negative control) fire **zero**.
- Pre-registration: frozen rules SHA `ac88825` (verified unchanged
  post-scan). Repo-file normalization deferred to a future PR.

### Notes

- Honesty invariants unchanged.
- The synthetic positive is a **constructive existence proof** that the engine
  *can* fire on a structured representation — it is authored to fire, so it
  is **not** an independent measurement. Real-trace generalisation is
  **UNPROVEN at v2.1** (stated plainly in ADR-5).
- "Real-world efficacy is still UNPROVEN — stated plainly. v2.1 closes the
  gap in the engine's *vocabulary and representation* (structured sinks +
  generic markers now exist and fire on a synthetic trajectory), but there
  is **no committed real trajectory corpus** to exercise it: the AgentDojo
  corpus is flat bait (no trajectories) and v2.1 defers all live capture
  (A10). So the structured-sink representation is measured on the **synthetic
  positive only**; real-trace generalisation remains the deferred gap. A
  deterministic offline matcher will **never** catch a determined obfuscator
  (the documented ceiling)."

## [2.0.0] - 2026-06-09

"Trajectory Taint-Correlation Detection" (ADR-4). Additive — a new
deterministic taint engine runs AFTER the single-action loop AND after the
ADR-2 `sequence` pass. It expresses the injection → consequence dataflow the
single-action engine cannot: a TAINTED source (an action on the untrusted-data
`tool-result:` channel carrying injection markers, AND **not** a
doc/comment quote) FOLLOWED BY a genuine sensitive real-action sink
(exfil / destructive / financial) later in the same action stream (forward-
correlated: the taint persists across intervening steps).

### Added

- New module `crates/scanner/src/taint.rs` — the deterministic
  taint-correlation engine. Self-contained by design (ADR-4 OQ1): copies
  the small `CompiledStep` / `step_match` shape from `sequence.rs` rather
  than sharing a helper, to keep zero blast-radius on the CRITICAL
  `matching.rs` and the live `sequence.rs` AGT-MEM-001 path.
- New rules (rule count 17 → 20): `AGT-TRJ-001` (injection + sensitive sink,
  base), `AGT-TRJ-002` (exfil sink family), `AGT-TRJ-003` (destructive sink
  family).
- A10 live capture (pre-registration + smoke): the committed AgentDojo
  corpus + a bounded live capture on AgentDojo banking-suite with
  **MiniMax-M3** (OpenRouter adapter), attack `important_instructions`,
  10 attacked pairs + 2 benign. **Real-world result: 0 / 10 attack-success
  on MiniMax** (the model refused every indirect injection); 28 API calls,
  65,550 tokens; real-usage proof.
- Synthetic positive (`trj-agentdojo-async-injection.jsonl` + friends) fires
  AGT-TRJ-001 / 002 / 003 via the real binary; the FinBot direct-injection
  fixture (negative control) and benign-trajectory traps fire **zero**.
- Pre-registration: `tests/corpus/PREREG-v2-agentdojo.md` (frozen before
  scanning). Proof: `tests/corpus/PROOF-v2-minimax.md` (the real-world
  0 / 10 + 65,550 tokens).
- Added: 8 commits `2610a0b..9e1a78a` on `v2.0-trajectory-taint` (Ralph
  v0 → F4, AMENDMENT-A feasibility F5A, deslop).

### Notes

- Honesty invariants unchanged: every finding is `is_candidate: true`, every
  formatter line is `CANDIDATE — ` prefixed, SARIF `level` is never `error`.
- No new runtime dependency; the detection core stays deterministic and
  offline; the synthetic precision/recall gate still
  **1.0000 / 1.0000 / FP = 0**.
- **Real-world efficacy is UNPROVEN at v2.0** (stated plainly in ADR-4 and
  the PROOF). Two measured reasons: (1) MiniMax-M3 resisted all 10
  injections, so no real positive trace exists; (2) a verified
  **representation/vocab gap** — AgentDojo's `<INFORMATION>…` marker and
  structured tool-call sinks (`send_money(…)`) do not overlap apohara's
  text-pattern `taint_source` / `taint_sink` vocabulary, so even a
  successful trace would very likely not fire. apohara is a **post-hoc**
  transcript scanner (recognisable-in-log ≠ would-have-prevented), and its
  rules are vocab-scoped to shell/coding agents. Per the pre-registration
  the rules were NOT retro-fitted to AgentDojo.

## [1.4.0] - 2026-06-09

"Independent Corpus + Prose-Gap Closure" (HYBRID 2+3; ADR-3). Closes the
"prose gap" — the corpus / rules co-evolved on the v1.0 synthetic gate; v1.4
adds two **independent**, externally-authored corpora to measure coverage
against attacks the project did not write, and uses AgentDojo's data-first
analysis to drive new prose rules. No engine refactor; pure rule + corpus
additions. AgentDojo recall **1 / 35 → 23 / 35** (0.029 → 0.657) on the
same committed corpus; synthetic gate intact.

### Added

- Independent corpora (non-gating cross-check):
  - **AgentDojo** (ethz-spylab, MIT) committed at `tests/corpus/agentdojo/`,
    35 injection-task GOALs across workspace / travel / banking / slack
    suites. Run with
    `cargo test -p apohara-compliance-scanner --test independent_corpus -- --ignored --nocapture`.
    Numbers reported in [BENCHMARK.md](BENCHMARK.md).
  - **AgentHarm** (ai-safety-institute; 176 augmented prompts / 44 base
    behaviors) — **eval-only / no-redistribution**, so no examples are
    committed; only a numbers/IDs-only report at
    `tests/corpus/agentharm-report.json` (strict-schema-validated).
- Data-first prose rules driven by the AgentDojo analysis: 13 new matches
  on attacked (data-exfil 10/12, web-exfil 4/4, financial 5/5, structuring
  1/1, PII 2/2, unauthorized-action 1/10, destructive 0/1 left deliberately
  to avoid false positives).
- `gitignore eval/` + AgentHarm canary leak guard (no eval-only corpus
  escapes to the tracked tree).
- Trust / supply-chain hardening: `SECURITY.md` re-checked; OpenSSF
  Scorecard workflow pinned; Dependabot (cargo + github-actions); CodeQL
  (Rust) workflow.

### Notes

- The 12 AgentDojo misses are **honestly out of reach for prose detection**:
  9 are unauthorized-but-benign-looking actions (create a calendar event,
  send an arbitrary email) whose maliciousness is injection context the
  scanner cannot see from the action text; 1 is a single "delete the file"
  destructive phrasing left unhandled to avoid false positives; 2 are
  security-code exfiltration phrasings. Closing these would require
  trajectory modeling (the v2.0 taint engine) or precision-eroding
  overreach — neither is in scope for v1.4.
- Honesty framing: what AgentDojo measures is **bait-keyword surface
  coverage over labeled injection STRINGS — NOT injection-consequence
  detection**. It shows whether apohara's vocabulary + word-boundary +
  source/context machinery surfaces the attack *class*; it does **not**
  show whether apohara detects the *consequence* of a successful injection
  (that is the v2.0 trajectory taint work, ADR-4).

## [1.1.0] - 2026-06-06

"Runtime & coverage". Additive features over v1.0.0 — the deterministic, offline
core is unchanged (the single-action matcher is byte-identical; the synthetic
precision/recall gate is untouched). Plus supply-chain hardening and trust docs.

### Added

- `scan-otlp <file|dir>`: read OTLP-exported telemetry (logs/traces, OTLP/JSON,
  single document or NDJSON) **off disk** — runtime coverage for the offline
  scanner (no socket, no listener, no network dependency). Tool/function records
  map to the same `session:{Tool}.input` actions a live transcript yields, so
  existing rules fire over exported telemetry. Post-hoc and exporter-bounded;
  findings stay candidates, never real-time.
- ASI06 (Memory & Context Poisoning) detection via `AGT-MEM-001` — an opt-in,
  additive **multi-action sequence** pass (ADR-2): untrusted/unsanitized content
  **followed by** a write to a memory/RAG sink. Distinct from `AGT-PI-003`
  (single-action injection markers); candidate-only, coverage bounded to shell
  persist commands + exported OTLP records. The 16 single-action rules and the
  frozen 3-field context DSL are unchanged (the rule count is now 17).
- `SECURITY.md` (disclosure policy, threat model, supply-chain / verify-a-release
  model) and `BENCHMARK.md` (reproducible synthetic precision/recall, leading
  with the baseline→tuned delta).
- OpenSSF Scorecard workflow, Dependabot (cargo + github-actions), and a CodeQL
  (Rust) workflow.

### Changed

- `release.yml`: all actions SHA-pinned; least-privilege per-job permissions
  (build retains `id-token`/`attestations`); cosign binary pinned to v2.6.3
  (cosign v3 `sign-blob` is not drop-in with the classic flags); pre-release
  tags never publish to crates.io.
- `verify.sh`: added a dependency-graph offline guard (`cargo tree` shows no
  network crate) alongside the existing source-text guard.

## [1.0.0] - 2026-06-05

"Validated + live". Phase 3 adds an opt-in LLM-assist triage path, a live
`PreToolUse` hook for in-the-moment candidate warnings, and adoption tracking —
all **without changing the deterministic, offline core**. Builds on the v0.3.0
coverage base (MITRE ATLAS, ISO/IEC 42001, EU AI Act, SARIF code scanning,
baseline/diff).

### Added

- `--llm-assist`: an EMITTER flag that writes a versioned triage manifest
  (`apohara-triage-manifest/1`) of the ambiguous (`ambiguity: true`) active
  candidates to stderr, so an orchestrator can triage the borderline long-tail
  out-of-band. stdout stays byte-identical and the binary never calls an LLM nor
  merges a verdict back — the offline / deterministic thesis is preserved.
- `scan-action <ACTION>`: a lightweight subcommand that matches a single
  observed-action string against the rules without reading any file or session
  transcript, with `--kind` to set the source label. Built for a live
  `PreToolUse` hook (`scripts/hooks/pretooluse-scan-action.sh`) that surfaces a
  candidate before a command runs — **warn-not-block** by default.
- `docs/adoption.md`: privacy-respecting adoption tracking (crates.io / GitHub
  Release / star counts, read out-of-band), with a CI guard asserting the crate
  has no outbound-HTTP / network client — no telemetry phones home.

### Notes

- Honesty invariants unchanged: every finding is `is_candidate: true`, every
  formatter line is `CANDIDATE — ` prefixed, SARIF `level` is never `error`.
- No new runtime dependency; the detection core stays deterministic and offline.

## [0.3.0] - 2026-06-05

First public release. `apohara-compliance` maps an AI coding-agent's observed
actions — or a repository's contents — to compliance and agentic-security
framework controls, surfacing **candidate** risks with citations for a human to
confirm. It never asserts compliance, certification, or audit conclusions.

### Added

#### Scanner

- Deterministic Rust scanner (`apohara-compliance-scanner`) with three modes:
  - `scan-session` — map an agent session transcript (newline-delimited JSON) to
    candidate findings, parsing observed tool actions (e.g. shell commands, file
    reads/writes) tolerantly: unknown or malformed objects are skipped with a
    logged reason, never a panic.
  - `scan-repo` — walk a repository (respecting `.gitignore`) and match file
    contents and paths, with an optional `--ext` extension allowlist.
  - `gap` — list carried controls for which no candidate evidence surfaced
    (the absence of a signal, never an assertion of non-compliance).
- Output formats: structured JSON (the scanner's own report), SARIF 2.1.0, and
  human-readable Markdown. Every finding is prefixed `CANDIDATE — `; SARIF
  `level` is constrained to `note`/`warning`, never `error`.
- Baseline / diff mode: annotate each finding with a SARIF `baselineState`
  (`new` / `unchanged` / `absent`) against a prior JSON report, with `--only-new`
  to emit only newly introduced candidates.

#### Detection engine

- Regex-based detection with conditional word-boundary anchoring and a context
  DSL (source scoping, require/deny context windows) that de-noises substring
  false positives while preserving recall. On the synthetic evaluation corpus
  this lifts precision from ~0.70 (naive substring matching) to 1.00 with no
  recall regression; a CI gate enforces a precision floor and a no-recall-
  regression bound.

#### Configuration and suppression

- `.apohara-compliance.toml` config for confidence/severity thresholds and
  severity overrides, with matching `--min-confidence` / `--min-severity` flags.
  Threshold drops are surfaced in a **visible** channel, never silently removed.
- `.apohara-suppress` allowlist: suppressed candidates are moved to a visible
  `suppressed` channel (recording the justification and matching rule), never
  dropped — preserving the audit trail.

#### Framework coverage

- OWASP Top 10 for Agentic Applications (2026)
- OWASP Agentic Skills Top 10
- OWASP Top 10 for LLM Applications (2025)
- MITRE ATLAS (5.6.0)
- ISO/IEC 42001 (2023)
- EU AI Act (Regulation (EU) 2024/1689)
- NIST AI RMF, NIST SP 800-53 Rev 5
- SOC 2 (AICPA TSC 2017)
- ISO/IEC 27001 (2022)

  Every citation carries only framework IDs, titles, versions, and source URLs —
  no reproduced framework prose. Draft-status controls are flagged as such and
  never presented as settled guidance.

#### CI integration

- Composite GitHub Action that runs the scanner and uploads SARIF results to
  GitHub code scanning. Because results are warnings/notes (never errors), the
  action surfaces candidates for review and cannot fail a build on findings.

[0.3.0]: https://github.com/SuarezPM/apohara-compliance/releases/tag/v0.3.0
