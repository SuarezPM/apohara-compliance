# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
