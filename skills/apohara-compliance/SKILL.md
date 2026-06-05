---
name: apohara-compliance
description: Map a coding agent's observed actions or a repository to compliance and agentic-security framework controls (OWASP Agentic/LLM Top 10, EU AI Act, NIST AI RMF, SP 800-53, SOC 2, ISO 27001). Surfaces candidate risks and suggested controls with citations for human confirmation — guidance and mapping only, never certification, audit, or legal advice. Trigger on compliance, agentic security, AI risk, control mapping, or framework gap-analysis prompts.
---

# apohara-compliance

Map what a coding agent actually *did* — or what a repository *contains* — to
compliance and agentic-security framework controls, and surface the result as
**ranked candidates with citations for a human to confirm**.

## What this skill is — and is NOT

This skill is a **guidance and mapping aid**. It drives a deterministic Rust
scanner that matches observed signals against a curated rule set and emits
**candidate** risks plus **suggested** controls, each with a published-source
citation, so a human (or a supervising agent) can review and decide.

It is **NOT**:

- a certification, attestation, or audit;
- legal advice or a compliance verdict;
- a guarantee that a system *is* or *is not* compliant.

Every scanner finding is a CANDIDATE, never an assertion. The scanner encodes
this structurally: each finding carries `is_candidate: true`, and the Markdown
and SARIF formatters prefix every finding line with the literal string
`CANDIDATE — ` (note the em dash). When you present results, preserve that
framing: say "this signal *suggests reviewing* control X", never "this is
compliant" / "certified" / "guaranteed". A false positive is a "please confirm",
not a wrong verdict.

## Acquiring the scanner

The scanner is a separate Rust binary (`apohara-compliance-scanner`). There are
two acquisition paths, in order of preference.

### 1. PRIMARY — build from source with `cargo install`

```bash
cargo install apohara-compliance-scanner
```

This builds from source on the user's machine. It is the **lowest-trust-
assumption** path: no opaque pre-built artifact is executed, and the rule set is
embedded from the canonical `references/*.yaml` at build time. Prefer this
whenever a Rust toolchain (`cargo`) is available.

On this path the scanner runs with its **build-time-embedded** rules as the
normal source — `rules_source: embedded-fallback` is the **expected steady
state** here, not an anomaly (the binary in `~/.cargo/bin` has no nearby
`references/` directory to load from).

### 2. FALLBACK — pre-built per-OS binary from GitHub Releases

For users **without** a Rust toolchain, download the matching pre-built binary
(linux x86_64, macOS arm64, macOS x86_64, Windows x86_64) from the project's
GitHub Releases.

**Downloading a pre-built binary is itself a supply-chain surface** — it is
exactly the ASI04 (Agentic Supply Chain) / AST02 risk this very tool exists to
surface. Treat it that way. `cargo install` from source (path 1) is the
lower-trust path; the pre-built binary is a convenience for the no-toolchain
case, and it MUST have its provenance verified **before execution**:

1. **Verify the signature / attestation.** Confirm the GitHub artifact
   attestation (`gh attestation verify <binary> --repo <owner>/<repo>`) or the
   Sigstore/cosign signature on the downloaded asset.
2. **Verify the checksum against the committed file.** Check `SHA256SUMS`
   against the copy **committed to the git-tagged source tree** — NOT merely the
   `SHA256SUMS` attached to the same Release (a compromised Release could ship a
   matching-but-malicious pair). The committed, source-tree checksum is the
   independent anchor.

Only run the binary once **both** the signature/attestation **and** the
committed-checksum match. If either fails, stop and fall back to `cargo install`.

## Pointing the scanner at the canonical rules

The **binary** resolves its rules via an ordered ladder (highest precedence
first): `--rules-dir <DIR>` → `APOHARA_RULES_DIR` env var →
`current_exe()`-relative `references/` → build-time-embedded copy.

When this skill is installed as a local project skill and you want it to use the
on-disk canonical `references/`, point the binary there explicitly:

```bash
apohara-compliance-scanner --rules-dir /abs/path/to/references scan-session …
# or
APOHARA_RULES_DIR=/abs/path/to/references apohara-compliance-scanner scan-repo …
```

**Do NOT use a bare `../../references/` relative path.** From an installed skill
dir such as `~/.claude/skills/apohara-compliance/`, `../../references/` resolves
to `~/.claude/`, **not** the repo root — it is wrong and will silently miss the
rules. The correct mechanism is a `references/`-only symlink placed INTO this
skill's installed directory, with its absolute path passed via `--rules-dir`
(or `APOHARA_RULES_DIR`). Never symlink the whole repo root as the skill dir.

On the `cargo install` primary path you may pass nothing: the binary's
build-time-embedded rules are the normal source, and `rules_source:
embedded-fallback` is expected and correct there.

## Usage / orchestration

The scanner exposes `scan-session`, `scan-repo`, `gap`, and `scan-action`
subcommands. For the file-based commands the path is a positional argument;
`--rules-dir` and `--format` are global flags.

### Scan an AI coding-agent session transcript

AI coding-agent session transcripts are newline-delimited JSON under
`~/.claude/projects/**/*.jsonl`. Point `scan-session` at one:

```bash
apohara-compliance-scanner scan-session ~/.claude/projects/<proj>/<session>.jsonl --format md
```

This parses the agent's observed actions (tool calls such as `Bash` commands and
`Read`/`Write` file paths) and matches them against the detection rules.

### Scan a repository

```bash
apohara-compliance-scanner scan-repo /path/to/repo --format json
```

This walks the repository (respecting `.gitignore`) and matches file
contents/paths against the same rule set.

### Match a single action in the moment (live PreToolUse hook)

`scan-action` matches ONE observed-action string against the rules without
reading any file or session transcript — built to run inside a coding-agent's
`PreToolUse` hook so a candidate surfaces *before* the action executes:

```bash
apohara-compliance-scanner scan-action "sudo rm -rf /var/cache" --format md
# → CANDIDATE — AGT-MIS-002 (sudo) and AGT-MIS-001 (rm -rf), for review
```

`--kind <SOURCE>` (default `session:Bash.input`) is the source label matched
against each rule's `source_kinds` prefix filter, so scoping behaves exactly as
on a real session action; use e.g. `--kind session:Write.input` to scan a file
path.

A ready-to-install hook ships at `scripts/hooks/pretooluse-scan-action.sh`. It
is **warn-not-block by default**: it prints any candidate to stderr and exits 0,
so the command still runs — a candidate is a "please review", never a verdict
that the command is malicious. Set `APOHARA_BLOCK_ON` to opt into blocking the
tool call for human review. Wire it in `.claude/settings.json`:

```jsonc
"hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [
  { "type": "command",
    "command": "/abs/path/to/scripts/hooks/pretooluse-scan-action.sh" } ] } ] }
```

### Output formats

`--format {json|sarif|md}` (default `json`):

- **`json`** — the scanner's own structured report; best for programmatic
  follow-up.
- **`sarif`** — SARIF 2.1.0, ingestible by CI / code-scanning UIs. Every
  `result.message.text` is prefixed `CANDIDATE — ` and `level` is `note` or
  `warning` (never `error`), so a CI surface cannot misread a candidate as a
  failing assertion.
- **`md`** — human-readable Markdown summary; each finding line is prefixed
  `CANDIDATE — `.

Diagnostics (which `rules_source` resolved, the `schema_version` behaviour,
per-object skip-with-reason lines, the session `version`/`gitBranch`/`cwd`
evidence) go to **stderr**; the report goes to **stdout** so it stays cleanly
pipeable.

### Reading a finding and presenting it

Each finding carries:

- `id` — the matched ASI / AGT / control id, and `title`.
- `status` — `official` or `draft`. Surface this: a `draft` control (e.g. a CSA
  Agentic-Profile row) must not be presented as settled guidance.
- `confidence` — baseline match confidence (0.0–1.0); a hit is a candidate
  signal, never a certainty.
- `triggering_signal` — the concrete keyword/pattern that fired.
- `citation` — `{url, version}` for the published source.
- `suggested_controls` — control ids to review for this finding.
- `cross_refs` — related ids (e.g. the ASI↔LLM crosswalk).
- `rules_source` — which ladder step produced the rules (`cli-dir`, `env-dir`,
  `exe-relative`, or `embedded-fallback`), plus the collapsed
  `file | embedded-fallback` audit view.
- `is_candidate` — always `true`.

Present each finding to the user as a **candidate to CONFIRM**, with its
`triggering_signal` and `citation`, and note its `status`. Never collapse a
finding into a compliance verdict. The full chain
signal → AGT rule → mapped control → published source (and official-vs-draft) is
the audit trail; preserve it when you summarize.

## Framework coverage

- **Primary:** OWASP Top 10 for Agentic Applications — ASI01–ASI10, **2026
  edition**.
- **Secondary:** OWASP Agentic Skills Top 10 — AST01–AST10 (usable to
  self-audit this skill).
- **Cross-referenced controls (49):** EU AI Act, NIST AI RMF (the CSA
  `AGENTIC-*` rows are a **March-2026 draft**, not official NIST — flagged
  `status: draft`), SP 800-53, SOC 2, ISO 27001, and OWASP LLM Top 10
  (recorded as **2025**, the official version — never "2026").

Data provenance and exact framework versions/dates are documented in the
project README. Citations carry only framework IDs/names/versions/URLs (facts),
never reproduced framework prose.
