---
name: release-version-and-documentation-update
description: Workflow command scaffold for release-version-and-documentation-update in apohara-compliance.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /release-version-and-documentation-update

Use this workflow when working on **release-version-and-documentation-update** in `apohara-compliance`.

## Goal

Documents a new release by updating ADRs, benchmarks, changelogs, open questions, and bumps version numbers.

## Common Files

- `docs/adr/ADR-*.md`
- `BENCHMARK.md`
- `crates/scanner/references/validation-log.md`
- `docs/open-questions.md`
- `README.md`
- `crates/scanner/Cargo.toml`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Create or update docs/adr/ADR-*.md to document the new architectural decision.
- Update BENCHMARK.md with new benchmark results.
- Update crates/scanner/references/validation-log.md with validation and quality notes.
- Update docs/open-questions.md with new or deferred questions.
- Update README.md with new version badges and lineage.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.