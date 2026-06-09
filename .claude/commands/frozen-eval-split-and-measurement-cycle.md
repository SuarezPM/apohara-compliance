---
name: frozen-eval-split-and-measurement-cycle
description: Workflow command scaffold for frozen-eval-split-and-measurement-cycle in apohara-compliance.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /frozen-eval-split-and-measurement-cycle

Use this workflow when working on **frozen-eval-split-and-measurement-cycle** in `apohara-compliance`.

## Goal

Freezes a preregistration corpus and evaluation split, implements deterministic split logic, then runs measurement scripts and records results/proofs.

## Common Files

- `tests/corpus/PREREG-*.md`
- `scripts/eval/split_*_devtest.py`
- `scripts/eval/scan_*_devtest.py`
- `tests/corpus/PROOF-*.md`
- `tests/corpus/*-report.json`
- `scripts/eval/validate_*_report.py`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Edit or create tests/corpus/PREREG-*.md to record preregistration, schema delta, and split details.
- Implement or update scripts/eval/split_*_devtest.py to generate deterministic dev/test splits.
- Implement or update scripts/eval/scan_*_devtest.py to run the scanner and collect results.
- Record measurement results in tests/corpus/PROOF-*.md and tests/corpus/*-report.json.
- Implement or update scripts/eval/validate_*_report.py to validate the measurement report schema.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.