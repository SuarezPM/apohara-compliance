---
name: add-or-update-taint-rule-and-propagate
description: Workflow command scaffold for add-or-update-taint-rule-and-propagate in apohara-compliance.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /add-or-update-taint-rule-and-propagate

Use this workflow when working on **add-or-update-taint-rule-and-propagate** in `apohara-compliance`.

## Goal

Adds a new taint rule or updates taint rule logic, propagates changes to core logic and rules reference, and updates/creates relevant tests.

## Common Files

- `crates/scanner/src/rules.rs`
- `crates/scanner/src/taint.rs`
- `crates/scanner/references/detection-rules.yaml`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Edit crates/scanner/src/rules.rs to add or update the TaintRule struct or logic.
- Edit crates/scanner/src/taint.rs to propagate changes to taint processing logic.
- Edit crates/scanner/references/detection-rules.yaml to add new rules or update rule metadata.
- Update or add tests in the test suite to cover the new/updated rule logic.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.