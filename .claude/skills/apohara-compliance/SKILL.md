```markdown
# apohara-compliance Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches the core development conventions and workflows for the `apohara-compliance` Python codebase. You will learn how to follow established coding standards, manage taint rule logic, handle evaluation splits and measurement cycles, and document releases. The guide covers file organization, code style, workflow steps, and command shortcuts to streamline contributions and maintenance.

## Coding Conventions

### File Naming
- Use **camelCase** for file names.
  - Example: `taintRules.py`, `scanDevtest.py`

### Import Style
- Use **relative imports** within modules.
  - Example:
    ```python
    from .utils import parse_rules
    from .scanner import TaintRule
    ```

### Export Style
- Use **named exports** (explicitly define what is exported).
  - Example:
    ```python
    def scan_file(file_path):
        ...

    def validate_report(report):
        ...

    __all__ = ["scan_file", "validate_report"]
    ```

## Workflows

### Add or Update Taint Rule and Propagate
**Trigger:** When adding a new taint rule, updating taint rule logic, or introducing a new taint-related feature  
**Command:** `/add-taint-rule`

1. Edit `crates/scanner/src/rules.rs` to add or update the `TaintRule` struct or logic.
2. Edit `crates/scanner/src/taint.rs` to propagate changes to taint processing logic.
3. Edit `crates/scanner/references/detection-rules.yaml` to add new rules or update rule metadata.
4. Update or add tests in the test suite to cover the new/updated rule logic.

**Example:**
```rust
// crates/scanner/src/rules.rs
pub struct TaintRule {
    // ...fields...
}

// crates/scanner/src/taint.rs
// Update logic to handle new rule

// crates/scanner/references/detection-rules.yaml
- id: new-taint-rule
  description: Example new taint rule
```

### Frozen Eval Split and Measurement Cycle
**Trigger:** When preregistering an evaluation split, running measurements, and recording results for a new version  
**Command:** `/freeze-eval-split`

1. Edit or create `tests/corpus/PREREG-*.md` to record preregistration, schema delta, and split details.
2. Implement or update `scripts/eval/split_*_devtest.py` to generate deterministic dev/test splits.
3. Implement or update `scripts/eval/scan_*_devtest.py` to run the scanner and collect results.
4. Record measurement results in `tests/corpus/PROOF-*.md` and `tests/corpus/*-report.json`.
5. Implement or update `scripts/eval/validate_*_report.py` to validate the measurement report schema.

**Example:**
```markdown
# tests/corpus/PREREG-2024-06.md
- Split: dev/test
- Schema delta: v2.1

# scripts/eval/split_main_devtest.py
# Deterministic split logic here

# scripts/eval/scan_main_devtest.py
# Run scanner and output results
```

### Release Version and Documentation Update
**Trigger:** When finalizing and documenting a new release version  
**Command:** `/release-docs`

1. Create or update `docs/adr/ADR-*.md` to document the new architectural decision.
2. Update `BENCHMARK.md` with new benchmark results.
3. Update `crates/scanner/references/validation-log.md` with validation and quality notes.
4. Update `docs/open-questions.md` with new or deferred questions.
5. Update `README.md` with new version badges and lineage.
6. Bump version in `crates/scanner/Cargo.toml`.
7. Add a new entry in `CHANGELOG.md` for the release.

**Example:**
```markdown
# docs/adr/ADR-2024-06.md
- Decision: Switch to deterministic splits

# BENCHMARK.md
| Version | Score |
|---------|-------|
| 2.1     | 98.7% |

# crates/scanner/Cargo.toml
version = "2.1.0"
```

## Testing Patterns

- **Framework:** Unknown (not explicitly detected)
- **File Pattern:** Test files use the `*.test.ts` pattern, suggesting some TypeScript-based tests.
- **Best Practice:** Place tests alongside or within a `tests/` directory, and ensure new or updated logic is covered by corresponding tests.

**Example:**
```typescript
// example.test.ts
import { scan_file } from '../src/scanFile'

test('should detect taint', () => {
  expect(scan_file('input.txt')).toContain('taint')
})
```

## Commands

| Command           | Purpose                                                                    |
|-------------------|----------------------------------------------------------------------------|
| /add-taint-rule   | Add or update a taint rule and propagate changes throughout the codebase   |
| /freeze-eval-split| Freeze evaluation split, run measurement cycle, and record results         |
| /release-docs     | Finalize and document a new release version                               |
```
