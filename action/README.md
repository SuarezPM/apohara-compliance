# apohara-compliance — GitHub Action

A composite GitHub Action that runs the
[`apohara-compliance-scanner`](https://github.com/SuarezPM/apohara-compliance)
over a repository or an AI coding-agent session transcript and uploads the result to
**GitHub code scanning** as SARIF 2.1.0.

> **These are CANDIDATES, not failures.** Every finding is surfaced as a
> code-scanning **warning** or **note**, *never* an `error`, and every message is
> prefixed with `CANDIDATE — `. The scanner maps agent actions / repository
> signals to compliance and security framework controls *for a human to review*.
> It does **not** assert compliance, certification, or that anything is
> "vulnerable" or "non-compliant". A code-scanning alert from this action means
> "a reviewer should look at this", not "this build is broken".

## Why warnings/notes, never errors

The scanner's SARIF `level` is structurally constrained to `warning`
(official-provenance control) or `note` (draft-provenance control) — it can
**never** emit `error`. Because of that, this action does not (and cannot) fail a
build on findings; results appear in the repository's **Security → Code scanning**
tab as candidates. This is the honesty contract of the whole project: candidates,
never assertions.

## Usage

```yaml
name: apohara-compliance
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # required to upload SARIF to code scanning

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: SuarezPM/apohara-compliance/action@main
        with:
          mode: scan-repo
          target: .
```

### Scan only specific file types (`scan-repo`)

```yaml
      - uses: SuarezPM/apohara-compliance/action@main
        with:
          mode: scan-repo
          target: .
          ext: rs,py        # walker reads only .rs/.py files (commodity filter)
```

### Baseline / diff (report only new candidates)

```yaml
      - uses: SuarezPM/apohara-compliance/action@main
        with:
          mode: scan-repo
          target: .
          baseline: .apohara/baseline.json   # a prior `--format json` report
          only-new: "true"                   # emit only baselineState == new
```

When `baseline` is set, each SARIF result carries a `baselineState`
(`new` / `unchanged` / `absent`, from the SARIF 2.1.0 enum). With
`only-new: "true"`, only `new` candidates are uploaded. A re-run with no changes
produces zero `new` candidates.

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `mode` | `scan-repo` | `scan-repo`, `scan-session`, or `gap`. |
| `target` | `.` | Repo root, or a `.jsonl` session transcript for `scan-session`. |
| `ext` | `""` | Comma-separated extension allowlist for `scan-repo` (e.g. `rs,py`). |
| `baseline` | `""` | Path to a prior `--format json` report for diff mode. |
| `only-new` | `false` | With `baseline`, emit only `baselineState == new`. |
| `rules-dir` | `""` | Path to canonical `references/*.yaml`; omit to use embedded rules. |
| `scanner-version` | `""` | Pin a crates.io version; omit for the latest. |
| `sarif-file` | `apohara-compliance.sarif` | SARIF output path. |
| `category` | `apohara-compliance` | SARIF category for the upload. |
| `upload` | `true` | Set `false` to skip the code-scanning upload. |

## How the binary is acquired

The action uses the **PRIMARY, lowest-trust-assumption** path from the skill's
`SKILL.md`: it installs a Rust toolchain and runs `cargo install
apohara-compliance-scanner`, building from source with the rules embedded from
the canonical `references/*.yaml` at build time. On this path the scanner reports
`rules_source: embedded-fallback`, which is the **expected steady state** (the
installed binary has no nearby `references/` to load), not an anomaly. Pass
`rules-dir` to point it at an on-disk `references/` if you prefer.

## Permissions

Uploading SARIF to code scanning requires `security-events: write`. On pull
requests from forks (where that permission is unavailable), set `upload: "false"`
to still produce the SARIF artifact without uploading.
