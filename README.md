<div align="center">

# apohara-compliance

**Audit what your AI coding agent _did_ — not just what your repo _contains_.**

[![CI](https://img.shields.io/github/actions/workflow/status/SuarezPM/apohara-compliance/release.yml?style=for-the-badge&label=CI)](https://github.com/SuarezPM/apohara-compliance/actions)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=for-the-badge)](#-license)
[![Rust](https://img.shields.io/badge/rust-1.74%2B-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org)
[![Version](https://img.shields.io/badge/version-1.0.0-purple?style=for-the-badge)](https://github.com/SuarezPM/apohara-compliance/releases)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-success?style=for-the-badge)](https://sarifweb.azurewebsites.net)

**[Quick Start](#-quick-start)** · **[Features](#-features)** · **[Frameworks](#-framework-coverage)** · **[How it works](#-how-it-works--honesty)** · **[Benchmark](BENCHMARK.md)** · **[Security](SECURITY.md)**

A deterministic Rust scanner that maps an AI coding agent's **observed actions** — or a repository — to compliance and agentic-security framework controls, surfacing **candidate** risks _with citations_ for a human to confirm.

</div>

---

```console
$ apohara-compliance-scanner scan-session session.jsonl --format md

# apohara-compliance — candidate findings

_Guidance/mapping only — these are CANDIDATES for review, not assertions of
compliance, certification, or audit conclusions._

**Rules source:** `embedded-fallback` · **Findings:** 5 · **Suppressed:** 0

## Findings

- CANDIDATE — AGT-MIS-001 Destructive Tool Invocation — status: official, confidence: 0.90
  - triggering_signal: rm -rf
  - suggested_controls: SP800-53:SI-7, EU-AI-ACT:Art-9, ISO27001:A.12.1
  - cross_refs: ASI02, ASI05, OWASP-LLM:LLM06, OWASP-LLM:LLM01, AML.T0053, AML.T0050
  - citation: https://doi.org/10.6028/NIST.SP.800-53r5 (version Rev 5)

- CANDIDATE — AGT-EXF-002 Unauthorized Outbound Network Call — status: official, confidence: 0.90
  - triggering_signal: curl http
  - suggested_controls: SP800-53:SC-7, SOC2:CC6.6, ISO27001:A.8.16, OWASP-LLM:LLM02
  - cross_refs: ASI02, ASI04, OWASP-LLM:LLM06, AML.T0025, ISO42001:A.6.2.6
  - citation: https://doi.org/10.6028/NIST.SP.800-53r5 (version Rev 5)

- CANDIDATE — AGT-PI-002 Roleplay Persona Manipulation — status: draft, confidence: 0.70
  - triggering_signal: act as
  - suggested_controls: OWASP-LLM:LLM01, NIST-AI-RMF:AGENTIC-MAP-PROMPT-SURFACE
  - cross_refs: ASI01, OWASP-LLM:LLM01, AML.T0051, AML.T0054
  - citation: https://genai.owasp.org/llm-top-10/ (version 2025)
```

> Real output from `scan-session` over the committed test fixture, trimmed to three of five findings. Every line is prefixed `CANDIDATE —`: a finding is a _please-confirm_, never a verdict.

---

## 💡 Concept

> [!NOTE]
> **The agent's actions are the attack surface.** Most AI-governance tooling inspects data-at-rest or the model itself. But when an AI coding agent runs `rm -rf`, opens an outbound `curl`, dumps a table, or follows an `act as …` instruction, the risk lives in **what it did** — the exact surface the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/) is built around.

`apohara-compliance` reads an AI coding-agent **session transcript** (the newline-delimited JSON record of every tool call it made) — or a repository — and maps the observed signals to framework controls. Each match is a candidate finding carrying the triggering signal, a confidence score, suggested controls, cross-framework references, and a citation (ID, name, version, source URL). A human reviewer decides what is real.

It is, as far as we know, the first developer-tier tool built directly on the OWASP Top 10 for Agentic Applications.

---

## ✨ Features

| | |
|---|---|
| 🎯 **Action-level scanning** | Maps an agent's actual tool calls (`scan-session`), not just files at rest. Also scans repositories (`scan-repo`). |
| 📑 **Cited candidates** | Every finding carries `{id, title, status, confidence, triggering_signal, citation(url+version), suggested_controls, cross_refs}`. No copyrighted framework prose is reproduced. |
| 🧭 **10-framework crosswalk** | One signal resolves across OWASP Agentic, OWASP LLM, MITRE ATLAS, ISO 42001, EU AI Act, NIST, SOC 2 and ISO 27001 — see the [coverage table](#-framework-coverage). |
| 🔌 **SARIF 2.1.0 output** | `--format sarif` is CI-ingestible by code scanning. Findings are `note`/`warning` — **never** `error`. A wrapping GitHub Action is included. |
| 🔍 **Gap analysis** | `gap` lists carried controls with **no** candidate evidence — "no signal observed for X", never "you fail X". |
| 📉 **Baseline diff** | `--baseline <prior.json> --only-new` reports only new findings via SARIF `baselineState`. |
| 🎚️ **Tunable + suppressible** | `--min-confidence` / `--min-severity` thresholds and a visible-by-default suppression channel via `.apohara-compliance.toml`. |
| 🦀 **Offline & deterministic** | Pure Rust, MSRV 1.74. No network, no API keys, no telemetry. Same input ⇒ same bytes out. |

---

## 🚀 Quick Start

```sh
# 1. Install the scanner (builds from source — lowest-trust path)
cargo install apohara-compliance-scanner

# 2. Audit an AI coding-agent session transcript
apohara-compliance-scanner scan-session ./session.jsonl --format md

# 3. Audit a repository and emit SARIF for code scanning
apohara-compliance-scanner scan-repo . --format sarif > results.sarif
```

<details>
<summary><b>Advanced usage</b> — formats, ASI view, diffing, gap analysis, config</summary>

```sh
# Surface OWASP Agentic (ASI01–ASI10) risks directly alongside the AGT findings
apohara-compliance-scanner scan-session ./session.jsonl --by-asi --format md

# Diff against a prior run — emit only NEW findings (SARIF baselineState)
apohara-compliance-scanner scan-repo . --format json > baseline.json
apohara-compliance-scanner scan-repo . --baseline baseline.json --only-new --format sarif

# Gap analysis: carried controls with no candidate evidence observed
apohara-compliance-scanner gap ./session.jsonl --format md

# Thresholds, file-extension filter, and project config
apohara-compliance-scanner scan-repo . --ext rs,py --min-confidence 0.8 \
  --min-severity 3 --config .apohara-compliance.toml --format json
```

**Global flags:** `--format {json|sarif|md}` (default `json`) · `--by-asi` · `--baseline <file>` · `--only-new` · `--min-confidence <f>` · `--min-severity <n>` · `--suppress <file>` · `--config <file>` · `--ext <list>` (repo only).

**Other acquisition paths.** Pre-built, signed per-OS binaries are published on [Releases](https://github.com/SuarezPM/apohara-compliance/releases). It also installs as an agent skill/plugin.

> [!WARNING]
> Downloading a pre-built binary is itself a supply-chain surface — the very risk this tool flags. Verify the build attestation and checksum before running it (see **[SECURITY.md → How to verify a release](SECURITY.md#how-to-verify-a-release)**), or prefer `cargo install` and build from source.

</details>

---

## 🧭 Framework coverage

Cross-references resolve along the chain **ASI → OWASP-LLM → ATLAS → ISO 42001 → EU AI Act**, with NIST and audit-standard controls hanging off each node.

| Framework | Version | Scope |
|---|---|---|
| **OWASP Top 10 for Agentic Applications** | **2026** (ASI01–ASI10) | Primary mapping target |
| OWASP Agentic Skills Top 10 | 2026 (AST01–AST10) | Draft project |
| OWASP Top 10 for LLM Applications | **2025** | LLM-layer cross-refs |
| MITRE ATLAS | 5.6.0 | Adversarial ML techniques |
| ISO/IEC 42001 | 2023 | AI management system |
| EU AI Act | Regulation (EU) 2024/1689 | High-risk obligations |
| NIST AI RMF | 1.0 | Govern / Map / Measure / Manage |
| NIST SP 800-53 | Rev 5 | Security & privacy controls |
| SOC 2 | AICPA TSC 2017 | Trust services criteria |
| ISO/IEC 27001 | 2022 | Information security |

---

## 🔬 How it works / honesty

> [!WARNING]
> **This is a guidance and mapping tool. It is NOT a certification, an audit, or legal advice.** Running it does not make a project "compliant". Every finding is a _candidate_ surfaced for human review — never an assertion that a control is met or violated, and never a substitute for a qualified auditor or counsel.

**Candidates only.** Findings are emitted as SARIF `note`/`warning`, never `error`, and every line is prefixed `CANDIDATE —`. A false positive is a "please confirm", not a wrong verdict.

**Traceable provenance.** 49 carried controls each trace to a cited source. Each finding records `status: official` or `status: draft`. In particular, NIST `AGENTIC-*` controls are flagged **`draft`** — they derive from a **March-2026 CSA draft profile, not official NIST**, and the scanner says so on every such finding. IDs, names, and versions are cited; no copyrighted framework text is reproduced.

**Measured, gated precision.** A committed CI harness runs the **real** scanner over a synthetic precision/recall corpus on every `cargo test`. On that corpus:

| Matcher (same synthetic corpus) | Precision | Recall |
|---|---|---|
| Naive substring baseline | 0.70 | 1.00 |
| Tuned engine (regex + word-boundary + context) | **1.00** | **1.00** |

The tuning removes the substring matcher's false positives (0.70 → 1.00 precision) **without regressing recall**. The build **fails below precision 0.85**. Full numbers, per-rule breakdown, the reproduction command, and the honest limitations are in **[BENCHMARK.md](BENCHMARK.md)** (the source of record).

> [!NOTE]
> Those are metrics on a **100% synthetic, hand-crafted fixture corpus** — fixture metrics, not a claim of real-world accuracy. No real agent session is committed or used for the gate.

---

## 🏗️ Repository layout

```text
apohara-compliance/
├── crates/scanner/          # the deterministic Rust scanner
│   ├── src/
│   │   ├── cli.rs           # clap CLI surface (scan-session / scan-repo / gap)
│   │   ├── matching.rs      # regex + word-boundary + context engine
│   │   ├── rules.rs         # rule loading + resolution ladder
│   │   ├── parse_session.rs # tolerant NDJSON session-transcript reader
│   │   ├── parse_repo.rs    # gitignore-respecting repo walker
│   │   ├── baseline.rs      # diff vs. a prior run (SARIF baselineState)
│   │   └── format/          # json · sarif · md · gap renderers
│   └── tests/               # integration + committed precision/recall gate
├── references/              # canonical framework rule + crosswalk YAML data
├── skills/                  # installable agent skill
├── action/                  # GitHub Action wrapper (uploads SARIF)
└── tests/fixtures/          # synthetic session + repo fixtures
```

---

## 🗺️ Roadmap

- [x] Action-level session scanning (`scan-session`)
- [x] Repository scanning (`scan-repo`) and gap analysis (`gap`)
- [x] SARIF 2.1.0 output + GitHub Action
- [x] Committed synthetic precision/recall CI gate
- [x] Baseline diffing (`--baseline` / `--only-new`)
- [x] Signed per-OS release binaries with build attestation ([how to verify](SECURITY.md#how-to-verify-a-release))
- [x] Per-rule precision reporting ([BENCHMARK.md](BENCHMARK.md))
- [ ] Expanded synthetic corpus
- [ ] Additional agent-transcript formats

---

## 🤝 Contributing

Contributions are welcome.

1. **Fork** the repository.
2. Create a feature **branch** (`git checkout -b feature/my-change`).
3. Make your change and run the tests: `cargo test` (the precision/recall gate runs here).
4. Open a **pull request**.

> Unless you state otherwise, any contribution you intentionally submit for inclusion in this work, as defined in the Apache-2.0 license, shall be dual-licensed as below, without any additional terms or conditions.

---

## 📄 License

Licensed under either of **[MIT](LICENSE-MIT)** or **[Apache-2.0](LICENSE-APACHE)**, at your option.

Maintained by **[SuarezPM](https://github.com/SuarezPM)**.
