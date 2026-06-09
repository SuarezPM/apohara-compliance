<div align="center">

# apohara-compliance

**Audit what your AI coding agent _did_ — not just what your repo _contains_.**

[![CI](https://img.shields.io/github/actions/workflow/status/SuarezPM/apohara-compliance/release-v3.yml?style=for-the-badge&label=CI)](https://github.com/SuarezPM/apohara-compliance/actions)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=for-the-badge)](#-license)
[![Rust](https://img.shields.io/badge/rust-1.74%2B-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org)
[![Version](https://img.shields.io/badge/version-2.2.0-purple?style=for-the-badge)](https://github.com/SuarezPM/apohara-compliance/releases)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-success?style=for-the-badge)](https://sarifweb.azurewebsites.net)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/SuarezPM/apohara-compliance/badge?style=for-the-badge)](https://scorecard.dev/viewer/?uri=github.com/SuarezPM/apohara-compliance)

**[Quick Start](#-quick-start)** · **[Features](#-features)** · **[Frameworks](#-framework-coverage)** · **[How it works / honesty](#-how-it-works--honesty)** · **[Benchmark](BENCHMARK.md)** · **[Security](SECURITY.md)**

A deterministic Rust scanner that maps an AI coding agent's **observed actions** — or a repository — to compliance and agentic-security framework controls, surfacing **candidate** risks _with citations_ for a human to confirm.

</div>

> **Honesty lineage at a glance.** `main` carries the v1.1 release **plus** the additive v2.0 → v2.1 → v2.2 trajectory/taint work (ADR-4 → ADR-5 → ADR-6). The latest crates.io / GitHub Release tag is still **v1.1.0** — the v2.x line is shipped on `main` but **not yet tagged/published** (Pablo-gated). Everything v2.x is offline + deterministic + byte-identical to v1.1 on the single-action engine; the additive passes do not change the existing rules. See **[How it works / honesty](#-how-it-works--honesty)** and **[BENCHMARK.md](BENCHMARK.md)** for the bound triple and the explicit co-headline limit.

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
| 🎯 **Action-level scanning** | Maps an agent's actual tool calls (`scan-session`), not just files at rest. Also scans repositories (`scan-repo`) and OTLP-exported telemetry off disk (`scan-otlp`, offline). |
| 🧠 **Multi-action sequence** | Beyond single-action signals, an ordered second pass surfaces OWASP **ASI06 (Memory & Context Poisoning)** candidates (`AGT-MEM-001`): untrusted content followed by a write to a memory/RAG sink — candidate-only, never a runtime guarantee. [ADR-2](docs/adr/ADR-2-multi-action-sequence-matching.md) |
| 🧬 **Trajectory taint-correlation** | A third, additive pass (`AGT-TRJ-001/002/003`) correlates an **injection marker in untrusted data the agent READ** (a `tool-result:` action) with a **later sensitive real-action sink** (exfil / destructive / financial) in the same stream. Post-hoc; recognisable-in-log ≠ would-have-prevented. [ADR-4](docs/adr/ADR-4-trajectory-taint-correlation.md) |
| 🏷️ **Representation-aware taint** | The v2.1 sink parser emits a reserved `sink:` action carrying canonical role tokens (`recipient=` / `amount=` / `url=` / `command=`, with a `const SINK_GRAMMAR` authority boundary) and the AGT-TRJ rules ship a taxonomy-derived **generic injection-marker** vocabulary. Closes the v2.0 representation gap. [ADR-5](docs/adr/ADR-5-representation-aware-taint-and-evasion-robust-matching.md) |
| 📊 **Real-trajectory measurement** | The v2.2 eval harness runs the **frozen** rules over real successful indirect-injection trajectories from last-gen frontier models (AgentDyn) and against live current-frontier models (OpenRouter) — bound triple + overlap-miss, no retro-fit. [ADR-6](docs/adr/ADR-6-real-trajectory-efficacy.md) |
| 🐚 **Structural shell tokenizer** | A `shlex`-backed pass catches flag-reordered destructive commands a substring scan cannot (e.g. `rm -r -f` / `rm -fr` / quoted-arg variants), folded into `AGT-MIS-004`. |
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

# Scan OTLP-exported telemetry (logs/traces) an OTel exporter wrote to disk.
# Runtime coverage for the OFFLINE scanner — it reads FILES only, no socket.
# Post-hoc and exporter-bounded; findings stay candidates, never real-time.
apohara-compliance-scanner scan-otlp ./otel-export.json --format sarif
apohara-compliance-scanner scan-otlp ./otel-logs/ --format md   # a directory of exports

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

The detection engine is built up in additive passes, each documented in its own ADR. The passes are independent and the scanner emits a `CANDIDATE —` line for any of them that fires.

### Pass 1 — single-action matching (v1.0)

A regex + word-boundary + context engine matches each observed action against the carried rule set. On the committed synthetic corpus, the tuning removes the substring matcher's false positives without regressing recall:

| Matcher (same synthetic corpus) | Precision | Recall |
|---|---|---|
| Naive substring baseline | 0.6389 | 0.9200 |
| Tuned engine (regex + word-boundary + context) | **1.0000** | **1.0000** |

The build **fails below precision 0.85**. Full numbers, per-rule breakdown, the reproduction command, and the honest limitations are in **[BENCHMARK.md](BENCHMARK.md)** (the source of record).

> [!NOTE]
> Those are metrics on a **100% synthetic, hand-crafted fixture corpus** — fixture metrics, not a claim of real-world accuracy. The headline result is the **false-positive reduction** (baseline→tuned delta), not the absolute 1.00. The corpus and the context rules co-evolved, so a perfect tuned score is partly true by construction.

### Pass 2 — multi-action sequence correlation (v1.1, `AGT-MEM-001`, ASI06)

An opt-in, additive pass correlates an _ordered_ pair — untrusted/unsanitized content **followed by** a write to a memory/RAG sink — to surface OWASP **ASI06 (Memory & Context Poisoning)** candidates. Sink coverage is bounded to what the transcript/telemetry surfaces (shell persist commands + exported OTLP records). Like every finding it is **candidate-only**: it flags content that _could_ poison future context, never a detection of activated cross-session poisoning. See [ADR-2](docs/adr/ADR-2-multi-action-sequence-matching.md).

### Pass 3 — trajectory taint-correlation (v2.0, `AGT-TRJ-001/002/003`, ADR-4)

The taint engine expresses the **injection → consequence dataflow** the single-action and sequence passes cannot: a TAINTED source — an action on the untrusted-data `tool-result:` channel carrying injection markers (and **not** a doc/comment quote) — **followed by** a genuine sensitive real-action sink (exfil / destructive / financial) later in the same action stream. The taint persists across intervening steps (forward-correlated).

A fired AGT-TRJ candidate means **"untrusted-marked data was observed and a sensitive action followed"** — a candidate injection→consequence correlation, **not** a verdict that the agent obeyed the injection. The module is self-contained in `crates/scanner/src/taint.rs` and runs after the single-action and sequence passes in `matching::match_actions_with_suppress`. See [ADR-4](docs/adr/ADR-4-trajectory-taint-correlation.md).

> **Honesty invariant.** Mechanism proven on synthetic positives; live MiniMax-M3 run on AgentDojo banking-suite `important_instructions` was **0 / 10** attack-success (the target refused every injection), so post-hoc detection on real successes is **0 / 0 — undefined** at v2.0. Real-world efficacy is **UNPROVEN at v2.0** (stated plainly in the PREREG + PROOF).

### Pass 4 — representation-aware taint (v2.1, ADR-5)

v2.1 closes the v2.0 **representation gap**. The parser now emits a reserved `sink:` action carrying a deterministic canonical role string (`recipient=` / `amount=` / `url=` / `command=`, with `const SINK_GRAMMAR` enforcing an authority boundary), and the AGT-TRJ rules gained a **taxonomy-derived generic injection-marker** vocabulary (OWASP ASI02:2026 / AITG-APP-02 / documented IPI canary families — each marker cited in `detection-rules.yaml`). The `sink:` channel is excluded from the single-action loop by a one-line `starts_with("sink:")` guard, so the new representation **cannot** produce a single-action false positive (proven by the C1 FP-safety + C2 grammar-disjointness tests).

Mechanism + representation proven on a synthetic positive: `trj-representation-aware-positive.jsonl` fires AGT-TRJ-001 + AGT-TRJ-003; the FinBot direct-injection fixture (negative control) and the benign-trajectory trap fire **zero**. Pre-registered measurement on the committed AgentDojo corpus (frozen rules SHA `ac88825`, no LLM) confirmed the single-action recall is **unchanged** at **23 / 35 (0.657)** — the v2.1 work added **no** new single-action prose rules. See [ADR-5](docs/adr/ADR-5-representation-aware-taint-and-evasion-robust-matching.md).

> **Honesty invariant.** Mechanism + representation proven on synthetic positives; the AgentDojo committed corpus is **flat bait** (no `tool-result:` → `sink:` dataflow), so it has zero trajectory items to exercise the structured-sink representation on a real trace. Real-world efficacy is **still UNPROVEN at v2.1** (stated plainly).

### Pass 5 — real-trajectory measurement (v2.2, ADR-6) — the bound triple + ceiling

v2.2 closes the v2.0/v2.1 "real-world efficacy UNPROVEN **by absence of any real trajectory**" gap. The engine is run, with the **same frozen rules** (blob SHA `dcd1ac6`, frozen BEFORE scanning) and the apohara-agnostic `wrap_agentdojo_trace.py` wrapper, over two externally-labeled corpora. The number is reported as a **bound triple** + its representation overlap-miss, and the correlation-not-causation ceiling is stated as a **co-headline of equal prominence**.

**HEADLINE.** apohara v2.1 post-hoc-recognises the injection → sink correlation in **169 / 236 (71.6 %)** of real successful indirect-injection trajectories from last-generation frontier models (AgentDyn open-ended suites). This closes the v2.0 "absence" gap — the mechanism fires on real traces, not only synthetic.

**CO-HEADLINE LIMIT (equal prominence, never buried).** It ALSO fires on **28.7 % (659 / 2295)** of **resisted** injections and **1.4 % (5 / 352)** of benign traces. apohara is a **candidate injection → consequence correlation surfacer**, NOT a success / causation discriminator: a resisted injection still carries the marker in a tool-result AND the agent still performs a legitimate structured sink, so the marker → sink correlation fires in both succeeded and resisted cases. **precision-on-success ≈ 169 / (169+659+5) = 169/833 ≈ 20 %.** The discriminating signal (did the agent OBEY the injection) is not representable in a deterministic post-hoc text-pattern model — this is the **quantified ceiling**.

**The bound triple — DOWNLOAD corpus** (AgentDyn `@ 5353cf7`, agentdojo 0.1.35, benchmark v1.2.2; attack `important_instructions`; **last-gen** models, date-labeled; open-ended suites; frozen rules `dcd1ac6`):

| | result |
|---|---|
| (a) model attack-success-rate (AgentDyn labels, apohara-independent) | gpt-5.1-2025-11-13 **33 / 851** (3.9 %) · gpt-5-mini-2025-08-07 **2 / 560** (0.4 %) · gemini-2.5-pro **122 / 560** (21.8 %) · gemini-2.5-flash **79 / 560** (14.1 %) |
| (b) apohara post-hoc AGT-TRJ detection on the 236 real successes | **169 / 236 (71.6 %)** — gpt-5.1 25/33 · gpt-5-mini 0/2 · gemini-2.5-pro 89/122 · gemini-2.5-flash 55/79 (AGT-TRJ-001 dominant, AGT-TRJ-003 secondary) |
| (c) false-positive control | failed-injection (RESISTED) FP **659 / 2295 (28.7 %)** · benign FP **5 / 352 (1.4 %)** ⇒ precision-on-success **169/833 ≈ 20 %** |

**Overlap-miss** (model-independent representation coverage of the 236 positives): marker `<information>` covered 232/236; role-mapped structured sink covered 180/236; BOTH 178/236; NEITHER 2/236. Covered sink roles: `url=170, recipient=60, amount=59, command=34`. MISSED arg-keys (OUTSIDE the frozen role map — the `iban`-analog): `path (161), subject (114), otp (87), title (79), body (68), recipients (68), repo_name (54), password (33)`. **Reported as-is, NEVER closed** — adding any of these after seeing traces would convert the number from a **MEASUREMENT** into a **FIT** (forbidden by the pre-registration).

**The bound triple — LIVE current-frontier** (via OpenRouter; suite `workspace`; attack `important_instructions_no_model_name`; same frozen rules + frozen wrapper + release binary; current-frontier models, date-labeled: gpt-5.5, gemini-3.5-flash, gemini-3.1-pro-preview, MiniMax-M3, claude-opus-4.8):

| | result |
|---|---|
| (a) attack-success TOTAL | **0 / 80 (0.0 %)** — EACH model 0 / 16 |
| (b) apohara post-hoc detection on successes | **0 / 0 — UNDEFINED** (no live success to detect on) |
| (c) false-positive control | failed-injection FP **0 / 80** · benign FP **0 / 15** (the download 28.7 % correlation-FP did **NOT** reproduce on this live set) |
| real LIVE usage | **224 API calls, all HTTP 200; 698,959 tokens** (smoke + live; under the 1 M cap); key never logged |

> **CAVEAT (stated).** The live run used `suite=workspace` (the standard AgentDojo suite), NOT AgentDyn's harder open-ended suites (shopping / github / dailylife) where last-gen models reached 14–22 % ASR — because the current-frontier OpenRouter IDs are not in AgentDyn's model registry. So the live 0/80 is on the **easier standard suite**; current-frontier behaviour on the harder open-ended attack is **UNMEASURED** (a documented follow-up). The download corpus (last-gen, open-ended) remains the only set with real successes.

> **Claim ceiling (verbatim, ADR-6).** *"deterministic, post-hoc, representation-aware injection → consequence CANDIDATE CORRELATION surfacer; mechanism + representation proven on synthetic positives; post-hoc recognition MEASURED on real successful trajectories (169/236, last-gen open-ended) with an explicit model-independent overlap-miss; ALSO fires on resisted (28.7 %) + benign (1.4 %) — a correlation surfacer, NOT a success / causation discriminator (precision-on-success ≈ 20 %); NOT efficacy / recall / prevention; recognisable-in-log ≠ would-have-prevented."*

Pre-registration (`tests/corpus/PREREG-v2.2-real-trajectory.md`, rules frozen at `dcd1ac6` **BEFORE** scanning, verified unchanged) and the schema-validated numbers-only report (`tests/corpus/v2.2-real-trajectory-report.json`) are committed; the AgentDyn trace content is gitignored. See [ADR-6](docs/adr/ADR-6-real-trajectory-efficacy.md) + `PROOF-v2.2-real-trajectory.md`.

---

## 🏗️ Repository layout

```text
apohara-compliance/
├── crates/scanner/                       # the deterministic Rust scanner
│   ├── src/
│   │   ├── cli.rs                        # clap CLI surface (scan-session / scan-repo / scan-otlp / gap)
│   │   ├── matching.rs                   # regex + word-boundary + context engine (orchestrates the passes)
│   │   ├── rules.rs                      # rule loading + resolution ladder
│   │   ├── sequence.rs                   # Pass 2 — multi-action AGT-MEM-001 (ADR-2)
│   │   ├── taint.rs                      # Pass 3-4 — trajectory taint + representation-aware (ADR-4/5)
│   │   ├── shell.rs                      # structural `shlex` shell pass — flag-reorder evasions (v2.1)
│   │   ├── model.rs                      # the candidate finding + rule data model
│   │   ├── parse_session.rs              # tolerant NDJSON session-transcript reader
│   │   ├── parse_otlp.rs                 # tolerant OTLP/JSON telemetry reader (offline, file-only)
│   │   ├── parse_repo.rs                 # gitignore-respecting repo walker
│   │   ├── baseline.rs                   # diff vs. a prior run (SARIF baselineState)
│   │   ├── config.rs / gap.rs / suppress.rs / triage.rs
│   │   └── format/                       # json · sarif · md · gap renderers
│   ├── tests/
│   │   ├── integration.rs                # unit + integration
│   │   ├── precision_recall.rs           # CI-gated synthetic precision/recall (v1.0)
│   │   ├── independent_corpus.rs         # AgentDojo / AgentHarm non-gating cross-check (v1.4)
│   │   └── trajectory_corpus.rs          # v2.0/v2.1 trajectory + AGT-TRJ positive/negative fixtures
│   └── references/                       # canonical framework rule + crosswalk YAML data
├── docs/adr/                             # ADR-2 sequence · ADR-3 corpus · ADR-4 taint · ADR-5 repr · ADR-6 efficacy
├── tests/corpus/                         # synthetic gate + AgentDojo + AgentHarm + v2.x PREREG/PROOF/report
├── references/                           # canonical rule + mapping data (mirror, symlinked into the crate)
├── skills/                               # installable agent skill
├── action/                               # GitHub Action wrapper (uploads SARIF)
├── tests/fixtures/                       # synthetic session + repo fixtures
└── scripts/                              # capture + eval harness (FINBOT, v2.2 buckets, polarity gate, …)
```

---

## 🗺️ Roadmap

**Shipped** (on `main`, not all on crates.io/Releases — see badge)

- [x] v1.0 — Action-level session scanning (`scan-session`), repo scanning (`scan-repo`), gap analysis (`gap`)
- [x] v1.0 — SARIF 2.1.0 output + GitHub Action
- [x] v1.0 — Committed synthetic precision/recall CI gate (precision floor 0.85, no-recall-regression bound)
- [x] v1.0 — Baseline diffing (`--baseline` / `--only-new`)
- [x] v1.0 — Signed per-OS release binaries with build attestation ([how to verify](SECURITY.md#how-to-verify-a-release))
- [x] v1.0 — Per-rule precision reporting ([BENCHMARK.md](BENCHMARK.md))
- [x] v1.1 — `scan-otlp` (OTLP-exported telemetry, offline) + `AGT-MEM-001` multi-action sequence pass (ADR-2)
- [x] v1.1 — `SECURITY.md` (disclosure / threat model / supply-chain verify) + `BENCHMARK.md` (reproducible)
- [x] v1.1 — OpenSSF Scorecard, Dependabot, CodeQL
- [x] v1.4 — Independent corpora (AgentDojo + AgentHarm, non-gating) for prose-rule coverage (ADR-3)
- [x] v2.0 — Trajectory taint-correlation engine (ADR-4): injection → consequence dataflow, post-hoc, offline
- [x] v2.1 — Representation-aware taint (ADR-5): `sink:` channel + `const SINK_GRAMMAR` role tokens + generic injection-marker vocabulary + structural `shlex` shell pass (AGT-MIS-004)
- [x] v2.2 — Real-trajectory measurement (ADR-6): bound triple on real AgentDyn successes (169/236) + live current-frontier cross-check (0/80 resisted); HONEST co-headline (28.7 % FP on resisted, ~20 % precision-on-success) — the framing IS the deliverable

**Exploring** — demand-driven, not committed

- [ ] v2.3 (proposed) — argument-value provenance discriminator to attack the 28.7 % correlation-FP (causal proxy, deterministic, offline). Pre-proposal at `.omc/plans/v2.3-followups.md` (consensus IN PROGRESS).
- [ ] v2.3 (proposed) — current-frontier on the harder AgentDyn open-ended suites (shopping / github / dailylife). Blocked by AgentDyn's model registry not carrying current-frontier OpenRouter IDs.
- [ ] v2.3 (proposed) — S2 shell AST escalation (conch-parser vendor) if the `shlex` pass proves insufficient on adversarial inputs.
- [ ] Repo-file normalisation (ADR-5 M4 deferred gap) — A3 homoglyph / zero-width / casing runs in the session value picker only; a future PR extends it to `parse_repo` for the dominant indirect-injection surface.
- [ ] Additional agent-transcript formats
- [ ] First-mover OWASP Agentic Skills (AST01–AST10) rules once the draft stabilises

---

## 🤝 Contributing

Contributions are welcome.

1. **Fork** the repository.
2. Create a feature **branch** (`git checkout -b feature/my-change`).
3. Make your change and run the tests: `cargo test` (the precision/recall gate + the trajectory + the independent-corpus gates all run here).
4. Open a **pull request**.

> Unless you state otherwise, any contribution you intentionally submit for inclusion in this work, as defined in the Apache-2.0 license, shall be dual-licensed as below, without any additional terms or conditions.

---

## 📄 License

Licensed under either of **[MIT](LICENSE-MIT)** or **[Apache-2.0](LICENSE-APACHE)**, at your option.

Maintained by **[SuarezPM](https://github.com/SuarezPM)**.
