<p align="center">
  <img src="assets/banner.svg" alt="APOHARA · Compliance — audit what your AI coding agent did" width="100%">
</p>

# apohara-compliance

**Audit what your AI coding agent _did_ — not just what your repo _contains_.**

A deterministic Rust scanner that maps an AI coding agent's **observed actions** — or a repository — to compliance and agentic-security framework controls, surfacing **candidate** risks _with citations_ for a human to confirm.

[![CI](https://img.shields.io/github/actions/workflow/status/SuarezPM/apohara-compliance/codeql.yml?style=for-the-badge&label=CI)](https://github.com/SuarezPM/apohara-compliance/actions)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=for-the-badge)](#-license)
[![Rust](https://img.shields.io/badge/rust-1.74%2B-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org)
[![Version](https://img.shields.io/badge/version-2.4.0-purple?style=for-the-badge)](https://github.com/SuarezPM/apohara-compliance/releases)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/SuarezPM/apohara-compliance/badge?style=for-the-badge)](https://scorecard.dev/viewer/?uri=github.com/SuarezPM/apohara-compliance)

## Contents

- [What it does](#-what-it-does)
- [Real output](#-real-output)
- [What we measured](#-what-we-measured)
- [Quick start](#-quick-start)
- [Framework coverage](#-framework-coverage)
- [How it works](#-how-it-works)
- [Repository layout](#-repository-layout)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## What it does

> Most AI-governance tooling inspects data-at-rest or the model itself. But when an AI coding agent runs `rm -rf`, opens an outbound `curl`, dumps a table, or follows an `act as …` instruction, the risk lives in **what it did** — the exact surface the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/) is built around.

`apohara-compliance` reads an AI coding-agent **session transcript** (the newline-delimited JSON record of every tool call it made) — or a repository — and maps the observed signals to framework controls. Each match is a candidate finding carrying the triggering signal, a confidence score, suggested controls, cross-framework references, and a citation (ID, name, version, source URL). A human reviewer decides what is real.

It is, as far as we know, the first developer-tier tool built directly on the OWASP Top 10 for Agentic Applications.

---

## Real output

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

## What we measured

Honesty is the deliverable. Every headline number below is reproducible from a frozen rules SHA, a pre-registered protocol, and a schema-validated report. The ceiling is stated as prominently as the result.

| | claim | scope | reference |
|---|---|---|---|
| v1.0 | Precision **1.0000** / Recall **1.0000** | 100% synthetic, hand-crafted fixture corpus (precision/recall CI gate floor: 0.85) | [BENCHMARK.md](BENCHMARK.md) |
| v1.4 | AgentDojo recall **23 / 35 (0.657)** | Static prose rules on the committed AgentDojo corpus (frozen rules SHA `ac88825`) | [ADR-3](docs/adr/ADR-3-independent-corpora-and-prose-rule-coverage.md) |
| v2.2 | AGT-TRJ detection **169 / 236 (71.6%)** on real AgentDyn successes | Last-gen frontier models, open-ended suites, frozen rules `dcd1ac6`; live current-frontier 0/80 on the standard suite (resisted all) | [ADR-6](docs/adr/ADR-6-real-trajectory-efficacy.md) |
| v2.2 | Co-headline: **28.7% (659/2295) FP on resisted** + **1.4% (5/352) on benign** | Same corpus; ⇒ precision-on-success ≈ 20% — post-hoc correlation is not a success/causation discriminator | [ADR-6](docs/adr/ADR-6-real-trajectory-efficacy.md) |
| v2.3 | AGT-TRJ-*-P coverage **100 / 192 (52.1%)** on test positives | Post-hoc substring-match proxy, frozen PREREG SHA `5e62e9e2`; BENIGN FP 0/352, FAILED FP 13.9% (halved vs v2.2) | [ADR-7](docs/adr/ADR-7-argument-value-provenance.md) |
| v2.4 | S2 shell AST parser **SHIPPED**, in-tree hand-rolled recursive descent, ~60 unit tests | Focused subset (pipeline \| subshell \| command_substitution \| heredoc \| simple + redirection); control flow + arithmetic EXPLICITLY OUT; 3-mechanism safety split | [ADR-9](docs/adr/ADR-9-posix-shell-parser-ativo.md) |
| v2.4 | AgentDyn open-ended frontier probe **PASS** (B-0.1) + live MINIMAX-M3 run **0 / 4 ASR on dailylife** (B-1) | 3 open-ended suites registered after venv reinstall; B-1 used `MINIMAX_API_KEY` (free tier, $0 cost); B-2 -P re-measure DEFERRED (0 injection-succeeded trajectories to re-measure) | [PROOF-v2.4-open-ended.md](PROOF-v2.4-open-ended.md) |

> **Claim ceiling (verbatim, ADR-6/ADR-7).** *Deterministic, post-hoc, representation-aware injection → consequence candidate correlation surfacer. Mechanism + representation proven on synthetic positives. Post-hoc recognition measured on real successful trajectories. Not efficacy / recall / prevention. Recognisable-in-log ≠ would-have-prevented.*

What is **not** claimed: real-time prevention, success/causation discrimination, efficacy on current-frontier harder suites (the v2.4 open-ended frontier probe is the first measurement attempt; **0/4 ASR on dailylife with MiniMax-M3** is documented honestly in [PROOF-v2.4-open-ended.md](PROOF-v2.4-open-ended.md) but is **not** a generalizable frontier result).

---

## Quick start

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

## Framework coverage

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

## How it works

<p align="center">
  <img src="assets/diagram.svg" alt="Compliance evidence matrix — 3 frameworks (OWASP-Agentic, NIST AI RMF, ISO/IEC 42001) × 3 finding types (prompt-injection, exfiltration, policy-violation), with a real human-review evidence sample (trace → tool_call → cited)" width="100%">
</p>

> [!WARNING]
> **This is a guidance and mapping tool. It is NOT a certification, an audit, or legal advice.** Running it does not make a project "compliant". Every finding is a _candidate_ surfaced for human review — never an assertion that a control is met or violated, and never a substitute for a qualified auditor or counsel.

The detection engine is built up in additive passes, each documented in its own ADR. The passes are independent and the scanner emits a `CANDIDATE —` line for any of them that fires. **Candidates only.** Findings are emitted as SARIF `note`/`warning`, never `error`, and every line is prefixed `CANDIDATE —`. A false positive is a "please confirm", not a wrong verdict.

**Traceable provenance.** 49 carried controls each trace to a cited source. Each finding records `status: official` or `status: draft`. In particular, NIST `AGENTIC-*` controls are flagged **`draft`** — they derive from a **March-2026 CSA draft profile, not official NIST**, and the scanner says so on every such finding. IDs, names, and versions are cited; no copyrighted framework text is reproduced.

### Pass 1 — single-action matching (v1.0)

A regex + word-boundary + context engine matches each observed action against the carried rule set. On the committed synthetic corpus, the tuning removes the substring matcher's false positives without regressing recall:

| Matcher (same synthetic corpus) | Precision | Recall |
|---|---|---|
| Naive substring baseline | 0.6389 | 0.9200 |
| Tuned engine (regex + word-boundary + context) | **1.0000** | **1.0000** |

The build **fails below precision 0.85**. Full numbers, per-rule breakdown, the reproduction command, and the honest limitations are in **[BENCHMARK.md](BENCHMARK.md)** (the source of record).

> Those are metrics on a **100% synthetic, hand-crafted fixture corpus** — fixture metrics, not a claim of real-world accuracy. The headline result is the **false-positive reduction** (baseline→tuned delta), not the absolute 1.00. The corpus and the context rules co-evolved, so a perfect tuned score is partly true by construction.

### Pass 2 — multi-action sequence correlation (v1.1, `AGT-MEM-001`, ASI06)

An opt-in, additive pass correlates an _ordered_ pair — untrusted/unsanitized content **followed by** a write to a memory/RAG sink — to surface OWASP **ASI06 (Memory & Context Poisoning)** candidates. Sink coverage is bounded to what the transcript/telemetry surfaces (shell persist commands + exported OTLP records). Like every finding it is **candidate-only**: it flags content that _could_ poison future context, never a detection of activated cross-session poisoning. See [ADR-2](docs/adr/ADR-2-multi-action-sequence-matching.md).

### Pass 3 — trajectory taint-correlation (v2.0, `AGT-TRJ-001/002/003`, ADR-4)

The taint engine expresses the **injection → consequence dataflow** the single-action and sequence passes cannot: a TAINTED source — an action on the untrusted-data `tool-result:` channel carrying injection markers (and **not** a doc/comment quote) — **followed by** a genuine sensitive real-action sink (exfil / destructive / financial) later in the same action stream. The taint persists across intervening steps (forward-correlated).

A fired AGT-TRJ candidate means **"untrusted-marked data was observed and a sensitive action followed"** — a candidate injection→consequence correlation, **not** a verdict that the agent obeyed the injection. The module is self-contained in `crates/scanner/src/taint.rs` and runs after the single-action and sequence passes in `matching::match_actions_with_suppress`. See [ADR-4](docs/adr/ADR-4-trajectory-taint-correlation.md).

### Pass 4 — representation-aware taint (v2.1, ADR-5)

v2.1 closes the v2.0 **representation gap**. The parser now emits a reserved `sink:` action carrying a deterministic canonical role string (`recipient=` / `amount=` / `url=` / `command=`, with `const SINK_GRAMMAR` enforcing an authority boundary), and the AGT-TRJ rules gained a **taxonomy-derived generic injection-marker** vocabulary (OWASP ASI02:2026 / AITG-APP-02 / documented IPI canary families — each marker cited in `detection-rules.yaml`). The `sink:` channel is excluded from the single-action loop by a one-line `starts_with("sink:")` guard, so the new representation **cannot** produce a single-action false positive (proven by the C1 FP-safety + C2 grammar-disjointness tests).

Mechanism + representation proven on a synthetic positive: `trj-representation-aware-positive.jsonl` fires AGT-TRJ-001 + AGT-TRJ-003; the FinBot direct-injection fixture (negative control) and the benign-trajectory trap fire **zero**. Pre-registered measurement on the committed AgentDojo corpus (frozen rules SHA `ac88825`, no LLM) confirmed the single-action recall is **unchanged** at **23 / 35 (0.657)** — the v2.1 work added **no** new single-action prose rules. See [ADR-5](docs/adr/ADR-5-representation-aware-taint-and-evasion-robust-matching.md).

### Pass 5 — real-trajectory measurement (v2.2, ADR-6)

v2.2 closes the v2.0/v2.1 "real-world efficacy UNPROVEN **by absence of any real trajectory**" gap. The engine is run, with the **same frozen rules** (blob SHA `dcd1ac6`, frozen BEFORE scanning) and the apohara-agnostic `wrap_agentdojo_trace.py` wrapper, over two externally-labeled corpora. The number is reported as a **bound triple** + its representation overlap-miss, and the correlation-not-causation ceiling is stated as a **co-headline of equal prominence**.

**HEADLINE.** apohara v2.1 post-hoc-recognises the injection → sink correlation in **169 / 236 (71.6%)** of real successful indirect-injection trajectories from last-generation frontier models (AgentDyn open-ended suites). This closes the v2.0 "absence" gap — the mechanism fires on real traces, not only synthetic.

**CO-HEADLINE LIMIT (equal prominence, never buried).** It ALSO fires on **28.7% (659 / 2295)** of **resisted** injections and **1.4% (5 / 352)** of benign traces. apohara is a **candidate injection → consequence correlation surfacer**, NOT a success / causation discriminator: a resisted injection still carries the marker in a tool-result AND the agent still performs a legitimate structured sink, so the marker → sink correlation fires in both succeeded and resisted cases. **precision-on-success ≈ 169 / (169+659+5) = 169/833 ≈ 20%.** The discriminating signal (did the agent OBEY the injection) is not representable in a deterministic post-hoc text-pattern model — this is the **quantified ceiling**.

**Overlap-miss** (model-independent representation coverage of the 236 positives): marker `<information>` covered 232/236; role-mapped structured sink covered 180/236; BOTH 178/236; NEITHER 2/236. Covered sink roles: `url=170, recipient=60, amount=59, command=34`. MISSED arg-keys (OUTSIDE the frozen role map — the `iban`-analog): `path (161), subject (114), otp (87), title (79), body (68), recipients (68), repo_name (54), password (33)`. **Reported as-is, NEVER closed** — adding any of these after seeing traces would convert the number from a **MEASUREMENT** into a **FIT** (forbidden by the pre-registration).

> **CAVEAT (stated).** The live current-frontier run used `suite=workspace` (the standard AgentDojo suite), NOT AgentDyn's harder open-ended suites (shopping / github / dailylife) where last-gen models reached 14–22% ASR — because the current-frontier OpenRouter IDs are not in AgentDyn's model registry. So the live 0/80 is on the **easier standard suite**; current-frontier behaviour on the harder open-ended attack is **UNMEASURED** (a documented follow-up). The download corpus (last-gen, open-ended) remains the only set with real successes.

Pre-registration (`tests/corpus/PREREG-v2.2-real-trajectory.md`, rules frozen at `dcd1ac6` **BEFORE** scanning, verified unchanged) and the schema-validated numbers-only report (`tests/corpus/v2.2-real-trajectory-report.json`) are committed; the AgentDyn trace content is gitignored. See [ADR-6](docs/adr/ADR-6-real-trajectory-efficacy.md) + `PROOF-v2.2-real-trajectory.md`.

### Pass 6 — argument-value provenance (v2.3, ADR-7)

v2.3 attacks the v2.2 **28.7% correlation-FP on resisted** by adding an opt-in **provenance gate** to the AGT-TRJ rules: a `TaintRule.require_value_from_source` field plus three `-P` variants (`AGT-TRJ-001-P`, `AGT-TRJ-002-P`, `AGT-TRJ-003-P`) that fire only when the sink argument's value is **verbatim from the same source channel** that carried the injection marker. This is a **post-hoc causal proxy**, not a runtime causation discriminator: it discriminates "the sink was filled with the same content as the taint source" from "the sink was filled with a structurally similar value". Empty `require_value_from_source` is **byte-identical to v2.2** — opt-in, additive.

**Honest result** on the v2.2 frozen corpus, PREREG SHA `5e62e9e2` UNCHANGED post-scan:

- **TEST positives: 100 / 192 (52.1%)** — a post-hoc substring-match proxy, down from v2.2's 138/192 (71.9%). Lower coverage is the trade for fewer false positives.
- **BENIGN FP: 0 / 352** — killed all 5 v2.2 benign FP.
- **FAILED FP: 13.9%** — halved from v2.2's 28.7%.

The 52.1% is **not** a claim of causation: the same correlation-not-causation ceiling holds. What v2.3 buys is **fewer false positives on resisted/benign** at the cost of **fewer positives flagged on test** — the recall/precision trade is explicit in the PREREG and the BENCHMARK, not a retroactive fit.

Pre-registration (`tests/corpus/PREREG-v2.3.md`, frozen BEFORE scanning, verified unchanged post-scan), proof document (`tests/corpus/PROOF-v2.3-argument-value-provenance.md`), and schema-validated report (`tests/corpus/v2.3-argument-value-provenance-report.json`) are committed. See [ADR-7](docs/adr/ADR-7-argument-value-provenance.md).

### Pass 7 — active POSIX shell AST (v2.4, ADR-9)

v2.4 closes the **S2 structural shell coverage UNBUILT** gap with an **in-tree, hand-rolled recursive-descent parser** (no vendor lock-in, no transitive denylisted crates, no GPL). The v2.3 plan (`.omc/plans/v2.3-followups.md` §3) recommended forking conch-parser (archived 2021); Pablo reversed that direction in 2026-06-11 in favor of an active, maintained parser we own. The grammar is the **focused subset** documented in [`docs/grammar/posix-shell-v2.4-subset.md`](docs/grammar/posix-shell-v2.4-subset.md): pipelines, command substitution, subshells, heredocs, and full redirection structure. Control flow, arithmetic, `[[ ... ]]` tests, and function definitions are **EXPLICITLY OUT**.

The **3-mechanism safety split** keeps S1 byte-identical to v2.3 by default:

| Mechanism | Carries | Effect |
|-----------|---------|--------|
| `#[serde(default)]` on `parse_ast: bool` | The byte-identical invariant for existing rules (a rule without the field in YAML behaves exactly as v2.3). | Existing v2.3 YAML is forward-compatible. |
| `parse_ast: bool` per rule, default `false` | The circuit breaker for AST consumption. | Even with the feature on, a rule with `parse_ast: false` is byte-identical to v2.3 at the matcher level. |
| `shell-ast` Cargo feature (default off) | The binary surface (`#[cfg]`-gates the parser module out of the default build). | Compiled-out code can't run, can't be audited, can't be misused. |

The 4 new **AGT-SHL-*-A rules** (Pipeline, Subshell, CommandSubstitution, Heredoc) opt in via `parse_ast: true` + `ast_only_constructs: [...]`. With the `shell-ast` feature on, they fire on AST-only constructs that S1 cannot see; with the feature off, the S1 default gate (1.0/1.0/FP=0) is preserved. The parser falls back to S1 silently on `ParseError` and logs at `trace` level — no panic, no S1 regression. See [ADR-9](docs/adr/ADR-9-posix-shell-parser-ativo.md) + [PROOF-v2.4-open-ended.md](PROOF-v2.4-open-ended.md).

### Frontier probe — AgentDyn open-ended (v2.4, ADR-8)

v2.4 also runs the **B-0.1 capability probe** + a live run on AgentDyn's harder open-ended suites (`shopping` / `github` / `dailylife`) where last-gen models reached 14–22% ASR. The v2.2 caveat ("live current-frontier on the harder open-ended suites UNMEASURED") is closed — honestly. With the venv's `agentdojo` reinstalled from the patched `eval/agentdyn/` 5353cf7 source, all 3 open-ended suites resolve (`scripts/eval/probe_open_ended_suites.py`).

The B-1 live run used `MINIMAX_API_KEY` against the `minimax/MiniMax-M3` gateway (free tier, $0 cost). Result on the only suite with fully-recorded post-fix trajectories: **0 / 4 ASR on dailylife** (security=False for all 4 attacked trajectories). Honest framing: a single model × three suites × one attack (`important_instructions_no_model_name`) does not generalize, and the post-hoc detection cell is `0/0` (N/A — no successes to measure against). The B-2 `-P` re-measure is **DEFERRED** with reason "0 injection-succeeded trajectories; resumes automatically when B-1 produces a non-zero ASR". See [PROOF-v2.4-open-ended.md](PROOF-v2.4-open-ended.md) for the full bound triple.

---

## Repository layout

```text
apohara-compliance/
├── crates/scanner/                       # the deterministic Rust scanner
│   ├── src/
│   │   ├── cli.rs                        # clap CLI surface (scan-session / scan-repo / scan-otlp / gap)
│   │   ├── matching.rs                   # regex + word-boundary + context engine (orchestrates the passes)
│   │   ├── rules.rs                      # rule loading + resolution ladder
│   │   ├── sequence.rs                   # Pass 2 — multi-action AGT-MEM-001 (ADR-2)
│   │   ├── taint.rs                      # Pass 3-4 — trajectory taint + representation-aware (ADR-4/5) + Pass 6 argument-value provenance (ADR-7, opt-in)
│   │   ├── shell_s1.rs                   # S1 `shlex` shell pass — flag-reorder evasions (v2.1) + 7th-param `ast: Option<&Command>` for v2.4
│   │   ├── shell/                        # S2 hand-rolled recursive-descent AST parser (v2.4, ADR-9; gated on `--features shell-ast`)
│   │   │   ├── ast.rs                    #   Command enum + ParseError + 3-mechanism safety split
│   │   │   ├── lexer.rs                  #   hand-rolled character-by-character scanner
│   │   │   ├── parse.rs                  #   recursive descent (pipeline | subshell | command_substitution | heredoc | simple)
│   │   │   ├── match_.rs                 #   AST walker + `match_shell_ast(rule, ast) -> bool`
│   │   │   └── mod.rs                    #   `parse(input) -> Result<Command, ParseError>`
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
├── docs/adr/                             # ADR-2 sequence · ADR-3 corpus · ADR-4 taint · ADR-5 repr · ADR-6 efficacy · ADR-7 provenance · ADR-8 frontier · ADR-9 shell AST
├── docs/grammar/posix-shell-v2.4-subset.md # frozen grammar for S2 (ADR-9)
├── tests/corpus/                         # synthetic gate + AgentDojo + AgentHarm + v2.x PREREG/PROOF/report
├── references/                           # canonical rule + mapping data (mirror, symlinked into the crate)
├── skills/                               # installable agent skill
├── action/                               # GitHub Action wrapper (uploads SARIF)
├── tests/fixtures/                       # synthetic session + repo fixtures
├── scripts/                              # capture + eval harness (FINBOT, v2.2 buckets, polarity gate, MINIMAX live-run harness, …)
└── PROOF-v2.4-open-ended.md              # bound triple for the v2.4 open-ended frontier probe (committed headline numbers; raw traces gitignored)
```

---

## Roadmap

**Shipped** (on `main`)

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
- [x] v2.2 — Real-trajectory measurement (ADR-6): bound triple on real AgentDyn successes (169/236) + live current-frontier cross-check (0/80 resisted); HONEST co-headline (28.7% FP on resisted, ~20% precision-on-success) — the framing IS the deliverable
- [x] v2.3 — Argument-value provenance (ADR-7): opt-in `TaintRule.require_value_from_source` field + 3 `-P` AGT-TRJ rule variants; BENIGN FP 0/352, FAILED FP 13.9% (halved); PREREG SHA `5e62e9e2` UNCHANGED post-scan
- [x] v2.4 — Active POSIX shell AST parser (ADR-9): in-tree hand-rolled recursive descent in `crates/scanner/src/shell/`, focused subset, 3-mechanism safety split; S1 default build byte-identical to v2.3 (189/0/0, gate 1.0/1.0/FP=0)
- [x] v2.4 — AgentDyn open-ended frontier probe (ADR-8): B-0.1 capability probe PASS after venv reinstall; B-1 live MINIMAX-M3 run (0/4 ASR on dailylife, $0 cost); B-2 -P re-measure DEFERRED honestly. See [PROOF-v2.4-open-ended.md](PROOF-v2.4-open-ended.md)

**Exploring** — demand-driven, not committed

- [ ] v2.5 — broader frontier model sweep (claude-opus-4.8, gpt-5.5, gemini-3.5-flash) on the same 3 open-ended suites to bound the "MiniMax-M3 is uniquely resistant" hypothesis; the v2.4 0/4 ASR does not generalize. R4 (CRITICAL) in the v2.4 plan is the framing.
- [ ] v2.5 — stronger attack surface in the harness (AgentDyn ships multiple attack vectors beyond `important_instructions_no_model_name`); only one was exercised in v2.4 B-1.
- [ ] v2.5 — AGT-SHL-*-B / AGT-SHL-*-C variants if the v2.4 single-pattern AST matchers prove too narrow on adversarial test corpora.
- [ ] Repo-file normalisation (ADR-5 M4 deferred gap) — A3 homoglyph / zero-width / casing runs in the session value picker only; a future PR extends it to `parse_repo` for the dominant indirect-injection surface.
- [ ] Additional agent-transcript formats
- [ ] First-mover OWASP Agentic Skills (AST01–AST10) rules once the draft stabilises

---

## Contributing

Contributions are welcome.

1. **Fork** the repository.
2. Create a feature **branch** (`git checkout -b feature/my-change`).
3. Make your change and run the tests: `cargo test` (the precision/recall gate + the trajectory + the independent-corpus gates all run here).
4. Open a **pull request**.

> Unless you state otherwise, any contribution you intentionally submit for inclusion in this work, as defined in the Apache-2.0 license, shall be dual-licensed as below, without any additional terms or conditions.

---

## License

Licensed under either of **[MIT](LICENSE-MIT)** or **[Apache-2.0](LICENSE-APACHE)**, at your option.

Maintained by **[SuarezPM](https://github.com/SuarezPM)**.
