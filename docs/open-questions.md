# Open questions

Gated / deferred decisions tracked outside the ADRs. Each entry names the gate and the
trigger that closes it.

## Version badge (Pablo-gated)

`README.md:10` version badge = `version-1.1.0`. v1.4 + v2.0 + v2.1 are on `main` with no new
tag, so the badge lags the codebase. The badge tracks the last **release tag**, and
tagging/release is Pablo-gated — bump the badge to whatever tag v2.1 eventually cuts. No
badge edit lands until that tag exists.

## Real-positive trajectory trace (deferred — closes the UNPROVEN gap)

v2.1 closes the representation gap in the engine's vocabulary (structured `sink:` + generic markers
fire on a synthetic trajectory) but real-world efficacy stays UNPROVEN: there is no committed REAL
trajectory where an injection succeeded and a sensitive sink followed. **Gate to close:** a
reproducibly-jailbreakable, in-domain (coding/shell-agent) target + corpus. v2.0 spent 65.5k
MiniMax tokens for 0/10 (the target refused all), so live capture is fully deferred (A10) until
such a target exists. NEVER iterate a live run to manufacture a positive (that is fitting).

## S2 — full shell AST escalation (deferred)

WS2-b ships S1 (`shlex` tokenizer: argv + flag-set, no pipeline/subshell structure). If structural
coverage proves insufficient (e.g. pipelines, command substitution, here-docs), escalate to
`conch-parser` (pure-Rust, no runtime) — **gated** on a green `cargo tree -e no-dev` + `cargo audit`.
NOT `brush-parser`/`flash` (the disqualifier is a transitive `tokio` on the dep-graph denylist).

## v2.3 — argument-value provenance: what v2.3 is NOT (the deferred extensions)

ADR-7 commits to a SPECIFIC frozen semantics: ASCII-lowercase normalization,
6-character length floor, exact-substring comparison, no weights, no semantic
similarity. The following extensions are EXPLICITLY deferred to a future
prereg (NOT in v2.3):

- **Unicode case folding** — v2.3 is ASCII-only. Non-ASCII characters in
  authority-role values are passed through as-is and will not match a non-
  ASCII source value. A `to_lowercase` on `chars().flat_map(|c| c.to_lowercase())`
  could be added with a separate prereg freeze.
- **Semantic similarity** — v2.3 is exact-substring only. `evil@attacker.test`
  matches; `evil(at)attacker(dot)test` does not. No fuzzy match, no
  Levenshtein, no embedding similarity. Adding a similarity threshold
  requires a prereg freeze of the threshold value AND a separate corpus.
- **Cross-step value laundering** — PACT (arxiv 2605.11039) accumulates
  cross-step value flows; apohara does not. This is the runtime-side
  extension; apohara stays post-hoc over transcripts.
- **New `sink:` role fields (`iban`, `otp`, etc.)** — v2.2 documented 8
  missed arg-keys (`iban`, `otp`, `path`, `subject`, `body`, `recipients`,
  `repo_name`, `password`); v2.3 did NOT add any of them. Each is a
  separate prereg + separate FROZEN benchmark.
- **AGT-TRJ-002-P firing on destructive commands** — the verbatim-flow
  constraint makes this rare on the v2.2 corpus (0/192 fires). A future
  prereg could explore alternative similarity measures for this code if
  evidence shows it's worth closing the destructive-action gap.

## v2.3 follow-up B — AgentDyn open-ended frontier run (DEFERRED, Pablo-gated)

v2.2's live run used `suite=workspace` (the AgentDojo standard suite) because
the current-frontier OpenRouter IDs are NOT in AgentDyn's `model_registry.py`.
The result was 0/80 (all models resisted). AgentDyn provides 3 harder
open-ended suites (shopping, github, dailylife) where last-gen models reached
14–22% ASR; current-frontier behavior on those is UNMEASURED.

**Gate to close:** AgentDyn supports custom model registration (env var,
config override, or monkey-patch of `model_registry.py`) so the
`run_openrouter_e2e.py` harness can target the harder suites. If custom
registration works, estimate token budget for 5 models × 3 suites (~5M
tokens estimated, dependent on model tier). **Pablo-gated** — explicit
authorization + OpenRouter key budget required before the run. Phase B-0
feasibility check is the only committed work; the B-1 run is DEFERRED.

## v2.3 follow-up C — S2 full shell AST escalation (conch-parser gate)

WS2-b ships S1 (`shlex` tokenizer). The S2 escalation to a full POSIX shell
AST is **gated** on a green `cargo tree -e no-dev` + `cargo audit` for the
candidate parser. Investigation COMPLETE (per `.omc/plans/v2.3-followups.md`
§3):

| Candidate | Verdict |
|---|---|
| `conch-parser` (ipetkov, Apache-2.0/MIT) | **PASSES** the dep-graph + audit gate (only dep is `void`; no denylisted crate). ⚠️ ARCHIVED since 2021 — no upstream maintenance. Mitigation: vendor/fork into `crates/conch-parser-vendor/`. |
| `brush-parser` | DISQUALIFIED (transitive `tokio` on the dep-graph denylist). |
| `flash` | DISQUALIFIED (GPL-3.0 license incompatible with apohara's dual Apache-2.0/MIT). |
| `yash-syntax` | DISQUALIFIED (GPL-3.0-or-later). |

S2 is DECORRELATED from the v2.3 causal-proxy deliverable and can proceed
independently. Implementation is a separate workstream (not in v2.3).
