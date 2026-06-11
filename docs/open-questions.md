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

## v2.3 follow-up B — AgentDyn open-ended frontier run (REPLACED by ADR-8, 2026-06-11)

~~Original gate (v2.3 plan, 2026-06-08): "AgentDyn supports custom model
registration (env var, config override, or monkey-patch of `model_registry.py`)."~~

**REPLACED** by ADR-8 (`docs/adr/ADR-8-agentdyn-open-ended-frontier.md`) on
2026-06-11. The v2.4 RALPLAN consensus (`.omc/plans/v2.4-argument-value-provenance-followups.md`
Rev 2) discovered the v2.2 harness already bypasses AgentDyn's
`model_registry.py` entirely — `OpenAILLM(client, model)` is instantiated
directly with the OpenRouter id (`scripts/eval/run_openrouter_e2e.py:124-134`).
The `--suite` flag is already wired to `get_suites(BENCH)[args.suite]` (line
166). The "registry override + monkey-patch" mechanism in the v2.3 plan was
solving a non-existent problem. The actual v2.4 deliverable is a capability
probe (B-0.1) + a per-(model, suite) token cap (currently a single global
cap at line 141) + a Pablo-gated live run (B-1) + a -P re-measure (B-2,
conditional on v2.3 + B-1). **Pablo-gated** — explicit authorization +
OpenRouter key budget required before B-1.

## v2.3 follow-up C — S2 full shell AST escalation (REPLACED by ADR-9, 2026-06-11)

~~Original gate (v2.3 plan, 2026-06-08): "fork/vendor conch-parser into
`crates/conch-parser-vendor/`" — gated on a green `cargo tree -e no-dev` +
`cargo audit` for the candidate parser.~~

**REPLACED** by ADR-9 (`docs/adr/ADR-9-posix-shell-parser-ativo.md`) on
2026-06-11. Pablo reversed the vendor direction (2026-06-11): **design our
own active, maintained parser from scratch in apohara**. The v2.4 RALPLAN
consensus decided hand-rolled recursive descent, in-tree, no external deps,
focused subset (pipeline | subshell | command_substitution | heredoc | simple
+ redirection; control flow and arithmetic are EXPLICITLY OUT). Three-mechanism
safety split per ADR-9: `#[serde(default)]` on `parse_ast: bool` (v2.3 → v2.4
transition), per-rule `parse_ast: bool` (circuit breaker), and `shell-ast`
Cargo feature (binary surface). All three are kept; none is redundant.
