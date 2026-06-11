# ADR-9: Active POSIX Shell Parser — built from scratch (no vendor lock-in)

**Status:** ACCEPTED (v2.4, 2026-06-11, US-001..US-005 complete + verified).
Base = v2.3 (ADR-7) on `main` @ 9c574f4.
Plan: `.omc/plans/v2.4-argument-value-provenance-followups.md` (Rev 2,
consensus). Implementation: branch `feature/v2.4-b-c` (Pablo-gated push).
Honesty lineage: v2.0/ADR-4 (synthetic positives) → v2.1/ADR-5
(representation gap closed) → v2.2/ADR-6 (real-trajectory measurement) →
v2.3/ADR-7 (causal proxy, post-hoc, verbatim-flow) → **v2.4/ADR-9
(closes the "S2 structural shell coverage UNBUILT" gap with our own
active, maintained parser — no vendor lock-in, no transitive
denylisted crates, no GPL).**
Honesty lineage: v2.0/ADR-4 (synthetic positives) → v2.1/ADR-5
(representation gap closed) → v2.2/ADR-6 (real-trajectory measurement) →
v2.3/ADR-7 (causal proxy, post-hoc, verbatim-flow) → **v2.4/ADR-9
(closes the "S2 structural shell coverage UNBUILT" gap with our own
active, maintained parser — no vendor lock-in, no transitive
denylisted crates, no GPL).**

## Context

WS2-b ships S1 (`shlex` tokenizer: argv + flag-set, no
pipeline/subshell/command-substitution/heredoc structure). The v2.3
plan (`.omc/plans/v2.3-followups.md` §3) recommended forking
conch-parser into `crates/conch-parser-vendor/`. Pablo reversed that
direction (2026-06-11): **design our own active, maintained parser
from scratch in apohara.**

The S2 gate (dep-graph + audit clean) is still in force — the parser
we write MUST NOT pull in transitive denylisted crates (reqwest,
hyper, tokio, mio, socket2, rustls, native-tls, openssl, axum, warp,
tonic, h2, ureq, isahc, surf). The S1 byte-identical invariant is
preserved.

## Decision

**Hand-rolled recursive-descent parser, in-tree, no external deps.**
Lives in `crates/scanner/src/shell/`:

- `ast.rs` — `Command` enum + `ParseError` + helpers.
- `lexer.rs` — token stream (Word, Pipe, LParen, RParen, DollarLParen,
  Backtick, Lt, Gt, DGreat, DLess, GreatAnd, And, Semi, Newline, EOF, ...).
- `parse.rs` — recursive descent: `parse_command_list`, `parse_pipeline`,
  `parse_command`, `parse_subshell`, `parse_command_substitution`,
  `parse_simple`, `parse_redirection`, `parse_heredoc_body`.
- `match.rs` — `match_shell_ast(rule: &ShellRule, ast: &Command) -> bool`
  (consumes the AST; rules can match on `Pipeline`, `Subshell`, etc.).
- `mod.rs` — `pub fn parse(input: &str) -> Result<Command, ParseError>`
  and `pub fn match_with_fallback(rule: &ShellRule, input: &str) -> MatchResult`
  (tries AST, falls back to S1 on error or when feature is off).

Grammar (focused subset, hand-rolled):

```
program        := pipeline ((';' | '\n') pipeline)*
pipeline       := command ('|' command)*
command        := subshell | command_substitution | simple
subshell       := '(' pipeline ')'
command_substitution := '$(' pipeline ')' | '`' pipeline '`'
simple         := word+ redirection* heredoc?
redirection    := (redir_op word)+
heredoc        := '<<' word '\n' .*? '\n' word
redir_op       := '<' | '>' | '>>' | '2>' | '2>&1' | '>&' | '<&' | ...
word           := quoted | unquoted_run | $VAR | ${VAR}
quoted         := "'" .*? "'" | '"' .*? '"'  (with backslash escapes in "")
```

Size estimate: ~250–350 lines of Rust for the parser, ~80 lines for
the AST, ~80 lines for the matcher helper. Total ~450 lines, fully
unit-tested.

### Three-mechanism safety split (Rev 2, Critic)

There are three distinct safety mechanisms, each carrying a separate
invariant. None is redundant.

| Mechanism | Carries | Why distinct |
|-----------|---------|--------------|
| `#[serde(default)]` on `parse_ast: bool` | The byte-identical invariant for existing rules (a rule without the field in YAML behaves exactly as v2.3). | This is the v2.3 → v2.4 transition mechanism. Without it, every existing shell rule would need a YAML edit. |
| `parse_ast: bool` per rule, default `false` | The circuit breaker for AST consumption (a rule that hasn't opted in never matches via AST, even if the AST is available). | Even with the Cargo feature on, a rule with `parse_ast: false` is byte-identical to v2.3 at the matcher level. |
| `shell-ast` Cargo feature (default off) | The binary surface (the AST module is `#[cfg]`-gated out of the production build). | Compiled-out code can't run, can't be audited, can't be misused. The dep graph is unchanged regardless of feature state (in-tree code adds no deps). |

### Schema

```rust
// In ShellRule (existing struct), add an opt-in field:
#[serde(default)]
pub parse_ast: bool,  // default false → S1 byte-identical
```

When `parse_ast: true`, the matcher tries the AST first. If AST parse
fails (unbalanced quote, unterminated heredoc, etc.), the matcher
silently falls back to S1 and logs `parse_ast, fallback_to_s1,
error_kind=...` at `trace` level. AST-only rules (Pipeline, Subshell,
CommandSubstitution, Heredoc) gain a positive match only when the AST
is *available* and the construct is present.

When `parse_ast: false` (default), the matcher is **byte-identical**
to v2.3. The gate is 1.0/1.0/FP=0, single-action byte-identical, no
change.

## Drivers

- **D1 — Active, maintained parser:** Pablo's explicit reversal of
  v2.3's vendor-conch-parser plan. We own the code; no upstream
  bitrot; no transitive denylisted crates; no GPL.
- **D2 — S1 fallback guarantee:** every existing shell rule is
  byte-identical when `parse_ast: false` (the default). The
  `#[serde(default)]` carries this invariant for existing YAML.
- **D3 — Three-mechanism safety:** the per-rule flag is the
  circuit breaker; the Cargo feature is the binary-surface control;
  neither is redundant.
- **D4 — Honest report:** S1 detection count vs S2 detection count
  (with `parse_ast: true`). Difference = structural coverage delta.
  Report even if delta is 0.

## Alternatives considered

- **B1 (chosen):** Hand-rolled recursive descent. Zero new dep; full
  control; deterministic; matches the S1 `shlex` style (small,
  focused, owned); the S2 grammar we need (pipelines, command
  substitution, subshell, heredoc-with-command, redirection) is small
  enough for hand-rolled.

### Rejected

- **Vendor conch-parser (the v2.3 plan):** archived since 2021, no
  upstream maintenance. Pablo reversed the direction.
- **brush-parser (reubeno/brush, MIT, v0.4.0 2026-05-03):** actively
  maintained but transitive `tokio` on the dep-graph denylist. The
  entire scanner is sync, deterministic, and runs offline; pulling in
  `tokio` to parse shell contradicts the project posture.
- **flash / mystsh (raphamorim, GPL-3.0):** license-incompatible with
  apohara's dual Apache-2.0/MIT.
- **esh (lambdanature, 0.1.0 prerelease, 0 stars):** too immature
  for a security-critical path.
- **kaish (tobert, MIT):** full shell + VFS + MCP, not parser-only.
- **parable / rable (research, MSRV 1.93+):** low adoption,
  research-stage.
- **nom parser combinators:** transitive `memchr` + `minimal-lexical`
  are unnecessary for a 6-construct shell grammar. We already shun
  transitive crates elsewhere in the scanner.
- **lalrpop parser generator:** build-time codegen is a new
  supply-chain surface; the `.lalrpop` file is harder to audit than
  ~300 lines of straight-line Rust.
- **pest (PEG):** PEG's "first match wins" hides ambiguity in the
  exact places (here-end, nested quoting) where POSIX shell has real
  LR(1) needs.
- **pred_recdec (BNF-as-recursive-descent):** adds a dep for ~300
  lines we can write by hand.

## Consequences

- **If the parser compiles + all unit tests + parity tests + the
  Cargo dep-graph stays clean:** S2 ships behind `parse_ast: true`
  on a per-rule opt-in. The gate remains 1.0/1.0/FP=0 with S1
  default. S2 fixtures (pipeline, subshell, command substitution,
  heredoc-with-command) fire their AST rule when `parse_ast: true`
  and fall back to S1 when `parse_ast: false` or parse fails.
- **If the parser diverges from S1 on the 95% case:** R5 fires
  (MED/HIGH). The parity test (every S1 fixture also passes the
  S2 AST path when AST is *available*) catches this in C-2.2
  before the E2E.
- **If the parser panics on malformed input:** R7 fires
  (LOW/CRIT). C-0.2 freezes the error model; C-2.4 covers the
  fallback test. All error paths return `Err(ParseError)`; no
  panic.
- **If the parser introduces a dep-graph violation:** R6 fires
  (LOW/HIGH). The parser is in-tree (no deps), and `verify.sh`
  checks `cargo tree -e no-dev` for denylisted crates. Belt and
  suspenders.
- **Code surface:** ~450 lines of straight-line Rust in
  `crates/scanner/src/shell/`. Readable, auditable, owned.

## Follow-ups

- **Grammar scope freeze (Pablo-gated):** the focused subset
  (pipeline | subshell | command_substitution | heredoc | simple
  + redirection) is the boundary. `if/while/for/case`, arithmetic
  `$((...))`, `[[ ... ]]`, `function` definitions are EXPLICITLY
  OUT. Adding any of them is a future ADR.
- **Open-questions.md update:** post-consensus, the C gate entry
  becomes "C-0 grammar frozen (2026-06-XX); see ADR-9. S2 ships in
  v2.4 with the in-tree parser."
- **README roadmap:** v2.4 row in the "What we measured" table
  (S1 baseline vs S2 detection delta, if any).
- **Future work (deferred):** if a real-world trajectory exposes
  another shell construct that S1 + S2 both miss, that becomes
  v2.5's C-1 work.

## References

- `crates/scanner/src/shell.rs:101-144, 155-222` — S1 implementation
  (`shlex`-based); the C-1.4 signature change ripples to one call
  site at `crates/scanner/src/matching.rs:399`.
- `crates/scanner/src/rules.rs:244-262` — `ShellRule` struct.
  Adding `parse_ast: bool` with `#[serde(default)]` mirrors the
  v2.3 pattern of `require_value_from_source` on `TaintRule` (line
  290).
- `docs/open-questions.md` § "S2 — full shell AST escalation
  (deferred)" — the original gate entry; superseded by ADR-9.
- `.omc/plans/v2.4-argument-value-provenance-followups.md` Rev 2 —
  the consensus plan.
- PACT (arxiv 2605.11039) — argument provenance at runtime. apohara
  v2.4 C stays post-hoc, like v2.3.
- ARM (arxiv 2604.04035) — Layer-3 string-match saves ~60%.
  Validates the v2.3 approach; v2.4 C extends structural coverage
  to the shell AST layer.
