# POSIX Shell Grammar Subset — apohara v2.4 (S2)

**Status:** FROZEN (US-001, 2026-06-11, RALPLAN Rev 2 consensus).
Base: origin/main @ 9c574f4 (v2.3 + README + diagram pushed).
ADR: `docs/adr/ADR-9-posix-shell-parser-ativo.md`. Plan:
`.omc/plans/v2.4-argument-value-provenance-followups.md` Rev 2.

This is the **focused subset** of POSIX shell that apohara's S2 AST parser
covers. S1 (`shlex` tokenizer) remains the default; S2 is opt-in per
shell rule via `parse_ast: true`. Control flow, arithmetic, `[[ ]]`
tests, and function definitions are **EXPLICITLY OUT** of scope.

---

## 1. Why a focused subset (Pablo's direction, 2026-06-11)

The v2.3 plan (`.omc/plans/v2.3-followups.md` §3) recommended forking
conch-parser (Apache-2.0/MIT, archived since 2021) into
`crates/conch-parser-vendor/`. Pablo reversed that direction
(2026-06-11): **design our own active, maintained parser from scratch
in apohara**. RALPLAN Rev 2 consensus chose **hand-rolled recursive
descent** over nom (parser combinators), lalrpop (parser generator),
pest (PEG), and any external parser (license or dep-graph violations).

The grammar is small because the S1 `shlex` tokenizer already handles
the 95% case of `rm -rf`-style commands. S2 only needs to see what S1
cannot: pipeline structure, command substitution, subshell grouping,
heredoc bodies, and full redirection structure.

---

## 2. The focused subset

### 2.1 In scope (constructs the parser MUST handle)

| Construct | Why S2 needs it | Why S1 misses it |
|-----------|-----------------|------------------|
| `Simple` command (word + flag-set + arg) | Confirms S1's output; AST is the canonical form | S1 already handles; S2 confirms structure |
| `Pipeline` (`a \| b \| c`) | See the whole pipeline as a single matched unit | S1 tokenizes the `\|` but does not know it joins commands |
| `CommandSubstitution` (`$(cmd)` or `` `cmd` ``) | Reveals the inner command the agent injected | S1 tokenizes the `$(` and `)` but does not recurse into the body |
| `Subshell` (`(cmd)`) | Reveals the inner command | S1 tokenizes the parens but does not recurse |
| `Heredoc` (`cmd <<EOF\nbody\nEOF`) | The body is the actual injection vector | S1 tokenizes `<<EOF` and the body but does not link them as a single matched construct |
| `Redirection` (`<`, `>`, `>>`, `2>`, `2>&1`, `>&`, `<&`) | Full redirection structure | S1 partially; S2 gives the full graph |

### 2.2 Out of scope (EXPLICITLY deferred)

| Construct | Why out |
|-----------|---------|
| `if` / `while` / `for` / `case` blocks | apohara does not trigger on control-flow structure alone. A `for` loop is not a sensitivity vector. |
| `function` definitions | Same as above. Functions are static; the matched construct is what the function is *called with*. |
| Arithmetic `$((...))` | Bash-ism, not POSIX; not a security vector. |
| `[[ ... ]]` test command | Bash-ism; `[ ... ]` (POSIX) is tokenized as a Simple command. |
| `select` / `coproc` | Rare; not in POSIX. |
| `coproc` | Bash-only. |
| Brace expansion (`{a,b,c}`) | Glob expansion is shell-side, not parser-side. |
| Tilde expansion (`~user`) | Same. |
| Process substitution (`<()`) | Bash-ism. |
| Parameter expansion (`${foo:-bar}`) | Tokenized as a Word; the *content* is the argument to the command. |
| `trap` / `exec` / `eval` | Builtin commands, tokenized as Simple. |
| Aliases | Resolved at shell runtime, not parse time. |
| Heredoc with quoted delimiter (`cmd <<'EOF'`) | S2 sees the body; the quoting is preserved as a Word token. |
| Heredoc with `<<-` (leading tabs stripped) | Out of scope; the body is still a heredoc. |

---

## 3. The grammar (EBNF, focused subset)

```ebnf
program             := pipeline ((';' | '\n') pipeline)* ;

pipeline            := command ('|' command)* ;

command             := subshell
                    | command_substitution_dollar
                    | command_substitution_backtick
                    | simple ;

subshell            := '(' pipeline ')' ;

command_substitution_dollar := '$(' pipeline ')' ;

command_substitution_backtick := '`' pipeline '`' ;

simple              := word+ redirection* heredoc? ;

redirection         := redir_op word ;

redir_op            := '<'
                    | '<&'
                    | '>'
                    | '>&'
                    | '>>'
                    | '2>'
                    | '2>&1' ;

heredoc             := '<<' word '\n' heredoc_body '\n' word ;

heredoc_body        := .*? ;   (* non-greedy match; body ends at the line that exactly equals the delimiter word *)

word                := quoted_single
                    | quoted_double
                    | unquoted_run
                    | dollar_var
                    | dollar_brace_var
                    | backslash_escape
                    | bare_chars ;

quoted_single       := "'" .*? "'" ;   (* no escape processing *)

quoted_double       := '"' .*? '"' ;   (* backslash escapes active: \\, \$, \`, \", \n, \t *)

dollar_var          := '$' identifier ;

dollar_brace_var     := '${' identifier (':-' | ':+' | ':=' | '?' | '#' | '%' | '##' | '%%' | '/' | '//' | ':' | '::' | '[^}]')? '}' ;

backslash_escape    := '\' any_char ;   (* inside double-quoted or unquoted *)

bare_chars          := [^ \t\n|&;<>()$'"\\`]+ ;   (* any char not in the metacharacter set *)

identifier          := [A-Za-z_][A-Za-z0-9_]* ;
```

### 3.1 Token types (lexer)

| Token | Source |
|-------|--------|
| `Word` | A `word` production (carries the resolved value) |
| `Pipe` | `\|` |
| `LParen`, `RParen` | `(`, `)` |
| `DollarLParen`, `RParen` | `$(`, `)` (the closing `)` of a command substitution is shared with `RParen`) |
| `Backtick` | `` ` `` |
| `Lt`, `Gt`, `DGreat`, `DLess` | `<`, `>`, `>>`, `<<` |
| `GreatAnd`, `LessAnd` | `>&`, `<&` |
| `And` | `&&` |
| `Or` | `\|\|` |
| `Semi` | `;` |
| `Newline` | `\n` (a real newline; not a literal backslash-n in a quoted string) |
| `EOF` | End of input |

### 3.2 Metacharacter set (for `bare_chars`)

The 14 characters that terminate a bare word and are recognized by the
lexer: space, tab, newline, `|`, `&`, `;`, `<`, `>`, `(`, `)`, `$`, `` ` ``,
`\`, `"`, `'`.

---

## 4. The error model

```rust
// Note: NO `thiserror` dep. The parser is in-tree and adds zero new
// deps. Display is implemented manually with `std::fmt::Write` to keep
// the dep graph clean (matches the rest of the scanner's minimal-deps
// posture).

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    UnbalancedQuote(usize),
    UnterminatedHeredoc { start: usize, delimiter: String },
    UnexpectedToken { offset: usize, expected: &'static str, got: String },
    UnexpectedEof(&'static str),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnbalancedQuote(off) =>
                write!(f, "unbalanced quote at byte offset {off}"),
            Self::UnterminatedHeredoc { start, delimiter } =>
                write!(f, "unterminated heredoc starting at byte offset {start} (delimiter `{delimiter}`)"),
            Self::UnexpectedToken { offset, expected, got } =>
                write!(f, "unexpected token at byte offset {offset}: expected {expected}, got {got}"),
            Self::UnexpectedEof(expected) =>
                write!(f, "unexpected end of input: expected {expected}"),
        }
    }
}

impl std::error::Error for ParseError {}
```

**Invariant:** all error paths return `Err(ParseError)`. The parser
NEVER panics on malformed input. The matcher falls back to S1 silently
when the parser returns `Err` (see §5).

---

## 5. Three-mechanism safety split (per ADR-9, Rev 2)

There are three distinct safety mechanisms, each carrying a separate
invariant. None is redundant.

| Mechanism | Carries | Why distinct |
|-----------|---------|--------------|
| `#[serde(default)]` on `parse_ast: bool` | The byte-identical invariant for existing rules (a rule without the field in YAML behaves exactly as v2.3). | This is the v2.3 → v2.4 transition mechanism. Without it, every existing shell rule would need a YAML edit. |
| `parse_ast: bool` per rule, default `false` | The circuit breaker for AST consumption (a rule that hasn't opted in never matches via AST, even if the AST is available). | Even with the Cargo feature on, a rule with `parse_ast: false` is byte-identical to v2.3 at the matcher level. |
| `shell-ast` Cargo feature (default off) | The binary surface (the AST module is `#[cfg]`-gated out of the production build). | Compiled-out code can't run, can't be audited, can't be misused. The dep graph is unchanged regardless of feature state (in-tree code adds no deps). |

**Default build:** `--features` empty → S1 only → byte-identical to
v2.3 → gate 1.0/1.0/FP=0 holds. New code in `crates/scanner/src/shell/`
is `#[cfg(feature = "shell-ast")]`-gated and compiled out.

**Opt-in build:** `--features shell-ast` → AST module compiled in →
rules with `parse_ast: true` consume the AST → S2 rules (e.g.
`AGT-SHL-PIPELINE-A`) fire on AST-only constructs (pipeline,
subshell, command substitution, heredoc). S1 still runs for
`parse_ast: false` rules.

**Fallback path:** if the parser returns `Err(ParseError)` for a
given input, the matcher silently falls back to S1 and logs at
`trace` level: `parse_ast, fallback_to_s1, error_kind=...`. S1 may
still fire a (different) finding, or no finding — the S1 path is
the zero-regression safety net.

---

## 6. API surface (frozen)

```rust
// crates/scanner/src/shell/mod.rs

#[cfg(feature = "shell-ast")]
pub mod ast;
#[cfg(feature = "shell-ast")]
pub mod lexer;
#[cfg(feature = "shell-ast")]
pub mod parse;
#[cfg(feature = "shell-ast")]
pub mod match_;

#[cfg(feature = "shell-ast")]
pub use ast::Command;
#[cfg(feature = "shell-ast")]
pub use ast::ParseError;

/// Try to parse the input as a shell AST. Returns Err on any malformed input.
#[cfg(feature = "shell-ast")]
pub fn parse(input: &str) -> Result<Command, ParseError> {
    let tokens = lexer::tokenize(input)?;
    parse::parse_command_list(&tokens)
}
```

The matcher (`crates/scanner/src/matching.rs:399`) gains an
`ast: Option<&Command>` parameter on `match_shell`. The signature
ripple is one call site; see US-004.

---

## 7. Size estimate (per ADR-9)

| File | Estimated lines | What it does |
|------|----------------|--------------|
| `ast.rs` | ~80 | `Command` enum, `ParseError`, helpers |
| `lexer.rs` | ~120 | Token enum, `tokenize` |
| `parse.rs` | ~250–350 | Recursive descent |
| `match.rs` | ~80 | `match_shell_ast(rule, ast) -> bool` |
| `mod.rs` | ~20 | Feature gating, re-exports |
| Unit tests | ~400 (21+ tests × ~20 lines each) | Inline `#[cfg(test)] mod tests` in each file |
| **Total** | **~550–650** | One focused module |

---

## 8. Test plan (per US-003)

| Category | Cases | What it exercises |
|----------|-------|-------------------|
| **Simple** | `ls -la /tmp`, `rm -rf /`, `echo "hello world"`, `grep -E 'pat' file`, `cmd --flag=value` | S1-equivalent path; AST shape |
| **Pipeline** | `rm -rf / \| cat`, `ps aux \| grep evil \| awk '{print $2}'`, `false \| true` | AST structure (Pipeline node) |
| **Subshell** | `(rm -rf /)`, `((echo a; echo b))` | Subshell node, nested pipelines |
| **CommandSubstitution** | `$(rm -rf /)`, `` `rm -rf /` ``, `echo $(whoami)` | Dollar and backtick variants |
| **Heredoc** | `cat <<EOF\nhello\nEOF`, `rm -rf / <<EOF\nbody\nEOF`, `cat <<'EOF'\nliteral $var\nEOF` | Heredoc body capture |
| **Quoting** | `'single quotes'`, `"double $quotes"`, `\$literal`, `"back\\\"slash"`, `'unclosed` → Err | Unbalanced quote error path |
| **Error paths** | `unterminated heredoc`, `unexpected token`, `unexpected EOF`, `(((unbalanced` | All `ParseError` variants, never panic |

**Parity test:** every S1 fixture in `tests/corpus/shell/` that
passes S1 also passes the S2 AST path when AST is *available*. The
S1 default gate remains 1.0/1.0/FP=0.

**Fallback test:** a deliberately-broken input (e.g. unterminated
quote) → `ParseError::UnbalancedQuote` → matcher falls back to S1 →
no panic, same result as `parse_ast: false`.

---

## 9. References

- `crates/scanner/src/shell.rs:101-144, 155-222` — S1 implementation
  (`shlex`-based).
- `crates/scanner/src/rules.rs:244-262` — `ShellRule` struct; the
  `parse_ast: bool` field mirrors the v2.3 `require_value_from_source`
  pattern at line 290.
- `crates/scanner/src/matching.rs:399` — the single call site of
  `match_shell`; the signature change ripples here.
- `docs/adr/ADR-9-posix-shell-parser-ativo.md` — the decision.
- `.omc/plans/v2.4-argument-value-provenance-followups.md` Rev 2 —
  the consensus plan.

**Sign-off:** Planner Rev 0 → Architect Rev 1 (SOUND-WITH-CHANGES) →
Critic Rev 2 (ITERATE) → Re-Critic APPROVE on Rev 2. Consensus
reached 2026-06-11.
