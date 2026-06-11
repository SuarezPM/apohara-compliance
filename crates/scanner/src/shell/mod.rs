// apohara-compliance — v2.4 S2 shell AST module.
//
// In-tree, hand-rolled recursive-descent parser for the focused POSIX
// shell subset documented in `docs/grammar/posix-shell-v2.4-subset.md`.
// S1 (`shlex` tokenizer in `super::shell_s1`) remains the deterministic
// default; S2 is opt-in per shell rule via `parse_ast: true` on
// `ShellRule`.
//
// Three-mechanism safety split (per ADR-9 Rev 2):
//   1. `#[serde(default)]` on `parse_ast: bool` — v2.3 → v2.4 transition.
//   2. Per-rule `parse_ast: bool` — circuit breaker for AST consumption.
//   3. `shell-ast` Cargo feature (default off) — binary surface.
//
// This whole module is `#[cfg(feature = "shell-ast")]`-gated. With the
// feature off, none of the code is compiled into the scanner binary.

#[cfg(feature = "shell-ast")]
pub mod ast;
#[cfg(feature = "shell-ast")]
pub mod lexer;
#[cfg(feature = "shell-ast")]
pub mod match_;
#[cfg(feature = "shell-ast")]
pub mod parse;

#[cfg(feature = "shell-ast")]
pub use ast::Command;
#[cfg(feature = "shell-ast")]
pub use ast::ParseError;

/// Try to parse the input as a shell AST. Returns `Err(ParseError)` on
/// any malformed input. The caller (the matcher) is expected to fall
/// back to S1 silently on `Err`.
#[cfg(feature = "shell-ast")]
pub fn parse(input: &str) -> Result<Command, ParseError> {
    let tokens = lexer::tokenize(input)?;
    parse::parse_program(&tokens)
}
