// apohara-compliance — v2.4 S2 shell AST types.
//
// `Command` is the public AST surface. `ParseError` is the only
// failure mode (no panics). Display is manual to keep the dep graph
// clean (no `thiserror` dep — see the grammar doc §4 for rationale).

/// A parsed shell command, in the focused subset documented in
/// `docs/grammar/posix-shell-v2.4-subset.md` §2.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// A simple command: one or more words, optional redirections,
    /// optional heredoc. The inner `Vec<Word>` is the argv; the
    /// trailing `Vec<Redirection>` and `Option<Heredoc>` are the
    /// shell-level I/O wiring.
    Simple {
        argv: Vec<Word>,
        redirections: Vec<Redirection>,
        heredoc: Option<Heredoc>,
    },

    /// A pipeline: one or more commands joined by `|`. S1 cannot see
    /// this as a single unit; S2 can.
    Pipeline(Vec<Command>),

    /// A subshell: `( pipeline )`. The inner `Box<Command>` is the
    /// pipeline inside the parens.
    Subshell(Box<Command>),

    /// Command substitution: `$( pipeline )` or `` ` pipeline ` ``.
    /// The `kind` field disambiguates the syntax.
    Substitution {
        kind: SubstitutionKind,
        body: Box<Command>,
    },
}

/// How a `CommandSubstitution` was syntactically introduced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubstitutionKind {
    /// `$( pipeline )` — POSIX form.
    DollarParen,
    /// `` ` pipeline ` `` — legacy form.
    Backtick,
}

/// A single shell word, as the lexer/parser resolved it. The `text`
/// field carries the canonical form (escape sequences resolved,
/// quotes stripped) for use by the matcher. The `raw` field is the
/// original source slice for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Word {
    pub text: String,
    pub raw: String,
}

impl Word {
    pub fn new(text: impl Into<String>, raw: impl Into<String>) -> Self {
        Self { text: text.into(), raw: raw.into() }
    }
}

/// A single redirection: `redir_op` applied to `word` (the file
/// descriptor target, or the fd duplication target like `&1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirection {
    pub op: RedirOp,
    pub target: Word,
}

/// The redirection operator. `Dup` covers `>&` and `<&` (fd
/// duplication); the `target` word carries the fd number or `-`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirOp {
    Lt,        // <
    Gt,        // >
    DGreat,    // >>
    DLess,     // <<
    DupOut,    // >&
    DupIn,     // <&
}

/// A heredoc: the `delimiter` word (no quotes, no expansion) and the
/// body lines (preserved verbatim, newlines and all). The `quoted`
/// field records whether the original delimiter was quoted
/// (`<<'EOF'`) — when true, the body is NOT subject to parameter
/// expansion in the real shell, but apohara treats both forms
/// uniformly for matching purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heredoc {
    pub delimiter: String,
    pub body: String,
    pub quoted: bool,
}

/// The only failure mode of the S2 parser. NEVER panics on
/// malformed input. The matcher falls back to S1 on `Err`.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parseerror_display_is_informative() {
        let e = ParseError::UnbalancedQuote(42);
        assert_eq!(e.to_string(), "unbalanced quote at byte offset 42");

        let e = ParseError::UnterminatedHeredoc { start: 7, delimiter: "EOF".into() };
        assert_eq!(
            e.to_string(),
            "unterminated heredoc starting at byte offset 7 (delimiter `EOF`)"
        );
    }

    #[test]
    fn word_construction() {
        let w = Word::new("hello", "\"hello\"");
        assert_eq!(w.text, "hello");
        assert_eq!(w.raw, "\"hello\"");
    }

    #[test]
    fn command_partial_eq() {
        let a = Command::Simple {
            argv: vec![Word::new("rm", "rm"), Word::new("-rf", "-rf")],
            redirections: vec![],
            heredoc: None,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}
