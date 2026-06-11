// apohara-compliance — v2.4 S2 shell lexer.
//
// Hand-rolled character-by-character scanner. Tokenizes the focused
// subset documented in `docs/grammar/posix-shell-v2.4-subset.md` §3.1.
// Returns `Vec<Spanned<Token>>`; the parser consumes the token stream.
//
// All error paths return `Err(ParseError)`. The lexer never panics.

use super::ast::ParseError;

/// A token with its starting byte offset. The offset is the position
/// of the first character of the token in the original input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spanned<T> {
    pub token: T,
    pub offset: usize,
}

impl<T> Spanned<T> {
    pub fn new(token: T, offset: usize) -> Self {
        Self { token, offset }
    }
}

/// The token types emitted by the lexer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// A shell word (argv, redirection target, heredoc delimiter).
    /// The `text` is the canonical (de-quoted, escape-resolved) form;
    /// `raw` is the original source slice.
    Word { text: String, raw: String },

    // Punctuation
    Pipe,           // |
    LParen,         // (
    RParen,         // )
    Semi,           // ;
    Newline,        // \n (real newline)
    Eof,            // end of input

    // Redirections
    Lt,             // <
    Gt,             // >
    DGreat,         // >>
    DLess,          // <<
    DupOut,         // >&
    DupIn,          // <&

    // Logical (out of scope for v2.4 Simple matching; included for
    // forward-compat and to keep the lexer honest about `&&`/`||`).
    And,            // &&
    Or,             // ||
}


/// Tokenize the input. Returns `Err(ParseError)` on unbalanced quotes.
/// All other malformed input is handled by the parser.
pub fn tokenize(input: &str) -> Result<Vec<Spanned<Token>>, ParseError> {
    let mut lx = Lexer { input: input.as_bytes(), pos: 0 };
    let mut out = Vec::new();

    loop {
        lx.skip_whitespace_and_comments()?;
        if lx.is_eof() {
            out.push(Spanned::new(Token::Eof, lx.pos));
            return Ok(out);
        }

        let start = lx.pos;
        let b = lx.peek();

        let tok = match b {
            b'|' => {
                if lx.peek_at(1) == Some(b'|') {
                    lx.advance(2);
                    Token::Or
                } else {
                    lx.advance(1);
                    Token::Pipe
                }
            }
            b'(' => { lx.advance(1); Token::LParen }
            b')' => { lx.advance(1); Token::RParen }
            b';' => { lx.advance(1); Token::Semi }
            b'\n' => { lx.advance(1); Token::Newline }
            b'<' => {
                if lx.peek_at(1) == Some(b'&') {
                    lx.advance(2);
                    Token::DupIn
                } else if lx.peek_at(1) == Some(b'<') {
                    lx.advance(2);
                    Token::DLess
                } else {
                    lx.advance(1);
                    Token::Lt
                }
            }
            b'>' => {
                if lx.peek_at(1) == Some(b'&') {
                    lx.advance(2);
                    Token::DupOut
                } else if lx.peek_at(1) == Some(b'>') {
                    lx.advance(2);
                    Token::DGreat
                } else {
                    lx.advance(1);
                    Token::Gt
                }
            }
            b'&' => {
                if lx.peek_at(1) == Some(b'&') {
                    lx.advance(2);
                    Token::And
                } else {
                    return Err(ParseError::UnexpectedToken {
                        offset: start,
                        expected: "&& or ; or end of word",
                        got: "&".to_string(),
                    });
                }
            }
            b'\'' => {
                let tok = lx.read_single_quoted(start)?;
                out.push(Spanned::new(tok, start));
                continue;
            }
            b'"' => {
                let tok = lx.read_double_quoted(start)?;
                out.push(Spanned::new(tok, start));
                continue;
            }
            // Bare `$` and `` ` ``: emit as a one-character Word so the
            // parser can decide how to combine them with surrounding
            // tokens (e.g. `$(` = Word `$` + LParen; `` `cmd` `` =
            // Word `` ` `` + Word `cmd` + Word `` ` ``).
            b'$' | b'`' => {
                lx.advance(1);
                Token::Word {
                    text: (b as char).to_string(),
                    raw: (b as char).to_string(),
                }
            }
            b'\\' => {
                lx.advance(1);
                if lx.is_eof() {
                    return Err(ParseError::UnterminatedHeredoc {
                        start,
                        delimiter: String::new(),
                    });
                }
                lx.advance(1);
                // The backslash itself is consumed; the escaped char
                // becomes the start of the next word. Re-enter.
                continue;
            }
            _ => {
                lx.read_bare_word()?;
                let (text, raw) = lx.take_word_buffer(start);
                Token::Word { text, raw }
            }
        };

        out.push(Spanned::new(tok, start));
    }
}

struct Lexer<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn is_eof(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn peek(&self) -> u8 {
        self.input[self.pos]
    }

    fn peek_at(&self, n: usize) -> Option<u8> {
        self.input.get(self.pos + n).copied()
    }

    fn advance(&mut self, n: usize) {
        self.pos += n;
    }

    fn skip_whitespace_and_comments(&mut self) -> Result<(), ParseError> {
        while !self.is_eof() {
            let b = self.peek();
            if b == b' ' || b == b'\t' || b == b'\r' {
                self.advance(1);
            } else if b == b'#' {
                // Shell comment: `#` at word boundary, runs to end of
                // line. Only at start of word (not after a non-whitespace
                // token on the same line — but we always re-enter here
                // between tokens, so this is correct).
                while !self.is_eof() && self.peek() != b'\n' {
                    self.advance(1);
                }
            } else {
                break;
            }
        }
        Ok(())
    }

    /// Read a single-quoted word. Returns `Err(ParseError::UnbalancedQuote)`
    /// if the closing `'` is not found before EOF.
    fn read_single_quoted(&mut self, start: usize) -> Result<Token, ParseError> {
        self.advance(1); // consume opening '
        let text_start = self.pos;
        while !self.is_eof() && self.peek() != b'\'' {
            self.advance(1);
        }
        if self.is_eof() {
            return Err(ParseError::UnbalancedQuote(start));
        }
        let text = std::str::from_utf8(&self.input[text_start..self.pos])
            .map_err(|_| ParseError::UnbalancedQuote(start))?
            .to_string();
        self.advance(1); // consume closing '
        Ok(Token::Word {
            text,
            raw: std::str::from_utf8(&self.input[start..self.pos])
                .map_err(|_| ParseError::UnbalancedQuote(start))?
                .to_string(),
        })
    }

    /// Read a double-quoted word with backslash escapes. Returns
    /// `Err(ParseError::UnbalancedQuote)` on missing closing `"`.
    fn read_double_quoted(&mut self, start: usize) -> Result<Token, ParseError> {
        self.advance(1); // consume opening "
        let text_start = self.pos;
        while !self.is_eof() && self.peek() != b'"' {
            if self.peek() == b'\\' && self.peek_at(1).is_some() {
                self.advance(2); // skip the escape pair
            } else {
                self.advance(1);
            }
        }
        if self.is_eof() {
            return Err(ParseError::UnbalancedQuote(start));
        }
        let text = std::str::from_utf8(&self.input[text_start..self.pos])
            .map_err(|_| ParseError::UnbalancedQuote(start))?
            .to_string();
        self.advance(1); // consume closing "
        Ok(Token::Word {
            text,
            raw: std::str::from_utf8(&self.input[start..self.pos])
                .map_err(|_| ParseError::UnbalancedQuote(start))?
                .to_string(),
        })
    }

    /// Read a bare (unquoted) word. Stops at any of the 14
    /// metacharacters: space, tab, newline, `|`, `&`, `;`, `<`, `>`,
    /// `(`, `)`, `$`, `` ` ``, `\`, `"`, `'`.
    fn read_bare_word(&mut self) -> Result<(), ParseError> {
        while !self.is_eof() {
            let b = self.peek();
            if matches!(b,
                b' ' | b'\t' | b'\n' | b'|' | b'&' | b';' | b'<' | b'>' |
                b'(' | b')' | b'$' | b'`' | b'\\' | b'"' | b'\''
            ) {
                break;
            }
            self.advance(1);
        }
        Ok(())
    }

    /// Take the buffer that was read into `input[start..pos]`. The
    /// `start` is the offset of the first character of the word.
    fn take_word_buffer(&self, start: usize) -> (String, String) {
        let raw = std::str::from_utf8(&self.input[start..self.pos])
            .unwrap_or("")
            .to_string();
        // For bare words, the canonical form == the raw form (no
        // escapes to resolve in bare context).
        (raw.clone(), raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_simple() {
        let toks = tokenize("rm -rf /").unwrap();
        let kinds: Vec<&Token> = toks.iter().map(|s| &s.token).collect();
        assert!(matches!(kinds[0], Token::Word { text, .. } if text == "rm"));
        assert!(matches!(kinds[1], Token::Word { text, .. } if text == "-rf"));
        assert!(matches!(kinds[2], Token::Word { text, .. } if text == "/"));
        assert!(matches!(kinds[3], Token::Eof));
    }

    #[test]
    fn tokenize_single_quoted() {
        let toks = tokenize("'hello world'").unwrap();
        assert!(matches!(&toks[0].token, Token::Word { text, raw } if text == "hello world" && raw == "'hello world'"));
    }

    #[test]
    fn tokenize_double_quoted_with_escape() {
        let toks = tokenize(r#""back\"slash""#).unwrap();
        assert!(matches!(&toks[0].token, Token::Word { text, .. } if text == r#"back\"slash"#));
    }

    #[test]
    fn tokenize_unbalanced_quote_errors() {
        let err = tokenize("'unclosed").unwrap_err();
        assert!(matches!(err, ParseError::UnbalancedQuote(0)));
    }

    #[test]
    fn tokenize_pipeline_separators() {
        let toks = tokenize("a | b").unwrap();
        assert!(matches!(toks[0].token, Token::Word { .. }));
        assert!(matches!(toks[1].token, Token::Pipe));
        assert!(matches!(toks[2].token, Token::Word { .. }));
    }

    #[test]
    fn tokenize_redirections() {
        // The lexer emits redirection operators greedily (`>`, `>>`,
        // `>&`, `<&`) but does NOT recognise `2>&1` as an atomic
        // token — that's a redirection-with-fd-prefix pattern the
        // parser (US-003) reassembles from `2` (bare word) + `>&` +
        // `1` (bare word). This test asserts the lexer-level shape.
        let toks = tokenize("cmd > out 2>&1").unwrap();
        let kinds: Vec<&Token> = toks.iter().map(|s| &s.token).collect();
        assert!(matches!(kinds[0], Token::Word { .. }));
        assert!(matches!(kinds[1], Token::Gt));
        assert!(matches!(kinds[2], Token::Word { text, .. } if text == "out"));
        assert!(matches!(kinds[3], Token::Word { text, .. } if text == "2"));
        assert!(matches!(kinds[4], Token::DupOut));
        assert!(matches!(kinds[5], Token::Word { text, .. } if text == "1"));
    }

    #[test]
    fn tokenize_heredoc_op() {
        let toks = tokenize("cat <<EOF").unwrap();
        assert!(matches!(toks[1].token, Token::DLess));
    }

    #[test]
    fn tokenize_dollar_paren_and_backtick() {
        let toks = tokenize("$(cmd) `cmd2`").unwrap();
        // `$(` becomes Word `$` + LParen (kept simple for the parser
        // to combine). ` `cmd2` `` becomes Word ` ` + Word `cmd2` + Word ` `.
        assert!(matches!(&toks[0].token, Token::Word { text, .. } if text == "$"));
        assert!(matches!(toks[1].token, Token::LParen));
    }
}
