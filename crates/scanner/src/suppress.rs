// Visible allowlist suppression (US-F0-2 / plan Step 0.2, fix #4).
//
// A `.apohara-suppress` file is a gitleaks-style allowlist applied AFTER a
// signal matches but BEFORE the candidate enters the ACTIVE findings list. A
// suppressed candidate is NEVER dropped: it moves into the report's visible
// `suppressed` channel (see model::SuppressedFinding), still `is_candidate`.
//
// File format (one rule per line; `#` starts a comment; blank lines ignored):
//
//   AGT-EXF-001                      # suppress every match of this agt_code
//   AGT-EXF-001:SELECT * FROM        # suppress only this (agt_code, signal) pair
//   *:repo-file:tests/fixtures/*     # suppress any code whose SOURCE glob matches
//   AGT-MIS-001:*:repo-file/secret*  # agt_code + source glob (signal wildcarded)
//
// Each line is `agt_code[:signal][:source_glob]` where any leading positional
// part may be `*` to wildcard it. A trailing `# reason` on the line (after the
// pattern, separated by whitespace) is recorded as the human justification.

use std::path::Path;

/// One parsed allowlist entry. A field set to `None` matches anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressRule {
    /// AGT-* code to match, or `None` for any.
    pub agt_code: Option<String>,
    /// Exact triggering signal to match, or `None` for any.
    pub signal: Option<String>,
    /// Glob on the observed-action `source`, or `None` for any.
    pub source_glob: Option<String>,
    /// Human justification (the in-file comment after the pattern, if any).
    pub reason: String,
    /// The verbatim pattern text (audit trail / `suppressed_by`).
    pub raw: String,
}

/// A loaded allowlist (possibly empty).
#[derive(Debug, Clone, Default)]
pub struct SuppressList {
    pub rules: Vec<SuppressRule>,
}

impl SuppressList {
    /// Load a `.apohara-suppress` file. A missing file is NOT an error — it
    /// yields an empty list (suppression is opt-in).
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(SuppressList::default())
            }
            Err(e) => return Err(format!("failed to read suppress file {}: {e}", path.display())),
        };
        Ok(Self::parse(&text))
    }

    /// Parse allowlist text into rules (whitespace/`#`-comment tolerant).
    pub fn parse(text: &str) -> Self {
        let mut rules = Vec::new();
        for line in text.lines() {
            // Split off a trailing "# reason" comment (reason is human-facing).
            let (pattern, reason) = match line.find('#') {
                Some(i) => (line[..i].trim(), line[i + 1..].trim()),
                None => (line.trim(), ""),
            };
            if pattern.is_empty() {
                continue;
            }
            // Positional fields: agt_code[:signal][:source_glob]. `*` = any.
            // Split into at most 3 parts so a signal containing ':' is allowed
            // ONLY when no source glob is present; source globs themselves may
            // contain ':' (e.g. `repo-file:...`), so we cap at 3 and treat the
            // 3rd part as the (possibly colon-bearing) source glob remainder.
            let parts: Vec<&str> = pattern.splitn(3, ':').collect();
            let agt_code = field(parts.first().copied());
            let signal = field(parts.get(1).copied());
            let source_glob = field(parts.get(2).copied());
            let reason = if reason.is_empty() {
                "allowlisted".to_string()
            } else {
                reason.to_string()
            };
            rules.push(SuppressRule {
                agt_code,
                signal,
                source_glob,
                reason,
                raw: pattern.to_string(),
            });
        }
        SuppressList { rules }
    }

    /// First matching rule for a (agt_code, signal, source) triple, if any.
    pub fn matching(&self, agt_code: &str, signal: &str, source: &str) -> Option<&SuppressRule> {
        // `map_or(true, ..)` (not `is_none_or`) to honor the 1.74 MSRV declared
        // in the workspace package (is_none_or stabilized in 1.82).
        self.rules.iter().find(|r| {
            r.agt_code.as_deref().map_or(true, |c| c == agt_code)
                && r.signal.as_deref().map_or(true, |s| s == signal)
                && r
                    .source_glob
                    .as_deref()
                    .map_or(true, |g| glob_match(g, source))
        })
    }
}

/// Treat `*` as a wildcard for any positional field (`*`/empty → `None`).
fn field(part: Option<&str>) -> Option<String> {
    match part.map(str::trim) {
        None | Some("") | Some("*") => None,
        Some(s) => Some(s.to_string()),
    }
}

/// Minimal glob: `*` matches any run of characters (including empty); every
/// other char is literal. Sufficient for source allowlists like
/// `repo-file:tests/fixtures/*` without pulling a glob dependency.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    // Classic two-pointer wildcard match with backtracking.
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_agt_only_and_pair() {
        let list = SuppressList::parse("AGT-EXF-001\nAGT-PI-001:DAN # noisy in prose");
        assert_eq!(list.rules.len(), 2);
        assert_eq!(list.rules[0].agt_code.as_deref(), Some("AGT-EXF-001"));
        assert_eq!(list.rules[0].signal, None);
        assert_eq!(list.rules[0].reason, "allowlisted");
        assert_eq!(list.rules[1].signal.as_deref(), Some("DAN"));
        assert_eq!(list.rules[1].reason, "noisy in prose");
    }

    #[test]
    fn skips_comments_and_blanks() {
        let list = SuppressList::parse("# header\n\n   \nAGT-MIS-001\n");
        assert_eq!(list.rules.len(), 1);
    }

    #[test]
    fn matches_by_code_signal_and_source_glob() {
        let list = SuppressList::parse("AGT-EXF-001:SELECT * FROM:repo-file:*report.sql");
        let r = list.matching("AGT-EXF-001", "SELECT * FROM", "repo-file:src/report.sql");
        assert!(r.is_some());
        // Wrong source does not match.
        assert!(list
            .matching("AGT-EXF-001", "SELECT * FROM", "repo-file:src/other.sql")
            .is_none());
    }

    #[test]
    fn wildcard_agt_matches_any_code() {
        let list = SuppressList::parse("*:*:repo-file:tests/fixtures/*");
        assert!(list
            .matching("AGT-PI-001", "DAN", "repo-file:tests/fixtures/x.md")
            .is_some());
    }

    #[test]
    fn glob_basic() {
        assert!(glob_match("repo-file:*", "repo-file:src/a.rs"));
        assert!(glob_match("*report.sql", "repo-file:src/report.sql"));
        assert!(glob_match("a*c", "abc"));
        assert!(!glob_match("a*c", "abd"));
        assert!(glob_match("*", "anything"));
    }
}
