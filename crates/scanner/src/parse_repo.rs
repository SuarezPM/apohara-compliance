// Repository walker — walks a directory respecting `.gitignore` and surfaces
// observable actions (file paths + file contents) to feed the rule matcher.
//
// Gitignore-respect (proven by the repo-fixture's ignored `secret.env`): the
// `ignore` crate's `WalkBuilder` honours `.gitignore`/`.ignore` files. We force
// `require_git(false)` so a fixture directory that is NOT itself a git repo
// still has its `.gitignore` applied — otherwise the standard behaviour only
// activates gitignore handling inside a real git working tree.

use std::path::Path;

use ignore::WalkBuilder;

use crate::matching::ObservedAction;

/// Per-file byte budget: only the first slice of each file is scanned for
/// signals. Detection signals are short literals, so a head slice is sufficient
/// and keeps a huge file from dominating the scan.
const MAX_BYTES_PER_FILE: usize = 256 * 1024;

/// Outcome of walking a repository.
pub struct RepoParse {
    pub actions: Vec<ObservedAction>,
    /// Per-path notes (e.g. unreadable file), logged to stderr by the caller.
    pub skips: Vec<String>,
}

/// Walk `root`, honouring `.gitignore`, and collect observable actions: one for
/// each file's relative path, plus one for the (head-truncated) text contents of
/// each readable file.
///
/// `ext_filter` (US-F2-4 #5) is a WALKER-level file-extension allowlist: when
/// non-empty, only files whose extension (case-insensitive, no leading dot) is
/// in the set are read — BOTH the path and the content action are suppressed for
/// the rest. An EMPTY slice means no filtering, so the default behavior is
/// byte-identical to the prior walker. This is a commodity CLI filter, NOT a
/// detection-rule context field (ADR-1's 3-field context DSL stays frozen); it
/// adds no tree-sitter / language parsing.
pub fn parse_repo(root: &Path, ext_filter: &[String]) -> RepoParse {
    let mut actions = Vec::new();
    let mut skips = Vec::new();

    // Normalize the allowlist to lowercase once. Empty ⇒ "accept all".
    let allow: Vec<String> = ext_filter.iter().map(|e| e.to_ascii_lowercase()).collect();

    let walker = WalkBuilder::new(root)
        .standard_filters(true) // .gitignore + hidden + parents
        .require_git(false) // apply .gitignore even without a .git dir
        .git_ignore(true)
        .git_exclude(true)
        .hidden(false) // do scan dotfiles like .gitignore-listed-but-present configs
        .build();

    for result in walker {
        let entry = match result {
            Ok(e) => e,
            Err(e) => {
                skips.push(format!("walk error: {e}"));
                continue;
            }
        };

        // Only regular files carry scannable content.
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }

        let path = entry.path();
        let rel = path.strip_prefix(root).unwrap_or(path);
        let rel_str = rel.to_string_lossy().to_string();

        // WALKER extension filter (US-F2-4 #5): when an allowlist is set, skip a
        // file (both its path AND its content action) unless its extension
        // matches. A file with no extension never matches a non-empty allowlist.
        if !allow.is_empty() && !extension_allowed(path, &allow) {
            skips.push(format!("{rel_str}: extension not in --ext filter"));
            continue;
        }

        // The path itself is an observable signal (e.g. a `dump_all.sql` name).
        actions.push(ObservedAction::new(
            format!("repo-path:{rel_str}"),
            rel_str.clone(),
        ));

        match read_head(path) {
            Ok(text) => {
                actions.push(ObservedAction::new(format!("repo-file:{rel_str}"), text));
            }
            Err(reason) => {
                skips.push(format!("{rel_str}: {reason}"));
            }
        }
    }

    RepoParse { actions, skips }
}

/// True when `path`'s extension (lowercased, no dot) is in the `allow` list.
/// A file without an extension is never allowed by a non-empty list. `allow` is
/// assumed already lowercased by the caller.
fn extension_allowed(path: &Path, allow: &[String]) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => allow.iter().any(|a| a == &ext.to_ascii_lowercase()),
        None => false,
    }
}

/// Read up to `MAX_BYTES_PER_FILE` bytes of a file as UTF-8 (lossy). Binary or
/// unreadable files are reported as a skip reason rather than failing the scan.
fn read_head(path: &Path) -> Result<String, String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|e| format!("open: {e}"))?;
    let mut buf = vec![0u8; MAX_BYTES_PER_FILE];
    let n = file.read(&mut buf).map_err(|e| format!("read: {e}"))?;
    buf.truncate(n);
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn walks_files_and_collects_path_and_content_actions() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a.sql"), "SELECT * FROM users").unwrap();
        let parse = parse_repo(dir.path(), &[]);
        // Expect a path action AND a content action for a.sql.
        assert!(parse.actions.iter().any(|a| a.value.contains("a.sql")));
        assert!(parse
            .actions
            .iter()
            .any(|a| a.value.contains("SELECT * FROM users")));
    }

    #[test]
    fn respects_gitignore() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".gitignore"), "ignored.txt\n").unwrap();
        fs::write(dir.path().join("ignored.txt"), "sudo rm -rf /").unwrap();
        fs::write(dir.path().join("kept.txt"), "hello").unwrap();

        let parse = parse_repo(dir.path(), &[]);
        // The ignored file's content must NOT appear as an action.
        assert!(
            !parse.actions.iter().any(|a| a.value.contains("sudo rm -rf")),
            "gitignored file should be skipped by the walker"
        );
        assert!(parse.actions.iter().any(|a| a.value.contains("kept.txt")));
    }

    #[test]
    fn ext_filter_restricts_to_named_extensions() {
        // US-F2-4 #5: `--ext rs,py` only reads .rs/.py files; a .sql/.md file is
        // skipped entirely (neither its path nor its content surfaces).
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("keep.rs"), "fn main() {}").unwrap();
        fs::write(dir.path().join("keep.py"), "print('hi')").unwrap();
        fs::write(dir.path().join("drop.sql"), "SELECT * FROM users").unwrap();
        fs::write(dir.path().join("README.md"), "docs here").unwrap();

        let parse = parse_repo(dir.path(), &["rs".into(), "py".into()]);
        // .rs/.py present.
        assert!(parse.actions.iter().any(|a| a.value.contains("keep.rs")));
        assert!(parse.actions.iter().any(|a| a.value.contains("keep.py")));
        // .sql/.md absent — path AND content suppressed by the walker filter.
        assert!(!parse.actions.iter().any(|a| a.value.contains("drop.sql")));
        assert!(!parse.actions.iter().any(|a| a.value.contains("SELECT * FROM")));
        assert!(!parse.actions.iter().any(|a| a.value.contains("README.md")));
    }

    #[test]
    fn ext_filter_is_case_insensitive_and_dotless() {
        // Extensions are matched lowercased and without a leading dot, so `--ext
        // RS` matches `main.rs` and `Main.RS` alike.
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("Main.RS"), "fn main() {}").unwrap();
        let parse = parse_repo(dir.path(), &["rs".into()]);
        assert!(parse.actions.iter().any(|a| a.value.contains("Main.RS")));
    }

    #[test]
    fn empty_ext_filter_is_identical_to_no_filter() {
        // An empty allowlist reads everything (byte-identical default behavior).
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a.sql"), "SELECT * FROM users").unwrap();
        fs::write(dir.path().join("b.rs"), "fn main() {}").unwrap();
        let parse = parse_repo(dir.path(), &[]);
        assert!(parse.actions.iter().any(|a| a.value.contains("a.sql")));
        assert!(parse.actions.iter().any(|a| a.value.contains("b.rs")));
    }
}
