// Tolerant AI coding-agent session-transcript reader (newline-delimited JSON),
// keyed on the top-level `type` discriminator.
//
// FORMAT NOTE (R1 / PM-2): the agent session JSONL schema is undocumented and
// version-dependent (transcripts live on-disk under `~/.claude/projects`). The
// `type` set is NOT fixed across transcripts. The
// canonical union observed on this machine (live-derived 2026-06-05, captured +
// sanitized in tests/fixtures/session-sample.jsonl) is:
//
//   permission-mode, file-history-snapshot, user, last-prompt, system,
//   attachment, ai-title, assistant, queue-operation, mode, agent-name
//
// We do NOT hardcode that as an exhaustive set. The parser CLASSIFIES-OR-SKIPS
// EVERY object with a logged reason and NEVER panics:
//   * a known `type` is handled (assistant objects yield observed actions; all
//     other known types are recognized + skipped as "no actions to extract");
//   * an UNKNOWN `type` is skipped with reason "unknown type: <t>";
//   * an object with no `type` is skipped with reason "missing type";
//   * a truncated/garbled line that fails to parse is skipped with reason
//     "json parse error: <e>".
//
// From `assistant` objects we extract `tool_use` blocks from
// `message.content[]`, pulling the tool-relevant input string (Bash→command,
// Read/Write/Edit→file_path, …) as an [`ObservedAction`] to feed the matcher.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::matching::ObservedAction;

/// Outcome of parsing a session transcript.
pub struct SessionParse {
    /// Observed actions (tool inputs) to feed the rule matcher.
    pub actions: Vec<ObservedAction>,
    /// Every distinct top-level `type` seen (for the classify-or-skip audit).
    pub observed_types: BTreeSet<String>,
    /// Per-object skip reasons (logged to stderr by the caller).
    pub skips: Vec<String>,
    /// Session evidence captured from object metadata.
    pub evidence: SessionEvidence,
}

/// Lightweight session evidence pulled from object metadata fields.
#[derive(Debug, Default, Clone)]
pub struct SessionEvidence {
    pub version: Option<String>,
    pub git_branch: Option<String>,
    pub cwd: Option<String>,
}

/// The agent version family this parser was written against (R1).
/// A different major/minor triggers a best-effort warning, never a failure.
const EXPECTED_MAJOR: u64 = 2;
const EXPECTED_MINOR: u64 = 1;

/// Parse a session transcript from raw NDJSON text. Pure (no I/O) so it is
/// trivially unit-testable; the CLI reads the file and hands the text in.
pub fn parse_session(text: &str) -> SessionParse {
    let mut actions = Vec::new();
    let mut observed_types = BTreeSet::new();
    let mut skips = Vec::new();
    let mut evidence = SessionEvidence::default();

    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let lineno = lineno + 1;

        // Tolerant parse: a truncated/garbled line is skipped, never fatal.
        let obj: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                skips.push(format!("line {lineno}: json parse error: {e}"));
                continue;
            }
        };

        // Capture evidence opportunistically from any object that carries it.
        capture_evidence(&obj, &mut evidence, &mut skips);

        // Every object is classified by its top-level `type` discriminator.
        let kind = match obj.get("type").and_then(Value::as_str) {
            Some(t) => t.to_string(),
            None => {
                skips.push(format!("line {lineno}: missing type discriminator"));
                continue;
            }
        };
        observed_types.insert(kind.clone());

        match kind.as_str() {
            "assistant" => {
                let extracted = extract_assistant_actions(&obj);
                if extracted.is_empty() {
                    skips.push(format!("line {lineno}: assistant object, no tool_use blocks"));
                }
                actions.extend(extracted);
            }
            // Known, non-actionable object types: recognized + skipped (no
            // tool inputs to extract). Listed for documentation; the wildcard
            // below would also catch them, but enumerating the observed union
            // makes drift diff-able (PM-2).
            "user"
            | "system"
            | "attachment"
            | "queue-operation"
            | "permission-mode"
            | "mode"
            | "ai-title"
            | "agent-name"
            | "last-prompt"
            | "file-history-snapshot" => {
                skips.push(format!("line {lineno}: '{kind}' carries no observable action"));
            }
            other => {
                skips.push(format!("line {lineno}: unknown type: '{other}' (skipped)"));
            }
        }
    }

    SessionParse {
        actions,
        observed_types,
        skips,
        evidence,
    }
}

/// Pull observable tool inputs from one `assistant` object's
/// `message.content[]` `tool_use` blocks.
fn extract_assistant_actions(obj: &Value) -> Vec<ObservedAction> {
    let mut out = Vec::new();
    let content = obj
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(Value::as_array);
    let Some(blocks) = content else {
        return out;
    };

    for block in blocks {
        if block.get("type").and_then(Value::as_str) != Some("tool_use") {
            continue;
        }
        let name = block.get("name").and_then(Value::as_str).unwrap_or("");
        let input = block.get("input");
        if let Some(value) = relevant_input(name, input) {
            out.push(ObservedAction::new(format!("session:{name}.input"), value));
        }
    }
    out
}

/// Pick the rule-relevant input string for a given tool.
///
/// `Bash`→`command`; file tools (`Read`/`Write`/`Edit`/`MultiEdit`/`NotebookEdit`)
/// →`file_path`; for any other tool we scan all string-valued input fields so a
/// signal in, e.g., a `WebFetch.url` or a free-form arg is not missed.
fn relevant_input(name: &str, input: Option<&Value>) -> Option<String> {
    let input = input?;
    match name {
        "Bash" => input
            .get("command")
            .and_then(Value::as_str)
            .map(str::to_string),
        "Read" | "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => input
            .get("file_path")
            .and_then(Value::as_str)
            .map(str::to_string),
        _ => {
            // Concatenate every top-level string field so an embedded signal in
            // an unknown tool's args is still observable.
            let joined: Vec<&str> = input
                .as_object()
                .map(|m| m.values().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            if joined.is_empty() {
                None
            } else {
                Some(joined.join(" "))
            }
        }
    }
}

/// Opportunistically capture `version`/`gitBranch`/`cwd` from any object, and
/// version-gate the session `version` with a best-effort warning on a jump.
fn capture_evidence(obj: &Value, ev: &mut SessionEvidence, skips: &mut Vec<String>) {
    if ev.version.is_none() {
        if let Some(v) = obj.get("version").and_then(Value::as_str) {
            ev.version = Some(v.to_string());
            if let Some(warn) = version_gate(v) {
                skips.push(warn);
            }
        }
    }
    if ev.git_branch.is_none() {
        if let Some(b) = obj.get("gitBranch").and_then(Value::as_str) {
            ev.git_branch = Some(b.to_string());
        }
    }
    if ev.cwd.is_none() {
        if let Some(c) = obj.get("cwd").and_then(Value::as_str) {
            ev.cwd = Some(c.to_string());
        }
    }
}

/// Best-effort version gate: parse `major.minor.patch` and warn on a major/minor
/// jump away from what the parser was written against. Never fails.
fn version_gate(version: &str) -> Option<String> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next().and_then(|m| m.parse::<u64>().ok())?;
    if major != EXPECTED_MAJOR || minor != EXPECTED_MINOR {
        Some(format!(
            "warning: session version {version} differs from the parser's tested \
             {EXPECTED_MAJOR}.{EXPECTED_MINOR}.x family; parsing best-effort"
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_bash_command_from_assistant() {
        // NDJSON: one object per physical line — keep the literal single-line.
        let line = r#"{"type":"assistant","version":"2.1.161","gitBranch":"main","cwd":"/x","message":{"role":"assistant","content":[{"type":"tool_use","name":"Bash","input":{"command":"sudo rm -rf /tmp"}}]}}"#;
        let p = parse_session(line);
        assert_eq!(p.actions.len(), 1);
        assert!(p.actions[0].value.contains("rm -rf"));
        assert_eq!(p.evidence.version.as_deref(), Some("2.1.161"));
        assert_eq!(p.evidence.git_branch.as_deref(), Some("main"));
        assert_eq!(p.evidence.cwd.as_deref(), Some("/x"));
    }

    #[test]
    fn read_tool_yields_file_path_action() {
        let line = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Read","input":{"file_path":"/etc/passwd"}}]}}"#;
        let p = parse_session(line);
        assert_eq!(p.actions.len(), 1);
        assert_eq!(p.actions[0].value, "/etc/passwd");
    }

    #[test]
    fn unknown_type_is_skipped_with_reason_not_panic() {
        let line = r#"{"type":"brand-new-kind","payload":"x"}"#;
        let p = parse_session(line);
        assert!(p.actions.is_empty());
        assert!(p.skips.iter().any(|s| s.contains("unknown type")));
        assert!(p.observed_types.contains("brand-new-kind"));
    }

    #[test]
    fn missing_type_is_skipped_with_reason() {
        let line = r#"{"sessionId":"abc","note":"no type here"}"#;
        let p = parse_session(line);
        assert!(p.skips.iter().any(|s| s.contains("missing type")));
    }

    #[test]
    fn truncated_line_is_skipped_not_panic() {
        let line = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash"#;
        let p = parse_session(line);
        assert!(p.actions.is_empty());
        assert!(p.skips.iter().any(|s| s.contains("json parse error")));
    }

    #[test]
    fn system_and_queue_operation_classified_without_panic() {
        let text = concat!(
            r#"{"type":"system","subtype":"stop_hook_summary"}"#,
            "\n",
            r#"{"type":"queue-operation","operation":"enqueue","content":"hi"}"#,
        );
        let p = parse_session(text);
        assert!(p.observed_types.contains("system"));
        assert!(p.observed_types.contains("queue-operation"));
        assert!(p.actions.is_empty());
    }

    #[test]
    fn version_gate_warns_on_jump_but_does_not_fail() {
        let line = r#"{"type":"user","version":"9.9.9","message":{"content":"hi"}}"#;
        let p = parse_session(line);
        assert_eq!(p.evidence.version.as_deref(), Some("9.9.9"));
        assert!(p.skips.iter().any(|s| s.contains("differs from the parser")));
    }
}
