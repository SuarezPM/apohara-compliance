// Structural SHELL-COMMAND matching (ADR-5 S1 / AC3.3) — the flag-reordering pass.
//
// This is an ADDITIVE pass that runs AFTER the single-action loop, the ADR-2
// `sequence` pass, AND the ADR-4 `taint` pass in
// `matching::match_actions_with_suppress`. It expresses what a literal-substring
// family regex cannot: tokenize a REAL executed Bash command into argv + flags
// and fire when the invoked BINARY equals `rule.binary` AND every flag in
// `rule.all_flags` is present — order-, spacing-, and bundling-INVARIANT. This
// defeats the cheap flag-REORDERING / spacing / short-bundling evasions the
// AGT-MIS-001 regex family misses (`rm -r -f -v`, `rm  --force  --recursive`,
// `rm -frv`, `/bin/rm -rf`).
//
// SELF-CONTAINED by design (mirrors taint.rs / sequence.rs): this module copies
// the small compile/match shape rather than sharing a helper, to keep zero
// blast-radius on the CRITICAL `matching.rs` and the live single-action loop. The
// only external matching primitive it reuses is `regex` for the require/deny
// context fragments (the SAME structural guards as the FROZEN 3-modifier DSL).
//
// TOKENIZER: `shlex::split` (pure-Rust, zero-dep, offline, POSIX word-splitting,
// PINNED >=1.3.0 post-RUSTSEC-2024-0006). On unbalanced quotes `shlex::split`
// returns `None` — that action is SKIPPED (never panics).
//
// HONESTY (ADR-5): a fired shell candidate means "a command whose binary + flag
// SET matches a known-destructive structural pattern was observed" — a CANDIDATE,
// never proof of intent or harm. `is_candidate` is forced true via `build_finding`.

use crate::matching::{build_finding, ObservedAction};
use crate::model::{Finding, SuppressedFinding, SuppressionOrigin};
use crate::rules::{RuleData, ShellRule};
use crate::suppress::SuppressList;
use regex::{Regex, RegexBuilder};

#[cfg(feature = "shell-ast")]
use crate::shell::Command;

/// A compiled [`ShellRule`] (ADR-5 S1). `agt_index` is the positional index into
/// the FULL `rules.detection.rules[]` (preserved by `compile_rules`, like ADR-2/4).
pub(crate) struct CompiledShell {
    agt_index: usize,
    /// The invoked binary basename to match (e.g. `rm`).
    binary: String,
    /// The required NORMALIZED short-flag SET (e.g. `["r", "f"]`). Every entry
    /// must be present (as a short flag OR a known long alias) for the rule to fire.
    all_flags: Vec<String>,
    require: Vec<Regex>,
    deny: Vec<Regex>,
}

fn compile_ctx(agt_code: &str, kind: &str, fragments: &[String]) -> Vec<Regex> {
    fragments
        .iter()
        .filter_map(|f| match RegexBuilder::new(f).case_insensitive(true).build() {
            Ok(re) => Some(re),
            Err(e) => {
                eprintln!(
                    "apohara-compliance-scanner: warning: {agt_code} shell {kind} fragment {f:?} \
                     is not a valid regex ({e}); ignoring this fragment"
                );
                None
            }
        })
        .collect()
}

/// Compile one shell rule. `agt_index` MUST be the index into the full rules vec.
pub(crate) fn compile_shell(agt_index: usize, agt_code: &str, rule: &ShellRule) -> CompiledShell {
    CompiledShell {
        agt_index,
        binary: rule.binary.clone(),
        all_flags: rule.all_flags.clone(),
        require: compile_ctx(agt_code, "require_context", &rule.require_context),
        deny: compile_ctx(agt_code, "deny_context", &rule.deny_context),
    }
}

/// Map a known long flag to its short-name alias for the destructive-command
/// family (e.g. `recursive` → `r`, `force` → `f`). Returns the canonical short
/// name when the long flag is recognized; otherwise the long name itself (so an
/// unknown long flag is still recorded under its own name, never silently dropped).
///
/// The alias table is INTENTIONALLY small and family-scoped: the only long flags a
/// destructive `rm`/`shred`/`dd` rule asks for today are recursive/force/verbose.
/// Adding a flag family is a one-line addition here (no DSL change).
fn long_to_short(long: &str) -> &str {
    match long {
        "recursive" => "r",
        "force" => "f",
        "verbose" => "v",
        other => other,
    }
}

/// Tokenize a command's argv into (binary basename, normalized flag SET).
///
/// Returns `None` when the command cannot be tokenized (unbalanced quotes →
/// `shlex::split` returns `None`) or is empty — the caller SKIPS such an action.
///
/// Flag normalization:
///   * `argv[0]` basename is the binary (`/bin/rm` → `rm`).
///   * a `--long` token maps via [`long_to_short`] (e.g. `--force` → `f`).
///   * a bundled short `-rf` expands to individual chars `r`, `f`.
///   * `--` ends flag parsing (POSIX end-of-options); subsequent tokens are operands.
///   * a bare `-` (stdin) and operands (non-`-`-prefixed) are ignored for the flag SET.
fn tokenize(command: &str) -> Option<(String, Vec<String>)> {
    let argv = shlex::split(command)?;
    let mut it = argv.into_iter();
    let bin_raw = it.next()?;
    // Basename: the final path component, so `/bin/rm` and `./rm` both → `rm`.
    let binary = bin_raw
        .rsplit('/')
        .next()
        .unwrap_or(&bin_raw)
        .to_string();
    if binary.is_empty() {
        return None;
    }

    let mut flags: Vec<String> = Vec::new();
    let mut end_of_opts = false;
    for tok in it {
        if end_of_opts {
            continue;
        }
        if tok == "--" {
            end_of_opts = true;
            continue;
        }
        if let Some(long) = tok.strip_prefix("--") {
            // `--force` / `--recursive=...` → take the name before any `=`.
            let name = long.split('=').next().unwrap_or(long);
            if !name.is_empty() {
                flags.push(long_to_short(name).to_string());
            }
        } else if let Some(short) = tok.strip_prefix('-') {
            // A bare `-` (stdin) carries no flag chars.
            if short.is_empty() {
                continue;
            }
            // Bundled short flags `-rf` → `r`, `f` (each char is a flag).
            for c in short.chars() {
                flags.push(c.to_string());
            }
        }
        // Non-`-` tokens are operands (paths, etc.) — ignored for the flag SET.
    }
    Some((binary, flags))
}

/// Run every compiled shell rule over the action stream, APPENDING candidates
/// (ADR-5: the single trailing call from the matcher, after the taint pass).
///
/// For each action whose `source` is `session:Bash`-prefixed (a REAL executed
/// command), tokenize `action.value`; fire a candidate when the binary basename
/// equals `rule.binary` AND every required flag is present, subject to the
/// require/deny context guards over the RAW command. One candidate per (rule,
/// action). A no-op when no shell rule is loaded (keeps single-action + sequence
/// + taint output byte-identical).
///
/// v2.4 S2 (ADR-9, US-004): the 7th parameter `ast: Option<&Command>` is a
/// forward-compatibility slot for the S2 AST path. With the `shell-ast` Cargo
/// feature OFF, the parameter does not exist (the signature is byte-identical
/// to v2.3 — 6 params, no AST). With the feature ON, the caller may pass the
/// per-action AST; the S1 body below remains byte-identical to v2.3 and
/// IGNORES the parameter (the S2 path is driven by the separate
/// `match_shell_ast_only` loop in `matching.rs`). This keeps the
/// three-mechanism safety split: `#[serde(default)] parse_ast: bool` carries
/// the v2.3 compat invariant; `parse_ast: true` is the circuit breaker; the
/// `shell-ast` feature is the binary-surface control.
#[cfg_attr(not(feature = "shell-ast"), allow(dead_code))]
pub(crate) fn match_shell(
    actions: &[ObservedAction],
    shells: &[CompiledShell],
    rules: &RuleData,
    suppress: &SuppressList,
    findings: &mut Vec<Finding>,
    suppressed: &mut Vec<SuppressedFinding>,
    #[cfg(feature = "shell-ast")] ast: Option<&Command>,
) {
    // v2.4 S2: S1 is byte-identical to v2.3 — the AST parameter is intentionally
    // not consulted here. The S2 AST path runs as a separate loop in
    // `matching.rs` (see `match_shell_ast_only`), which is gated on
    // `cfg!(feature = "shell-ast")` AND the rule's `ast_only_constructs` being
    // non-empty. This split keeps the S1 default build zero-regression and the
    // S2 build additive.
    #[cfg(feature = "shell-ast")]
    {
        let _ = ast; // silence unused warnings; the param is reserved for future S2 wiring.
    }
    for shell in shells {
        for action in actions {
            // Structural matching applies only to REAL executed commands.
            if !action.source.starts_with("session:Bash") {
                continue;
            }
            // Unbalanced quotes ⇒ shlex returns None ⇒ skip (never panic).
            let Some((binary, flags)) = tokenize(&action.value) else {
                continue;
            };
            if binary != shell.binary {
                continue;
            }
            // Every required flag must be present (order-/spacing-/bundling-invariant).
            if !shell
                .all_flags
                .iter()
                .all(|needed| flags.iter().any(|f| f == needed))
            {
                continue;
            }
            // require_context: if non-empty, ≥1 fragment must be in the RAW command.
            if !shell.require.is_empty()
                && !shell.require.iter().any(|re| re.is_match(&action.value))
            {
                continue;
            }
            // deny_context: any fragment present suppresses (e.g. --dry-run, echo).
            if shell.deny.iter().any(|re| re.is_match(&action.value)) {
                continue;
            }

            let rule = &rules.detection.rules[shell.agt_index];
            // Signal = the structural match (binary + the required flag SET), so the
            // audit trail names WHAT fired without echoing the raw command.
            let signal = format!("{} {}", shell.binary, shell.all_flags.join(""));
            let finding = build_finding(rule, &signal, rules);
            if let Some(m) = suppress.matching(&rule.agt_code, &signal, &action.source) {
                eprintln!(
                    "apohara-compliance-scanner: suppressed: {} by {}",
                    rule.agt_code, m.raw
                );
                suppressed.push(SuppressedFinding {
                    finding,
                    reason: m.reason.clone(),
                    suppressed_by: m.raw.clone(),
                    origin: SuppressionOrigin::Allowlist,
                });
            } else {
                eprintln!(
                    "apohara-compliance-scanner: match: {} shell {:?} in {}",
                    rule.agt_code, signal, action.source
                );
                findings.push(finding);
            }
            // One candidate per rule per action stream (first-match-fires + break).
            break;
        }
    }
}

/// v2.4 S2 AST-only pass (ADR-9, US-004).
///
/// Iterates the rules ONCE. For each rule whose `ast_only_constructs` is
/// non-empty, the matcher tries the S2 AST path: parse each `session:Bash`
/// action's text, call `match_shell_ast(rule.ast_only_constructs, &ast)`,
/// and on hit, fire a candidate with the rule's `agt_code` (e.g.
/// `AGT-SHL-PIPELINE-A`).
///
/// On `ParseError` the matcher falls back to S1 silently. The fallback is:
///   * the AST parser is silent about ParseError in the public surface — no
///     panic, no finding emission from S2;
///   * a `trace`-level log line is emitted to stderr carrying
///     `(parse_ast, fallback_to_s1, error_kind)` so an operator can
///     confirm the fallback happened.
///   * the rule does NOT fire on the S2 path (an AST-only rule has no S1
///     fallback shape to consult, so the finding is suppressed entirely).
///
/// The whole function is `#[cfg(feature = "shell-ast")]`-gated: with the
/// feature off (the default), this is a no-op and the report is
/// byte-identical to v2.3.
#[cfg(feature = "shell-ast")]
pub(crate) fn match_shell_ast_only(
    actions: &[ObservedAction],
    rules: &RuleData,
    suppress: &SuppressList,
    findings: &mut Vec<Finding>,
    suppressed: &mut Vec<SuppressedFinding>,
) {
    use crate::shell;
    use crate::shell::match_::match_shell_ast;

    for rule in rules.detection.rules.iter() {
        let Some(shell_rule) = &rule.shell else {
            continue;
        };
        // AST-only rules have non-empty ast_only_constructs. The circuit
        // breaker (parse_ast: false) is ALSO checked: a rule with
        // `ast_only_constructs` set but `parse_ast: false` is silently
        // ignored (defensive — the field-pairing is the contract).
        if shell_rule.ast_only_constructs.is_empty() || !shell_rule.parse_ast {
            continue;
        }

        for action in actions {
            // AST-only matching applies only to REAL executed commands,
            // same as S1.
            if !action.source.starts_with("session:Bash") {
                continue;
            }

            // Try the AST. On any error, fall back to S1 silently.
            let ast = match shell::parse(&action.value) {
                Ok(ast) => ast,
                Err(e) => {
                    eprintln!(
                        "apohara-compliance-scanner: trace: parse_ast=true \
                         fallback_to_s1 error_kind={:?} agt_code={} source={}",
                        e, rule.agt_code, action.source
                    );
                    continue;
                }
            };

            if !match_shell_ast(&shell_rule.ast_only_constructs, &ast) {
                continue;
            }

            // The signal describes the AST construct that fired (audit trail
            // without echoing the raw command). With one tag in the rule
            // (the common case), use the tag verbatim. With multiple tags,
            // use the first one.
            let signal = shell_rule
                .ast_only_constructs
                .first()
                .cloned()
                .unwrap_or_else(|| "AST".to_string());

            let finding = build_finding(rule, &signal, rules);
            if let Some(m) = suppress.matching(&rule.agt_code, &signal, &action.source) {
                eprintln!(
                    "apohara-compliance-scanner: suppressed: {} by {}",
                    rule.agt_code, m.raw
                );
                suppressed.push(SuppressedFinding {
                    finding,
                    reason: m.reason.clone(),
                    suppressed_by: m.raw.clone(),
                    origin: SuppressionOrigin::Allowlist,
                });
            } else {
                eprintln!(
                    "apohara-compliance-scanner: match: {} ast_only_constructs={:?} in {}",
                    rule.agt_code, shell_rule.ast_only_constructs, action.source
                );
                findings.push(finding);
            }
            // One candidate per (rule, action) — first-match-fires + break.
            // We do NOT break out of the OUTER action loop (a rule with
            // ast_only_constructs can fire on multiple actions in a stream);
            // but we DO break out of the rule's action loop after the first
            // hit, matching S1's per-rule behavior.
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{load_embedded, ShellRule};

    /// A shell rule shaped like AGT-MIS-004: structural destructive `rm` requiring
    /// the recursive+force flag SET, denying dry-run / echo.
    fn rm_rf_rule() -> ShellRule {
        ShellRule {
            binary: "rm".into(),
            all_flags: vec!["r".into(), "f".into()],
            require_context: vec![],
            deny_context: vec!["--dry-run".into(), "dry run".into(), "echo ".into()],
            parse_ast: false,
            ast_only_constructs: vec![],
        }
    }

    fn run_with(rule: ShellRule, source: &str, command: &str) -> Vec<Finding> {
        let data = load_embedded().expect("embedded rules");
        let compiled = compile_shell(0, "AGT-MIS-004", &rule);
        let mut findings = Vec::new();
        let mut suppressed = Vec::new();
        let actions = vec![ObservedAction::new(source, command)];
        #[cfg(feature = "shell-ast")]
        match_shell(
            &actions,
            &[compiled],
            &data,
            &SuppressList::default(),
            &mut findings,
            &mut suppressed,
            None,
        );
        #[cfg(not(feature = "shell-ast"))]
        match_shell(
            &actions,
            &[compiled],
            &data,
            &SuppressList::default(),
            &mut findings,
            &mut suppressed,
        );
        findings
    }

    fn fires(command: &str) -> bool {
        !run_with(rm_rf_rule(), "session:Bash.input", command).is_empty()
    }

    // ---- Flag-order / spacing / bundling INVARIANCE: all must fire ----

    #[test]
    fn rm_rf_bundled_fires() {
        assert!(fires("rm -rf /var/tmp/x"));
    }

    #[test]
    fn rm_fr_reordered_bundle_fires() {
        assert!(fires("rm -fr /var/tmp/x"));
    }

    #[test]
    fn rm_r_f_separate_flags_fire() {
        assert!(fires("rm -r -f /var/tmp/x"));
    }

    #[test]
    fn rm_f_r_separate_reordered_flags_fire() {
        assert!(fires("rm -f -r /var/tmp/x"));
    }

    #[test]
    fn rm_long_recursive_force_fires() {
        assert!(fires("rm --recursive --force /srv/data"));
    }

    #[test]
    fn rm_rfv_bundle_with_extra_flag_fires() {
        // -rfv: the required SET {r,f} is a SUBSET of {r,f,v} → fires.
        assert!(fires("rm -rfv /opt/old"));
    }

    #[test]
    fn abs_path_binary_basename_fires() {
        assert!(fires("/bin/rm -rf /var/tmp/x"));
    }

    #[test]
    fn extra_spacing_and_mixed_short_long_fires() {
        assert!(fires("rm  -r   --force   /srv/data"));
    }

    // ---- NEGATIVES: must NOT fire ----

    #[test]
    fn rm_only_recursive_does_not_fire() {
        // Only ONE of the two required flags present → no fire (structural SET).
        assert!(!fires("rm -r ./build"));
    }

    #[test]
    fn rm_dry_run_is_denied() {
        // deny_context `--dry-run` suppresses even though {r,f} are present.
        assert!(!fires("rm --dry-run -rf /var/tmp/x"));
    }

    #[test]
    fn echo_of_command_is_denied() {
        // deny_context `echo ` suppresses a printed (not executed) command.
        assert!(!fires("echo rm -rf /var/tmp/x"));
    }

    #[test]
    fn wrong_binary_ls_does_not_fire() {
        assert!(!fires("ls -rf ./build"));
    }

    #[test]
    fn wrong_binary_rsync_does_not_fire() {
        assert!(!fires("rsync -r src/ dst/"));
    }

    #[test]
    fn non_bash_source_does_not_fire() {
        // Structural matching applies only to REAL executed commands (session:Bash).
        assert!(run_with(rm_rf_rule(), "repo-file:cleanup.sh", "rm -rf /var/tmp/x").is_empty());
        assert!(run_with(rm_rf_rule(), "tool-result:t1", "rm -rf /var/tmp/x").is_empty());
    }

    #[test]
    fn unbalanced_quotes_do_not_panic_and_do_not_fire() {
        // shlex::split returns None on an unbalanced quote → action skipped.
        assert!(!fires("rm -rf '/var/tmp/unclosed"));
        assert!(!fires("rm -rf \"half"));
    }

    #[test]
    fn empty_command_does_not_panic_or_fire() {
        assert!(!fires(""));
        assert!(!fires("   "));
    }

    #[test]
    fn end_of_options_separator_treats_later_tokens_as_operands() {
        // After `--`, `-rf` is an OPERAND (a weird filename), NOT flags → no fire.
        assert!(!fires("rm -- -rf"));
    }

    #[test]
    fn determinism_same_input_same_output_5x() {
        for _ in 0..5 {
            assert!(fires("rm -f -r /workspace/build"));
            assert!(!fires("rm -r ./build"));
        }
    }

    // ---- tokenize() unit coverage ----

    #[test]
    fn tokenize_extracts_basename_and_expands_bundles() {
        let (bin, flags) = tokenize("/usr/bin/rm -rf /tmp/x").expect("tokenizes");
        assert_eq!(bin, "rm");
        assert!(flags.contains(&"r".to_string()) && flags.contains(&"f".to_string()));
    }

    #[test]
    fn tokenize_maps_long_aliases_to_short() {
        let (_bin, flags) = tokenize("rm --recursive --force --verbose /x").expect("tokenizes");
        assert!(flags.contains(&"r".to_string()));
        assert!(flags.contains(&"f".to_string()));
        assert!(flags.contains(&"v".to_string()));
    }

    #[test]
    fn tokenize_returns_none_on_unbalanced_quote() {
        assert!(tokenize("rm -rf '/x").is_none());
    }
}
