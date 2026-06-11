// apohara-compliance — v2.4 S2 shell AST matcher helper.
//
// `match_shell_ast(rule_constructs, ast)` is the AST-side counterpart
// to the S1 `match_shell` in `super::super::shell_s1`. It consumes the
// AST and returns `true` if any of the rule's `ast_only_constructs`
// list is satisfied by the AST shape.
//
// Rule side of the API: `ShellRule` gains a new field
// `ast_only_constructs: Vec<String>` (e.g. `["Pipeline", "Subshell"]`)
// which is checked here. The `#[serde(default)]` on the field
// (introduced in US-004) keeps existing rules byte-identical.

use super::ast::Command;

/// AST shape tags accepted in `rule_constructs`. A rule's
/// `ast_only_constructs: Vec<String>` lists the tags the rule wants to
/// match on; the matcher returns `true` if *any* of them is present in
/// the AST.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Construct {
    Simple,
    Pipeline,
    Subshell,
    CommandSubstitution,
    Heredoc,
    Redirection,
}

/// Map a string tag (from YAML) to a `Construct`. Unknown tags are
/// silently ignored (treated as no match). This keeps the matcher
/// forward-compatible with future constructs.
fn tag_to_construct(tag: &str) -> Option<Construct> {
    match tag {
        "Simple" => Some(Construct::Simple),
        "Pipeline" => Some(Construct::Pipeline),
        "Subshell" => Some(Construct::Subshell),
        "CommandSubstitution" | "CommandSubst" => Some(Construct::CommandSubstitution),
        "Heredoc" => Some(Construct::Heredoc),
        "Redirection" => Some(Construct::Redirection),
        _ => None,
    }
}

/// Does the AST contain at least one `Pipeline` node (anywhere in the
/// tree, including inside a subshell or command substitution)?
fn ast_has_pipeline(cmd: &Command) -> bool {
    match cmd {
        Command::Pipeline(items) => {
            if items.len() > 1 {
                return true;
            }
            items.iter().any(ast_has_pipeline)
        }
        Command::Subshell(inner) => ast_has_pipeline(inner),
        Command::Substitution { body, .. } => ast_has_pipeline(body),
        Command::Simple { .. } => false,
    }
}

/// Does the AST contain at least one `Subshell` node?
fn ast_has_subshell(cmd: &Command) -> bool {
    match cmd {
        Command::Subshell(_) => true,
        Command::Pipeline(items) => items.iter().any(ast_has_subshell),
        Command::Substitution { body, .. } => ast_has_subshell(body),
        Command::Simple { .. } => false,
    }
}

/// Does the AST contain at least one `CommandSubstitution` node?
fn ast_has_command_substitution(cmd: &Command) -> bool {
    match cmd {
        Command::Substitution { .. } => true,
        Command::Pipeline(items) => items.iter().any(ast_has_command_substitution),
        Command::Subshell(inner) => ast_has_command_substitution(inner),
        Command::Simple { .. } => false,
    }
}

/// Does the AST contain at least one heredoc (anywhere in the tree)?
fn ast_has_heredoc(cmd: &Command) -> bool {
    match cmd {
        Command::Simple { heredoc, .. } => heredoc.is_some(),
        Command::Pipeline(items) => items.iter().any(ast_has_heredoc),
        Command::Subshell(inner) => ast_has_heredoc(inner),
        Command::Substitution { body, .. } => ast_has_heredoc(body),
    }
}

/// Does the AST contain at least one redirection (in any Simple)?
fn ast_has_redirection(cmd: &Command) -> bool {
    match cmd {
        Command::Simple { redirections, .. } => !redirections.is_empty(),
        Command::Pipeline(items) => items.iter().any(ast_has_redirection),
        Command::Subshell(inner) => ast_has_redirection(inner),
        Command::Substitution { body, .. } => ast_has_redirection(body),
    }
}

/// Does the AST have a `Simple` command (anywhere in the tree)?
fn ast_has_simple(cmd: &Command) -> bool {
    match cmd {
        Command::Simple { .. } => true,
        Command::Pipeline(items) => items.iter().any(ast_has_simple),
        Command::Subshell(inner) => ast_has_simple(inner),
        Command::Substitution { body, .. } => ast_has_simple(body),
    }
}

/// Walk the AST and return `true` if any of the rule's
/// `ast_only_constructs` tags is present.
pub fn match_shell_ast(rule_constructs: &[String], ast: &Command) -> bool {
    for tag in rule_constructs {
        let Some(cons) = tag_to_construct(tag) else {
            continue;
        };
        let hit = match cons {
            Construct::Simple => ast_has_simple(ast),
            Construct::Pipeline => ast_has_pipeline(ast),
            Construct::Subshell => ast_has_subshell(ast),
            Construct::CommandSubstitution => ast_has_command_substitution(ast),
            Construct::Heredoc => ast_has_heredoc(ast),
            Construct::Redirection => ast_has_redirection(ast),
        };
        if hit {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ast::Word;
    use super::super::parse::parse_program;
    use super::super::lexer::tokenize;

    fn parse(input: &str) -> Command {
        let toks = tokenize(input).expect("tokenize");
        parse_program(&toks).expect("parse")
    }

    fn tags<const N: usize>(items: [&str; N]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    // -------- Simple --------

    #[test]
    fn matches_simple_on_simple_command() {
        let ast = parse("rm -rf /");
        assert!(match_shell_ast(&tags(["Simple"]), &ast));
        assert!(!match_shell_ast(&tags(["Pipeline"]), &ast));
        assert!(!match_shell_ast(&tags(["Subshell"]), &ast));
    }

    #[test]
    fn matches_simple_on_echo() {
        let ast = parse("echo hello");
        assert!(match_shell_ast(&tags(["Simple"]), &ast));
    }

    #[test]
    fn empty_constructs_returns_false() {
        let ast = parse("rm -rf /");
        assert!(!match_shell_ast(&[], &ast));
    }

    // -------- Pipeline --------

    #[test]
    fn matches_pipeline_on_pipe() {
        let ast = parse("rm -rf / | cat");
        assert!(match_shell_ast(&tags(["Pipeline"]), &ast));
    }

    #[test]
    fn matches_pipeline_inside_subshell() {
        // `(a | b)` → Subshell wrapping a Pipeline. The Pipeline tag
        // should still match anywhere in the tree.
        let ast = parse("(echo a | echo b)");
        assert!(match_shell_ast(&tags(["Pipeline"]), &ast));
    }

    #[test]
    fn matches_pipeline_three_stages() {
        let ast = parse("a | b | c");
        assert!(match_shell_ast(&tags(["Pipeline"]), &ast));
    }

    // -------- Subshell --------

    #[test]
    fn matches_subshell() {
        let ast = parse("(rm -rf /)");
        assert!(match_shell_ast(&tags(["Subshell"]), &ast));
    }

    #[test]
    fn matches_subshell_nested() {
        let ast = parse("((echo a; echo b))");
        assert!(match_shell_ast(&tags(["Subshell"]), &ast));
    }

    #[test]
    fn no_subshell_on_plain_simple() {
        let ast = parse("rm -rf /");
        assert!(!match_shell_ast(&tags(["Subshell"]), &ast));
    }

    // -------- CommandSubstitution --------

    #[test]
    fn matches_command_subst_dollar() {
        let ast = parse("$(rm -rf /)");
        assert!(match_shell_ast(&tags(["CommandSubstitution"]), &ast));
    }

    #[test]
    fn matches_command_subst_backtick() {
        let ast = parse("`rm -rf /`");
        assert!(match_shell_ast(&tags(["CommandSubstitution"]), &ast));
    }

    #[test]
    fn no_command_subst_on_plain_simple() {
        let ast = parse("rm -rf /");
        assert!(!match_shell_ast(&tags(["CommandSubstitution"]), &ast));
    }

    // -------- Heredoc --------

    #[test]
    fn matches_heredoc_on_cat() {
        let input = "cat <<EOF\nhello\nEOF";
        let ast = parse(input);
        assert!(match_shell_ast(&tags(["Heredoc"]), &ast));
    }

    #[test]
    fn matches_heredoc_with_rm() {
        let input = "rm -rf / <<EOF\nbody\nEOF";
        let ast = parse(input);
        assert!(match_shell_ast(&tags(["Heredoc"]), &ast));
    }

    #[test]
    fn no_heredoc_on_plain_command() {
        let ast = parse("cat /etc/passwd");
        assert!(!match_shell_ast(&tags(["Heredoc"]), &ast));
    }

    // -------- Quoting matcher safety --------

    #[test]
    fn no_constructs_on_quoted_echo() {
        let ast = parse("echo 'hello world'");
        // No pipeline, no subshell, no substitution, no heredoc.
        assert!(!match_shell_ast(&tags(["Pipeline", "Subshell", "CommandSubstitution", "Heredoc"]), &ast));
    }

    #[test]
    fn matches_simple_on_quoted() {
        let ast = parse("echo 'hello world'");
        assert!(match_shell_ast(&tags(["Simple"]), &ast));
    }

    // -------- Redirection --------

    #[test]
    fn matches_redirection() {
        let ast = parse("cmd > out");
        assert!(match_shell_ast(&tags(["Redirection"]), &ast));
    }

    #[test]
    fn no_redirection_on_plain() {
        let ast = parse("cmd arg");
        assert!(!match_shell_ast(&tags(["Redirection"]), &ast));
    }

    // -------- Multiple tags (any-of) --------

    #[test]
    fn any_of_tags() {
        // A rule with constructs = [Pipeline, Subshell] should match
        // if EITHER is present. A plain Simple matches neither.
        let plain = parse("rm -rf /");
        assert!(!match_shell_ast(&tags(["Pipeline", "Subshell"]), &plain));

        let piped = parse("a | b");
        assert!(match_shell_ast(&tags(["Pipeline", "Subshell"]), &piped));

        let subshelled = parse("(a)");
        assert!(match_shell_ast(&tags(["Pipeline", "Subshell"]), &subshelled));
    }

    // -------- Unknown tags are ignored --------

    #[test]
    fn unknown_tag_silently_ignored() {
        // An unknown tag doesn't match. A known tag in the same list
        // can still match (any-of semantics) on an AST that does
        // contain it.
        let piped = parse("a | b");
        assert!(match_shell_ast(&tags(["Pipeline", "FutureTag"]), &piped));
        // Only the unknown tag: no match.
        assert!(!match_shell_ast(&tags(["FutureTag"]), &piped));
    }

    // -------- Tag aliases --------

    #[test]
    fn command_subst_alias() {
        let ast = parse("$(rm -rf /)");
        // `CommandSubst` is accepted as an alias for
        // `CommandSubstitution`.
        assert!(match_shell_ast(&tags(["CommandSubst"]), &ast));
    }

    // -------- AST-only rule against simple command (no false positive) --------

    #[test]
    fn ast_only_pipeline_rule_does_not_fire_on_simple() {
        // The contract: a rule that ONLY consumes AST-only constructs
        // must NOT match a plain Simple command. The S1 path handles
        // plain Simple commands.
        let ast = parse("rm -rf /");
        assert!(!match_shell_ast(&tags(["Pipeline"]), &ast));
        assert!(!match_shell_ast(&tags(["Subshell"]), &ast));
        assert!(!match_shell_ast(&tags(["CommandSubstitution"]), &ast));
        assert!(!match_shell_ast(&tags(["Heredoc"]), &ast));
    }

    #[test]
    fn ast_rule_fires_on_pipeline_only_fixture() {
        // The S2 parity contract: `rm -rf / | cat` is a pipeline that
        // an AST-only rule (e.g. `AGT-SHL-PIPELINE-A`) must match.
        let ast = parse("rm -rf / | cat");
        assert!(match_shell_ast(&tags(["Pipeline"]), &ast));
    }

    #[test]
    fn direct_construction_simple() {
        // Direct AST construction (no parser roundtrip): a
        // Command::Simple must match the `Simple` tag.
        let ast = Command::Simple {
            argv: vec![Word::new("rm", "rm")],
            redirections: vec![],
            heredoc: None,
        };
        assert!(match_shell_ast(&tags(["Simple"]), &ast));
        assert!(!match_shell_ast(&tags(["Pipeline"]), &ast));
    }
}
