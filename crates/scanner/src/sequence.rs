// Multi-action SEQUENCE matching (ADR-2) — the ASI06 second pass.
//
// This is the ADDITIVE pass that runs AFTER the single-action loop in
// `matching::match_actions_with_suppress`. It expresses the one thing the
// single-action engine cannot: an ORDERED correlation — a `source_step` action
// FOLLOWED BY a `sink_step` action later in the same observed-action stream.
//
// It reuses the single-action primitives by construction: each step compiles its
// `signals` with `matching::compile_signal` (the same conditional-`\b` regexes)
// and applies the same `source_kinds` PREFIX filter. The only new logic is the
// ordered pairing + one-finding-per-rule dedup. Findings are built with
// `matching::build_finding`, so a sequence candidate is byte-shape-identical to a
// single-action one (and `is_candidate` is forced true — honesty invariant).
//
// HONESTY / ASI06: a fired AGT-MEM-001 means "untrusted content was observed and
// a memory/persist write followed — content that COULD poison future context."
// It is a CANDIDATE, never a detection of activated cross-session poisoning, and
// its sink coverage is bounded to what the parsers surface (Bash persist commands
// + generic OTLP records; see ADR-2 amendment B).

use crate::matching::{build_finding, compile_signal, ObservedAction};
use crate::model::{Finding, SuppressedFinding, SuppressionOrigin};
use crate::rules::{RuleData, SequenceRule};
use crate::suppress::SuppressList;
use regex::Regex;

/// One compiled sequence step: the OR-set of signal regexes + the `source_kinds`
/// prefix filter (kept verbatim, a cheap `starts_with`).
pub(crate) struct CompiledStep {
    regexes: Vec<(String, Regex)>,
    source_kinds: Vec<String>,
}

/// A compiled [`SequenceRule`] (ADR-2). `agt_index` is the positional index into
/// the FULL `rules.detection.rules[]` (preserved by `compile_rules`, ADR-2 amend A).
pub(crate) struct CompiledSequence {
    agt_index: usize,
    source_step: CompiledStep,
    sink_step: CompiledStep,
}

fn compile_step(step: &crate::rules::SequenceStep) -> CompiledStep {
    CompiledStep {
        regexes: step
            .signals
            .iter()
            .map(|s| (s.clone(), compile_signal(s)))
            .collect(),
        source_kinds: step.source_kinds.clone(),
    }
}

/// Compile one sequence rule for the engine. `agt_index` MUST be the index into the
/// full rules vec (ADR-2 amendment A — never renumbered).
pub(crate) fn compile_sequence(agt_index: usize, rule: &SequenceRule) -> CompiledSequence {
    CompiledSequence {
        agt_index,
        source_step: compile_step(&rule.source_step),
        sink_step: compile_step(&rule.sink_step),
    }
}

/// Does this step match the action? A step matches when the action's `source`
/// PREFIX-matches one of `source_kinds` (empty = any source) AND at least one of
/// the step's signal regexes matches `action.value`. Returns the matched signal
/// string (for the triggering-signal label) on success.
fn step_match<'a>(step: &'a CompiledStep, action: &ObservedAction) -> Option<&'a str> {
    let source_ok = step.source_kinds.is_empty()
        || step
            .source_kinds
            .iter()
            .any(|k| action.source.starts_with(k.as_str()));
    if !source_ok {
        return None;
    }
    step.regexes
        .iter()
        .find(|(_, re)| re.is_match(&action.value))
        .map(|(sig, _)| sig.as_str())
}

/// Run every compiled sequence over the action stream, APPENDING any candidates to
/// `findings` / `suppressed` (ADR-2: the single trailing call from the matcher).
///
/// For each sequence rule: scan actions in order; remember the FIRST source_step
/// match; when a sink_step match occurs at a LATER index, fire exactly ONE
/// candidate for the rule (ordered "followed-by"). Allowlist suppression reuses the
/// same visible-channel routing as the single-action path.
pub(crate) fn match_sequences(
    actions: &[ObservedAction],
    sequences: &[CompiledSequence],
    rules: &RuleData,
    suppress: &SuppressList,
    findings: &mut Vec<Finding>,
    suppressed: &mut Vec<SuppressedFinding>,
) {
    for seq in sequences {
        // The earliest source_step signal seen so far (None until one matches).
        let mut pending_source: Option<&str> = None;
        for action in actions {
            if pending_source.is_none() {
                if let Some(sig) = step_match(&seq.source_step, action) {
                    pending_source = Some(sig);
                    // A source action could itself also be a sink for a different
                    // rule, but for THIS rule the sink must come at a later index,
                    // so do not also test the sink on the same action.
                    continue;
                }
            }
            if let Some(source_sig) = pending_source {
                if let Some(sink_sig) = step_match(&seq.sink_step, action) {
                    let rule = &rules.detection.rules[seq.agt_index];
                    // Triggering signal records BOTH ends of the correlation so a
                    // reviewer sees what fired (source marker → persist sink).
                    let signal = format!("{source_sig} → {sink_sig}");
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
                            "apohara-compliance-scanner: match: {} sequence {:?}",
                            rule.agt_code, signal
                        );
                        findings.push(finding);
                    }
                    // One candidate per rule per scan (dedup), like the
                    // single-action path's `(agt_code, signal)` dedup.
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{load_embedded, SequenceRule, SequenceStep};

    fn mem_sequence() -> SequenceRule {
        SequenceRule {
            source_step: SequenceStep {
                signals: vec!["untrusted source".into(), "unsanitized content".into()],
                source_kinds: vec![],
            },
            sink_step: SequenceStep {
                signals: vec!["INSERT INTO embeddings".into(), "upsert".into()],
                source_kinds: vec!["session:Bash".into(), "otlp:".into()],
            },
        }
    }

    fn run(actions: &[ObservedAction]) -> Vec<Finding> {
        // Build the embedded rules, then drive ONLY the sequence pass with a
        // synthetic AGT-MEM-001-like compiled sequence pointing at a real rule
        // index (use rule 0 — the test asserts firing/ordering, not the rule body).
        let data = load_embedded().expect("embedded rules");
        let compiled = compile_sequence(0, &mem_sequence());
        let mut findings = Vec::new();
        let mut suppressed = Vec::new();
        match_sequences(actions, &[compiled], &data, &SuppressList::default(), &mut findings, &mut suppressed);
        findings
    }

    #[test]
    fn source_then_sink_fires_one_candidate() {
        let actions = vec![
            ObservedAction::new("session:Read.input", "loaded unsanitized content from a doc"),
            ObservedAction::new("session:Bash.input", "psql -c 'INSERT INTO embeddings VALUES (...)'"),
        ];
        let f = run(&actions);
        assert_eq!(f.len(), 1, "one ordered source→sink pair = one candidate");
        assert!(f[0].is_candidate, "honesty: sequence finding is a candidate");
    }

    #[test]
    fn sink_before_source_does_not_fire() {
        // Reverse order: the persist happens BEFORE any untrusted-content marker.
        let actions = vec![
            ObservedAction::new("session:Bash.input", "psql -c 'INSERT INTO embeddings VALUES (...)'"),
            ObservedAction::new("session:Read.input", "loaded unsanitized content from a doc"),
        ];
        assert!(run(&actions).is_empty(), "sink before source must NOT fire (ordering)");
    }

    #[test]
    fn source_without_sink_does_not_fire() {
        let actions = vec![ObservedAction::new(
            "session:Read.input",
            "loaded unsanitized content from a doc",
        )];
        assert!(run(&actions).is_empty(), "a source marker alone is not a sequence");
    }

    #[test]
    fn sink_without_source_does_not_fire() {
        let actions = vec![ObservedAction::new(
            "session:Bash.input",
            "psql -c 'INSERT INTO embeddings VALUES (...)'",
        )];
        assert!(run(&actions).is_empty(), "a persist alone is not a sequence");
    }

    #[test]
    fn sink_source_kind_scopes_the_persist() {
        // The persist verb in a NON-Bash/NON-otlp source must not satisfy the sink.
        let actions = vec![
            ObservedAction::new("session:Read.input", "unsanitized content"),
            ObservedAction::new("webhook:other", "upsert into the cache"),
        ];
        assert!(run(&actions).is_empty(), "sink_step source_kinds must scope the persist");
    }
}
