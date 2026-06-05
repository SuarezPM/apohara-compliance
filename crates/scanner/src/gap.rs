// Gap-analysis (US-F1-4) — the COMPLEMENT over the 49 carried controls.
//
// `gap` runs a NORMAL scan, collects the set of control ids that appeared in any
// active finding's `suggested_controls` AND resolve to the 49 carried controls
// (controls-49.yaml), then reports the COMPLEMENT: every one of the 49 that NO
// finding referenced — surfaced as "no candidate evidence observed for control X".
//
// CONTROL UNIVERSE = THE 49 ONLY (plan fix #11d). `build_finding` maps some
// controls OUTSIDE the 49 (GDPR/CCPA/HIPAA/PCI/FinCEN cited verbatim from the
// taxonomy for traceability); `find_control` resolves only the 49. The gap
// universe is the audited, fully-provenanced 49 (each carries `consilium_ref` +
// `status`). Externally-cited standards are NOT in the universe because the
// project carries no full control catalog for them — the gap output states this
// scope explicitly.
//
// HONESTY (plan §2 / R5): a gap line says "no candidate evidence observed for
// <id>", NEVER "non-compliant"/"violates"/"is vulnerable to"/"failing". An
// explicit disclaimer states that absence of evidence is not evidence of a gap.
// The framing is consistent with the candidates-only thesis: a gap is the ABSENCE
// of a candidate signal, surfaced for manual review — never an assertion.

use serde::Serialize;

use crate::model::{ControlStatus, Report, RulesSource};
use crate::rules::RuleData;

/// The honesty disclaimer that leads every gap report — absence of evidence is
/// not evidence of a gap (plan §2 principle 1 / R5).
pub const GAP_DISCLAIMER: &str = "Absence of evidence is not evidence of a gap; \
this lists controls for which the scan surfaced no candidate signal — review manually.";

/// The explicit scope statement (plan fix #11d): the gap universe is the 49
/// carried controls ONLY; externally-cited standards are out of scope.
pub const GAP_SCOPE: &str = "Gap is computed over the 49 carried controls; \
externally-cited standards (GDPR/HIPAA/…) are out of scope for gap analysis.";

/// One control in the 49 for which the scan surfaced NO candidate evidence.
///
/// Carries the control's id + title + status (official|draft) + consilium_ref so
/// a reviewer has the full provenance without re-reading controls-49.yaml. The
/// `message` is the candidate/absence-framed line ("no candidate evidence
/// observed for <id> (<title>)") reused by the md + sarif emitters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GapControl {
    /// The control id (one of the 49).
    pub id: String,
    /// The control's human title.
    pub title: String,
    /// Official-vs-draft provenance of the control.
    pub status: ControlStatus,
    /// The `compliance-suite.md:LINE` traceability token.
    pub consilium_ref: String,
    /// The candidate/absence-framed line for this control.
    pub message: String,
}

/// A gap-analysis report: the complement of the 49 over the scan's evidence.
///
/// `scope` + `disclaimer` are surfaced in EVERY format so the honesty framing and
/// the 49-only universe statement travel with the structured output too (not just
/// the human Markdown). `gaps` lists the zero-evidence controls; `covered` is the
/// count of the 49 that DID get candidate evidence (audit completeness).
#[derive(Debug, Clone, Serialize)]
pub struct GapReport {
    /// Expanded rules source used for this run (audit view).
    pub rules_source: RulesSource,
    /// Collapsed AC-9 `file|embedded-fallback` view.
    pub rules_source_collapsed: &'static str,
    /// The 49-only universe statement (plan fix #11d).
    pub scope: &'static str,
    /// The absence-of-evidence disclaimer (honesty).
    pub disclaimer: &'static str,
    /// Total size of the control universe (always 49).
    pub universe: usize,
    /// How many of the 49 got candidate evidence in this scan.
    pub covered: usize,
    /// The controls (from the 49 ONLY) with zero candidate evidence.
    pub gaps: Vec<GapControl>,
}

/// Build the candidate/absence-framed line for one control. Centralized so the
/// json `message`, the md bullet, and the sarif result text all read identically
/// and all pass the extended NEGATIVE guard (never "non-compliant"/"violates"/…).
fn gap_message(id: &str, title: &str) -> String {
    format!("no candidate evidence observed for {id} ({title})")
}

/// Compute the gap report: the COMPLEMENT of the 49 over the control ids that any
/// ACTIVE finding referenced and that resolve to the 49.
///
/// Only the 49 carried controls (`rules.controls.controls`) form the universe
/// (plan fix #11d). A finding's `suggested_controls` entry that is NOT one of the
/// 49 (e.g. `GDPR:Art-32`) is ignored for evidence — it can neither cover a gap
/// nor enter the universe. Suppressed/allowlisted candidates are NOT counted as
/// evidence: a control is only "covered" by an ACTIVE finding.
pub fn compute_gap(report: &Report, rules: &RuleData) -> GapReport {
    // The set of the 49 control ids that some ACTIVE finding referenced.
    let universe: Vec<&str> = rules
        .controls
        .controls
        .iter()
        .map(|c| c.id.as_str())
        .collect();

    let mut covered_ids: Vec<&str> = Vec::new();
    for finding in &report.findings {
        for ctrl in &finding.suggested_controls {
            // Only the 49 count as evidence (find_control semantics); an external
            // id like GDPR:Art-32 is out of universe and cannot cover anything.
            if universe.contains(&ctrl.as_str()) && !covered_ids.contains(&ctrl.as_str()) {
                covered_ids.push(ctrl.as_str());
            }
        }
    }

    // The complement: every one of the 49 NOT covered, in controls-49.yaml order.
    let gaps: Vec<GapControl> = rules
        .controls
        .controls
        .iter()
        .filter(|c| !covered_ids.contains(&c.id.as_str()))
        .map(|c| GapControl {
            id: c.id.clone(),
            title: c.title.clone(),
            status: ControlStatus::from_yaml_status(&c.status),
            consilium_ref: c.consilium_ref.clone(),
            message: gap_message(&c.id, &c.title),
        })
        .collect();

    GapReport {
        rules_source: report.rules_source,
        rules_source_collapsed: report.rules_source_collapsed,
        scope: GAP_SCOPE,
        disclaimer: GAP_DISCLAIMER,
        universe: universe.len(),
        covered: covered_ids.len(),
        gaps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matching::{match_actions_with_suppress, ObservedAction};
    use crate::rules::load_embedded;
    use crate::suppress::SuppressList;

    /// Build a report from one observed action (active findings only).
    fn report_for(source: &str, value: &str, data: &RuleData) -> Report {
        let actions = vec![ObservedAction::new(source, value)];
        let outcome = match_actions_with_suppress(&actions, data, &SuppressList::default());
        Report::with_suppressed(data.source, outcome.findings, outcome.suppressed)
    }

    #[test]
    fn gap_universe_is_the_49_and_complement_sums_to_49() {
        // The universe is exactly the 49; covered + gaps == 49 (partition).
        let data = load_embedded().expect("rules");
        let report = report_for("session:Bash.input", "sudo rm -rf /var/cache", &data);
        let gap = compute_gap(&report, &data);
        assert_eq!(gap.universe, 49);
        assert_eq!(gap.covered + gap.gaps.len(), 49, "covered+gaps partition the 49");
    }

    #[test]
    fn covered_control_is_not_a_gap_uncovered_control_is() {
        // AGT-MIS-001 (sudo rm -rf) maps to SP800-53:SI-7 (one of the 49); that
        // control must NOT appear as a gap, while an unrelated control (e.g.
        // EU-AI-ACT:Art-73, no fixture evidence) MUST.
        let data = load_embedded().expect("rules");
        let report = report_for("session:Bash.input", "sudo rm -rf /var/cache", &data);
        let gap = compute_gap(&report, &data);

        let covered_ctrl = "SP800-53:SI-7";
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.suggested_controls.iter().any(|c| c == covered_ctrl)),
            "fixture must reference {covered_ctrl}"
        );
        assert!(
            !gap.gaps.iter().any(|g| g.id == covered_ctrl),
            "{covered_ctrl} has evidence and must NOT be a gap"
        );
        assert!(
            gap.gaps.iter().any(|g| g.id == "EU-AI-ACT:Art-73"),
            "a zero-evidence control must be listed as a gap"
        );
    }

    #[test]
    fn external_control_is_never_in_the_universe() {
        // GDPR:Art-32 is cited by a rule but is OUTSIDE the 49: it can neither be a
        // gap (not in universe) nor count as covering one.
        let data = load_embedded().expect("rules");
        // A no-evidence scan: every one of the 49 is a gap, none is GDPR.
        let report = Report::with_suppressed(data.source, vec![], vec![]);
        let gap = compute_gap(&report, &data);
        assert_eq!(gap.covered, 0);
        assert_eq!(gap.gaps.len(), 49);
        assert!(
            !gap.gaps.iter().any(|g| g.id.starts_with("GDPR")),
            "external standards are out of the 49 universe"
        );
    }

    #[test]
    fn gap_messages_are_absence_framed_never_assertive() {
        // Every gap line reads as absence-of-evidence, never an assertion. This is
        // the in-crate mirror of the extended verify.sh NEGATIVE guard.
        let data = load_embedded().expect("rules");
        let report = Report::with_suppressed(data.source, vec![], vec![]);
        let gap = compute_gap(&report, &data);
        let banned = [
            "is compliant",
            "certified",
            "guaranteed",
            "non-compliant",
            "violates",
            "is vulnerable to",
            "detected",
            "you have ASI",
            "failing",
        ];
        for g in &gap.gaps {
            let lower = g.message.to_lowercase();
            assert!(
                g.message.starts_with("no candidate evidence observed for "),
                "gap line must be absence-framed: {}",
                g.message
            );
            for b in banned {
                assert!(
                    !lower.contains(&b.to_lowercase()),
                    "gap line {:?} contains banned phrase {b:?}",
                    g.message
                );
            }
        }
        // The header strings carry the disclaimer + the 49-scope statement.
        assert!(gap.disclaimer.contains("Absence of evidence is not evidence of a gap"));
        assert!(gap.scope.contains("49 carried controls"));
        assert!(gap.scope.contains("out of scope"));
    }

    #[test]
    fn gap_control_carries_status_and_consilium_ref() {
        // Each gap control surfaces its provenance: status + consilium_ref.
        let data = load_embedded().expect("rules");
        let report = Report::with_suppressed(data.source, vec![], vec![]);
        let gap = compute_gap(&report, &data);
        // A draft control (AGENTIC-*) must surface status: draft.
        let agentic = gap
            .gaps
            .iter()
            .find(|g| g.id.contains("AGENTIC-"))
            .expect("an AGENTIC- draft control is a gap on the empty scan");
        assert_eq!(agentic.status, ControlStatus::Draft);
        assert!(agentic.consilium_ref.starts_with("compliance-suite.md:"));
    }
}
