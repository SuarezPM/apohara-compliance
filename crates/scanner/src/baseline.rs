// Baseline/diff mode (US-F2-4).
//
// A baseline is a PRIOR run's own JSON report (`--format json`). On a run with
// `--baseline <file>`, every emitted finding is annotated with a SARIF 2.1.0
// `result.baselineState`:
//
//   * "new"       — a finding NOT present in the baseline,
//   * "unchanged" — a finding present in BOTH the baseline and the current run,
//   * "absent"    — a finding in the baseline but GONE now (re-emitted so a
//                   reviewer sees what disappeared; SARIF allows absent results).
//
// Identity is the finding's `(id, triggering_signal)` key (model.rs
// `Finding::identity_key`) — `Finding` carries no observed-action source, so that
// pair is the stable, byte-deterministic key present in the JSON baseline.
//
// Honesty: annotation never asserts; `is_candidate` stays `true` on every result
// (active, unchanged, or absent). Without `--baseline`, this module is never
// invoked and the output is byte-identical to the pre-US-F2-4 default shape.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;

use crate::model::{Citation, ControlStatus, Finding, Report, RulesSource};

/// A lenient view of a baseline finding. Only the fields needed to (a) compute
/// the identity key and (b) reconstruct an `absent` finding are read; any extra
/// keys in the JSON (e.g. `ambiguity`, `baseline_state`, `rules_source_collapsed`)
/// are ignored, so a baseline produced by any version of the scanner still loads.
#[derive(Debug, Deserialize)]
struct BaselineFinding {
    id: String,
    title: String,
    #[serde(default)]
    status: BaselineStatus,
    #[serde(default)]
    confidence: f32,
    triggering_signal: String,
    #[serde(default)]
    citation: BaselineCitation,
    #[serde(default)]
    suggested_controls: Vec<String>,
    #[serde(default)]
    cross_refs: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum BaselineStatus {
    #[default]
    Official,
    Draft,
}

#[derive(Debug, Default, Deserialize)]
struct BaselineCitation {
    #[serde(default)]
    url: String,
    #[serde(default)]
    version: String,
}

#[derive(Debug, Deserialize)]
struct BaselineReport {
    #[serde(default)]
    findings: Vec<BaselineFinding>,
}

/// The parsed baseline: the prior findings, kept for both the identity-key set
/// and `absent` reconstruction.
pub struct Baseline {
    findings: Vec<BaselineFinding>,
}

impl Baseline {
    /// Load a baseline from a prior scan's JSON report.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read baseline {}: {e}", path.display()))?;
        let report: BaselineReport = serde_json::from_str(&text).map_err(|e| {
            format!(
                "baseline {} is not a valid scanner JSON report: {e}",
                path.display()
            )
        })?;
        Ok(Baseline {
            findings: report.findings,
        })
    }

    /// The set of `(id, triggering_signal)` identity keys in the baseline.
    fn keys(&self) -> BTreeSet<(String, String)> {
        self.findings
            .iter()
            .map(|f| (f.id.clone(), f.triggering_signal.clone()))
            .collect()
    }
}

/// Annotate a report against a baseline (US-F2-4). Each ACTIVE finding gets a
/// `baselineState` of `new` (not in the baseline) or `unchanged` (in both). For
/// each baseline finding absent from the current ACTIVE set, an extra `absent`
/// finding is APPENDED so the disappearance is visible. The suppressed channel is
/// left untouched (a suppressed candidate is not an active result to diff).
///
/// Honesty: every annotated/synthesized finding is still `is_candidate == true`.
pub fn annotate(report: Report, baseline: &Baseline) -> Report {
    let baseline_keys = baseline.keys();
    let current_keys: BTreeSet<(String, String)> =
        report.findings.iter().map(|f| f.identity_key()).collect();

    let Report {
        rules_source,
        rules_source_collapsed,
        findings,
        suppressed,
    } = report;

    // (1) Annotate the active findings: new vs unchanged.
    let mut annotated: Vec<Finding> = findings
        .into_iter()
        .map(|f| {
            let state = if baseline_keys.contains(&f.identity_key()) {
                "unchanged"
            } else {
                "new"
            };
            f.with_baseline_state(state)
        })
        .collect();

    // (2) Append `absent` findings: in the baseline, gone from the current run.
    for bf in &baseline.findings {
        let key = (bf.id.clone(), bf.triggering_signal.clone());
        if !current_keys.contains(&key) {
            annotated.push(absent_finding(bf, rules_source).with_baseline_state("absent"));
        }
    }

    Report {
        rules_source,
        rules_source_collapsed,
        findings: annotated,
        suppressed,
    }
}

/// Reconstruct a `Finding` for a baseline entry that is gone now, so it can be
/// emitted as an `absent` result. Built via `Finding::new`, so `is_candidate` is
/// forced `true`. The reconstructed finding carries this run's `rules_source`
/// (the prior source is not authoritative for the current run's header).
fn absent_finding(bf: &BaselineFinding, rules_source: RulesSource) -> Finding {
    Finding::new(
        bf.id.clone(),
        bf.title.clone(),
        match bf.status {
            BaselineStatus::Official => ControlStatus::Official,
            BaselineStatus::Draft => ControlStatus::Draft,
        },
        bf.confidence,
        bf.triggering_signal.clone(),
        Citation {
            url: bf.citation.url.clone(),
            version: bf.citation.version.clone(),
        },
        bf.suggested_controls.clone(),
        bf.cross_refs.clone(),
        rules_source,
    )
}

/// Filter to ONLY `new` findings (US-F2-4 `--only-new`). `unchanged` and `absent`
/// findings are dropped. Intended to run AFTER [`annotate`]; on a report with no
/// `baseline_state` annotations it removes everything (so it is gated by the
/// caller to `--baseline` + `--only-new`).
pub fn only_new(report: Report) -> Report {
    let Report {
        rules_source,
        rules_source_collapsed,
        findings,
        suppressed,
    } = report;
    let kept = findings
        .into_iter()
        .filter(|f| f.baseline_state == Some("new"))
        .collect();
    Report {
        rules_source,
        rules_source_collapsed,
        findings: kept,
        suppressed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::json::to_json;
    use crate::model::RulesSource;

    fn finding(id: &str, signal: &str) -> Finding {
        Finding::new(
            id.into(),
            "Some Risk".into(),
            ControlStatus::Official,
            0.9,
            signal.into(),
            Citation {
                url: "https://example/...".into(),
                version: "1".into(),
            },
            vec!["SP800-53:SI-7".into()],
            vec!["ASI02".into()],
            RulesSource::EmbeddedFallback,
        )
    }

    fn report(findings: Vec<Finding>) -> Report {
        Report::with_suppressed(RulesSource::EmbeddedFallback, findings, vec![])
    }

    /// Build a baseline directly from a set of findings via their JSON report.
    fn baseline_from(findings: Vec<Finding>) -> Baseline {
        let json = to_json(&report(findings));
        let report: BaselineReport = serde_json::from_str(&json).unwrap();
        Baseline {
            findings: report.findings,
        }
    }

    #[test]
    fn unchanged_when_baseline_equals_current() {
        // A re-run with NO changes → every active finding is `unchanged`, zero `new`.
        let current = vec![finding("AGT-MIS-001", "rm -rf"), finding("AGT-EXF-001", "SELECT * FROM")];
        let base = baseline_from(current.clone());
        let out = annotate(report(current), &base);
        assert!(out.findings.iter().all(|f| f.baseline_state == Some("unchanged")));
        assert_eq!(out.findings.iter().filter(|f| f.baseline_state == Some("new")).count(), 0);
        // No absent findings (nothing disappeared).
        assert!(out.findings.iter().all(|f| f.baseline_state != Some("absent")));
    }

    #[test]
    fn new_finding_is_marked_new() {
        let base = baseline_from(vec![finding("AGT-MIS-001", "rm -rf")]);
        let current = vec![finding("AGT-MIS-001", "rm -rf"), finding("AGT-EXF-001", "SELECT * FROM")];
        let out = annotate(report(current), &base);
        let exf = out.findings.iter().find(|f| f.id == "AGT-EXF-001").unwrap();
        assert_eq!(exf.baseline_state, Some("new"));
        let mis = out.findings.iter().find(|f| f.id == "AGT-MIS-001").unwrap();
        assert_eq!(mis.baseline_state, Some("unchanged"));
    }

    #[test]
    fn gone_finding_is_marked_absent() {
        let base = baseline_from(vec![finding("AGT-MIS-001", "rm -rf"), finding("AGT-EXF-001", "SELECT * FROM")]);
        let current = vec![finding("AGT-MIS-001", "rm -rf")];
        let out = annotate(report(current), &base);
        let absent: Vec<_> = out.findings.iter().filter(|f| f.baseline_state == Some("absent")).collect();
        assert_eq!(absent.len(), 1, "the gone EXF-001 must surface as absent");
        assert_eq!(absent[0].id, "AGT-EXF-001");
        assert!(absent[0].is_candidate, "absent finding still a candidate");
    }

    #[test]
    fn only_new_keeps_only_new() {
        let base = baseline_from(vec![finding("AGT-MIS-001", "rm -rf")]);
        let current = vec![finding("AGT-MIS-001", "rm -rf"), finding("AGT-EXF-001", "SELECT * FROM")];
        let annotated = annotate(report(current), &base);
        let filtered = only_new(annotated);
        assert_eq!(filtered.findings.len(), 1);
        assert_eq!(filtered.findings[0].id, "AGT-EXF-001");
        assert_eq!(filtered.findings[0].baseline_state, Some("new"));
    }

    #[test]
    fn identity_key_uses_id_and_signal() {
        // Same id, different signal → different identity → `new`.
        let base = baseline_from(vec![finding("AGT-MIS-001", "rm -rf")]);
        let current = vec![finding("AGT-MIS-001", "chmod 777")];
        let out = annotate(report(current), &base);
        assert_eq!(out.findings.iter().find(|f| f.triggering_signal == "chmod 777").unwrap().baseline_state, Some("new"));
        // And the rm -rf one is now absent.
        assert!(out.findings.iter().any(|f| f.baseline_state == Some("absent") && f.triggering_signal == "rm -rf"));
    }
}
