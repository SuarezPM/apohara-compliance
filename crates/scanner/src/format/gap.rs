// Gap-analysis output formatters (US-F1-4). Three views over one `GapReport`:
//   * json  — the PRIMARY structured format for gap (the model serializes 1:1).
//   * md    — a human Markdown summary, every gap line absence-framed.
//   * sarif — a minimal valid SARIF 2.1.0 run; gap items are INFORMATIONAL
//             results at level "note" carrying the "no candidate evidence
//             observed" message. They must NOT read as assertions.
//
// HONESTY: every emitted line is absence/candidate-framed ("no candidate evidence
// observed for <id>"), never "non-compliant"/"violates"/"is vulnerable to". The
// disclaimer + the 49-scope statement lead the md output and are carried in the
// json + sarif properties so the framing travels with the structured output too.

use std::fmt::Write as _;

use serde_json::{json, Value};

use crate::gap::GapReport;

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const DRIVER_NAME: &str = "apohara-compliance-scanner";
const DRIVER_URI: &str = "https://github.com/SuarezPM/apohara-compliance";

/// Serialize a gap report as pretty JSON (the primary structured gap format).
pub fn to_json(report: &GapReport) -> String {
    serde_json::to_string_pretty(report).expect("GapReport is always JSON-serializable")
}

/// Render a gap report as a Markdown summary. The disclaimer + the 49-scope
/// statement lead the document; every control line is absence-framed.
pub fn to_markdown(report: &GapReport) -> String {
    let mut out = String::new();

    out.push_str("# apohara-compliance — gap analysis (controls with no candidate evidence)\n\n");
    // Scope (fix #11d) + the absence-of-evidence disclaimer (honesty) lead the doc.
    let _ = writeln!(out, "_{}_\n", report.scope);
    let _ = writeln!(out, "_{}_\n", report.disclaimer);
    let _ = writeln!(
        out,
        "**Rules source:** `{}` · **Universe:** {} controls · **With candidate evidence:** {} · \
         **No candidate evidence:** {}\n",
        report.rules_source_collapsed,
        report.universe,
        report.covered,
        report.gaps.len(),
    );

    if report.gaps.is_empty() {
        out.push_str("Every carried control surfaced at least one candidate signal in this scan.\n");
        return out;
    }

    out.push_str("## Controls with no candidate evidence\n\n");
    for g in &report.gaps {
        // Absence-framed line + the control's provenance (status + consilium_ref).
        let _ = writeln!(
            out,
            "- {message} — status: `{status}`, consilium_ref: `{cref}`",
            message = g.message,
            status = g.status.label(),
            cref = g.consilium_ref,
        );
    }

    out
}

/// Render a gap report as a minimal valid SARIF 2.1.0 document. Each gap is an
/// INFORMATIONAL result at level "note"; the scope + disclaimer ride in the run
/// properties. The message is absence-framed — it never reads as an assertion.
pub fn to_sarif(report: &GapReport) -> String {
    let sarif = build_sarif(report);
    serde_json::to_string_pretty(&sarif).expect("gap SARIF document is always serializable")
}

/// Build the gap SARIF `Value` (split out so tests can assert on structure).
fn build_sarif(report: &GapReport) -> Value {
    // One rule descriptor + one note-level result per zero-evidence control.
    let rules: Vec<Value> = report
        .gaps
        .iter()
        .map(|g| {
            json!({
                "id": g.id,
                "name": g.title,
                "shortDescription": { "text": g.title },
                "properties": { "status": g.status.label() }
            })
        })
        .collect();

    let results: Vec<Value> = report
        .gaps
        .iter()
        .map(|g| {
            json!({
                "ruleId": g.id,
                // Informational — a gap is the ABSENCE of a candidate signal, the
                // softest level; NEVER "error"/"warning" (no defect asserted).
                "level": "note",
                "message": { "text": g.message },
                "properties": {
                    "status": g.status.label(),
                    "consilium_ref": g.consilium_ref,
                    "kind": "absence-of-candidate-evidence"
                }
            })
        })
        .collect();

    json!({
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [{
            "tool": {
                "driver": {
                    "name": DRIVER_NAME,
                    "informationUri": DRIVER_URI,
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules
                }
            },
            "properties": {
                "analysis": "gap",
                "scope": report.scope,
                "disclaimer": report.disclaimer,
                "rules_source": report.rules_source_collapsed,
                "universe": report.universe,
                "covered": report.covered
            },
            "results": results
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gap::compute_gap;
    use crate::model::Report;
    use crate::rules::load_embedded;

    /// A no-evidence gap report (all 49 are gaps) for deterministic assertions.
    fn empty_scan_gap() -> GapReport {
        let data = load_embedded().expect("rules");
        let report = Report::with_suppressed(data.source, vec![], vec![]);
        compute_gap(&report, &data)
    }

    #[test]
    fn json_carries_scope_disclaimer_and_gap_messages() {
        let g = empty_scan_gap();
        let out = to_json(&g);
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert!(v["scope"].as_str().unwrap().contains("49 carried controls"));
        assert!(v["disclaimer"]
            .as_str()
            .unwrap()
            .contains("Absence of evidence is not evidence of a gap"));
        assert_eq!(v["universe"], 49);
        assert_eq!(v["gaps"].as_array().unwrap().len(), 49);
        assert!(v["gaps"][0]["message"]
            .as_str()
            .unwrap()
            .starts_with("no candidate evidence observed for "));
        assert!(v["gaps"][0]["consilium_ref"].is_string());
    }

    #[test]
    fn md_leads_with_scope_and_disclaimer_and_every_line_absence_framed() {
        let g = empty_scan_gap();
        let md = to_markdown(&g);
        assert!(md.contains("Gap is computed over the 49 carried controls"));
        assert!(md.contains("Absence of evidence is not evidence of a gap"));
        // Every control bullet is absence-framed.
        for line in md.lines().filter(|l| l.starts_with("- ")) {
            assert!(
                line.starts_with("- no candidate evidence observed for "),
                "gap md line not absence-framed: {line}"
            );
        }
    }

    #[test]
    fn md_no_banned_assertive_vocabulary() {
        // In-crate mirror of the extended verify.sh NEGATIVE guard (fix #6b).
        let md = to_markdown(&empty_scan_gap()).to_lowercase();
        for b in [
            "is compliant",
            "certified",
            "guaranteed",
            "non-compliant",
            "violates",
            "is vulnerable to",
            "detected",
            "you have asi",
        ] {
            assert!(!md.contains(b), "gap md contains banned phrase {b:?}");
        }
    }

    #[test]
    fn sarif_is_2_1_0_with_note_level_absence_results() {
        let g = empty_scan_gap();
        let v = build_sarif(&g);
        assert_eq!(v["version"], "2.1.0");
        assert!(v["$schema"].is_string());
        assert_eq!(v["runs"][0]["properties"]["analysis"], "gap");
        assert!(v["runs"][0]["properties"]["scope"]
            .as_str()
            .unwrap()
            .contains("49 carried controls"));
        for r in v["runs"][0]["results"].as_array().unwrap() {
            // Informational note level only — never error/warning.
            assert_eq!(r["level"], "note");
            let text = r["message"]["text"].as_str().unwrap();
            assert!(
                text.starts_with("no candidate evidence observed for "),
                "sarif gap result not absence-framed: {text}"
            );
        }
    }
}
