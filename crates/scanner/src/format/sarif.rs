// SARIF 2.1.0 formatter.
//
// Shape (validated against the OASIS SARIF 2.1.0 schema):
//   { version: "2.1.0", $schema: <2.1.0 schema url>, runs: [ {
//       tool: { driver: { name, informationUri, version, rules: [ {id, name,
//                 shortDescription, properties} ] } },
//       results: [ { ruleId, level, message:{text}, locations?, properties } ]
//   } ] }
//
// Honesty constraints (plan R5 / fix 8):
//   * `level` is ALWAYS "note" or "warning", NEVER "error" — a finding is a
//     candidate, not a defect.
//   * every `result.message.text` STARTS WITH the literal "CANDIDATE — ".
//   * `properties` carries {citation, confidence, status, cross_refs,
//     suggested_controls, rules_source} for full auditability.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::format::CANDIDATE_PREFIX;
use crate::model::{ControlStatus, Finding, Report, SuppressedFinding, SuppressionOrigin};

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str =
    "https://json.schemastore.org/sarif-2.1.0.json";
const DRIVER_NAME: &str = "apohara-compliance-scanner";
const DRIVER_URI: &str = "https://github.com/SuarezPM/apohara-compliance";

/// Render a report as a SARIF 2.1.0 JSON document (pretty-printed).
pub fn to_sarif(report: &Report) -> String {
    let sarif = build(report);
    serde_json::to_string_pretty(&sarif).expect("SARIF document is always serializable")
}

/// Build the SARIF `Value` (split out so tests can assert on structure).
pub fn build(report: &Report) -> Value {
    // De-duplicate the tool.driver.rules[] by ruleId; each detection code that
    // fired contributes one rule descriptor — including allowlist-suppressed
    // findings, which are ordinary results that merge into the SAME run.
    let mut rule_descriptors: BTreeMap<String, Value> = BTreeMap::new();
    let suppressed_findings = report.suppressed.iter().map(|s| &s.finding);
    for f in report.findings.iter().chain(suppressed_findings) {
        rule_descriptors.entry(f.id.clone()).or_insert_with(|| {
            json!({
                "id": f.id,
                "name": f.title,
                "shortDescription": { "text": f.title },
                "properties": { "status": f.status.label() }
            })
        });
    }
    let rules: Vec<Value> = rule_descriptors.into_values().collect();

    // SARIF 2.1.0 has exactly ONE runs[].results[] per run. Allowlist-suppressed
    // candidates are MERGED into that single array, each carrying a
    // `result.suppressions` property (§3.27.23) — NOT a separate collection.
    let mut results: Vec<Value> = report.findings.iter().map(result_for).collect();
    results.extend(report.suppressed.iter().map(suppressed_result_for));

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
                "rules_source": report.rules_source_collapsed
            },
            "results": results
        }]
    })
}

/// One SARIF `result` object for a finding.
fn result_for(f: &Finding) -> Value {
    let message = format!(
        "{CANDIDATE_PREFIX}{title} (signal: {signal}). Review suggested control(s): {ctrls}. \
         Source provenance: {status}.",
        title = f.title,
        signal = f.triggering_signal,
        ctrls = f.suggested_controls.join(", "),
        status = f.status.label(),
    );

    let mut result = json!({
        "ruleId": f.id,
        "level": level_for(f.status),
        "message": { "text": message },
        "properties": {
            "citation": { "url": f.citation.url, "version": f.citation.version },
            "confidence": f.confidence,
            "status": f.status.label(),
            "cross_refs": f.cross_refs,
            "suggested_controls": f.suggested_controls,
            "rules_source": f.rules_source_collapsed,
            "is_candidate": f.is_candidate
        }
    });

    // Baseline/diff annotation (US-F2-4). `result.baselineState` is a top-level
    // result property in SARIF 2.1.0 (§3.27.24), with enum
    // none|unchanged|updated|new|absent. Emitted ONLY when `--baseline` set the
    // value (`Some`), so a run without `--baseline` stays byte-identical to the
    // pre-US-F2-4 SARIF (no `baselineState` key).
    if let Some(state) = f.baseline_state {
        result["baselineState"] = json!(state);
    }

    result
}

/// A SARIF `result` for a suppressed candidate, routed by its `origin`
/// (US-F1-2 / plan fix iter-3 #1) — the two MUST NOT be conflated:
///
///   * `Allowlist` (a HUMAN decision: `.apohara-suppress` / `[[suppress]]`) →
///     `result.suppressions:[{kind:"external", justification:<reason>}]`
///     (SARIF 2.1.0 §3.27.23 / §3.35.2). The `kind` `external` marks an
///     allowlist-file decision, not an in-source annotation.
///   * `Threshold` (a TOOL-INTERNAL scoring decision: `--min-confidence` /
///     `--min-severity` / `[thresholds]`) → a NORMAL result carrying
///     `properties.dropped_by_threshold: true` and NO `suppressions` property,
///     so a tool filter can never masquerade as a human allowlist.
///
/// Both routes still merge into the SINGLE `runs[].results[]` array and keep the
/// `CANDIDATE — ` prefix + `is_candidate: true` — fully visible either way.
fn suppressed_result_for(s: &SuppressedFinding) -> Value {
    let mut result = result_for(&s.finding);
    match s.origin {
        SuppressionOrigin::Allowlist => {
            result["suppressions"] = json!([{
                "kind": "external",
                "justification": s.reason
            }]);
            // Audit: which allowlist pattern moved this candidate.
            result["properties"]["suppressed_by"] = json!(s.suppressed_by);
        }
        SuppressionOrigin::Threshold => {
            // NO `suppressions` property — this is a tool filter, not a human
            // allowlist. The drop is surfaced as an ordinary, visible result.
            result["properties"]["dropped_by_threshold"] = json!(true);
            result["properties"]["dropped_reason"] = json!(s.reason);
        }
    }
    result
}

/// SARIF level — NEVER "error". A draft-provenance finding is downgraded to
/// "note" (lower-trust source ⇒ softer signal); official is "warning".
fn level_for(status: ControlStatus) -> &'static str {
    match status {
        ControlStatus::Official => "warning",
        ControlStatus::Draft => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Citation, RulesSource};

    fn suppressed(f: Finding, reason: &str) -> SuppressedFinding {
        SuppressedFinding {
            finding: f,
            reason: reason.to_string(),
            suppressed_by: "AGT-PI-002:act as".to_string(),
            origin: SuppressionOrigin::Allowlist,
        }
    }

    fn threshold_dropped(f: Finding, reason: &str) -> SuppressedFinding {
        SuppressedFinding {
            finding: f,
            reason: reason.to_string(),
            suppressed_by: "threshold:min-confidence 0.85".to_string(),
            origin: SuppressionOrigin::Threshold,
        }
    }

    fn finding(status: ControlStatus) -> Finding {
        Finding::new(
            "AGT-PI-002".into(),
            "Roleplay Persona Manipulation".into(),
            status,
            0.7,
            "act as".into(),
            Citation {
                url: "https://owasp.org/...".into(),
                version: "2025".into(),
            },
            vec!["OWASP-LLM:LLM01".into()],
            vec!["ASI01".into()],
            RulesSource::EmbeddedFallback,
        )
    }

    #[test]
    fn sarif_has_version_and_schema() {
        let v = build(&Report::new(
            RulesSource::EmbeddedFallback,
            vec![finding(ControlStatus::Official)],
        ));
        assert_eq!(v["version"], "2.1.0");
        assert!(v["$schema"].is_string());
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], DRIVER_NAME);
    }

    #[test]
    fn every_result_message_starts_with_candidate_prefix() {
        let v = build(&Report::new(
            RulesSource::EmbeddedFallback,
            vec![finding(ControlStatus::Official), finding(ControlStatus::Draft)],
        ));
        for r in v["runs"][0]["results"].as_array().unwrap() {
            let text = r["message"]["text"].as_str().unwrap();
            assert!(text.starts_with(CANDIDATE_PREFIX), "missing prefix: {text}");
        }
    }

    #[test]
    fn level_is_never_error() {
        for status in [ControlStatus::Official, ControlStatus::Draft] {
            let lvl = level_for(status);
            assert!(lvl == "note" || lvl == "warning", "level was {lvl}");
        }
    }

    #[test]
    fn properties_carry_status_and_provenance() {
        let v = build(&Report::new(
            RulesSource::EmbeddedFallback,
            vec![finding(ControlStatus::Draft)],
        ));
        let props = &v["runs"][0]["results"][0]["properties"];
        assert_eq!(props["status"], "draft");
        assert_eq!(props["rules_source"], "embedded-fallback");
        // confidence is an f32 (0.7) so JSON widens it to f64 — compare with a
        // tolerance rather than for exact bit-equality.
        let conf = props["confidence"].as_f64().unwrap();
        assert!((conf - 0.7).abs() < 1e-6, "confidence was {conf}");
        assert!(props["suggested_controls"].is_array());
    }

    #[test]
    fn suppressed_merges_into_single_results_array_with_suppressions() {
        // US-F0-2: active + suppressed share ONE runs[].results[] array; the
        // suppressed result carries result.suppressions[{kind:external}]; the
        // active result has NO suppressions property.
        let report = Report::with_suppressed(
            RulesSource::EmbeddedFallback,
            vec![finding(ControlStatus::Official)],
            vec![suppressed(finding(ControlStatus::Official), "known prose FP")],
        );
        let v = build(&report);
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2, "one results[] array carries both");

        let active: Vec<&Value> = results
            .iter()
            .filter(|r| r.get("suppressions").is_none())
            .collect();
        let supp: Vec<&Value> = results
            .iter()
            .filter(|r| r.get("suppressions").is_some())
            .collect();
        assert_eq!(active.len(), 1, "active result has NO suppressions property");
        assert_eq!(supp.len(), 1, "suppressed result carries suppressions");

        let s = &supp[0]["suppressions"][0];
        assert_eq!(s["kind"], "external");
        assert_eq!(s["justification"], "known prose FP");
        // Still a candidate, still CANDIDATE-prefixed.
        let text = supp[0]["message"]["text"].as_str().unwrap();
        assert!(text.starts_with(CANDIDATE_PREFIX));
        assert_eq!(supp[0]["properties"]["is_candidate"], true);
    }

    #[test]
    fn threshold_drop_uses_properties_not_suppressions() {
        // RAC-1.2 (SARIF split, fix iter-3 #1): a threshold-dropped candidate is
        // a NORMAL result carrying properties.dropped_by_threshold:true and NO
        // `suppressions` property — it must NOT masquerade as a human allowlist.
        let report = Report::with_suppressed(
            RulesSource::EmbeddedFallback,
            vec![finding(ControlStatus::Official)],
            vec![threshold_dropped(
                finding(ControlStatus::Official),
                "below min-confidence 0.85",
            )],
        );
        let v = build(&report);
        let results = v["runs"][0]["results"].as_array().unwrap();
        // Both share the single results[] array.
        assert_eq!(results.len(), 2, "one results[] array carries both");
        // NO result carries a `suppressions` property (neither active nor dropped).
        for r in results {
            assert!(
                r.get("suppressions").is_none(),
                "threshold drop must NOT use the SARIF suppressions property: {r}"
            );
        }
        // Exactly one result is flagged dropped_by_threshold, with the reason.
        let dropped: Vec<&Value> = results
            .iter()
            .filter(|r| r["properties"]["dropped_by_threshold"] == json!(true))
            .collect();
        assert_eq!(dropped.len(), 1, "one dropped_by_threshold result");
        assert_eq!(
            dropped[0]["properties"]["dropped_reason"],
            "below min-confidence 0.85"
        );
        // Still a candidate, still CANDIDATE-prefixed.
        let text = dropped[0]["message"]["text"].as_str().unwrap();
        assert!(text.starts_with(CANDIDATE_PREFIX));
        assert_eq!(dropped[0]["properties"]["is_candidate"], true);
    }

    #[test]
    fn baseline_state_emitted_only_when_set_and_valid_enum() {
        // US-F2-4: a finding annotated with baselineState carries a top-level
        // `result.baselineState` from the SARIF 2.1.0 enum. A finding without an
        // annotation carries NO baselineState key (byte-identical default shape).
        const VALID: [&str; 5] = ["none", "unchanged", "updated", "new", "absent"];

        let annotated = finding(ControlStatus::Official).with_baseline_state("new");
        let plain = finding(ControlStatus::Official);
        let v = build(&Report::new(RulesSource::EmbeddedFallback, vec![annotated, plain]));
        let results = v["runs"][0]["results"].as_array().unwrap();

        let with_state: Vec<&Value> = results
            .iter()
            .filter(|r| r.get("baselineState").is_some())
            .collect();
        assert_eq!(with_state.len(), 1, "only the annotated result carries baselineState");
        let state = with_state[0]["baselineState"].as_str().unwrap();
        assert_eq!(state, "new");
        assert!(VALID.contains(&state), "baselineState must be a valid SARIF enum: {state}");

        // The un-annotated result must NOT carry the key (default shape preserved).
        let without: Vec<&Value> = results
            .iter()
            .filter(|r| r.get("baselineState").is_none())
            .collect();
        assert_eq!(without.len(), 1, "the plain result has no baselineState");
    }

    #[test]
    fn allowlist_and_threshold_coexist_in_one_run_distinctly() {
        // Both origins in ONE report: the allowlist result carries suppressions,
        // the threshold result carries dropped_by_threshold — never conflated.
        let report = Report::with_suppressed(
            RulesSource::EmbeddedFallback,
            vec![],
            vec![
                suppressed(finding(ControlStatus::Official), "human allowlist"),
                threshold_dropped(finding(ControlStatus::Draft), "below min-severity 8"),
            ],
        );
        let v = build(&report);
        let results = v["runs"][0]["results"].as_array().unwrap();
        let with_supp = results
            .iter()
            .filter(|r| r.get("suppressions").is_some())
            .count();
        let with_threshold = results
            .iter()
            .filter(|r| r["properties"]["dropped_by_threshold"] == json!(true))
            .count();
        assert_eq!(with_supp, 1, "exactly one allowlist suppression");
        assert_eq!(with_threshold, 1, "exactly one threshold drop");
        // The allowlist result must NOT carry dropped_by_threshold and vice versa.
        for r in results {
            let is_allowlist = r.get("suppressions").is_some();
            let is_threshold = r["properties"]["dropped_by_threshold"] == json!(true);
            assert!(!(is_allowlist && is_threshold), "origins must not mix: {r}");
        }
    }
}
