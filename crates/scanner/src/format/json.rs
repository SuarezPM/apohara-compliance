// Own-JSON report formatter.
//
// The `Report`/`Finding` model already derives `Serialize` (model.rs), with
// `status` and `rules_source` carried both per-finding and in the report header.
// This is just pretty serialization — no reshaping — so the JSON output is a
// faithful, round-trippable view of the in-memory model.

use crate::model::Report;

/// Serialize a report as pretty JSON.
pub fn to_json(report: &Report) -> String {
    // serde_json only fails to serialize on non-string map keys / NaN floats,
    // neither of which our model can produce, so the result is stable.
    serde_json::to_string_pretty(report).expect("Report is always JSON-serializable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Citation, ControlStatus, Finding, RulesSource, SuppressedFinding, SuppressionOrigin,
    };

    fn sample_finding() -> Finding {
        Finding::new(
            "AGT-MIS-001".into(),
            "Destructive Tool Invocation".into(),
            ControlStatus::Official,
            0.9,
            "rm -rf".into(),
            Citation {
                url: "https://csrc.nist.gov/...".into(),
                version: "r5".into(),
            },
            vec!["SP800-53:SI-7".into()],
            vec!["ASI02".into()],
            RulesSource::EmbeddedFallback,
        )
    }

    fn sample_report() -> Report {
        Report::new(RulesSource::EmbeddedFallback, vec![sample_finding()])
    }

    #[test]
    fn json_carries_status_rules_source_and_is_candidate() {
        let out = to_json(&sample_report());
        assert!(out.contains("\"status\": \"official\""));
        assert!(out.contains("embedded-fallback"));
        assert!(out.contains("\"is_candidate\": true"));
        assert!(out.contains("AGT-MIS-001"));
    }

    #[test]
    fn json_pretty_is_valid_and_reparses() {
        let out = to_json(&sample_report());
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(v["findings"][0]["triggering_signal"], "rm -rf");
    }

    #[test]
    fn json_includes_visible_suppressed_array() {
        // US-F0-2: a suppressed candidate is visible in JSON under `suppressed`,
        // out of `findings`, still `is_candidate`.
        let suppressed = SuppressedFinding {
            finding: sample_finding(),
            reason: "known fixture".into(),
            suppressed_by: "AGT-MIS-001".into(),
            origin: SuppressionOrigin::Allowlist,
        };
        let report =
            Report::with_suppressed(RulesSource::EmbeddedFallback, vec![], vec![suppressed]);
        let out = to_json(&report);
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert!(v["findings"].as_array().unwrap().is_empty());
        assert_eq!(v["suppressed"][0]["reason"], "known fixture");
        assert_eq!(v["suppressed"][0]["finding"]["id"], "AGT-MIS-001");
        assert_eq!(v["suppressed"][0]["finding"]["is_candidate"], true);
    }
}
