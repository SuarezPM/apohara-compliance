// Human-readable Markdown summary.
//
// Every finding line STARTS WITH the literal "CANDIDATE — " (plan fix 8) so a
// reader can never mistake a row for a compliance assertion. Each line carries
// the citation (url + version), the triggering_signal, the status, and the
// suggested controls — the full "why did this fire / how trustworthy" trail.

use std::fmt::Write as _;

use crate::format::CANDIDATE_PREFIX;
use crate::model::{Finding, Report, SuppressionOrigin};

/// Render a report as a Markdown summary string.
pub fn to_markdown(report: &Report) -> String {
    let mut out = String::new();

    out.push_str("# apohara-compliance — candidate findings\n\n");
    let _ = writeln!(
        out,
        "_Guidance/mapping only — these are CANDIDATES for review, not assertions of \
         compliance, certification, or audit conclusions._\n"
    );
    let _ = writeln!(
        out,
        "**Rules source:** `{}` · **Findings:** {} · **Suppressed:** {}\n",
        report.rules_source_collapsed,
        report.findings.len(),
        report.suppressed.len(),
    );

    if report.findings.is_empty() && report.suppressed.is_empty() {
        out.push_str("No candidate signals matched.\n");
        return out;
    }

    if report.findings.is_empty() {
        out.push_str("## Findings\n\nNo active candidate signals matched.\n\n");
    } else {
        out.push_str("## Findings\n\n");
        for f in &report.findings {
            // The candidate prefix MUST lead every finding line.
            let _ = writeln!(out, "{}", finding_line(f, None));
        }
    }

    // Suppressed candidates are NEVER hidden — they get visible sections, still
    // `CANDIDATE — `-prefixed (US-F0-2 / US-F1-2 / plan fix #4). The two origins
    // render under DISTINCT headings so a reader can tell a HUMAN allowlist
    // decision apart from a TOOL-INTERNAL threshold drop (plan fix iter-3 #1).
    let allowlisted: Vec<_> = report
        .suppressed
        .iter()
        .filter(|s| s.origin == SuppressionOrigin::Allowlist)
        .collect();
    let dropped: Vec<_> = report
        .suppressed
        .iter()
        .filter(|s| s.origin == SuppressionOrigin::Threshold)
        .collect();

    if !allowlisted.is_empty() {
        out.push_str("\n## Suppressed (allowlisted)\n\n");
        let _ = writeln!(
            out,
            "_These candidates were moved here by your allowlist — not dropped. \
             They remain CANDIDATES for review._\n"
        );
        for s in allowlisted {
            let reason = format!("{} (by `{}`)", s.reason, s.suppressed_by);
            let _ = writeln!(out, "{}", finding_line(&s.finding, Some(&reason)));
        }
    }

    if !dropped.is_empty() {
        out.push_str("\n## Dropped by threshold\n\n");
        let _ = writeln!(
            out,
            "_These candidates fell below a `--min-confidence`/`--min-severity` \
             threshold (a tool filter, NOT a human allowlist) — not dropped from \
             the report. They remain CANDIDATES for review._\n"
        );
        for s in dropped {
            let reason = format!("{} (by `{}`)", s.reason, s.suppressed_by);
            let _ = writeln!(out, "{}", finding_line(&s.finding, Some(&reason)));
        }
    }

    out
}

/// Render one finding as a CANDIDATE-prefixed Markdown bullet. When `reason` is
/// `Some`, an extra `suppressed: <reason>` sub-line is appended (suppressed
/// section); the prefix leads the line in both cases.
fn finding_line(f: &Finding, reason: Option<&str>) -> String {
    let mut line = format!(
        "- {prefix}**{id}** {title} — status: `{status}`, confidence: {conf:.2}\n  \
         - triggering_signal: `{signal}`\n  \
         - suggested_controls: {ctrls}\n  \
         - cross_refs: {xrefs}\n  \
         - citation: <{url}> (version {ver})",
        prefix = CANDIDATE_PREFIX,
        id = f.id,
        title = f.title,
        status = f.status.label(),
        conf = f.confidence,
        signal = f.triggering_signal,
        ctrls = join_or_dash(&f.suggested_controls),
        xrefs = join_or_dash(&f.cross_refs),
        url = f.citation.url,
        ver = f.citation.version,
    );
    if let Some(reason) = reason {
        let _ = write!(line, "\n  - suppressed: {reason}");
    }
    line
}

fn join_or_dash(items: &[String]) -> String {
    if items.is_empty() {
        "—".to_string()
    } else {
        items.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Citation, ControlStatus, Finding, RulesSource, SuppressedFinding, SuppressionOrigin,
    };

    fn sample_finding(status: ControlStatus) -> Finding {
        Finding::new(
            "AGT-EXF-001".into(),
            "Database Dump Request".into(),
            status,
            0.9,
            "SELECT * FROM".into(),
            Citation {
                url: "https://csrc.nist.gov/...".into(),
                version: "r5".into(),
            },
            vec!["SP800-53:AC-3".into()],
            vec!["ASI02".into()],
            RulesSource::CliDir,
        )
    }

    fn report(status: ControlStatus) -> Report {
        Report::new(RulesSource::CliDir, vec![sample_finding(status)])
    }

    #[test]
    fn every_finding_line_starts_with_candidate_prefix() {
        let md = to_markdown(&report(ControlStatus::Official));
        let finding_lines: Vec<&str> = md
            .lines()
            .filter(|l| l.contains("AGT-EXF-001"))
            .collect();
        assert!(!finding_lines.is_empty());
        for l in finding_lines {
            // The list bullet "- " precedes the prefix; assert the prefix is present.
            assert!(
                l.trim_start_matches("- ").starts_with(CANDIDATE_PREFIX),
                "finding line missing CANDIDATE prefix: {l}"
            );
        }
    }

    #[test]
    fn includes_citation_signal_status_and_controls() {
        let md = to_markdown(&report(ControlStatus::Draft));
        assert!(md.contains("SELECT * FROM"));
        assert!(md.contains("status: `draft`"));
        assert!(md.contains("SP800-53:AC-3"));
        assert!(md.contains("csrc.nist.gov"));
        assert!(md.contains("version r5"));
    }

    #[test]
    fn empty_report_is_explicit() {
        let r = Report::new(RulesSource::EmbeddedFallback, vec![]);
        let md = to_markdown(&r);
        assert!(md.contains("No candidate signals matched"));
    }

    #[test]
    fn suppressed_section_is_visible_and_candidate_prefixed() {
        // US-F0-2: a suppressed candidate renders under "Suppressed (allowlisted)"
        // still CANDIDATE-prefixed, with its reason.
        let supp = SuppressedFinding {
            finding: sample_finding(ControlStatus::Official),
            reason: "known fixture".into(),
            suppressed_by: "AGT-EXF-001".into(),
            origin: SuppressionOrigin::Allowlist,
        };
        let r = Report::with_suppressed(RulesSource::CliDir, vec![], vec![supp]);
        let md = to_markdown(&r);
        assert!(md.contains("## Suppressed (allowlisted)"), "{md}");
        // The suppressed finding line still leads with the CANDIDATE prefix.
        let line = md
            .lines()
            .find(|l| l.contains("AGT-EXF-001"))
            .expect("suppressed finding line present");
        assert!(
            line.trim_start_matches("- ").starts_with(CANDIDATE_PREFIX),
            "suppressed line missing CANDIDATE prefix: {line}"
        );
        assert!(md.contains("suppressed: known fixture"), "{md}");
    }
}
