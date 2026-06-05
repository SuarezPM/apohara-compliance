// Output model — a `Finding` is always a CANDIDATE, never an assertion.
//
// Every field exists so a downstream consumer can audit "why did this fire and
// how trustworthy is the source" without re-running the scanner: the triggering
// signal, the cited published source (url + version), the official-vs-draft
// status of the matched control, and which rules source the scanner loaded
// (on-disk file vs. the embedded build-time copy).
//
// The honesty thesis (plan §2 principle 1, AC-9) is encoded structurally: the
// `is_candidate` field is ALWAYS `true` and is serialized, so machine output can
// never be misread as a compliance assertion.

use serde::Serialize;

/// Official-vs-draft provenance of a matched control or risk id.
///
/// Surfaced per-finding (plan fix 4 / PM-1b) so a consumer cannot silently treat
/// a CSA-draft control as settled NIST guidance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ControlStatus {
    Official,
    Draft,
}

impl ControlStatus {
    /// Lowercase label, matching the serde representation. Shared by the
    /// Markdown and SARIF emitters.
    pub fn label(self) -> &'static str {
        match self {
            ControlStatus::Official => "official",
            ControlStatus::Draft => "draft",
        }
    }

    /// Map a YAML `status` string onto the typed enum (default: official).
    /// Shared by the matcher and the gap module so the parse is defined once.
    pub fn from_yaml_status(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "draft" => ControlStatus::Draft,
            _ => ControlStatus::Official,
        }
    }
}

/// Which rules source the resolution ladder selected (plan ADR-1 / R6).
///
/// Serialized in its expanded form for full auditability, while
/// [`RulesSource::collapsed`] exposes the AC-9 `file|embedded-fallback` view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RulesSource {
    /// `--rules-dir <path>` CLI flag (ladder step 1).
    CliDir,
    /// `APOHARA_RULES_DIR` env var (ladder step 2).
    EnvDir,
    /// `current_exe()`-relative sibling/`../` `references/` dir (ladder step 3).
    ExeRelative,
    /// `include_str!` build-time embedded copy (ladder step 4, final fallback).
    EmbeddedFallback,
}

impl RulesSource {
    /// Collapsed AC-9 view: any on-disk source is `file`, the embedded copy is
    /// `embedded-fallback`. This is the value that lands in a [`Finding`].
    pub fn collapsed(self) -> &'static str {
        match self {
            RulesSource::CliDir | RulesSource::EnvDir | RulesSource::ExeRelative => "file",
            RulesSource::EmbeddedFallback => "embedded-fallback",
        }
    }
}

/// The published-source citation for a finding (AC-9: `citation(url + version)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Citation {
    pub url: String,
    pub version: String,
}

/// A single CANDIDATE finding (AC-9 + consensus additions).
///
/// Fields map to spec AC-9 plus the plan's hardening additions: `status`
/// (fix 4), `rules_source` (fix 7), and the always-true `is_candidate`
/// invariant (plan §3).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    /// The matched ASI / AGT / control id (AC-9 `asi_id/control`).
    pub id: String,
    /// Human-readable title of the matched risk/control.
    pub title: String,
    /// Official-vs-draft provenance of the matched id.
    pub status: ControlStatus,
    /// Baseline confidence for the keyword match (0.0–1.0); a hit is a
    /// candidate signal, never a certainty.
    pub confidence: f32,
    /// The concrete signal that fired (the keyword/pattern observed).
    pub triggering_signal: String,
    /// Published-source citation (url + framework version).
    pub citation: Citation,
    /// Suggested controls to review for this finding (control ids).
    pub suggested_controls: Vec<String>,
    /// Cross-references to related ids (e.g. ASI↔LLM crosswalk).
    pub cross_refs: Vec<String>,
    /// Which rules source produced this finding (expanded, for audit).
    pub rules_source: RulesSource,
    /// Collapsed AC-9 `file|embedded-fallback` view of `rules_source`.
    pub rules_source_collapsed: &'static str,
    /// ALWAYS `true` — encodes the candidates-never-assertions contract so
    /// output can never read as a compliance assertion.
    pub is_candidate: bool,
    /// Deterministic borderline flag (US-F1-1 / ADR-2 split). Set `true` by the
    /// engine ONLY for a candidate that was KEPT despite a `deny_context` fragment
    /// being present (because `require_context` also matched) — a concrete,
    /// byte-deterministic "borderline" rule. It ANNOTATES, never asserts:
    /// `is_candidate` stays `true`. Omitted from JSON/SARIF when `false` (via
    /// `skip_serializing_if`) so the pre-US-F1-1 default output shape is preserved
    /// byte-for-byte for pinned consumers.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub ambiguity: bool,
    /// Baseline/diff annotation (US-F2-4) — one of the SARIF 2.1.0
    /// `result.baselineState` enum values (`new`|`unchanged`|`absent`; the wider
    /// enum also allows `none`|`updated`, unused here). Set ONLY when a
    /// `--baseline <file>` is supplied: `new` = not in the baseline; `unchanged`
    /// = present in both; `absent` = in the baseline but gone now. Omitted from
    /// JSON/SARIF when `None` (via `skip_serializing_if`) so a run WITHOUT
    /// `--baseline` is byte-identical to the pre-US-F2-4 default shape. It
    /// ANNOTATES, never asserts: `is_candidate` stays `true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_state: Option<&'static str>,
}

impl Finding {
    /// Construct a finding, forcing the `is_candidate` invariant to `true` and
    /// deriving the collapsed rules-source view from `rules_source`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        title: String,
        status: ControlStatus,
        confidence: f32,
        triggering_signal: String,
        citation: Citation,
        suggested_controls: Vec<String>,
        cross_refs: Vec<String>,
        rules_source: RulesSource,
    ) -> Self {
        Finding {
            id,
            title,
            status,
            confidence,
            triggering_signal,
            citation,
            suggested_controls,
            cross_refs,
            rules_source,
            rules_source_collapsed: rules_source.collapsed(),
            is_candidate: true,
            // Default: not borderline. The engine opts a finding into ambiguity
            // via `with_ambiguity`; `is_candidate` is unaffected either way.
            ambiguity: false,
            // Default: no baseline annotation. Set only when `--baseline` is
            // supplied, via `with_baseline_state`.
            baseline_state: None,
        }
    }

    /// Mark this finding as deterministically borderline (US-F1-1). Chainable so
    /// the engine can flag a kept-despite-deny_context candidate without widening
    /// the `Finding::new` signature. Never touches `is_candidate`.
    pub fn with_ambiguity(mut self, ambiguity: bool) -> Self {
        self.ambiguity = ambiguity;
        self
    }

    /// Annotate this finding with a SARIF `baselineState` (US-F2-4). Chainable so
    /// the diff pass can tag a finding without widening `Finding::new`. Never
    /// touches `is_candidate`.
    pub fn with_baseline_state(mut self, state: &'static str) -> Self {
        self.baseline_state = Some(state);
        self
    }

    /// Stable identity key for baseline/diff (US-F2-4). A finding is "the same"
    /// across two runs when its detection id AND its triggering signal match.
    /// `Finding` does not carry the observed-action source, so the key is
    /// `(id, triggering_signal)` — byte-stable and present in the JSON baseline.
    pub fn identity_key(&self) -> (String, String) {
        (self.id.clone(), self.triggering_signal.clone())
    }
}

/// WHY a candidate left the ACTIVE findings list (US-F1-2 / plan fix iter-3 #1).
///
/// These two origins MUST NOT be conflated (honesty): an `Allowlist` move is a
/// HUMAN decision (`.apohara-suppress` / `[[suppress]]`) and on SARIF becomes a
/// `result.suppressions[{kind:"external"}]`; a `Threshold` move is a
/// TOOL-INTERNAL scoring decision (`--min-confidence` / `--min-severity` /
/// `[thresholds]`) and on SARIF becomes a NORMAL result carrying
/// `properties.dropped_by_threshold: true` with NO `suppressions` property — so
/// a tool filter can never masquerade as a human allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SuppressionOrigin {
    /// Moved by a human allowlist (`.apohara-suppress` file or `[[suppress]]`).
    Allowlist,
    /// Dropped by a tool-internal threshold (`--min-confidence`/`--min-severity`).
    Threshold,
}

/// A candidate that left the ACTIVE findings list but was NEVER deleted (US-F0-2
/// allowlist / US-F1-2 thresholds, plan fix #4). Both origins stay VISIBLE here.
///
/// Honesty: a suppressed candidate is still built via [`Finding::new`], so
/// `is_candidate` is still forced `true`. Suppression only changes *where* the
/// candidate is surfaced (the visible `suppressed` channel), with the `reason` +
/// the pattern/threshold that matched it + the `origin` discriminator recorded
/// so the SARIF formatter routes allowlist→suppressions vs threshold→properties.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SuppressedFinding {
    /// The candidate that was suppressed (still `is_candidate == true`).
    pub finding: Finding,
    /// Human-readable justification for the suppression.
    pub reason: String,
    /// The allowlist pattern (US-F0-2) or threshold tag (US-F1-2) that matched.
    pub suppressed_by: String,
    /// WHY it was suppressed — allowlist (human) vs threshold (tool). Drives the
    /// SARIF allowlist-vs-threshold split. Defaults to `Allowlist` for the
    /// existing US-F0-2 file path; threshold drops set it explicitly.
    pub origin: SuppressionOrigin,
}

/// Top-level report: a header carrying the resolved `rules_source` plus the
/// candidate findings (plan §3 — `rules_source` lives in the report header AND
/// per-finding so an auditor always sees which rules were used).
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// Expanded rules source used for this run (audit view).
    pub rules_source: RulesSource,
    /// Collapsed AC-9 `file|embedded-fallback` view.
    pub rules_source_collapsed: &'static str,
    /// The candidate findings.
    pub findings: Vec<Finding>,
    /// Candidates moved here by the allowlist — never dropped (US-F0-2).
    pub suppressed: Vec<SuppressedFinding>,
}

impl Report {
    /// Build a report header from the resolved rules source. The `suppressed`
    /// channel starts empty; use [`Report::with_suppressed`] to populate it.
    ///
    /// Retained as the simple constructor used across the formatter tests and as
    /// public API; the binary path uses [`Report::with_suppressed`].
    #[allow(dead_code)]
    pub fn new(rules_source: RulesSource, findings: Vec<Finding>) -> Self {
        Report {
            rules_source,
            rules_source_collapsed: rules_source.collapsed(),
            findings,
            suppressed: Vec::new(),
        }
    }

    /// Build a report carrying both active and allowlist-suppressed candidates.
    pub fn with_suppressed(
        rules_source: RulesSource,
        findings: Vec<Finding>,
        suppressed: Vec<SuppressedFinding>,
    ) -> Self {
        Report {
            rules_source,
            rules_source_collapsed: rules_source.collapsed(),
            findings,
            suppressed,
        }
    }
}
