// `.apohara-compliance.toml` config loader (US-F1-2 / plan Step 1.2, closes #6).
//
// The single user-facing EXTENSIBILITY surface. Three sections, all OPTIONAL so
// an absent or partial config never changes behavior:
//
//   [thresholds]                      # TOOL-INTERNAL scoring filters
//   min_confidence = 0.85             # drop findings below this confidence
//   min_severity   = 8                # drop findings below this severity
//
//   [[suppress]]                      # HUMAN allowlist (gitleaks-style)
//   agt_code     = "AGT-PI-002"       # required: the rule to suppress
//   source_glob  = "repo-file:*.md"   # optional: scope to a source glob
//   reason       = "docs, not live"   # required: the human justification
//
//   [severity]                        # OVERRIDE a rule's effective severity
//   AGT-PI-002 = 5                    # used by the --min-severity comparison
//
// Honesty split (plan fix iter-3 #1): `[[suppress]]` is a HUMAN decision and
// feeds the SAME allowlist path as the `.apohara-suppress` file (it lowers to a
// `suppress::SuppressRule`), so a suppressed candidate stays VISIBLE with its
// `reason` and renders as a SARIF `result.suppressions[{kind:external}]`. The
// `[thresholds]` filters are a TOOL-INTERNAL scoring decision — they are applied
// separately in `main.rs` and NEVER masquerade as a human allowlist on SARIF.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::suppress::{SuppressList, SuppressRule};

/// The canonical config file name discovered beside a scan target.
pub const CONFIG_FILE: &str = ".apohara-compliance.toml";

/// `[thresholds]` — tool-internal scoring filters (both optional).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Thresholds {
    /// Findings with `confidence < min_confidence` move to the visible
    /// threshold-drop channel. A CLI `--min-confidence` overrides this.
    pub min_confidence: Option<f32>,
    /// Findings with `effective_severity < min_severity` move to the visible
    /// threshold-drop channel. A CLI `--min-severity` overrides this.
    pub min_severity: Option<u8>,
}

/// One `[[suppress]]` entry — the TOML equivalent of a `.apohara-suppress`
/// allowlist line. Rule-specific (`agt_code` + optional `source_glob`) AND
/// global both work; an entry with no `source_glob` suppresses every source.
#[derive(Debug, Clone, Deserialize)]
pub struct SuppressEntry {
    /// The AGT-* rule code to suppress (required).
    pub agt_code: String,
    /// Optional glob on the observed-action `source` (e.g. `repo-file:*.md`).
    /// Absent = matches any source (global suppression for this `agt_code`).
    #[serde(default)]
    pub source_glob: Option<String>,
    /// Human justification recorded in the visible suppressed channel.
    pub reason: String,
}

/// The fully-parsed `.apohara-compliance.toml`.
///
/// `[severity]` is a free-form `AGT-CODE = u8` table, captured as a map so any
/// rule code can be overridden without a fixed schema.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub thresholds: Thresholds,
    #[serde(default)]
    pub suppress: Vec<SuppressEntry>,
    /// `AGT-CODE -> overriding severity` used by the `--min-severity` compare.
    #[serde(default)]
    pub severity: std::collections::BTreeMap<String, u8>,
}

impl Config {
    /// Parse config from a TOML string.
    pub fn parse(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|e| format!("failed to parse config: {e}"))
    }

    /// Load config from an explicit path. The path MUST exist (typo guard) —
    /// callers use [`Config::discover`] for the optional beside-target lookup.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config {}: {e}", path.display()))?;
        Self::parse(&text)
    }

    /// Discover a `.apohara-compliance.toml` beside the scan target. A missing
    /// file is NOT an error — it yields a default (empty) config (config is
    /// opt-in, so an absent config must be byte-identical to no-config).
    pub fn discover(target_dir: &Path) -> Result<Self, String> {
        let path = target_dir.join(CONFIG_FILE);
        if !path.exists() {
            return Ok(Config::default());
        }
        Self::load(&path)
    }

    /// Lower the `[[suppress]]` entries into a [`SuppressList`] so they feed the
    /// EXACT same allowlist-suppression path as the `.apohara-suppress` file
    /// (plan Step 1.2: both should reuse `suppress.rs`). The `raw` audit token
    /// is synthesized as `config:[[suppress]] <agt_code>` so SARIF/stderr show
    /// the suppression came from the config, not a file line.
    pub fn suppress_list(&self) -> SuppressList {
        let rules = self
            .suppress
            .iter()
            .map(|e| SuppressRule {
                agt_code: Some(e.agt_code.clone()),
                // The config entry has no signal granularity (gitleaks-style is
                // rule + source scoped), so any signal of the rule matches.
                signal: None,
                source_glob: e.source_glob.clone(),
                reason: e.reason.clone(),
                raw: format!("config:[[suppress]] {}", e.agt_code),
            })
            .collect();
        SuppressList { rules }
    }
}

/// Resolve the config: an explicit `--config <path>` wins (must exist), else a
/// `.apohara-compliance.toml` discovered beside the scan target (missing → empty).
pub fn resolve(config_flag: Option<&Path>, target_dir: Option<PathBuf>) -> Result<Config, String> {
    if let Some(path) = config_flag {
        if !path.exists() {
            return Err(format!("config file not found: {}", path.display()));
        }
        return Config::load(path);
    }
    let dir = target_dir.unwrap_or_else(|| PathBuf::from("."));
    Config::discover(&dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_is_all_defaults() {
        let c = Config::parse("").expect("empty config parses");
        assert!(c.thresholds.min_confidence.is_none());
        assert!(c.thresholds.min_severity.is_none());
        assert!(c.suppress.is_empty());
        assert!(c.severity.is_empty());
    }

    #[test]
    fn round_trips_full_schema() {
        // RAC-1.3: a unit test round-trips the .apohara-compliance.toml schema.
        let text = r#"
[thresholds]
min_confidence = 0.85
min_severity = 8

[[suppress]]
agt_code = "AGT-PI-002"
source_glob = "repo-file:*.md"
reason = "illustrative prose in docs, not a live injection"

[[suppress]]
agt_code = "AGT-EXF-001"
reason = "global allowlist for this rule"

[severity]
AGT-PI-002 = 5
AGT-MIS-001 = 3
"#;
        let c = Config::parse(text).expect("full schema parses");
        assert_eq!(c.thresholds.min_confidence, Some(0.85));
        assert_eq!(c.thresholds.min_severity, Some(8));
        assert_eq!(c.suppress.len(), 2);
        assert_eq!(c.suppress[0].agt_code, "AGT-PI-002");
        assert_eq!(c.suppress[0].source_glob.as_deref(), Some("repo-file:*.md"));
        assert!(c.suppress[0].reason.contains("illustrative"));
        // Second entry is GLOBAL (no source_glob).
        assert_eq!(c.suppress[1].agt_code, "AGT-EXF-001");
        assert!(c.suppress[1].source_glob.is_none());
        assert_eq!(c.severity.get("AGT-PI-002"), Some(&5));
        assert_eq!(c.severity.get("AGT-MIS-001"), Some(&3));
    }

    #[test]
    fn suppress_entries_lower_to_allowlist_rules() {
        // The [[suppress]] entries must feed the SAME allowlist path: a
        // rule-specific (agt_code + source_glob) AND a global entry both match.
        let text = r#"
[[suppress]]
agt_code = "AGT-EXF-001"
source_glob = "repo-file:*report.sql"
reason = "known fixture"

[[suppress]]
agt_code = "AGT-PI-001"
reason = "noisy in this repo"
"#;
        let list = Config::parse(text).unwrap().suppress_list();
        // Rule-specific + source-scoped: matches the scoped source, not others.
        assert!(list
            .matching("AGT-EXF-001", "SELECT * FROM", "repo-file:src/report.sql")
            .is_some());
        assert!(list
            .matching("AGT-EXF-001", "SELECT * FROM", "repo-file:src/other.sql")
            .is_none());
        // Global (no source_glob): matches any source for that rule.
        let g = list.matching("AGT-PI-001", "DAN", "anything:else");
        assert!(g.is_some());
        assert_eq!(g.unwrap().reason, "noisy in this repo");
        // The audit token names the config origin.
        let m = list
            .matching("AGT-EXF-001", "SELECT * FROM", "repo-file:src/report.sql")
            .unwrap();
        assert_eq!(m.raw, "config:[[suppress]] AGT-EXF-001");
    }

    #[test]
    fn discover_missing_file_is_empty_not_error() {
        let tmp = tempfile::TempDir::new().unwrap();
        let c = Config::discover(tmp.path()).expect("missing config is not an error");
        assert!(c.suppress.is_empty());
        assert!(c.thresholds.min_confidence.is_none());
    }
}
