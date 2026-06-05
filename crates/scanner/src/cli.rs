// CLI surface (clap). Parsing lives here; orchestration lives in main.rs.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "apohara-compliance-scanner",
    about = "Map coding-agent actions or a repository to compliance/security controls — \
             surfacing CANDIDATES, never asserting compliance.",
    version
)]
pub struct Cli {
    /// Directory holding the canonical references/*.yaml rule files.
    /// Highest-precedence step of the rules resolution ladder.
    #[arg(long, global = true, value_name = "DIR")]
    pub rules_dir: Option<PathBuf>,

    /// Output format for the candidate report.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Json)]
    pub format: OutputFormat,

    /// Path to a `.apohara-suppress` allowlist. If omitted, a `.apohara-suppress`
    /// beside the scan target is used when present. Allowlisted candidates are
    /// moved to the VISIBLE suppressed channel, never dropped (US-F0-2).
    #[arg(long, global = true, value_name = "FILE")]
    pub suppress: Option<PathBuf>,

    /// Path to a `.apohara-compliance.toml` config (thresholds + [[suppress]] +
    /// [severity]). If omitted, a `.apohara-compliance.toml` beside the scan
    /// target is used when present (US-F1-2).
    #[arg(long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Drop findings with confidence below this value into the VISIBLE
    /// threshold-drop channel (a tool-internal filter, NOT a human allowlist).
    /// Overrides `[thresholds] min_confidence` from the config (US-F1-2).
    #[arg(long, global = true, value_name = "FLOAT")]
    pub min_confidence: Option<f32>,

    /// Drop findings whose EFFECTIVE severity (rule severity, possibly overridden
    /// by `[severity]`) is below this value into the VISIBLE threshold-drop
    /// channel. Overrides `[thresholds] min_severity` from the config (US-F1-2).
    #[arg(long, global = true, value_name = "INT")]
    pub min_severity: Option<u8>,

    /// Opt-in: in ADDITION to the normal AGT-* candidates, surface a companion
    /// ASI candidate (OWASP Top 10 for Agentic Applications) for each distinct
    /// ASI risk the active AGT findings cross-reference (US-F1-3). De-duplicated
    /// by ASI id; each companion records ALL the triggering AGT codes. OFF by
    /// default — when omitted the output is byte-identical to the pre-US-F1-3
    /// build (no extra field, no extra findings).
    #[arg(long, global = true, default_value_t = false)]
    pub by_asi: bool,

    /// Path to a prior scan's JSON report, used as the baseline for diff mode
    /// (US-F2-4). When supplied, each emitted finding is annotated with a SARIF
    /// `baselineState`: `new` (absent from the baseline), `unchanged` (present in
    /// both), or `absent` (in the baseline but gone now — surfaced as an extra
    /// result). The baseline format is the scanner's OWN JSON report
    /// (`--format json`). Identity is `(id, triggering_signal)`. When omitted,
    /// the output is byte-identical to a run without baseline (no `baselineState`
    /// field).
    #[arg(long, global = true, value_name = "FILE")]
    pub baseline: Option<PathBuf>,

    /// With `--baseline`: emit ONLY findings whose `baselineState` is `new`
    /// (US-F2-4). A no-op without `--baseline`. `absent` results are also dropped
    /// under this filter (they are not `new`).
    #[arg(long, global = true, default_value_t = false)]
    pub only_new: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Json,
    Sarif,
    Md,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan an AI coding-agent session transcript (~/.claude/projects/**/*.jsonl).
    ScanSession {
        /// Path to the .jsonl session transcript.
        path: PathBuf,
    },
    /// Scan a repository directory for compliance-relevant signals.
    ScanRepo {
        /// Path to the repository root.
        path: PathBuf,
        /// Restrict the walker to files with one of these extensions
        /// (comma-separated, no dots — e.g. `--ext rs,py`). This is a
        /// WALKER/CLI filter that decides which files are even read, NOT a
        /// detection-rule context field (ADR-1's context DSL stays the frozen
        /// 3-field set). Matching is case-insensitive. Omitted ⇒ all files are
        /// read (byte-identical to the prior behavior). No tree-sitter / no
        /// language parsing — scan-repo is commodity (US-F2-4 #5).
        #[arg(long, value_name = "LIST", value_delimiter = ',')]
        ext: Vec<String>,
    },
    /// Gap analysis: run a normal scan, then list the carried controls (the 49
    /// in controls-49.yaml ONLY) for which NO finding surfaced candidate
    /// evidence — the COMPLEMENT over the 49 (US-F1-4 / fix #11d). Externally-
    /// cited standards (GDPR/HIPAA/…) are OUT of scope: the project carries no
    /// full catalog for them. Honesty: a gap is the ABSENCE of a candidate
    /// signal ("no candidate evidence observed for X"), never an assertion of
    /// non-compliance. Accepts the same input as scan-*: a `.jsonl` session
    /// transcript is scanned as a session, any other path as a repo directory.
    Gap {
        /// Path to a `.jsonl` session transcript OR a repository root.
        path: PathBuf,
    },
}
