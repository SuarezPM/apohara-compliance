// Rule-set loader + reference-path resolution LADDER (ADR-1, the heart of US-003).
//
// The scanner binary resolves the canonical `references/*.yaml` via an ordered
// ladder, falling back to a build-time-embedded copy only as a last resort:
//
//   (1) --rules-dir <path>            (CLI flag, passed in)
//   (2) APOHARA_RULES_DIR             (env var, set by the skill)
//   (3) current_exe()-relative        (a sibling or ../ `references/` dir)
//   (4) include_str! embedded copy     (final, schema_version-gated fallback)
//
// Anti-drift hardening (ADR-1 / R6):
//   * A `SCHEMA_VERSION` constant is compiled into the binary. When rules load
//     from a FILE PATH (ladder steps 1–3), the YAML header `schema_version` is
//     compared to it; on mismatch the loader returns Err — NO silent fallback.
//     The caller (main) turns that into a non-zero process exit.
//   * The embedded copy (step 4) is `include_str!`-d FROM the canonical
//     `references/*.yaml` at build time, so embedded == canonical within a
//     release. There is no on-disk file to compare on that path, so the embedded
//     copy is authoritative by construction.
//   * The chosen `RulesSource` is emitted to stderr on load and is attachable to
//     findings + the report header.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::model::RulesSource;

/// Rules schema version compiled into the binary (ADR-1).
///
/// Must match the `schema_version:` header in every `references/*.yaml` loaded
/// from a file path. A deliberate bump here requires a coordinated rules update.
pub const SCHEMA_VERSION: u32 = 1;

/// The canonical reference file names, resolved by the ladder / embedded.
const ASI_FILE: &str = "asi-2026.yaml";
const AST_FILE: &str = "ast-2026.yaml";
const ATLAS_FILE: &str = "atlas-2026.yaml";
const ISO42001_FILE: &str = "iso42001-2023.yaml";
const EU_AI_ACT_FILE: &str = "eu-ai-act-2024.yaml";
const CONTROLS_FILE: &str = "controls-49.yaml";
const CROSSWALK_FILE: &str = "crosswalk-asi-llm.yaml";
const DETECTION_FILE: &str = "detection-rules.yaml";

// --- Build-time embedded copies, sourced FROM the canonical references/ (R6) ---
//
// CARGO_MANIFEST_DIR is crates/scanner; `references/` is the canonical source
// dir vendored INSIDE the crate (so `cargo package`/`cargo install` ships it),
// with the repo-root `references/` a symlink to it — ONE physical copy. This
// guarantees the embedded bytes equal the canonical YAML at build time (the
// drift test asserts this).
const EMBEDDED_ASI: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/references/asi-2026.yaml"));
const EMBEDDED_AST: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/references/ast-2026.yaml"));
const EMBEDDED_ATLAS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/references/atlas-2026.yaml"
));
const EMBEDDED_ISO42001: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/references/iso42001-2023.yaml"
));
const EMBEDDED_EU_AI_ACT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/references/eu-ai-act-2024.yaml"
));
const EMBEDDED_CONTROLS: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/references/controls-49.yaml"));
const EMBEDDED_CROSSWALK: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/references/crosswalk-asi-llm.yaml"
));
const EMBEDDED_DETECTION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/references/detection-rules.yaml"
));

/// Error returned while resolving/loading rules.
#[derive(Debug)]
pub enum RulesError {
    /// A resolved YAML header `schema_version` did not match the compiled-in
    /// `SCHEMA_VERSION`. The caller MUST turn this into a non-zero exit (no
    /// silent fallback for file paths).
    SchemaMismatch {
        file: String,
        expected: u32,
        found: u32,
    },
    /// I/O error reading a rules file at a resolved path.
    Io { file: String, source: std::io::Error },
    /// YAML parse error.
    Parse { file: String, source: serde_norway::Error },
}

impl fmt::Display for RulesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RulesError::SchemaMismatch {
                file,
                expected,
                found,
            } => write!(
                f,
                "rules schema_version mismatch in {file}: binary expects {expected}, file declares {found}. \
                 Refusing to load stale rules; update the binary or the references."
            ),
            RulesError::Io { file, source } => {
                write!(f, "failed to read rules file {file}: {source}")
            }
            RulesError::Parse { file, source } => {
                write!(f, "failed to parse rules file {file}: {source}")
            }
        }
    }
}

impl std::error::Error for RulesError {}

// --- Deserialization structs matching the ACTUAL references/*.yaml shapes ---
//
// These mirror the FULL on-disk YAML so loading schema-validates every file and
// the complete reference set is in memory. The v0.1 matcher consumes the
// detection rules + the 49 controls; the ASI/AST/crosswalk sets and several
// metadata fields (severity, djl_rules, source_url, …) are loaded-and-validated
// but not yet read by application code, hence the targeted dead_code allows that
// document the schema rather than dropping fields.

/// `detection-rules.yaml` — header + the AGT-* rules (19 single-action +
/// AGT-MEM-001 sequence rule (ADR-2) + AGT-TRJ-001/002/003 taint rules (ADR-4)).
#[derive(Debug, Clone, Deserialize)]
pub struct DetectionRuleSet {
    pub schema_version: u32,
    pub rules: Vec<DetectionRule>,
}

/// One AGT-* detection rule (matches detection-rules.yaml `rules[]` entries).
///
/// CLOSED context-rule DSL (US-F1-1 / ADR-1): `source_kinds`, `require_context`,
/// and `deny_context` are the ONLY three context modifiers. This set is FROZEN —
/// no 4th context field may be added without a new ADR. Any richer matching
/// (taint/dataflow, tree-sitter/AST) is a separate ADR, not a quiet 4th field.
/// All three are `#[serde(default)]` so the existing single-action YAML (which
/// omits them) stays valid and an empty value is backward-compatible (matches any).
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct DetectionRule {
    pub agt_code: String,
    pub name: String,
    pub severity: u8,
    pub signals: Vec<String>,
    pub djl_rules: Vec<String>,
    pub maps_to_controls: Vec<String>,
    pub asi_xref: Vec<String>,
    pub default_confidence: f32,
    pub citation: String,
    /// Context DSL field 1 (CLOSED set): the candidate fires only when the
    /// observed-action `source` PREFIX-matches at least one entry
    /// (`source.starts_with(kind)`). Empty = matches any source (backward-compat).
    /// Entries MUST use the real source labels (e.g. `session:Bash`), never the
    /// non-existent `.command` suffix.
    #[serde(default)]
    pub source_kinds: Vec<String>,
    /// Context DSL field 2 (CLOSED set): regex fragments of which AT LEAST ONE
    /// must be present in the window around the match (the action value is the
    /// window). Empty = no positive-context requirement (backward-compat).
    #[serde(default)]
    pub require_context: Vec<String>,
    /// Context DSL field 3 (CLOSED set): regex fragments that, if ANY is present
    /// in the window, SUPPRESS the candidate (negative context; `regex` has no
    /// lookaround, so this is a separate post-match search over the value).
    /// Empty = nothing suppresses (backward-compat).
    #[serde(default)]
    pub deny_context: Vec<String>,
    /// MITRE ATLAS technique cross-references (US-F2-1). Optional `AML.T####`
    /// (optionally `.###`) ids that map this incident to a published ATLAS
    /// technique; defined in atlas-2026.yaml. These are surfaced as additional
    /// `Finding.cross_refs` (after the ASI + OWASP-LLM refs). NOT part of the
    /// CLOSED context DSL — they are reference metadata, not a matching modifier.
    /// Empty = no ATLAS mapping (the honest default for AGT families without a
    /// clean ATLAS technique).
    #[serde(default)]
    pub atlas_xref: Vec<String>,
    /// ISO/IEC 42001:2023 Annex A control cross-references (US-F2-2). Optional
    /// `ISO42001:A.#.#(.#)` ids that map this incident to a published Annex A
    /// control; defined in iso42001-2023.yaml. Surfaced as additional
    /// `Finding.cross_refs` (after the ASI + OWASP-LLM + ATLAS refs). NOT part of
    /// the CLOSED context DSL — they are reference metadata, not a matching
    /// modifier. Empty = no ISO 42001 mapping (the honest default for AGT families
    /// without a clean Annex A control).
    #[serde(default)]
    pub iso42001_xref: Vec<String>,
    /// EU AI Act (Regulation (EU) 2024/1689) Chapter III Section 2 article
    /// cross-references (US-F2-3). Optional `EU-AI-ACT:Art-#` ids that map this
    /// incident to a high-risk-system requirement defined in eu-ai-act-2024.yaml
    /// (a SEPARATE coverage layer, NOT folded into the 49 controls). Surfaced as
    /// additional `Finding.cross_refs` (after the ASI + OWASP-LLM + ATLAS + ISO
    /// 42001 refs). NOT part of the CLOSED context DSL — reference metadata, not a
    /// matching modifier. Empty = no EU AI Act mapping (the honest default for AGT
    /// families without a clean Section 2 article). Note: Art-9/12/14/15 already
    /// live in controls-49.yaml and may also appear in `maps_to_controls`; this
    /// field carries the SEPARATE-LAYER Art-10/11/13 that the 49-suite omits.
    #[serde(default)]
    pub eu_ai_act_xref: Vec<String>,
    /// Multi-action SEQUENCE rule (ADR-2). When present, this rule is NOT a
    /// single-action rule: `compile_rules` excludes it from the single-action
    /// signal set (its `signals` stay empty) and the separate second pass
    /// (`sequence.rs`) handles it. Absent (the default for all single-action
    /// rules) ⇒ ordinary single-action matching, byte-identically unchanged.
    /// This is a NEW rule-shape discriminator, NOT a 4th context-DSL field — the
    /// CLOSED 3-field context DSL (ADR-1) is untouched.
    #[serde(default)]
    pub sequence: Option<SequenceRule>,
    /// Multi-action TAINT rule (ADR-4). When present, this rule is NOT a
    /// single-action rule: `compile_rules` excludes it from the single-action
    /// signal set and the separate taint pass (`taint.rs`) handles it. Absent (the
    /// default) ⇒ ordinary single-action matching, byte-identically unchanged. Like
    /// `sequence`, this is a NEW rule-shape discriminator, NOT a 4th context-DSL
    /// field — the CLOSED 3-field context DSL (ADR-1) is untouched.
    #[serde(default)]
    pub taint: Option<TaintRule>,
    /// Structural SHELL rule (ADR-5 S1 / AC3.3). When present, this rule is NOT a
    /// single-action rule: `compile_rules` excludes it from the single-action
    /// signal set (its `signals` stay empty) and the separate shell pass
    /// (`shell.rs`) handles it. Absent (the default) ⇒ ordinary single-action
    /// matching, byte-identically unchanged. Like `sequence`/`taint`, this is a NEW
    /// rule-shape discriminator, NOT a 4th context-DSL field — the CLOSED 3-field
    /// context DSL (ADR-1) is untouched. It tokenizes a `session:Bash`-prefixed
    /// command into argv + flags and matches STRUCTURALLY (binary + required-flag
    /// SET), defeating flag-reordering/spacing/bundling evasions the regex families
    /// miss.
    #[serde(default)]
    pub shell: Option<ShellRule>,
}

/// A structural SHELL rule (ADR-5 S1 / AC3.3): tokenize a real executed Bash
/// command (`session:Bash`-prefixed action) into argv + flags and fire when the
/// invoked binary equals `binary` AND every flag in `all_flags` is present
/// (order-, spacing- and bundling-invariant). This defeats the flag-REORDERING /
/// spacing / short-bundling evasions a literal-substring family regex misses
/// (`rm -r -f -v`, `rm  --force  --recursive`, `rm -frv`). It is a CANDIDATE
/// (never proven destructive); `is_candidate` is forced true via `build_finding`.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct ShellRule {
    /// The invoked binary, matched on the argv[0] BASENAME (so `/bin/rm` → `rm`).
    pub binary: String,
    /// The SET of flags that must ALL be present for the rule to fire, in their
    /// NORMALIZED short-name form (e.g. `"r"`, `"f"`). A flag is satisfied by its
    /// short form OR any known long alias for the rule's family (e.g. `--recursive`
    /// ↔ `r`, `--force` ↔ `f`); bundled short flags (`-rf`) are expanded first.
    pub all_flags: Vec<String>,
    /// require_context fragments (regex, ≥1 must be present in the RAW command) —
    /// empty = no positive-context requirement (backward-compat with the DSL).
    #[serde(default)]
    pub require_context: Vec<String>,
    /// deny_context fragments (regex) — if ANY is present in the RAW command, the
    /// candidate is SUPPRESSED (e.g. `--dry-run`, `echo `). Empty = nothing denies.
    #[serde(default)]
    pub deny_context: Vec<String>,
}

/// A forward-correlated taint rule (ADR-4): a `taint_source` action (untrusted-data
/// channel carrying an injection marker) FOLLOWED BY a `taint_sink` action (a genuine
/// sensitive real-action) later in the same observed-action stream. Expresses the
/// injection→consequence PATTERN (a CANDIDATE correlation, never proven causation).
///
/// `require_value_from_source` (ADR-7 / v2.3, opt-in PROVENANCE GATE) — when
/// NON-empty, the rule additionally requires that authority-role values extracted
/// from the matched sink action (via the FROZEN `sink:` role map recorded in
/// PREREG-v2.3) be a substring of the latched `taint_source` action's `value`,
/// after ASCII-lowercasing + a 6-character length floor. This is a POST-HOC
/// *proxy* for injection→consequence causation: it kills the FP class where the
/// same sink fires on a clean trajectory (because the legit value won't appear in
/// the injection source), but does NOT prove the value was *lifted* from the
/// injection versus *coincidentally present* in the injection text. Verbatim-flow
/// only; no cross-step laundering (PACT does that, apohara does not). EMPTY
/// (the default) ⇒ ordinary AGT-TRJ behavior, byte-identically unchanged. The
/// `#[serde(default)]` keeps existing YAML rules deserialize unchanged, so
/// AGT-TRJ-001/002/003 byte-identical behavior is preserved without opt-in.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct TaintRule {
    pub taint_source: TaintStep,
    pub taint_sink: TaintStep,
    /// PROVENANCE GATE (v2.3, opt-in). Role names from the FROZEN `sink:` role
    /// map: `recipient`, `amount`, `url`, `command`. Empty = no provenance check
    /// (v2.2 byte-identical behavior). See PREREG-v2.3.md for frozen semantics.
    #[serde(default)]
    pub require_value_from_source: Vec<String>,
}

/// One step of a [`TaintRule`]. Extends the sequence-step shape with per-step
/// `require_context`/`deny_context` (the precision guards): the source `deny_context`
/// suppresses a doc/comment-quoted marker; the sink `require_context` demands a
/// specifically-sensitive action. `source_kinds` is the same PREFIX filter (the sink
/// scopes to real-action tools like `session:Bash`, never the chat channel).
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct TaintStep {
    pub signals: Vec<String>,
    #[serde(default)]
    pub source_kinds: Vec<String>,
    #[serde(default)]
    pub require_context: Vec<String>,
    #[serde(default)]
    pub deny_context: Vec<String>,
}

/// A two-step ordered correlation (ADR-2): a `source_step` action FOLLOWED BY a
/// `sink_step` action later in the same observed-action stream. The minimum
/// primitive that expresses ASI06 (memory/context poisoning = untrusted content
/// later persisted to a memory/RAG sink) without touching the single-action loop.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct SequenceRule {
    pub source_step: SequenceStep,
    pub sink_step: SequenceStep,
}

/// One step of a [`SequenceRule`]. Reuses the single-action primitives: `signals`
/// (OR of conditional-`\b` regexes, compiled by `matching::compile_signal`) and a
/// `source_kinds` PREFIX filter (empty = any source), identical in semantics to
/// the single-action path — no new matching primitive beyond ordered pairing.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct SequenceStep {
    pub signals: Vec<String>,
    #[serde(default)]
    pub source_kinds: Vec<String>,
}

/// `asi-2026.yaml` — header + ASI01..ASI10.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct AsiSet {
    pub schema_version: u32,
    pub version: String,
    pub source_url: String,
    pub risks: Vec<AsiRisk>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct AsiRisk {
    pub id: String,
    pub title: String,
    pub url: String,
    pub version: String,
    pub status: String,
}

/// `ast-2026.yaml` — header + AST01..AST10.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct AstSet {
    pub schema_version: u32,
    pub version: String,
    pub status: String,
    pub risks: Vec<AstRisk>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct AstRisk {
    pub id: String,
    pub title: String,
    pub title_status: String,
    pub url: String,
}

/// `atlas-2026.yaml` — header + the MITRE ATLAS technique cross-reference layer
/// (US-F2-1). A separate coverage layer, NOT folded into the 49 controls.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct AtlasSet {
    pub schema_version: u32,
    pub framework: String,
    pub version: String,
    pub source_url: String,
    pub verified_on: String,
    pub techniques: Vec<AtlasTechnique>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct AtlasTechnique {
    pub id: String,
    pub name: String,
    pub url: String,
    pub status: String,
}

/// `iso42001-2023.yaml` — header + the ISO/IEC 42001:2023 Annex A control
/// cross-reference layer (US-F2-2). A separate coverage layer, NOT folded into
/// the 49 controls. Carries only control codes + objective/title facts + an OWN
/// paraphrase (no verbatim ISO prose, which is copyrighted).
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Iso42001Set {
    pub schema_version: u32,
    pub framework: String,
    pub version: String,
    pub source_url: String,
    pub verified_on: String,
    pub status: String,
    pub controls: Vec<Iso42001Control>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Iso42001Control {
    pub id: String,
    pub objective: String,
    pub title: String,
    pub paraphrase: String,
    pub source_url: String,
}

/// `eu-ai-act-2024.yaml` — header + the EU AI Act (Regulation (EU) 2024/1689)
/// Chapter III Section 2 article cross-reference layer (US-F2-3). A separate
/// coverage layer, NOT folded into the 49 controls. Carries only official article
/// numbers + official article titles (facts) + an OWN paraphrase (no verbatim EU
/// regulation prose beyond the short official title, which is copyrighted).
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct EuAiActSet {
    pub schema_version: u32,
    pub framework: String,
    pub version: String,
    pub source_url: String,
    pub verified_on: String,
    pub status: String,
    pub articles: Vec<EuAiActArticle>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct EuAiActArticle {
    pub id: String,
    pub title: String,
    pub paraphrase: String,
    pub source_url: String,
}

/// `controls-49.yaml` — header + the 49 controls.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct ControlSet {
    pub schema_version: u32,
    pub controls: Vec<Control>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Control {
    pub id: String,
    pub title: String,
    pub framework: String,
    pub version: String,
    pub source_url: String,
    pub status: String,
    pub consilium_ref: String,
}

/// `crosswalk-asi-llm.yaml` — header + ASI→LLM rows.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct CrosswalkSet {
    pub schema_version: u32,
    pub llm_framework_version: String,
    pub crosswalk: Vec<CrosswalkRow>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct CrosswalkRow {
    pub asi_id: String,
    pub asi_title: String,
    pub llm_ids: Vec<String>,
    pub llm_titles: Vec<String>,
}

/// Minimal header used to read just `schema_version` before full deserialization.
#[derive(Debug, Deserialize)]
struct SchemaHeader {
    schema_version: u32,
}

/// The fully-loaded rule set + the source it was loaded from.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RuleData {
    pub source: RulesSource,
    pub asi: AsiSet,
    pub ast: AstSet,
    pub atlas: AtlasSet,
    pub iso42001: Iso42001Set,
    pub eu_ai_act: EuAiActSet,
    pub controls: ControlSet,
    pub crosswalk: CrosswalkSet,
    pub detection: DetectionRuleSet,
}

/// Resolve the rules directory via the ladder, load + validate the rule set, and
/// emit the chosen `RulesSource` to stderr.
///
/// `cli_dir` is the value of `--rules-dir` (if any). Env (`APOHARA_RULES_DIR`)
/// and `current_exe()`-relative lookup are consulted in order; the embedded copy
/// is the final fallback. For file paths (steps 1–3) a `schema_version` mismatch
/// is a hard error (no silent fallback).
pub fn load(cli_dir: Option<&Path>) -> Result<RuleData, RulesError> {
    match resolve_dir(cli_dir) {
        Some((dir, source)) => {
            let data = load_from_dir(&dir, source)?;
            eprintln!(
                "apohara-compliance-scanner: rules_source={} ({}) from {}",
                debug_source(source),
                source.collapsed(),
                dir.display()
            );
            Ok(data)
        }
        None => {
            let data = load_embedded()?;
            eprintln!(
                "apohara-compliance-scanner: rules_source={} ({}) [build-time embedded copy]",
                debug_source(RulesSource::EmbeddedFallback),
                RulesSource::EmbeddedFallback.collapsed()
            );
            Ok(data)
        }
    }
}

/// Walk the ladder (steps 1–3) and return the first existing rules dir + which
/// step matched. Returns `None` if no on-disk dir resolves (caller uses embedded).
fn resolve_dir(cli_dir: Option<&Path>) -> Option<(PathBuf, RulesSource)> {
    // (1) --rules-dir
    if let Some(dir) = cli_dir {
        if is_rules_dir(dir) {
            return Some((dir.to_path_buf(), RulesSource::CliDir));
        }
    }
    // (2) APOHARA_RULES_DIR
    if let Some(env_dir) = std::env::var_os("APOHARA_RULES_DIR") {
        let dir = PathBuf::from(env_dir);
        if is_rules_dir(&dir) {
            return Some((dir, RulesSource::EnvDir));
        }
    }
    // (3) current_exe()-relative: a sibling `references/` or one directory up.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            for candidate in [exe_dir.join("references"), exe_dir.join("../references")] {
                if is_rules_dir(&candidate) {
                    return Some((candidate, RulesSource::ExeRelative));
                }
            }
        }
    }
    None
}

/// A directory qualifies as a rules dir if the detection-rules file is present
/// (the minimal marker; full validation happens on load).
fn is_rules_dir(dir: &Path) -> bool {
    dir.join(DETECTION_FILE).is_file()
}

/// Load + validate every rule file from a resolved directory (file-path mode:
/// schema mismatch is a hard error).
fn load_from_dir(dir: &Path, source: RulesSource) -> Result<RuleData, RulesError> {
    let asi: AsiSet = read_yaml(dir, ASI_FILE)?;
    let ast: AstSet = read_yaml(dir, AST_FILE)?;
    let atlas: AtlasSet = read_yaml(dir, ATLAS_FILE)?;
    let iso42001: Iso42001Set = read_yaml(dir, ISO42001_FILE)?;
    let eu_ai_act: EuAiActSet = read_yaml(dir, EU_AI_ACT_FILE)?;
    let controls: ControlSet = read_yaml(dir, CONTROLS_FILE)?;
    let crosswalk: CrosswalkSet = read_yaml(dir, CROSSWALK_FILE)?;
    let detection: DetectionRuleSet = read_yaml(dir, DETECTION_FILE)?;
    Ok(RuleData {
        source,
        asi,
        ast,
        atlas,
        iso42001,
        eu_ai_act,
        controls,
        crosswalk,
        detection,
    })
}

/// Load every rule set from the build-time embedded copies (final fallback).
///
/// The embedded bytes are sourced from the canonical references at build time,
/// so they are authoritative by construction. We still assert their headers
/// match `SCHEMA_VERSION`: a drift between the binary's `SCHEMA_VERSION` and its
/// own embedded copy is a build-integrity bug, not a stale-on-disk situation.
pub fn load_embedded() -> Result<RuleData, RulesError> {
    let asi: AsiSet = parse_yaml(EMBEDDED_ASI, ASI_FILE)?;
    let ast: AstSet = parse_yaml(EMBEDDED_AST, AST_FILE)?;
    let atlas: AtlasSet = parse_yaml(EMBEDDED_ATLAS, ATLAS_FILE)?;
    let iso42001: Iso42001Set = parse_yaml(EMBEDDED_ISO42001, ISO42001_FILE)?;
    let eu_ai_act: EuAiActSet = parse_yaml(EMBEDDED_EU_AI_ACT, EU_AI_ACT_FILE)?;
    let controls: ControlSet = parse_yaml(EMBEDDED_CONTROLS, CONTROLS_FILE)?;
    let crosswalk: CrosswalkSet = parse_yaml(EMBEDDED_CROSSWALK, CROSSWALK_FILE)?;
    let detection: DetectionRuleSet = parse_yaml(EMBEDDED_DETECTION, DETECTION_FILE)?;
    Ok(RuleData {
        source: RulesSource::EmbeddedFallback,
        asi,
        ast,
        atlas,
        iso42001,
        eu_ai_act,
        controls,
        crosswalk,
        detection,
    })
}

/// Read + schema-check + deserialize a single YAML file from a directory.
fn read_yaml<T>(dir: &Path, file: &str) -> Result<T, RulesError>
where
    T: serde::de::DeserializeOwned,
{
    let path = dir.join(file);
    let text = std::fs::read_to_string(&path).map_err(|source| RulesError::Io {
        file: path.display().to_string(),
        source,
    })?;
    parse_yaml(&text, &path.display().to_string())
}

/// Schema-check (against the compiled-in `SCHEMA_VERSION`) then deserialize.
///
/// The schema check runs for BOTH file and embedded inputs; for file inputs a
/// mismatch is the loud failure path (no silent fallback) the plan mandates.
fn parse_yaml<T>(text: &str, file: &str) -> Result<T, RulesError>
where
    T: serde::de::DeserializeOwned,
{
    let header: SchemaHeader = serde_norway::from_str(text).map_err(|source| RulesError::Parse {
        file: file.to_string(),
        source,
    })?;
    if header.schema_version != SCHEMA_VERSION {
        return Err(RulesError::SchemaMismatch {
            file: file.to_string(),
            expected: SCHEMA_VERSION,
            found: header.schema_version,
        });
    }
    serde_norway::from_str(text).map_err(|source| RulesError::Parse {
        file: file.to_string(),
        source,
    })
}

/// Human-readable kebab name for a `RulesSource` (stderr/logging).
fn debug_source(source: RulesSource) -> &'static str {
    match source {
        RulesSource::CliDir => "cli-dir",
        RulesSource::EnvDir => "env-dir",
        RulesSource::ExeRelative => "exe-relative",
        RulesSource::EmbeddedFallback => "embedded-fallback",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Canonical `references/` dir, vendored inside the crate (CARGO_MANIFEST_DIR
    /// = crates/scanner). The repo-root `references/` is a symlink to this.
    fn canonical_references_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("references")
    }

    /// Copy the canonical references into a temp dir so tests can mutate a header
    /// without touching the real (US-002-owned) files.
    fn copy_references_to(dir: &Path) {
        let src = canonical_references_dir();
        for file in [
            ASI_FILE,
            AST_FILE,
            ATLAS_FILE,
            ISO42001_FILE,
            EU_AI_ACT_FILE,
            CONTROLS_FILE,
            CROSSWALK_FILE,
            DETECTION_FILE,
        ] {
            fs::copy(src.join(file), dir.join(file))
                .unwrap_or_else(|e| panic!("copy {file}: {e}"));
        }
    }

    /// Guards against parallel tests racing on the shared APOHARA_RULES_DIR env
    /// var. Rust runs unit tests in parallel; ladder tests mutate process env, so
    /// they must be serialized.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn embedded_copy_loads_and_matches_schema_version() {
        // Embedded copy is always loadable and on the compiled schema version.
        let data = load_embedded().expect("embedded rules load");
        assert_eq!(data.source, RulesSource::EmbeddedFallback);
        assert_eq!(data.detection.schema_version, SCHEMA_VERSION);
        assert_eq!(
            data.detection.rules.len(),
            27,
            "27 AGT-* rules expected (19 single-action + AGT-MIS-004 shell (ADR-5 S1) + \
             AGT-MEM-001 sequence (ADR-2) + AGT-TRJ-001/002/003 taint rules (ADR-4) + \
             AGT-TRJ-001/002/003-P provenance-gated taint variants (ADR-7 / v2.3))"
        );
        assert_eq!(data.asi.risks.len(), 10, "ASI01..ASI10");
        assert_eq!(data.controls.controls.len(), 49, "49 controls");
        // US-F2-1: the MITRE ATLAS coverage layer loads at version 5.6.0 and
        // every carried technique id is an `AML.T####` (optionally `.###`).
        assert_eq!(data.atlas.version, "5.6.0", "ATLAS data version 5.6.0");
        assert!(!data.atlas.techniques.is_empty(), "ATLAS techniques present");
        let atlas_id = regex::Regex::new(r"^AML\.T\d{4}(\.\d{3})?$").unwrap();
        for t in &data.atlas.techniques {
            assert!(atlas_id.is_match(&t.id), "ATLAS id {} malformed", t.id);
            assert_eq!(t.status, "official", "{} status must be official", t.id);
        }
        // The required prompt-injection technique is carried (RAC-2.1).
        assert!(
            data.atlas.techniques.iter().any(|t| t.id == "AML.T0051"),
            "AML.T0051 LLM Prompt Injection must be carried"
        );
        // US-F2-2: the ISO/IEC 42001:2023 Annex A coverage layer loads at
        // framework "ISO/IEC 42001" / version "2023" and every carried control id
        // is an `ISO42001:A.#.#(.#)`.
        assert_eq!(data.iso42001.framework, "ISO/IEC 42001", "ISO 42001 framework");
        assert_eq!(data.iso42001.version, "2023", "ISO 42001 version 2023");
        assert_eq!(data.iso42001.status, "official", "ISO 42001 layer status");
        assert!(!data.iso42001.controls.is_empty(), "ISO 42001 controls present");
        let iso_id = regex::Regex::new(r"^ISO42001:A\.\d+\.\d+(\.\d+)?$").unwrap();
        for c in &data.iso42001.controls {
            assert!(iso_id.is_match(&c.id), "ISO 42001 id {} malformed", c.id);
            assert!(!c.objective.is_empty(), "{} missing objective", c.id);
            assert!(!c.paraphrase.is_empty(), "{} missing paraphrase", c.id);
        }
        // The required event-log control is carried (RAC-2.2).
        assert!(
            data.iso42001
                .controls
                .iter()
                .any(|c| c.id == "ISO42001:A.6.2.8"),
            "ISO42001:A.6.2.8 AI system recording of event logs must be carried"
        );
        // US-F2-3: the EU AI Act (Regulation (EU) 2024/1689) Chapter III Section 2
        // article cross-reference layer loads at framework "EU AI Act" / version
        // "Regulation (EU) 2024/1689" and every carried article id is an
        // `EU-AI-ACT:Art-#`.
        assert_eq!(data.eu_ai_act.framework, "EU AI Act", "EU AI Act framework");
        assert_eq!(
            data.eu_ai_act.version, "Regulation (EU) 2024/1689",
            "EU AI Act version"
        );
        assert_eq!(data.eu_ai_act.status, "official", "EU AI Act layer status");
        assert!(
            !data.eu_ai_act.articles.is_empty(),
            "EU AI Act articles present"
        );
        let eu_id = regex::Regex::new(r"^EU-AI-ACT:Art-\d+$").unwrap();
        for a in &data.eu_ai_act.articles {
            assert!(eu_id.is_match(&a.id), "EU AI Act id {} malformed", a.id);
            assert!(!a.title.is_empty(), "{} missing title", a.id);
            assert!(!a.paraphrase.is_empty(), "{} missing paraphrase", a.id);
        }
        // The required Art-10/11/13 (RAC-2.3) are carried — the separate-layer
        // articles the 49-suite omits.
        for id in ["EU-AI-ACT:Art-10", "EU-AI-ACT:Art-11", "EU-AI-ACT:Art-13"] {
            assert!(
                data.eu_ai_act.articles.iter().any(|a| a.id == id),
                "{id} must be carried in the EU AI Act layer"
            );
        }
    }

    #[test]
    fn schema_version_mismatch_on_file_path_returns_err() {
        // A file path whose header declares a different schema_version MUST error
        // (main turns this Err into a non-zero process exit — no silent fallback).
        let tmp = TempDir::new().unwrap();
        copy_references_to(tmp.path());
        // Rewrite the detection file header to a mismatching schema_version.
        let det_path = tmp.path().join(DETECTION_FILE);
        let original = fs::read_to_string(&det_path).unwrap();
        let bumped = original.replace("schema_version: 1", "schema_version: 999");
        assert_ne!(original, bumped, "header replacement must take effect");
        fs::write(&det_path, bumped).unwrap();

        let err = load_from_dir(tmp.path(), RulesSource::CliDir)
            .expect_err("schema mismatch must be an error");
        match err {
            RulesError::SchemaMismatch {
                expected, found, ..
            } => {
                assert_eq!(expected, SCHEMA_VERSION);
                assert_eq!(found, 999);
            }
            other => panic!("expected SchemaMismatch, got {other:?}"),
        }
    }

    #[test]
    fn ladder_cli_dir_wins_over_env_and_embedded() {
        let _guard = ENV_LOCK.lock().unwrap();
        let cli = TempDir::new().unwrap();
        let env = TempDir::new().unwrap();
        copy_references_to(cli.path());
        copy_references_to(env.path());
        std::env::set_var("APOHARA_RULES_DIR", env.path());

        let data = load(Some(cli.path())).expect("load from cli dir");
        assert_eq!(
            data.source,
            RulesSource::CliDir,
            "--rules-dir must win over APOHARA_RULES_DIR"
        );

        std::env::remove_var("APOHARA_RULES_DIR");
    }

    #[test]
    fn ladder_env_dir_wins_when_no_cli_dir() {
        let _guard = ENV_LOCK.lock().unwrap();
        let env = TempDir::new().unwrap();
        copy_references_to(env.path());
        std::env::set_var("APOHARA_RULES_DIR", env.path());

        let data = load(None).expect("load from env dir");
        assert_eq!(
            data.source,
            RulesSource::EnvDir,
            "APOHARA_RULES_DIR must be used when --rules-dir is absent"
        );

        std::env::remove_var("APOHARA_RULES_DIR");
    }

    #[test]
    fn ladder_falls_back_to_embedded_when_nothing_resolves() {
        let _guard = ENV_LOCK.lock().unwrap();
        // No --rules-dir, no env, and a cli path that is NOT a rules dir.
        std::env::remove_var("APOHARA_RULES_DIR");
        let empty = TempDir::new().unwrap();
        // `empty` has no detection-rules.yaml, so step 1 misses; with env unset
        // and (in this environment) no exe-relative references/, the ladder must
        // land on the embedded copy.
        let data = load(Some(empty.path())).expect("embedded fallback");
        assert_eq!(data.source, RulesSource::EmbeddedFallback);
    }

    #[test]
    fn embedded_bytes_equal_canonical_references_on_disk() {
        // Build-time drift test (plan §7 / R6): the include_str!-embedded bytes
        // MUST equal the current canonical references/*.yaml on disk.
        let dir = canonical_references_dir();
        let cases = [
            (EMBEDDED_ASI, ASI_FILE),
            (EMBEDDED_AST, AST_FILE),
            (EMBEDDED_ATLAS, ATLAS_FILE),
            (EMBEDDED_ISO42001, ISO42001_FILE),
            (EMBEDDED_EU_AI_ACT, EU_AI_ACT_FILE),
            (EMBEDDED_CONTROLS, CONTROLS_FILE),
            (EMBEDDED_CROSSWALK, CROSSWALK_FILE),
            (EMBEDDED_DETECTION, DETECTION_FILE),
        ];
        for (embedded, file) in cases {
            let on_disk = fs::read_to_string(dir.join(file))
                .unwrap_or_else(|e| panic!("read canonical {file}: {e}"));
            assert_eq!(
                embedded, on_disk,
                "embedded {file} drifted from canonical references/{file}"
            );
        }
    }
}
