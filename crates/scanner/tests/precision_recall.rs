// Precision / recall harness over the SYNTHETIC labeled corpus (US-F1-5 / RAC-1.5).
//
// This is a CI GATE, not a report. `cargo test` runs the REAL compiled scanner
// (driven via CARGO_BIN_EXE_*, exactly like integration.rs — the binary is the
// only public surface) over every item in `tests/corpus/expected.json`, compares
// the fired AGT codes against the committed ground truth, and FAILS the test if:
//
//   * precision < PRECISION_FLOOR (0.85), OR
//   * recall    < the measured SUBSTRING BASELINE recall (no recall regression
//     vs. the Fase-0 substring matcher), OR
//   * the corpus is smaller than the pinned minimum (so a tiny corpus cannot
//     trivially score 1.0).
//
// To make the recall floor meaningful we ALSO measure a substring baseline in
// this harness: a plain case-insensitive `contains` of every rule signal over
// the same corpus (no word boundaries, no source scoping, no context DSL — i.e.
// the pre-US-F0-2 matcher). The tuned engine must not regress recall vs. that.
//
// HONESTY: these are SYNTHETIC-FIXTURE metrics, not real-world accuracy. The
// corpus is 100% crafted (no private ~/.claude sessions). Real-session metrics
// are non-gating, uncommitted, and a developer may note them locally. See
// `references/validation-log.md`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use serde::Deserialize;

// ---- Committed CI floors (the gate) -----------------------------------------

/// Hard precision floor on the synthetic corpus. Below this `cargo test` FAILS.
const PRECISION_FLOOR: f64 = 0.85;
/// Minimum FP-trap items — a tiny corpus cannot trivially hit precision 1.0.
const MIN_FP_TRAPS: usize = 30;
/// Minimum true-positive items — a tiny corpus cannot trivially hit recall 1.0.
const MIN_TRUE_POSITIVES: usize = 20;

// ---- Corpus schema (mirror of tests/corpus/expected.json) -------------------

#[derive(Debug, Deserialize)]
struct Corpus {
    min_fp_traps: usize,
    min_true_positives: usize,
    items: Vec<Item>,
}

#[derive(Debug, Deserialize)]
struct Item {
    id: String,
    /// "session-bash" | "session-read" | "repo-file".
    kind: String,
    input: String,
    /// repo-file items only: the on-disk file name the snippet gets.
    #[serde(default)]
    file_name: Option<String>,
    /// Ground truth — empty for an FP-trap.
    expected_agt_codes: Vec<String>,
}

// ---- Paths ------------------------------------------------------------------

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_apohara-compliance-scanner"))
}

/// Repo-root `references/` (CARGO_MANIFEST_DIR = crates/scanner). The corpus
/// ground truth was labeled against these canonical rules, so the harness pins
/// `--rules-dir` to them for determinism.
fn references_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../references")
}

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/expected.json")
}

fn load_corpus() -> Corpus {
    let text = std::fs::read_to_string(corpus_path()).expect("read tests/corpus/expected.json");
    serde_json::from_str(&text).expect("parse corpus JSON")
}

// ---- Engine runner: drive the REAL compiled scanner -------------------------

/// Run the real scanner on one item and return the set of fired AGT codes.
fn engine_fired(item: &Item) -> Vec<String> {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let rules = references_dir();
    let rules_arg = rules.to_string_lossy().into_owned();

    let output = match item.kind.as_str() {
        "repo-file" => {
            let name = item
                .file_name
                .as_deref()
                .unwrap_or_else(|| panic!("repo-file item {} needs file_name", item.id));
            std::fs::write(tmp.path().join(name), format!("{}\n", item.input))
                .expect("write repo-file snippet");
            run_json(&[
                "--rules-dir",
                &rules_arg,
                "scan-repo",
                &tmp.path().to_string_lossy(),
                "--format",
                "json",
            ])
        }
        "session-bash" | "session-read" => {
            let (tool, field) = if item.kind == "session-bash" {
                ("Bash", "command")
            } else {
                ("Read", "file_path")
            };
            // Build one assistant tool_use line — the parse_session.rs shape.
            let line = serde_json::json!({
                "type": "assistant",
                "message": { "content": [
                    { "type": "tool_use", "name": tool, "input": { field: item.input } }
                ]}
            })
            .to_string();
            let path = tmp.path().join("session.jsonl");
            std::fs::write(&path, format!("{line}\n")).expect("write session jsonl");
            run_json(&[
                "--rules-dir",
                &rules_arg,
                "scan-session",
                &path.to_string_lossy(),
                "--format",
                "json",
            ])
        }
        other => panic!("item {} has unknown kind {other:?}", item.id),
    };

    let v: serde_json::Value = serde_json::from_str(&output).expect("scanner emits valid JSON");
    let mut codes: Vec<String> = v["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .filter_map(|f| f["id"].as_str().map(str::to_string))
        .collect();
    codes.sort_unstable();
    codes.dedup();
    codes
}

/// Run the binary with args and return stdout (panicking with stderr on failure).
fn run_json(args: &[&str]) -> String {
    let out = Command::new(bin()).args(args).output().expect("binary runs");
    assert!(
        out.status.success(),
        "scanner exited non-zero for {args:?}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

// ---- Substring baseline (the pre-US-F0-2 matcher, for the recall floor) ------

/// `detection-rules.yaml` — just enough to pull every (agt_code, signal) pair.
#[derive(Debug, Deserialize)]
struct DetectionFile {
    rules: Vec<DetectionRuleLite>,
}

#[derive(Debug, Deserialize)]
struct DetectionRuleLite {
    agt_code: String,
    signals: Vec<String>,
}

/// Load every (agt_code, signal) pair from the canonical detection-rules.yaml.
fn load_signal_map() -> Vec<(String, String)> {
    let text = std::fs::read_to_string(references_dir().join("detection-rules.yaml"))
        .expect("read detection-rules.yaml");
    let parsed: DetectionFile = serde_norway::from_str(&text).expect("parse detection-rules.yaml");
    parsed
        .rules
        .into_iter()
        .flat_map(|r| {
            let code = r.agt_code;
            r.signals.into_iter().map(move |s| (code.clone(), s))
        })
        .collect()
}

/// The Fase-0 baseline matcher: a plain case-insensitive `contains` of each
/// signal over the item input — NO word boundaries, NO source scoping, NO
/// context DSL. This approximates the original substring matcher (matching.rs:57
/// pre-US-F0-2) so the harness can pin the recall floor at its baseline.
fn baseline_fired(item: &Item, signals: &[(String, String)]) -> Vec<String> {
    let hay = item.input.to_lowercase();
    let mut codes: Vec<String> = signals
        .iter()
        .filter(|(_, sig)| hay.contains(&sig.to_lowercase()))
        .map(|(code, _)| code.clone())
        .collect();
    codes.sort_unstable();
    codes.dedup();
    codes
}

// ---- Metrics ----------------------------------------------------------------

#[derive(Debug, Default, Clone, Copy)]
struct Counts {
    tp: usize,
    fp: usize,
    fn_: usize,
}

impl Counts {
    fn precision(&self) -> f64 {
        if self.tp + self.fp == 0 {
            1.0
        } else {
            self.tp as f64 / (self.tp + self.fp) as f64
        }
    }
    fn recall(&self) -> f64 {
        if self.tp + self.fn_ == 0 {
            1.0
        } else {
            self.tp as f64 / (self.tp + self.fn_) as f64
        }
    }
}

/// Accumulate overall + per-rule TP/FP/FN given a per-item "fired codes" fn.
fn score(corpus: &Corpus, mut fired: impl FnMut(&Item) -> Vec<String>) -> (Counts, BTreeMap<String, Counts>) {
    let mut overall = Counts::default();
    let mut per_rule: BTreeMap<String, Counts> = BTreeMap::new();
    for item in &corpus.items {
        let got = fired(item);
        let exp = &item.expected_agt_codes;
        // True positives: codes in both expected and got.
        for code in exp.iter().filter(|c| got.contains(c)) {
            overall.tp += 1;
            per_rule.entry(code.clone()).or_default().tp += 1;
        }
        // False positives: codes fired but not expected.
        for code in got.iter().filter(|c| !exp.contains(c)) {
            overall.fp += 1;
            per_rule.entry(code.clone()).or_default().fp += 1;
        }
        // False negatives: codes expected but not fired.
        for code in exp.iter().filter(|c| !got.contains(c)) {
            overall.fn_ += 1;
            per_rule.entry(code.clone()).or_default().fn_ += 1;
        }
    }
    (overall, per_rule)
}

// ---- The gate ---------------------------------------------------------------

#[test]
fn synthetic_corpus_precision_recall_gate() {
    let corpus = load_corpus();
    let signals = load_signal_map();

    // (1) Corpus-size floor — a tiny corpus cannot trivially hit 1.0.
    let fp_traps = corpus
        .items
        .iter()
        .filter(|i| i.expected_agt_codes.is_empty())
        .count();
    let true_positives = corpus.items.len() - fp_traps;
    // The pinned constants are the authority; the JSON mins must agree with them
    // (a drift guard so the corpus file and the gate cannot disagree silently).
    assert_eq!(
        corpus.min_fp_traps, MIN_FP_TRAPS,
        "corpus min_fp_traps must equal the pinned MIN_FP_TRAPS"
    );
    assert_eq!(
        corpus.min_true_positives, MIN_TRUE_POSITIVES,
        "corpus min_true_positives must equal the pinned MIN_TRUE_POSITIVES"
    );
    assert!(
        fp_traps >= MIN_FP_TRAPS,
        "corpus too small: {fp_traps} FP-traps < pinned minimum {MIN_FP_TRAPS}"
    );
    assert!(
        true_positives >= MIN_TRUE_POSITIVES,
        "corpus too small: {true_positives} true-positive items < pinned minimum {MIN_TRUE_POSITIVES}"
    );

    // (2) Measure the SUBSTRING BASELINE first (it sets the recall floor).
    let (base, _base_per_rule) = score(&corpus, |i| baseline_fired(i, &signals));
    // (3) Measure the TUNED ENGINE.
    let (eng, eng_per_rule) = score(&corpus, engine_fired);

    // Human-readable record (captured by `cargo test -- --nocapture`).
    eprintln!("== US-F1-5 synthetic precision/recall ==");
    eprintln!(
        "  corpus: {} items ({fp_traps} FP-traps, {true_positives} true-positives)",
        corpus.items.len()
    );
    eprintln!(
        "  SUBSTRING BASELINE: precision={:.4} recall={:.4} (TP={} FP={} FN={})",
        base.precision(),
        base.recall(),
        base.tp,
        base.fp,
        base.fn_
    );
    eprintln!(
        "  TUNED ENGINE      : precision={:.4} recall={:.4} (TP={} FP={} FN={})",
        eng.precision(),
        eng.recall(),
        eng.tp,
        eng.fp,
        eng.fn_
    );
    eprintln!("  per-rule (tuned engine):");
    for (code, c) in &eng_per_rule {
        eprintln!(
            "    {code}: precision={:.3} recall={:.3} (TP={} FP={} FN={})",
            c.precision(),
            c.recall(),
            c.tp,
            c.fp,
            c.fn_
        );
    }

    // (4) THE GATE.
    assert!(
        eng.precision() >= PRECISION_FLOOR,
        "PRECISION GATE FAILED: tuned-engine precision {:.4} < floor {PRECISION_FLOOR} \
         (TP={} FP={} FN={}). Do NOT relax the floor to go green — tune the rules or \
         flag the floor with evidence.",
        eng.precision(),
        eng.tp,
        eng.fp,
        eng.fn_
    );
    assert!(
        eng.recall() >= base.recall(),
        "RECALL REGRESSION GATE FAILED: tuned-engine recall {:.4} < substring baseline \
         recall {:.4}. The tuned engine must not miss a true positive the naive \
         substring matcher would have caught.",
        eng.recall(),
        base.recall()
    );
    // A5/M1 (ADR-5): the FP=0 moat is ENFORCED, not merely observed. The synthetic
    // corpus must stay byte-clean — any false positive fails the gate (sanctioned
    // NON-corpus gate-hardening, distinct from the corpus itself).
    assert_eq!(
        eng.fp, 0,
        "FP GATE FAILED: tuned-engine produced {} false positive(s) on the synthetic \
         corpus (TP={} FN={}). The FP=0 moat is enforced — fix the rule that overfires, \
         do NOT relax this assertion.",
        eng.fp, eng.tp, eng.fn_
    );
}
