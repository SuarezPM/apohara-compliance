// TRAJECTORY CORPUS — non-gating (v2.0 / ADR-4).
//
// Drives the REAL compiled scanner over multi-action trajectory fixtures and PRINTS
// the AGT-TRJ findings per fixture. It is `#[ignore]` on purpose: NEVER part of the
// CI gate, NO recall/precision assert that could become a second gate. The only
// assertions are liveness (the binary runs, emits valid JSON, the corpus is
// non-empty). The committed synthetic positives prove the engine MECHANISM fires;
// the FinBot fixture is a NEGATIVE CONTROL (direct-injection refusals → zero AGT-TRJ).
//
// HONESTY (ADR-4): a fired AGT-TRJ is a CANDIDATE injection→consequence CORRELATION,
// post-hoc over a transcript — NOT proof of causation, NOT inline prevention. The
// real-world (AgentDojo+MiniMax, Phase 5A) numbers are reported separately in
// BENCHMARK.md with the bound triple (attack-success-rate + k-of-N + failed-injection
// FP) and the template-scoped caveat — never as unqualified "efficacy".
//
// Run manually:
//   cargo test -p apohara-compliance-scanner --test trajectory_corpus -- --ignored --nocapture

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_apohara-compliance-scanner"))
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

/// Scan one trajectory fixture; return the fired AGT-TRJ codes (deduped, sorted).
fn agt_trj(file: &str) -> Vec<String> {
    let path = fixtures().join(file);
    let out = Command::new(bin())
        .args(["scan-session", &path.to_string_lossy(), "--format", "json"])
        .output()
        .expect("binary runs");
    assert!(out.status.success(), "scan-session {file} exited non-zero");
    let v: Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    let mut ids: Vec<String> = v["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .filter_map(|f| f["id"].as_str())
        .filter(|id| id.starts_with("AGT-TRJ"))
        .map(str::to_string)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

#[test]
#[ignore = "non-gating trajectory corpus; run with --ignored --nocapture"]
fn trajectory_corpus_report() {
    let positives = [
        "trj001-exfil-positive.jsonl",
        "trj002-destructive-positive.jsonl",
        "trj003-financial-positive.jsonl",
        // ADR-5 (WS1, AC2.3): the representation-aware structured-sink positive — a
        // generic marker on tool-result: → a structured `sink:` send_money action.
        "trj-representation-aware-positive.jsonl",
    ];

    eprintln!("== TRAJECTORY CORPUS — non-gating (v2.0 / ADR-4) ==");
    eprintln!("   CANDIDATE injection→consequence correlation; post-hoc, NOT prevention.");
    eprintln!("   -- committed synthetic positives (mechanism proof-of-life) --");
    let mut fired = 0usize;
    for f in &positives {
        let ids = agt_trj(f);
        eprintln!("     {f:<34} AGT-TRJ: {ids:?}");
        fired += usize::from(!ids.is_empty());
    }
    eprintln!("   synthetic positives firing: {fired}/{}", positives.len());

    eprintln!("   -- benign trajectory (must be empty) --");
    let benign = agt_trj("trj-benign-negative.jsonl");
    eprintln!("     trj-benign-negative.jsonl          AGT-TRJ: {benign:?}");

    // M2 structured-sink benign FP-trap (must be empty): internal recipient, no amount.
    let sink_trap = agt_trj("trj-structured-sink-benign-trap.jsonl");
    eprintln!("     trj-structured-sink-benign-trap    AGT-TRJ: {sink_trap:?} (expect [])");

    // FinBot DIRECT-injection fixture = negative control (uncommitted in some checkouts).
    let finbot = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/corpus/finbot/raw/finbot-1780783524-finbot-attack.jsonl");
    if finbot.exists() {
        let out = Command::new(bin())
            .args(["scan-session", &finbot.to_string_lossy(), "--format", "json"])
            .output()
            .expect("binary runs");
        let v: Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
        let trj: Vec<&str> = v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["id"].as_str())
            .filter(|id| id.starts_with("AGT-TRJ"))
            .collect();
        eprintln!("   -- finbot NEGATIVE CONTROL (direct injection, refusals) --");
        eprintln!("     finbot-*.jsonl                     AGT-TRJ: {trj:?} (expect [])");
    } else {
        eprintln!("   (finbot negative-control fixture absent in this checkout — skipped)");
    }

    eprintln!("   NOTE: real-world (AgentDojo+MiniMax) numbers — see BENCHMARK.md (Phase 5A),");
    eprintln!("         reported as the bound triple, post-hoc + template-scoped (never 'efficacy').");

    // Liveness only (this test is #[ignore], never a CI gate): the end-to-end harness
    // ran the real binary and at least one committed synthetic positive was recognized.
    // This is NOT a recall floor — it only proves the harness is wired, like
    // independent_corpus.rs's liveness assert.
    assert!(fired >= 1, "harness liveness: expected ≥1 synthetic positive to fire");
}
