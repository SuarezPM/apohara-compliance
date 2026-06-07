// INDEPENDENT CORPUS — non-gating (v1.4 HYBRID 2+3).
//
// Drives the REAL compiled scanner over the AgentDojo independent corpus
// (tests/corpus/agentdojo/) and PRINTS per-category recall + a baseline->tuned
// delta. It is `#[ignore]` on purpose: it is NEVER part of the CI gate and carries
// NO `assert!` on recall (a non-`#[ignore]` recall assert would silently become a
// second gate — see ADR / consensus item 5). The only assertions are liveness:
// the corpus is non-empty and every scan returns valid JSON.
//
// HONESTY (the v1.4 category caveat): an AgentDojo injection is untrusted DATA the
// agent reads (bait), not the agent's own action. Representing each GOAL as the
// agent's own tool input measures BAIT-KEYWORD SURFACE COVERAGE, NOT
// injection-consequence detection. See tests/corpus/agentdojo/SOURCE.md + BENCHMARK.md.
//
// Run manually:
//   cargo test -p apohara-compliance-scanner --test independent_corpus -- --ignored --nocapture

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Corpus {
    items: Vec<Item>,
}

#[derive(Debug, Deserialize)]
struct Item {
    id: String,
    #[serde(default)]
    category: String,
    /// The attacker GOAL prose, scanned as a synthetic chat-tool action input.
    input: String,
    expected_agt_codes: Vec<String>,
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_apohara-compliance-scanner"))
}

fn references_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../references")
}

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/agentdojo/expected.json")
}

/// One row of recall accounting.
#[derive(Default, Clone, Copy)]
struct Tally {
    n: usize,
    hits: usize,
}
impl Tally {
    fn rate(&self) -> f64 {
        if self.n == 0 {
            0.0
        } else {
            self.hits as f64 / self.n as f64
        }
    }
}

/// Fire the engine on one item via the B1 synthetic chat-tool action shape.
/// Returns the set of fired AGT codes (deduped).
fn engine_fired(item: &Item) -> Vec<String> {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let line = serde_json::json!({
        "type": "assistant",
        "message": { "content": [
            { "type": "tool_use", "name": "AgentChatMessage", "input": { "prompt": item.input } }
        ]}
    })
    .to_string();
    let path = tmp.path().join("session.jsonl");
    std::fs::write(&path, format!("{line}\n")).expect("write session jsonl");

    let rules = references_dir();
    let out = Command::new(bin())
        .args([
            "--rules-dir",
            &rules.to_string_lossy(),
            "scan-session",
            &path.to_string_lossy(),
            "--format",
            "json",
        ])
        .output()
        .expect("binary runs");
    assert!(
        out.status.success(),
        "scanner exited non-zero for {}\nstderr:\n{}",
        item.id,
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("scanner emits valid JSON");
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

/// Substring baseline: would a naive contains-match of the SAME rule signals fire any
/// expected code? Reads the rule signals from detection-rules.yaml so the printed
/// delta (baseline -> tuned) is honest, mirroring precision_recall.rs's approach.
fn baseline_fired(item: &Item, signals_by_code: &BTreeMap<String, Vec<String>>) -> Vec<String> {
    let hay = item.input.to_lowercase();
    let mut codes: Vec<String> = signals_by_code
        .iter()
        .filter(|(_, sigs)| sigs.iter().any(|s| hay.contains(&s.to_lowercase())))
        .map(|(code, _)| code.clone())
        .collect();
    codes.sort_unstable();
    codes.dedup();
    codes
}

/// Load `agt_code -> [signals]` from the canonical rules file for the baseline.
fn load_signals() -> BTreeMap<String, Vec<String>> {
    let path = references_dir().join("detection-rules.yaml");
    let text = std::fs::read_to_string(&path).expect("read detection-rules.yaml");
    let doc: serde_json::Value = serde_norway::from_str(&text).expect("parse rules yaml");
    let mut map = BTreeMap::new();
    if let Some(rules) = doc["rules"].as_array() {
        for r in rules {
            if let Some(code) = r["agt_code"].as_str() {
                let sigs: Vec<String> = r["signals"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                map.insert(code.to_string(), sigs);
            }
        }
    }
    map
}

fn hit(fired: &[String], expected: &[String]) -> bool {
    fired.iter().any(|c| expected.contains(c))
}

#[test]
#[ignore = "non-gating independent corpus; run with --ignored --nocapture"]
fn agentdojo_independent_corpus_recall() {
    let text = std::fs::read_to_string(corpus_path()).expect("read agentdojo expected.json");
    let corpus: Corpus = serde_json::from_str(&text).expect("parse agentdojo corpus");
    assert!(!corpus.items.is_empty(), "agentdojo corpus is empty"); // liveness only

    let signals = load_signals();

    let mut overall_tuned = Tally::default();
    let mut overall_base = Tally::default();
    let mut by_cat_tuned: BTreeMap<String, Tally> = BTreeMap::new();
    let mut by_cat_base: BTreeMap<String, Tally> = BTreeMap::new();

    for item in &corpus.items {
        let fired = engine_fired(item);
        let base = baseline_fired(item, &signals);
        let h_t = hit(&fired, &item.expected_agt_codes);
        let h_b = hit(&base, &item.expected_agt_codes);

        overall_tuned.n += 1;
        overall_tuned.hits += h_t as usize;
        overall_base.n += 1;
        overall_base.hits += h_b as usize;

        let cat = if item.category.is_empty() {
            "uncategorized".to_string()
        } else {
            item.category.clone()
        };
        let ct = by_cat_tuned.entry(cat.clone()).or_default();
        ct.n += 1;
        ct.hits += h_t as usize;
        let cb = by_cat_base.entry(cat).or_default();
        cb.n += 1;
        cb.hits += h_b as usize;
    }

    eprintln!("== INDEPENDENT CORPUS — non-gating (AgentDojo, v1.4) ==");
    eprintln!("   measures BAIT-KEYWORD SURFACE COVERAGE, NOT injection-consequence detection");
    eprintln!(
        "   OVERALL recall: baseline={:.4} ({}/{})  tuned={:.4} ({}/{})  delta={:+.4}",
        overall_base.rate(),
        overall_base.hits,
        overall_base.n,
        overall_tuned.rate(),
        overall_tuned.hits,
        overall_tuned.n,
        overall_tuned.rate() - overall_base.rate(),
    );
    eprintln!("   per-category (baseline -> tuned):");
    for (cat, t) in &by_cat_tuned {
        let b = by_cat_base.get(cat).copied().unwrap_or_default();
        eprintln!(
            "     {cat:<34} base={:.3} ({}/{})  tuned={:.3} ({}/{})  delta={:+.3}",
            b.rate(),
            b.hits,
            b.n,
            t.rate(),
            t.hits,
            t.n,
            t.rate() - b.rate(),
        );
    }
    // NO recall assert — this harness is documentation, never a gate.
}
