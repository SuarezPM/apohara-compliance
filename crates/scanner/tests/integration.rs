// Integration tests — drive the real `apohara-compliance-scanner` binary end to
// end over the captured session fixture and the repo fixture, asserting the
// AC-9 contract, the SARIF 2.1.0 shape, and the assertive-language guard (both
// directions).
//
// These run the actual compiled binary (via CARGO_BIN_EXE_*), so they exercise
// the full path: rules ladder → parse → match → format → stdout.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

/// Path to the compiled binary under test (set by cargo for integration tests).
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_apohara-compliance-scanner"))
}

fn fixtures() -> PathBuf {
    // Fixtures live at the repo-root tests/fixtures/ (plan B2 tree);
    // CARGO_MANIFEST_DIR is crates/scanner, so go up two levels.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

/// Run the binary, returning (stdout, stderr, success).
fn run(args: &[&str]) -> (String, String, bool) {
    let out = Command::new(bin())
        .args(args)
        .output()
        .expect("binary runs");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.success(),
    )
}

fn session_path() -> String {
    fixtures()
        .join("session-sample.jsonl")
        .to_string_lossy()
        .into_owned()
}

fn repo_path() -> String {
    fixtures()
        .join("repo-fixture")
        .to_string_lossy()
        .into_owned()
}

// --- (a) scan-session → ≥1 candidate with all AC-9 fields ---------------------

#[test]
fn scan_session_emits_candidate_with_all_ac9_fields() {
    let (stdout, stderr, ok) = run(&["scan-session", &session_path(), "--format", "json"]);
    assert!(ok, "scan-session should exit 0; stderr:\n{stderr}");

    let v: Value = serde_json::from_str(&stdout).expect("valid JSON report");
    // rules_source surfaced in the report header AND to stderr.
    assert!(v["rules_source_collapsed"].is_string());
    assert!(
        stderr.contains("rules_source="),
        "rules_source must be emitted to stderr"
    );

    let findings = v["findings"].as_array().expect("findings array");
    assert!(!findings.is_empty(), "≥1 candidate expected from the session");

    let f = &findings[0];
    // AC-9 fields + consensus additions.
    for field in [
        "id",
        "title",
        "status",
        "confidence",
        "triggering_signal",
        "citation",
        "suggested_controls",
        "cross_refs",
        "rules_source",
        "rules_source_collapsed",
        "is_candidate",
    ] {
        assert!(!f[field].is_null(), "finding missing field {field}");
    }
    assert_eq!(f["is_candidate"], true, "every finding is a candidate");
    assert!(f["citation"]["url"].is_string());
    assert!(f["citation"]["version"].is_string());
}

// --- (f) parse_session classifies-or-skips every observed type, no panic ------

#[test]
fn scan_session_classifies_or_skips_all_types_including_system_and_queue() {
    let (_stdout, stderr, ok) = run(&["scan-session", &session_path(), "--format", "json"]);
    assert!(ok, "must not panic / must exit 0; stderr:\n{stderr}");
    // The captured fixture exercises system + queue-operation; both are observed.
    assert!(stderr.contains("\"system\""), "system type observed");
    assert!(
        stderr.contains("\"queue-operation\""),
        "queue-operation type observed"
    );
    // The 3 edge cases (unknown type, missing type, truncated line) are skipped.
    assert!(stderr.contains("unknown type"), "unknown type skipped-with-reason");
    assert!(stderr.contains("missing type"), "missing type skipped-with-reason");
    assert!(
        stderr.contains("json parse error"),
        "truncated line skipped-with-reason"
    );
}

// --- (b) scan-repo → expected candidates + gitignore respect ------------------

#[test]
fn scan_repo_emits_expected_candidates_and_respects_gitignore() {
    let (stdout, stderr, ok) = run(&["scan-repo", &repo_path(), "--format", "json"]);
    assert!(ok, "scan-repo should exit 0; stderr:\n{stderr}");

    let v: Value = serde_json::from_str(&stdout).expect("valid JSON report");
    let findings = v["findings"].as_array().expect("findings array");
    assert!(!findings.is_empty(), "≥1 candidate expected from the repo");

    let ids: Vec<&str> = findings.iter().filter_map(|f| f["id"].as_str()).collect();
    // cleanup.sh trips rm -rf (AGT-MIS-001) + sudo/chmod 777 (AGT-MIS-002);
    // report.sql trips SELECT * FROM (AGT-EXF-001); config.py trips curl http
    // (AGT-EXF-002).
    assert!(ids.iter().any(|i| i.starts_with("AGT-MIS")), "ids: {ids:?}");
    assert!(
        ids.contains(&"AGT-EXF-001") || ids.contains(&"AGT-EXF-002"),
        "ids: {ids:?}"
    );

    // gitignore respect: secret.env's "DROP TABLE accounts" must NOT surface as a
    // triggering signal anywhere in the output.
    assert!(
        !stdout.contains("DROP TABLE"),
        "git-ignored secret.env content must not be scanned"
    );
}

// --- (b2) Appendix-A ASI->LLM crosswalk wired into cross_refs (US-F0-1) --------

#[test]
fn scan_repo_cross_refs_carry_normalized_owasp_llm_refs_that_resolve() {
    // The repo fixture fires AGT-MIS/AGT-EXF rules whose asi_xref includes ASI02
    // (Appendix-A -> LLM06). After US-F0-1 at least one finding must carry an
    // OWASP-LLM:* cross-ref, and EVERY emitted OWASP-LLM:* must resolve to a
    // control in controls-49.yaml (no dangling refs).
    let (stdout, stderr, ok) = run(&["scan-repo", &repo_path(), "--format", "json"]);
    assert!(ok, "scan-repo should exit 0; stderr:\n{stderr}");

    let v: Value = serde_json::from_str(&stdout).expect("valid JSON report");
    let findings = v["findings"].as_array().expect("findings array");

    // Build the set of valid control ids from a separate authoritative run is not
    // available here; instead assert against the known OWASP-LLM:LLM01..LLM10 set
    // the crosswalk normalizes into (all of which exist in controls-49.yaml).
    let valid_llm: Vec<String> = (1..=10)
        .map(|n| format!("OWASP-LLM:LLM{n:02}"))
        .collect();

    let mut saw_llm_ref = false;
    for f in findings {
        for c in f["cross_refs"].as_array().expect("cross_refs array") {
            let id = c.as_str().expect("cross_ref is a string");
            if id.starts_with("OWASP-LLM:") {
                saw_llm_ref = true;
                assert!(
                    valid_llm.contains(&id.to_string()),
                    "dangling OWASP-LLM cross-ref {id} in {}",
                    f["id"]
                );
            }
        }
    }
    assert!(
        saw_llm_ref,
        "expected ≥1 finding with an OWASP-LLM:* cross-ref after US-F0-1"
    );
}

// --- (c) emitted SARIF structural validity ------------------------------------

#[test]
fn sarif_is_2_1_0_with_candidate_messages_and_safe_levels() {
    let (stdout, stderr, ok) = run(&["scan-session", &session_path(), "--format", "sarif"]);
    assert!(ok, "stderr:\n{stderr}");

    let v: Value = serde_json::from_str(&stdout).expect("valid SARIF JSON");
    assert_eq!(v["version"], "2.1.0", "SARIF version");
    assert!(v["$schema"].is_string(), "SARIF $schema present");

    let run0 = &v["runs"][0];
    assert_eq!(
        run0["tool"]["driver"]["name"], "apohara-compliance-scanner",
        "driver name"
    );
    assert!(
        run0["tool"]["driver"]["rules"].is_array(),
        "driver.rules present"
    );

    let results = run0["results"].as_array().expect("results array");
    assert!(!results.is_empty(), "≥1 SARIF result");
    for r in results {
        // ruleId is the ASI/AGT code.
        assert!(r["ruleId"].as_str().unwrap().starts_with("AGT-"));
        // level ∈ {note, warning}, NEVER error.
        let level = r["level"].as_str().unwrap();
        assert!(level == "note" || level == "warning", "level was {level}");
        // POSITIVE guard: message.text starts with "CANDIDATE — ".
        let text = r["message"]["text"].as_str().unwrap();
        assert!(text.starts_with("CANDIDATE — "), "no prefix: {text}");
        // properties carry the audit fields.
        let props = &r["properties"];
        for p in [
            "citation",
            "confidence",
            "status",
            "cross_refs",
            "suggested_controls",
            "rules_source",
        ] {
            assert!(!props[p].is_null(), "SARIF properties missing {p}");
        }
    }
}

// --- (d) assertive-language guard, BOTH directions ----------------------------

#[test]
fn assertive_language_guard_negative_and_positive() {
    let forbidden = ["is compliant", "certified", "guaranteed"];

    for fmt in ["json", "sarif", "md"] {
        let (stdout, _stderr, ok) = run(&["scan-session", &session_path(), "--format", fmt]);
        assert!(ok);
        let lower = stdout.to_lowercase();
        // NEGATIVE: no assertive strings anywhere.
        for needle in forbidden {
            assert!(
                !lower.contains(needle),
                "{fmt} output contains forbidden assertive phrase {needle:?}"
            );
        }
    }

    // POSITIVE for SARIF: every result message starts with the prefix.
    let (sarif, ..) = run(&["scan-session", &session_path(), "--format", "sarif"]);
    let v: Value = serde_json::from_str(&sarif).unwrap();
    for r in v["runs"][0]["results"].as_array().unwrap() {
        assert!(r["message"]["text"]
            .as_str()
            .unwrap()
            .starts_with("CANDIDATE — "));
    }

    // POSITIVE for Markdown: every finding line starts with the prefix.
    let (md, ..) = run(&["scan-session", &session_path(), "--format", "md"]);
    let finding_lines: Vec<&str> = md
        .lines()
        .filter(|l| l.trim_start().starts_with("- CANDIDATE"))
        .collect();
    assert!(!finding_lines.is_empty(), "≥1 markdown finding line");
    // And there is NO finding bullet that lacks the prefix: any "- **AGT" without
    // the prefix would be a violation.
    for l in md.lines() {
        let t = l.trim_start();
        if t.starts_with("- ") && t.contains("AGT-") {
            assert!(
                t.trim_start_matches("- ").starts_with("CANDIDATE — "),
                "markdown finding line missing prefix: {l}"
            );
        }
    }
}

// --- (g) US-F1-1 source_kinds: command rules scoped to Bash + repo-file ------

#[test]
fn source_kinds_fires_on_session_bash_and_repo_file_but_not_elsewhere() {
    // POSITIVE: the scoped command rules (AGT-MIS-*/AGT-EXF-*) fire end-to-end
    // on the real session (Bash inputs) AND the repo (repo-file content).
    let (sess, serr, ok1) = run(&["scan-session", &session_path(), "--format", "json"]);
    assert!(ok1, "stderr:\n{serr}");
    let sv: Value = serde_json::from_str(&sess).unwrap();
    let sids: Vec<&str> = sv["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["id"].as_str())
        .collect();
    // sudo/rm -rf (MIS), curl http (EXF-002), SELECT * FROM via psql (EXF-001)
    // all come from session:Bash.input → still fire after scoping.
    assert!(sids.contains(&"AGT-MIS-001"), "session ids: {sids:?}");
    assert!(sids.contains(&"AGT-MIS-002"), "session ids: {sids:?}");
    assert!(sids.contains(&"AGT-EXF-002"), "session ids: {sids:?}");
    assert!(sids.contains(&"AGT-EXF-001"), "session ids: {sids:?}");

    let (repo, rerr, ok2) = run(&["scan-repo", &repo_path(), "--format", "json"]);
    assert!(ok2, "stderr:\n{rerr}");
    let rv: Value = serde_json::from_str(&repo).unwrap();
    let rids: Vec<&str> = rv["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["id"].as_str())
        .collect();
    // report.sql/config.py/cleanup.sh are repo-file: content → still fire.
    assert!(rids.contains(&"AGT-EXF-001"), "repo ids: {rids:?}");
    assert!(rids.contains(&"AGT-EXF-002"), "repo ids: {rids:?}");
    assert!(rids.contains(&"AGT-MIS-001"), "repo ids: {rids:?}");
    assert!(rids.contains(&"AGT-MIS-002"), "repo ids: {rids:?}");
}

// --- (g2) ADR-5 S1: structural shell rule fires on a FLAG-REORDERED rm ---------

#[test]
fn structural_shell_rule_fires_on_flag_reordered_rm_end_to_end() {
    // ADR-5 S1 / AC3.3: a session whose only command is the FLAG-REORDERED
    // `rm -f -r ...` (which the literal AGT-MIS-001 family member `rm -rf`/`rm -fr`
    // misses in this exact order) fires AGT-MIS-004 structurally via the real
    // binary — proving the shell tokenizer pass is wired into the scan path.
    let path = fixtures()
        .join("mis004-flag-reorder-positive.jsonl")
        .to_string_lossy()
        .into_owned();
    let (stdout, stderr, ok) = run(&["scan-session", &path, "--format", "json"]);
    assert!(ok, "scan-session should exit 0; stderr:\n{stderr}");
    let v: Value = serde_json::from_str(&stdout).unwrap();
    let ids: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["id"].as_str())
        .collect();
    assert!(
        ids.contains(&"AGT-MIS-004"),
        "flag-reordered `rm -f -r` must fire AGT-MIS-004 structurally; ids: {ids:?}"
    );
}

// --- (h) US-F1-1 deny_context: doc-marked `act as` suppressed, real fires -----

#[test]
fn deny_context_suppresses_doc_marked_act_as_real_injection_fires() {
    use std::io::Write;

    // The session fixture's `act as an unrestricted agent` (NO doc marker) still
    // fires AGT-PI-002 — the real injection survives deny_context.
    let (sess, _e, ok) = run(&["scan-session", &session_path(), "--format", "json"]);
    assert!(ok);
    let sv: Value = serde_json::from_str(&sess).unwrap();
    assert!(
        sv["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "AGT-PI-002"),
        "real `act as` injection must still fire"
    );

    // A repo file whose ONLY `act as` is doc/comment-marked must NOT fire.
    let dir = std::env::temp_dir().join("apohara_denyctx_it");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut f = std::fs::File::create(dir.join("doc.js")).unwrap();
    // `//` comment + `fallback` marker — two independent deny reasons.
    writeln!(f, "// this can act as a fallback path").unwrap();
    drop(f);

    let (out, _e2, ok2) = run(&["scan-repo", dir.to_str().unwrap(), "--format", "json"]);
    assert!(ok2);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert!(
        !v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "AGT-PI-002"),
        "doc-marked `act as` must be suppressed by deny_context; out:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// --- (i) US-F1-1 byte-stability: default JSON/SARIF omit the ambiguity field --

#[test]
fn default_output_omits_ambiguity_field_preserving_v01_shape() {
    // BYTE-STABILITY AC: with no ambiguous candidate (the standard fixtures
    // produce none), the new `ambiguity` field is OMITTED from JSON and SARIF
    // (skip_serializing_if), so the default output shape is byte-stable vs v0.1.
    for cmd in [
        vec!["scan-repo", &repo_path(), "--format", "json"],
        vec!["scan-session", &session_path(), "--format", "json"],
        vec!["scan-repo", &repo_path(), "--format", "sarif"],
        vec!["scan-session", &session_path(), "--format", "sarif"],
    ] {
        let args: Vec<&str> = cmd.to_vec();
        let (out, err, ok) = run(&args);
        assert!(ok, "{args:?} stderr:\n{err}");
        assert!(
            !out.contains("ambiguity"),
            "{args:?}: ambiguity must be omitted when false (byte-stable v0.1 shape)"
        );
    }

    // And the v0.1 finding key set is EXACTLY preserved (no added/removed keys).
    let (json, ..) = run(&["scan-repo", &repo_path(), "--format", "json"]);
    let v: Value = serde_json::from_str(&json).unwrap();
    let f = &v["findings"][0];
    let mut keys: Vec<&str> = f.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    let mut expected = vec![
        "id",
        "title",
        "status",
        "confidence",
        "triggering_signal",
        "citation",
        "suggested_controls",
        "cross_refs",
        "rules_source",
        "rules_source_collapsed",
        "is_candidate",
    ];
    expected.sort_unstable();
    assert_eq!(keys, expected, "default finding key set must equal v0.1");
}

// --- (e) a draft control's finding shows status: draft end-to-end -------------

#[test]
fn draft_control_status_surfaces_end_to_end() {
    // The session fixture contains an "act as" Bash command → AGT-PI-002, which
    // maps to the CSA draft control NIST-AI-RMF:AGENTIC-MAP-PROMPT-SURFACE.
    let (stdout, stderr, ok) = run(&["scan-session", &session_path(), "--format", "json"]);
    assert!(ok, "stderr:\n{stderr}");
    let v: Value = serde_json::from_str(&stdout).unwrap();
    let findings = v["findings"].as_array().unwrap();

    let draft = findings
        .iter()
        .find(|f| f["id"] == "AGT-PI-002")
        .expect("AGT-PI-002 should fire from the 'act as' signal");
    assert_eq!(
        draft["status"], "draft",
        "a finding mapping to a CSA draft control must read status: draft"
    );
    assert!(draft["suggested_controls"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c.as_str().unwrap().contains("AGENTIC-MAP-PROMPT-SURFACE")));

    // And it survives to SARIF as level "note" + status "draft".
    let (sarif, ..) = run(&["scan-session", &session_path(), "--format", "sarif"]);
    let s: Value = serde_json::from_str(&sarif).unwrap();
    let r = s["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["ruleId"] == "AGT-PI-002")
        .expect("AGT-PI-002 in SARIF");
    assert_eq!(r["level"], "note");
    assert_eq!(r["properties"]["status"], "draft");
}

// --- (j) US-F1-2 thresholds: --min-confidence drops the 0.7 AGT-PI-002 --------

#[test]
fn min_confidence_flag_moves_low_confidence_finding_to_threshold_channel() {
    // RAC-1.2: --min-confidence 0.85 moves the 0.7-confidence AGT-PI-002 finding
    // to the VISIBLE suppressed channel (origin "threshold", reason "below
    // min-confidence 0.85"); its SARIF result carries
    // properties.dropped_by_threshold:true and NO `suppressions` property.
    let (json, err, ok) = run(&[
        "scan-session",
        &session_path(),
        "--min-confidence",
        "0.85",
        "--format",
        "json",
    ]);
    assert!(ok, "stderr:\n{err}");
    let v: Value = serde_json::from_str(&json).unwrap();
    assert!(
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["id"] != "AGT-PI-002"),
        "0.7-confidence AGT-PI-002 must leave active findings"
    );
    let dropped: Vec<&Value> = v["suppressed"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["finding"]["id"] == "AGT-PI-002")
        .collect();
    assert_eq!(dropped.len(), 1, "moved to suppressed[], not deleted");
    assert_eq!(dropped[0]["origin"], "threshold");
    assert!(dropped[0]["reason"]
        .as_str()
        .unwrap()
        .contains("below min-confidence 0.85"));
    assert_eq!(dropped[0]["finding"]["is_candidate"], true);

    // SARIF: AGT-PI-002 is a NORMAL result with properties.dropped_by_threshold
    // and NO suppressions property.
    let (sarif, ..) = run(&[
        "scan-session",
        &session_path(),
        "--min-confidence",
        "0.85",
        "--format",
        "sarif",
    ]);
    let s: Value = serde_json::from_str(&sarif).unwrap();
    let r = s["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["ruleId"] == "AGT-PI-002")
        .expect("AGT-PI-002 still present as a merged result");
    assert_eq!(r["properties"]["dropped_by_threshold"], true);
    assert!(
        r.get("suppressions").is_none(),
        "threshold drop must NOT carry a SARIF suppressions property"
    );
    assert!(r["message"]["text"]
        .as_str()
        .unwrap()
        .starts_with("CANDIDATE — "));
}

#[test]
fn absent_config_and_flags_is_byte_identical_to_us_f1_1() {
    // RAC-1.2 golden: with no config/flags the output is byte-identical to the
    // pre-US-F1-2 (US-F1-1) shape — the threshold pass is a no-op passthrough.
    // The session fixture has no .apohara-compliance.toml beside it, so plain
    // and explicit-no-threshold runs must match.
    for fmt in ["json", "sarif", "md"] {
        let (plain, err, ok) = run(&["scan-session", &session_path(), "--format", fmt]);
        assert!(ok, "stderr:\n{err}");
        // No threshold keywords leak into the default output.
        assert!(
            !plain.contains("dropped_by_threshold"),
            "{fmt}: default output must not mention dropped_by_threshold"
        );
        assert!(
            !plain.contains("\"origin\""),
            "{fmt}: default output has empty suppressed[] → no origin field"
        );
    }
}

// --- (k) US-F1-2 [[suppress]] config → visible allowlist suppression ----------

#[test]
fn config_suppress_entry_moves_finding_to_visible_allowlist_channel() {
    // RAC-1.3: a [[suppress]] entry {agt_code, source_glob, reason} moves the
    // named finding to the VISIBLE suppressed channel (origin "allowlist") with
    // its reason; SARIF carries result.suppressions[{kind:"external"}]. Both the
    // rule-specific (AGT-EXF-001 + report.sql glob) AND global (AGT-PI-001)
    // entries in the sample config apply.
    let cfg = fixtures()
        .join("sample.apohara-compliance.toml")
        .to_string_lossy()
        .into_owned();

    let (json, err, ok) = run(&[
        "scan-repo",
        &repo_path(),
        "--config",
        &cfg,
        "--format",
        "json",
    ]);
    assert!(ok, "stderr:\n{err}");
    let v: Value = serde_json::from_str(&json).unwrap();

    // AGT-EXF-001 (rule-specific + source glob) is suppressed via the config.
    assert!(
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["id"] != "AGT-EXF-001"),
        "config [[suppress]] must move AGT-EXF-001 out of active findings"
    );
    let exf: Vec<&Value> = v["suppressed"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["finding"]["id"] == "AGT-EXF-001")
        .collect();
    assert_eq!(exf.len(), 1, "AGT-EXF-001 in the visible suppressed channel");
    assert_eq!(exf[0]["origin"], "allowlist");
    assert!(exf[0]["reason"].as_str().unwrap().contains("known scan-repo"));
    assert_eq!(exf[0]["suppressed_by"], "config:[[suppress]] AGT-EXF-001");

    // SARIF: AGT-EXF-001 carries suppressions[{kind:external}], NOT a threshold.
    let (sarif, ..) = run(&[
        "scan-repo",
        &repo_path(),
        "--config",
        &cfg,
        "--format",
        "sarif",
    ]);
    let s: Value = serde_json::from_str(&sarif).unwrap();
    let r = s["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["ruleId"] == "AGT-EXF-001")
        .expect("AGT-EXF-001 merged result present");
    assert_eq!(r["suppressions"][0]["kind"], "external");
    assert!(
        r["properties"].get("dropped_by_threshold").is_none(),
        "an allowlist suppression must NOT be tagged dropped_by_threshold"
    );
}

#[test]
fn config_severity_override_changes_min_severity_outcome() {
    // RAC-1.6: the sample config sets [severity] AGT-PI-002 = 9 (rule severity is
    // 7). With --min-severity 8, the override KEEPS AGT-PI-002 active (9 >= 8),
    // whereas without the override (rule 7 < 8) it would be threshold-dropped.
    let cfg = fixtures()
        .join("sample.apohara-compliance.toml")
        .to_string_lossy()
        .into_owned();

    // With the config override (severity 9) + --min-severity 8 → kept active.
    // --min-confidence 0 isolates the severity gate (the sample config's
    // [thresholds] min_confidence 0.85 would otherwise drop the 0.7 finding by
    // confidence first; CLI overrides it to 0 so only severity decides).
    let (json, err, ok) = run(&[
        "scan-session",
        &session_path(),
        "--config",
        &cfg,
        "--min-confidence",
        "0",
        "--min-severity",
        "8",
        "--format",
        "json",
    ]);
    assert!(ok, "stderr:\n{err}");
    let v: Value = serde_json::from_str(&json).unwrap();
    assert!(
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "AGT-PI-002"),
        "override severity 9 >= min 8 must keep AGT-PI-002 active"
    );

    // Without the override (no config), rule severity 7 < 8 → threshold-dropped.
    let (json2, ..) = run(&[
        "scan-session",
        &session_path(),
        "--min-severity",
        "8",
        "--format",
        "json",
    ]);
    let v2: Value = serde_json::from_str(&json2).unwrap();
    assert!(
        v2["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["id"] != "AGT-PI-002"),
        "rule severity 7 < min 8 must drop AGT-PI-002 without the override"
    );
    assert!(
        v2["suppressed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["finding"]["id"] == "AGT-PI-002" && s["origin"] == "threshold"),
        "the dropped AGT-PI-002 must be visible with origin threshold"
    );
}

// --- (n) US-F1-4 gap analysis over the 49 carried controls (fix #11d) ---------

#[test]
fn gap_lists_zero_evidence_controls_over_the_49_only_absence_framed() {
    // RAC-1.7: `gap` on the repo fixture lists controls (from the 49 ONLY) with
    // zero candidate evidence; the output carries the absence-of-evidence
    // disclaimer + the 49-scope statement; the EXTENDED NEGATIVE guard (fix #6b)
    // finds none of the banned phrases; a control WITH evidence is not a gap, a
    // control WITHOUT evidence is, and no external standard is in the universe.
    let extended_forbidden = [
        "is compliant",
        "certified",
        "guaranteed",
        "non-compliant",
        "violates",
        "is vulnerable to",
        "detected",
        "you have asi",
    ];

    // EXTENDED NEGATIVE guard across all three gap formats.
    for fmt in ["json", "sarif", "md"] {
        let (stdout, err, ok) = run(&["gap", &repo_path(), "--format", fmt]);
        assert!(ok, "gap {fmt} must succeed; stderr:\n{err}");
        let lower = stdout.to_lowercase();
        for needle in extended_forbidden {
            assert!(
                !lower.contains(needle),
                "gap {fmt} output contains forbidden phrase {needle:?}"
            );
        }
    }

    // JSON: the structured gap report (primary format).
    let (json, err, ok) = run(&["gap", &repo_path(), "--format", "json"]);
    assert!(ok, "stderr:\n{err}");
    let v: Value = serde_json::from_str(&json).unwrap();

    // Universe is the 49; covered + gaps partition it.
    assert_eq!(v["universe"], 49);
    let covered = v["covered"].as_u64().unwrap();
    let gaps = v["gaps"].as_array().unwrap();
    assert_eq!(covered as usize + gaps.len(), 49, "covered+gaps partition the 49");

    // Scope statement + disclaimer travel with the structured output.
    assert!(v["scope"].as_str().unwrap().contains("49 carried controls"));
    assert!(v["scope"].as_str().unwrap().contains("out of scope"));
    assert!(v["disclaimer"]
        .as_str()
        .unwrap()
        .contains("Absence of evidence is not evidence of a gap"));

    let gap_ids: Vec<&str> = gaps.iter().map(|g| g["id"].as_str().unwrap()).collect();
    // A control WITH candidate evidence (SP800-53:SI-7 via AGT-MIS-001 rm -rf) is
    // NOT a gap; a control WITHOUT evidence IS.
    assert!(
        !gap_ids.contains(&"SP800-53:SI-7"),
        "a control with candidate evidence must not be a gap"
    );
    assert!(
        gap_ids.contains(&"EU-AI-ACT:Art-73"),
        "a zero-evidence control must be listed as a gap"
    );
    // External standards are out of the 49 universe — never a gap.
    assert!(
        !gap_ids.iter().any(|id| id.starts_with("GDPR")),
        "externally-cited standards are out of scope for gap analysis"
    );
    // Every gap carries provenance + an absence-framed message.
    for g in gaps {
        assert!(g["status"].as_str().unwrap() == "official" || g["status"] == "draft");
        assert!(g["consilium_ref"]
            .as_str()
            .unwrap()
            .starts_with("compliance-suite.md:"));
        assert!(g["message"]
            .as_str()
            .unwrap()
            .starts_with("no candidate evidence observed for "));
    }

    // Markdown: disclaimer + scope lead the doc; every control bullet is
    // absence-framed.
    let (md, ..) = run(&["gap", &repo_path(), "--format", "md"]);
    assert!(md.contains("Gap is computed over the 49 carried controls"));
    assert!(md.contains("Absence of evidence is not evidence of a gap"));
    for l in md.lines().filter(|l| l.starts_with("- ")) {
        assert!(
            l.starts_with("- no candidate evidence observed for "),
            "gap md line not absence-framed: {l}"
        );
    }

    // SARIF: version 2.1.0, every gap result is informational note-level.
    let (sarif, ..) = run(&["gap", &repo_path(), "--format", "sarif"]);
    let s: Value = serde_json::from_str(&sarif).unwrap();
    assert_eq!(s["version"], "2.1.0");
    for r in s["runs"][0]["results"].as_array().unwrap() {
        assert_eq!(r["level"], "note");
        assert!(r["message"]["text"]
            .as_str()
            .unwrap()
            .starts_with("no candidate evidence observed for "));
    }
}

// --- (j) baseline/diff mode (US-F2-4) -----------------------------------------

#[test]
fn baseline_rerun_with_no_changes_yields_zero_new_all_unchanged() {
    use std::io::Write;
    // RAC-2.4: a re-run with the SAME scan as its baseline → every active finding
    // is `unchanged`, ZERO `new`. The baseline format is the scanner's own JSON.
    let (base_json, _e, ok) = run(&["scan-repo", &repo_path(), "--format", "json"]);
    assert!(ok);

    let dir = std::env::temp_dir().join("apohara_baseline_it");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let base_path = dir.join("baseline.json");
    let mut f = std::fs::File::create(&base_path).unwrap();
    f.write_all(base_json.as_bytes()).unwrap();
    drop(f);

    let (out, _e2, ok2) = run(&[
        "scan-repo",
        &repo_path(),
        "--baseline",
        base_path.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(ok2);
    let v: Value = serde_json::from_str(&out).unwrap();
    let findings = v["findings"].as_array().unwrap();
    assert!(!findings.is_empty(), "expected ≥1 finding to annotate");
    let new_count = findings
        .iter()
        .filter(|f| f["baseline_state"] == "new")
        .count();
    assert_eq!(new_count, 0, "a no-change re-run must yield zero `new`");
    assert!(
        findings.iter().all(|f| f["baseline_state"] == "unchanged"),
        "every finding must be `unchanged`; out:\n{out}"
    );

    // SARIF validates the baselineState enum on the same re-run.
    let (sarif, ..) = run(&[
        "scan-repo",
        &repo_path(),
        "--baseline",
        base_path.to_str().unwrap(),
        "--format",
        "sarif",
    ]);
    let s: Value = serde_json::from_str(&sarif).unwrap();
    assert_eq!(s["version"], "2.1.0");
    const VALID: [&str; 5] = ["none", "unchanged", "updated", "new", "absent"];
    for r in s["runs"][0]["results"].as_array().unwrap() {
        let st = r["baselineState"].as_str().expect("baselineState present");
        assert!(VALID.contains(&st), "invalid SARIF baselineState: {st}");
        // Level is still never error (preserved invariant).
        assert!(r["level"] == "warning" || r["level"] == "note");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn baseline_new_absent_and_only_new_filter() {
    use std::io::Write;
    // RAC-2.4: a SHRUNK baseline (a single finding kept + one phantom) makes the
    // other current findings `new` and the phantom `absent`; `--only-new` keeps
    // only the `new` ones.
    let (base_json, _e, ok) = run(&["scan-repo", &repo_path(), "--format", "json"]);
    assert!(ok);
    let full: Value = serde_json::from_str(&base_json).unwrap();
    let all = full["findings"].as_array().unwrap();
    assert!(all.len() >= 2, "fixture must yield ≥2 findings for this test");

    // Keep ONLY the first finding; add a phantom that no longer fires.
    let mut kept = vec![all[0].clone()];
    let mut phantom = all[0].clone();
    phantom["id"] = Value::String("AGT-GONE-999".into());
    phantom["triggering_signal"] = Value::String("legacy-signal".into());
    phantom["title"] = Value::String("Legacy Risk".into());
    kept.push(phantom);
    let mut shrunk = full.clone();
    shrunk["findings"] = Value::Array(kept);

    let dir = std::env::temp_dir().join("apohara_baseline_diff_it");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let base_path = dir.join("shrunk.json");
    let mut f = std::fs::File::create(&base_path).unwrap();
    f.write_all(serde_json::to_string(&shrunk).unwrap().as_bytes())
        .unwrap();
    drop(f);

    // Full diff: at least one `new`, exactly one `absent` (the phantom).
    let (out, _e2, ok2) = run(&[
        "scan-repo",
        &repo_path(),
        "--baseline",
        base_path.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(ok2);
    let v: Value = serde_json::from_str(&out).unwrap();
    let findings = v["findings"].as_array().unwrap();
    let new_count = findings.iter().filter(|f| f["baseline_state"] == "new").count();
    let absent: Vec<&Value> = findings
        .iter()
        .filter(|f| f["baseline_state"] == "absent")
        .collect();
    assert!(new_count >= 1, "expected ≥1 new finding; out:\n{out}");
    assert_eq!(absent.len(), 1, "the phantom must surface as a single absent");
    assert_eq!(absent[0]["id"], "AGT-GONE-999");
    assert_eq!(absent[0]["is_candidate"], true, "absent still a candidate");

    // `--only-new`: only `new` survive (no unchanged, no absent).
    let (only_new, ..) = run(&[
        "scan-repo",
        &repo_path(),
        "--baseline",
        base_path.to_str().unwrap(),
        "--only-new",
        "--format",
        "json",
    ]);
    let vn: Value = serde_json::from_str(&only_new).unwrap();
    let fn_: &Vec<Value> = vn["findings"].as_array().unwrap();
    assert!(!fn_.is_empty(), "--only-new must keep the new findings");
    assert!(
        fn_.iter().all(|f| f["baseline_state"] == "new"),
        "--only-new must keep ONLY `new`; out:\n{only_new}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn baseline_absent_for_explicit_path_is_an_error() {
    // An explicit `--baseline <path>` that does not exist is a LOUD error.
    let (_o, stderr, ok) = run(&[
        "scan-repo",
        &repo_path(),
        "--baseline",
        "/nonexistent/baseline.json",
        "--format",
        "json",
    ]);
    assert!(!ok, "a missing explicit baseline must be a non-zero exit");
    assert!(stderr.contains("baseline"), "error must name the baseline: {stderr}");
}

#[test]
fn default_output_omits_baseline_state_preserving_v01_shape() {
    // RAC-2.4: WITHOUT `--baseline`, the JSON/SARIF carries NO baseline_state /
    // baselineState — byte-shape preserved for pinned consumers.
    let (json, ..) = run(&["scan-repo", &repo_path(), "--format", "json"]);
    assert!(
        !json.contains("baseline_state"),
        "default JSON must not carry baseline_state"
    );
    let (sarif, ..) = run(&["scan-repo", &repo_path(), "--format", "sarif"]);
    assert!(
        !sarif.contains("baselineState"),
        "default SARIF must not carry baselineState"
    );
}

// --- (k) scan-repo --ext walker filter (US-F2-4 #5) ---------------------------

#[test]
fn ext_filter_reads_only_named_extensions() {
    // RAC-2.4: `--ext rs,py` reads only matching files; default reads all.
    // The fixture has cleanup.sh (.sh), report.sql (.sql), config.py (.py).
    let (with_ext, stderr, ok) = run(&[
        "scan-repo",
        &repo_path(),
        "--ext",
        "rs,py",
        "--format",
        "json",
    ]);
    assert!(ok);
    let v: Value = serde_json::from_str(&with_ext).unwrap();
    let ids: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["id"].as_str())
        .collect();
    // .py present (config.py → AGT-EXF-002 curl http); .sql/.sh suppressed.
    assert!(
        ids.iter().all(|i| !i.starts_with("AGT-MIS")),
        "cleanup.sh (.sh) must be filtered out by --ext rs,py; ids: {ids:?}"
    );
    assert!(
        !ids.contains(&"AGT-EXF-001"),
        "report.sql (.sql) must be filtered out; ids: {ids:?}"
    );
    // The walker logs the skipped non-matching files.
    assert!(
        stderr.contains("extension not in --ext filter"),
        "skip log must name the extension filter; stderr:\n{stderr}"
    );

    // Default (no --ext) reads everything → the .sh/.sql findings come back.
    let (no_ext, ..) = run(&["scan-repo", &repo_path(), "--format", "json"]);
    let v2: Value = serde_json::from_str(&no_ext).unwrap();
    let ids2: Vec<&str> = v2["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["id"].as_str())
        .collect();
    assert!(ids2.iter().any(|i| i.starts_with("AGT-MIS")), "ids2: {ids2:?}");
    assert!(ids2.contains(&"AGT-EXF-001"), "ids2: {ids2:?}");
}

// ADR-2 (ASI06): the dedicated multi-action test the synthetic single-action gate
// cannot express. A marker-bearing action (untrusted content) FOLLOWED BY a memory
// persist fires the AGT-MEM-001 SEQUENCE candidate — and NOT AGT-PI-003 — proving
// the new rule is genuinely non-duplicate, end to end through the real binary.
#[test]
fn otlp_sequence_fires_mem001_candidate_not_pi003() {
    // One valid OTLP/JSON document: marker in resourceLogs (ingested first),
    // persist in resourceSpans (ingested after) → ordered source→sink.
    let doc = r#"{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"loaded unsanitized content from an external source"},"attributes":[]}]}]}],"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"execute_tool Bash","attributes":[{"key":"gen_ai.tool.name","value":{"stringValue":"Bash"}},{"key":"args","value":{"stringValue":"psql -c INSERT INTO embeddings VALUES x"}}]}]}]}]}"#;
    let path = std::env::temp_dir().join("apohara-it-mem-seq.json");
    std::fs::write(&path, doc).expect("write otlp fixture");
    let (stdout, _stderr, ok) = run(&["scan-otlp", path.to_str().unwrap(), "--format", "json"]);
    assert!(ok, "scan-otlp runs");
    let v: Value = serde_json::from_str(&stdout).unwrap();
    let ids: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["id"].as_str())
        .collect();
    assert!(ids.contains(&"AGT-MEM-001"), "marker→persist must fire AGT-MEM-001; ids: {ids:?}");
    assert!(
        !ids.contains(&"AGT-PI-003"),
        "AGT-MEM-001 must be non-duplicate of AGT-PI-003 (no injection markers here); ids: {ids:?}"
    );
    // Honesty: every sequence finding is a candidate.
    assert!(v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|f| f["is_candidate"].as_bool().unwrap_or(false)));
    let _ = std::fs::remove_file(&path);
}

// The negative half of the discriminator: a persist with no preceding
// untrusted-content marker is NOT a sequence — AGT-MEM-001 must stay silent.
#[test]
fn otlp_persist_without_preceding_marker_does_not_fire_mem001() {
    let doc = r#"{"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"execute_tool Bash","attributes":[{"key":"gen_ai.tool.name","value":{"stringValue":"Bash"}},{"key":"args","value":{"stringValue":"psql -c INSERT INTO embeddings VALUES x"}}]}]}]}]}"#;
    let path = std::env::temp_dir().join("apohara-it-mem-noseq.json");
    std::fs::write(&path, doc).expect("write otlp fixture");
    let (stdout, _e, ok) = run(&["scan-otlp", path.to_str().unwrap(), "--format", "json"]);
    assert!(ok);
    let v: Value = serde_json::from_str(&stdout).unwrap();
    let ids: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["id"].as_str())
        .collect();
    assert!(!ids.contains(&"AGT-MEM-001"), "persist alone must not fire AGT-MEM-001; ids: {ids:?}");
    let _ = std::fs::remove_file(&path);
}

// --- ADR-4 (v2.0): trajectory taint rules fire via the REAL binary -----------
// Proof-of-life on committed synthetic positives + the finbot negative control.

fn trj_ids(file: &str) -> Vec<String> {
    let path = fixtures().join(file).to_string_lossy().into_owned();
    let (stdout, stderr, ok) = run(&["scan-session", &path, "--format", "json"]);
    assert!(ok, "scan-session {file} should exit 0; stderr:\n{stderr}");
    let v: Value = serde_json::from_str(&stdout).expect("valid JSON report");
    let mut ids: Vec<String> = v["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .filter_map(|f| f["id"].as_str())
        .filter(|id| id.starts_with("AGT-TRJ"))
        .map(str::to_string)
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

#[test]
fn agt_trj_synthetic_positives_fire_their_rule() {
    assert_eq!(trj_ids("trj001-exfil-positive.jsonl"), vec!["AGT-TRJ-001"]);
    assert_eq!(trj_ids("trj002-destructive-positive.jsonl"), vec!["AGT-TRJ-002"]);
    assert_eq!(trj_ids("trj003-financial-positive.jsonl"), vec!["AGT-TRJ-003"]);
}

#[test]
fn agt_trj_representation_aware_structured_sink_positive_fires() {
    // ADR-5 (WS1, AC2.3): a GENERIC taxonomy-derived marker (`<INFORMATION>` /
    // `you must now`) on a `tool-result:` source FOLLOWED BY a STRUCTURED `sink:`
    // action (send_money with an EXTERNAL recipient + amount) fires an AGT-TRJ
    // candidate via the new representation-aware `sink:` channel. This is the
    // constructive existence proof (A3) — authored to fire, NOT a measurement.
    let ids = trj_ids("trj-representation-aware-positive.jsonl");
    assert!(
        ids.contains(&"AGT-TRJ-001".to_string()),
        "structured-sink exfil (external recipient) must fire AGT-TRJ-001; got {ids:?}"
    );
    assert!(
        ids.contains(&"AGT-TRJ-003".to_string()),
        "structured-sink financial (amount) must fire AGT-TRJ-003; got {ids:?}"
    );
}

#[test]
fn agt_trj_benign_trajectory_does_not_fire() {
    // Tainted read followed by a benign, non-sensitive action (no sink) → no fire.
    assert!(
        trj_ids("trj-benign-negative.jsonl").is_empty(),
        "a tainted read + benign action must not fire any AGT-TRJ"
    );
}

#[test]
fn agt_trj_structured_sink_benign_trap_fires_zero() {
    // M2: the de-facto WS1 FP gate. A tainted read FOLLOWED BY a BENIGN structured
    // tool-call (internal recipient `teammate`, no external `@`, no amount; the
    // free-text `body` is excluded by C1-b) must fire ZERO AGT-TRJ — the structured
    // sink require_context (external recipient / amount) is not satisfied. This trap
    // lives in the integration harness, NEVER the precision_recall corpus (which
    // stays single-action and structurally blind to `sink:`).
    assert!(
        trj_ids("trj-structured-sink-benign-trap.jsonl").is_empty(),
        "a benign structured sink (internal recipient, no amount) must fire zero AGT-TRJ"
    );
}

#[test]
fn agt_trj_finbot_is_a_negative_control() {
    // COMMITTED negative control (CI-guaranteed): a direct-injection trajectory where the
    // injection marker reaches a tool-result (it taints) but the agent REFUSES via chat —
    // the only downstream action is the chat tool, NOT a real-action sink. Sink-existence
    // must fire ZERO AGT-TRJ. This exercises the core "structural, not deny-list" thesis
    // in a fresh clone, independent of the (uncommitted) live FinBot capture.
    assert!(
        trj_ids("trj-direct-injection-refusal-negative.jsonl").is_empty(),
        "committed direct-injection refusal negative control must fire zero AGT-TRJ"
    );

    // BONUS: if the real (uncommitted) FinBot capture is present locally, assert it too.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/corpus/finbot/raw/finbot-1780783524-finbot-attack.jsonl");
    if path.exists() {
        let (stdout, _stderr, ok) = run(&["scan-session", &path.to_string_lossy(), "--format", "json"]);
        assert!(ok);
        let v: Value = serde_json::from_str(&stdout).expect("valid JSON");
        let trj: Vec<&str> = v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["id"].as_str())
            .filter(|id| id.starts_with("AGT-TRJ"))
            .collect();
        assert!(trj.is_empty(), "finbot live capture must also fire zero AGT-TRJ; got {trj:?}");
    }
}

// --- v2.4 S2 (ADR-9, US-004) — AST-only SHELL fixtures ----------------------
//
// These tests are the integration counterpart to `crates/scanner/src/shell/
// match_.rs::tests`. They drive the COMPILED BINARY over `--kind session:Bash.input`
// actions containing the four S2 AST constructs and assert that the
// AGT-SHL-*-A rules fire.
//
// The tests are feature-gated on `shell-ast`: with the S1 default build
// (`--no-default-features`) the AGT-SHL-*-A rules are byte-identical no-ops
// (their AST module is `#[cfg]`-gated out). With `--features shell-ast`
// compiled in, the AST matcher runs and the rules fire on the four
// construct-only fixtures.
//
// Each test inverts the design contract: a CONSTRUCT-MATCHING fixture fires
// its rule; a NON-CONSTRUCT fixture does NOT fire its rule.

/// Drive the binary with a single `--kind` action. Returns the set of AGT-*
/// ids that fired.
fn scan_action_ids(action: &str) -> std::collections::BTreeSet<String> {
    let (stdout, _stderr, ok) = run(&["scan-action", action, "--kind", "session:Bash.input", "--format", "json"]);
    assert!(ok, "scan-action should exit 0; stdout={stdout}");
    let v: Value = serde_json::from_str(&stdout).expect("valid JSON");
    v["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .filter_map(|f| f["id"].as_str().map(String::from))
        .collect()
}

#[cfg(feature = "shell-ast")]
#[test]
fn s2_pipeline_fixture_fires_shl_pipeline_a_and_not_others() {
    // v2.4 S2 (ADR-9, US-004): a pipeline-only command fires AGT-SHL-PIPELINE-A
    // (and only that rule). Subshell / CommandSubstitution / Heredoc rules do
    // NOT fire on a plain pipeline.
    let ids = scan_action_ids("rm -rf / | cat");
    assert!(
        ids.contains("AGT-SHL-PIPELINE-A"),
        "AGT-SHL-PIPELINE-A must fire on a pipeline; got {ids:?}"
    );
    assert!(
        !ids.contains("AGT-SHL-SUBSHELL-A"),
        "AGT-SHL-SUBSHELL-A must NOT fire on a plain pipeline; got {ids:?}"
    );
    assert!(
        !ids.contains("AGT-SHL-COMMANDSUBST-A"),
        "AGT-SHL-COMMANDSUBST-A must NOT fire on a plain pipeline; got {ids:?}"
    );
    assert!(
        !ids.contains("AGT-SHL-HEREDOC-A"),
        "AGT-SHL-HEREDOC-A must NOT fire on a plain pipeline; got {ids:?}"
    );
}

#[cfg(feature = "shell-ast")]
#[test]
fn s2_subshell_fixture_fires_shl_subshell_a() {
    // Subshell-only: `(rm -rf /)`. The S2 parser sees Subshell wrapping a
    // Simple, so AGT-SHL-SUBSHELL-A fires.
    let ids = scan_action_ids("(rm -rf /)");
    assert!(
        ids.contains("AGT-SHL-SUBSHELL-A"),
        "AGT-SHL-SUBSHELL-A must fire on a subshell; got {ids:?}"
    );
    assert!(
        !ids.contains("AGT-SHL-PIPELINE-A"),
        "subshell-only must NOT also fire the pipeline rule; got {ids:?}"
    );
}

#[cfg(feature = "shell-ast")]
#[test]
fn s2_command_substitution_fixture_fires_shl_commandsubst_a() {
    // Dollar-form command substitution: `$(rm -rf /)`. The S2 parser sees a
    // CommandSubstitution wrapping a Simple, so AGT-SHL-COMMANDSUBST-A fires.
    let ids = scan_action_ids("$(rm -rf /)");
    assert!(
        ids.contains("AGT-SHL-COMMANDSUBST-A"),
        "AGT-SHL-COMMANDSUBST-A must fire on $(...); got {ids:?}"
    );
    assert!(
        !ids.contains("AGT-SHL-SUBSHELL-A"),
        "command substitution must NOT also fire the subshell rule; got {ids:?}"
    );
}

#[cfg(feature = "shell-ast")]
#[test]
fn s2_backtick_command_substitution_fixture_fires_shl_commandsubst_a() {
    // Backtick form: `` `rm -rf /` `` — same rule fires (the matcher treats
    // DollarParen and Backtick as the same construct).
    let ids = scan_action_ids("`rm -rf /`");
    assert!(
        ids.contains("AGT-SHL-COMMANDSUBST-A"),
        "AGT-SHL-COMMANDSUBST-A must fire on backtick form; got {ids:?}"
    );
}

#[cfg(feature = "shell-ast")]
#[test]
fn s2_heredoc_fixture_fires_shl_heredoc_a() {
    // Heredoc with body: `cat <<EOF\nhello\nEOF`. The S2 parser captures the
    // heredoc body, so AGT-SHL-HEREDOC-A fires.
    let input = "cat <<EOF\nhello\nEOF";
    let ids = scan_action_ids(input);
    assert!(
        ids.contains("AGT-SHL-HEREDOC-A"),
        "AGT-SHL-HEREDOC-A must fire on a heredoc; got {ids:?}"
    );
    assert!(
        !ids.contains("AGT-SHL-PIPELINE-A"),
        "heredoc-only must NOT also fire the pipeline rule; got {ids:?}"
    );
}

#[cfg(feature = "shell-ast")]
#[test]
fn s2_fallback_on_unbalanced_quote_does_not_panic() {
    // Deliberately-broken input → ParseError → silent S1 fallback → no panic,
    // no AGT-SHL-*-A finding (the AST-only rules have no S1 fallback shape).
    // We also confirm the binary still exits 0 (no panic propagated).
    let (stdout, _stderr, ok) = run(&[
        "scan-action",
        "rm -rf 'unclosed",
        "--kind",
        "session:Bash.input",
        "--format",
        "json",
    ]);
    assert!(ok, "scan-action must not panic on unbalanced quote");
    let v: Value = serde_json::from_str(&stdout).expect("valid JSON");
    let shl_a: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["id"].as_str())
        .filter(|id| id.starts_with("AGT-SHL-") && id.ends_with("-A"))
        .collect();
    assert!(
        shl_a.is_empty(),
        "ParseError must not emit AST-only findings; got {shl_a:?}"
    );
}

#[cfg(feature = "shell-ast")]
#[test]
fn s2_pipeline_rule_does_not_fire_on_plain_simple_command() {
    // AGT-SHL-PIPELINE-A must NOT fire on `rm -rf /` (plain Simple, no
    // pipeline). This is the S2 parity contract.
    let ids = scan_action_ids("rm -rf /");
    assert!(
        !ids.contains("AGT-SHL-PIPELINE-A"),
        "pipeline rule must not fire on plain rm -rf; got {ids:?}"
    );
    assert!(
        !ids.contains("AGT-SHL-SUBSHELL-A"),
        "subshell rule must not fire on plain rm -rf; got {ids:?}"
    );
    assert!(
        !ids.contains("AGT-SHL-COMMANDSUBST-A"),
        "command-substitution rule must not fire on plain rm -rf; got {ids:?}"
    );
    assert!(
        !ids.contains("AGT-SHL-HEREDOC-A"),
        "heredoc rule must not fire on plain rm -rf; got {ids:?}"
    );
}
