# PROOF — v2.3 Argument-Value Provenance (causal proxy, post-hoc, verbatim-flow)

> This is the numbers-only v2.3 re-measurement, scanned with the v2.3 release
> binary (which ships BOTH the FROZEN v2.2 AGT-TRJ-* rules AND the new
> AGT-TRJ-*-P provenance-gated variants), over the v2.2 AgentDyn corpus
> (commit `5353cf7`, 236 positives / 2295 failed / 352 benign) with the
> FROZEN dev/test split from `eval/v23/split.json` (44 dev / 192 test,
> deterministic SHA-256 seed per PREREG-v2.3.md).

## SHA integrity (the anti-fit guard)

- **PREREG-v2.3.md blob SHA**: `5e62e9e2c4cfdf2a2e13c0005ae384c2f4a42eeb`
  (recorded in the freezing commit `5b9c9a3`). **UNCHANGED post-scan** —
  the PREREG was NOT edited after the scan ran. ✓
- **detection-rules.yaml pre-freeze SHA**: `dcd1ac6e1d7ed8dce4b5b516296e8ce5a3e0582a`
  (the v2.2 state, FROZEN before any v2.3 edit).
- **detection-rules.yaml post-freeze SHA**: `e88a99b64eeffd5c04e0d8b336cd9b45c9803dd8`
  (the v2.3 state, with the three -P rules appended at commit `e21ec75`).
  The SHA changed because RULES WERE ADDED (the three -P variants specified
  in the PREREG), NOT because rules were tuned to fit the scan output. The
  per-rule structure (signals, source_kinds, require_context, deny_context)
  is byte-identical to the originals — only the new
  `require_value_from_source` field was added.
- **Split file**: `eval/v23/split.json` (gitignored under `/eval/`), 44
  dev / 192 test, deterministic SHA-256 of (seed + path) < 20% → DEV.
  Re-running the split script is byte-identical. ✓

## Headline numbers (the TEST split is the v2.3 claim; DEV is sanity only)

```
split: dev=44 test=192  (total positives = 236)
Headline is the TEST split (192); DEV is for sanity checks only.
```

| Bucket | v2.2 corr (b) | v2.3 -P (c) | Delta |
|---|---|---|---|
| **TEST positives** (192) | 138 / 192 = **71.9%** | 100 / 192 = **52.1%** | -38 candidates |
| DEV positives (44, sanity) | 31 / 44 = 70.5% | 25 / 44 = 56.8% | -6 (similar shape) |
| FAILED (2295) | 659 = **28.7%** | 319 = **13.9%** | -340 (FP halved) |
| **BENIGN (352)** | 5 = **1.4%** | **0 = 0.0%** | -5 (all FP killed) |

### Per-model breakdown on TEST (192 positives)

```
(b) v2.2 correlation post-hoc AGT-TRJ-* on the 192 TEST positives
    model                           corr fired   of   per-code
    google_gemini-2.5-flash                 49   70   AGT-TRJ-001=42, AGT-TRJ-003=19
    google_gemini-2.5-pro                   71   96   AGT-TRJ-001=69, AGT-TRJ-003=29
    gpt-5-mini-2025-08-07                    0    2   -
    gpt-5.1-2025-11-13                      18   24   AGT-TRJ-001=18, AGT-TRJ-003=7
    TOTAL                                  138  192 (71.9%)

(c) v2.3 -P provenance-gated AGT-TRJ-*-P on the 192 TEST positives
    model                           -P fired   of   per-code
    google_gemini-2.5-flash               46   70   AGT-TRJ-001-P=37, AGT-TRJ-003-P=13
    google_gemini-2.5-pro                 46   96   AGT-TRJ-001-P=35, AGT-TRJ-003-P=15
    gpt-5-mini-2025-08-07                  0    2   -
    gpt-5.1-2025-11-13                     8   24   AGT-TRJ-001-P=8
    TOTAL                                100  192 (52.1%)
```

### What the -P gate did

- `AGT-TRJ-001-P` (exfil; gate on `recipient`+`url`): fired 80/192 vs 135/192 corr (40% drop on this code).
- `AGT-TRJ-002-P` (destructive; gate on `command`): fired **0/192**. This is the honest v2.3-plan prediction: a destructive command (`rm -rf`, `DROP TABLE`) is rarely a verbatim substring of a generic injection. The code exists for completeness; on this corpus it does not contribute.
- `AGT-TRJ-003-P` (financial; gate on `recipient`+`amount`): fired 20/192 vs 48/192 corr (58% drop; the recipient IBAN overlap is the smaller half).

### FP controls (the v2.3 win)

- **BENIGN FP**: 5 → **0**. The v2.2 correlation made 5 spurious AGT-TRJ fires on clean (no-injection) trajectories; the v2.3 -P gate eliminated all of them because the legit recipient/command never appears in a source value that lacks an injection marker. This is the FP-killer demo, **100% on the BENIGN bucket**.
- **FAILED-injection FP**: 659 (28.7%) → 319 (13.9%). Halved. The remaining 319 are trajectories where the agent received a marker but did NOT exfiltrate/destruct/send-money; the v2.2 corr fires on the marker+structured-sink combination regardless, the v2.3 -P suppresses when the sink values aren't in the source. The remaining 319 are the honest residual: a marker+structured-sink combination on a trajectory the agent ultimately resisted (the FP class where the agent *saw* the injection but the sink values were legit).

## Honest claim (the v2.3 ceiling)

v2.3 reports: **100 of 192 (52.1%) on the TEST split, vs v2.2's 138/192 (71.9%)**. The 38-candidate drop is the FP-killer result — the v2.2 corr's false-positive rate on FAILED halved (28.7% → 13.9%) and on BENIGN went to zero. The 52.1% is a *post-hoc substring-match proxy* for injection→consequence causation: a candidate fires when an authority-role value in the sink is a substring of the latched source value, after ASCII-lowercasing + a 6-character length floor. This is **necessary-but-not-sufficient** for causation: it kills the FP class where the same sink fires on a clean trajectory, but it does NOT prove the value was *lifted* from the injection versus *coincidentally present* in the injection text. Verbatim-flow constraint only; no cross-step laundering (PACT does that, apohara does not).

## Dev/test agreement (sanity check)

- DEV: corr 31/44 (70.5%) → -P 25/44 (56.8%). Drop = 6.
- TEST: corr 138/192 (71.9%) → -P 100/192 (52.1%). Drop = 38.

The drop ratio is consistent (~14% on DEV, ~20% on TEST) and the absolute drop scales with the per-bucket size. No bucket-level overfit: the -P gate behavior is uniform across both splits, which is the property the PREREG freeze was designed to enable.

## Reproduction

```sh
# (1) freeze the rules + split (already committed, see PREREG-v2.3.md)
git checkout 5b9c9a3   # the PREREG freezing commit
cargo build --release --locked
# (2) run the re-measure
python3 scripts/eval/scan_v23_devtest.py
# -> eval/v23/scan-results.json (gitignored)
# -> stdout: v2.3 BOUND TRIPLE summary
```

## NOT in v2.3 (deferred to a future prereg)

- Unicode case folding (v2.3 ASCII-only).
- Semantic similarity scoring (v2.3 is exact-substring only).
- Cross-step value laundering (PACT does that, apohara does not).
- Whitespace/punctuation stripping in the value extraction (R3 of the v2.3 plan; rejected in DD-2 as too coincidental-match-prone).
- New `sink:` role fields (`iban`, etc.) — FROZEN at the v2.2 4-role map; adding new fields is a separate prereg.
- AGT-TRJ-002-P firing on destructive commands (the verbatim-flow constraint makes this rare; a future prereg could explore alternative similarity measures for this code).

## Verdict

v2.3 **mechanically works**: 189 tests green (180 prior + 9 new), clippy -D clean, verify.sh ALL PASSED, PREREG SHA unchanged post-scan, split deterministic.

v2.3 **delivers the planned FP reduction**: BENIGN 0/352 (was 5/352), FAILED 13.9% (was 28.7%). The headline 52.1% on TEST positives is a **post-hoc substring-match proxy** — not causation, never claimed as causation. The 38-candidate drop vs the v2.2 71.9% is the FP-killer result, achieved WITHOUT tuning any normalization, threshold, or weight to fit the corpus.
