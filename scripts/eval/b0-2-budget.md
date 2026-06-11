# B-0.2 — Open-Ended Frontier Budget Table

**Status:** PENDING PABLO GO (US-007, 2026-06-11). Base = v2.3 (ADR-7).
Plan: `.omc/plans/v2.4-argument-value-provenance-followups.md` Rev 2.
Companion: `b0-1-probe-results.md` (US-006: PASS, all 3 open-ended
suites registered in the patched venv).

## 1. B-0.1 verdict (recap)

**PASS.** With the venv's `agentdojo` reinstalled from
`eval/agentdyn/` (the 5353cf7 source tree), all three open-ended suites
resolve:
- `shopping`: 20 user tasks × 9 injection tasks × 39 tools
- `github`: 20 × 9 × 34
- `dailylife`: 20 × 10 × 27

The patched venv is the **prerequisite** for B-1. Re-running the probe
is ~50 ms and zero-cost (`scripts/eval/probe_open_ended_suites.py`).

## 2. Cost basis (v2.2 baseline)

v2.2's live run (PR #10, 9a8bf64) used `suite=workspace` and 4 frontier
models × 20 user tasks. The cumulative token spend was **~700k tokens**
across all models, suites, and trajectories. The `--cap` was 1,000,000
and was not hit.

That means **~17.5k tokens per (model, user_task)** on the workspace
suite with avg 1.3 trajectory steps per task.

## 3. Open-ended trajectory length (estimated)

The AgentDyn paper / open-ended suite docs cite an **avg 7.1 trajectory
steps** per task (vs ~1.3 on workspace). The 7× trajectory-length
multiplier is the single biggest cost driver, plus:
- **Multi-app tasks** (avg 3.17 apps per task) → longer context windows
- **Helpful third-party instructions** (not just adversarial) →
  models can produce longer, more elaborate trajectories before the
  injection fires
- **Harder prompt-injection** (the last-gen gemini-2.5 family reached
  14–22% ASR on these suites)

**Conservative per-(model, suite) estimate: ~120k tokens.** This is
the 7× trajectory multiplier applied to the v2.2 baseline.

## 4. Per-(model, suite) budget

| (model, suite) | Est. tokens | Per-pair cap (`--cap-per-pair`) | Hard ceil (3× est) |
|----------------|-------------|----------------------------------|---------------------|
| (gpt-5.5, shopping) | 120,000 | 150,000 | 360,000 |
| (gpt-5.5, github) | 120,000 | 150,000 | 360,000 |
| (gpt-5.5, dailylife) | 120,000 | 150,000 | 360,000 |
| (claude-sonnet-4.6, shopping) | 120,000 | 150,000 | 360,000 |
| (claude-sonnet-4.6, github) | 120,000 | 150,000 | 360,000 |
| (claude-sonnet-4.6, dailylife) | 120,000 | 150,000 | 360,000 |
| (gemini-3.5-flash, shopping) | 120,000 | 150,000 | 360,000 |
| (gemini-3.5-flash, github) | 120,000 | 150,000 | 360,000 |
| (gemini-3.5-flash, dailylife) | 120,000 | 150,000 | 360,000 |
| (claude-opus-4.8, shopping) | 120,000 | 150,000 | 360,000 |
| (claude-opus-4.8, github) | 120,000 | 150,000 | 360,000 |
| (claude-opus-4.8, dailylife) | 120,000 | 150,000 | 360,000 |
| (MiniMax-M3, shopping) | 120,000 | 150,000 | 360,000 |
| (MiniMax-M3, github) | 120,000 | 150,000 | 360,000 |
| (MiniMax-M3, dailylife) | 120,000 | 150,000 | 360,000 |
| **TOTAL (5 models × 3 suites)** | **1,800,000** | **2,250,000** | **5,400,000** |

**Recommended global `--cap`:** **3,000,000 tokens** (gives ~50% headroom
over the 1.8M estimate, hard-stops well before the 5.4M worst case).

**Recommended `--cap-per-pair`:** **150,000 tokens** (the v2.4 default
set in US-006, rationale documented in the help text).

## 5. The `MINIMAX_API_KEY` cost question

The v2.2 plan assumed OpenRouter paid API access. The v2.4 plan (per
Pablo, 2026-06-11) switches to **`MINIMAX_API_KEY` (MiniMax-M3) for
free-tier access**. The other 4 frontier models above are illustrative;
the **actual B-1 run uses the MINIMAX API gateway** with whatever
frontier model id MiniMax exposes (the opencode config maps
`minimax/MiniMax-M3` → `MiniMax-M3` at `https://api.minimax.io/anthropic`).

Concretely, the B-1 run reduces to:
- **1 model × 3 suites × 1 trajectory cap** (smoke test, 100k tokens)
- **Then 3 pairs total** (or 9 if we sweep the open-ended suites
  multiple times), with `--cap-per-pair=150000` and `--cap=3000000`.
- **Free tier**: no spend required, but rate limits may force
  serialization. The hard cap is the safety net against runaway loops.

## 6. Pablo decision (B-0.3)

This file is the **B-0.2 deliverable**. The B-0.3 decision (Pablo's
go/no-go on B-1) is recorded separately at
`scripts/eval/b0-3-pablo-decision.md` (created when Pablo responds).

| Decision | Action |
|----------|--------|
| **GO** (recommended) | Proceed to US-008 (B-1 live run) with the recommended caps. |
| **REDUCE** (subset) | Run a smaller grid (e.g. 1 model × 1 suite) to validate the harness end-to-end before the full 5×3. |
| **DEFER** (DD-A A2) | B-1 stays unfunded. The open-ended frontier gap remains UNMEASURED, documented honestly. US-008, US-009 marked DEFERRED. |

**This file is gitignored** (see `.gitignore` `scripts/eval/b0-*`). It
serves as the cost basis Pablo reviews when making the B-0.3 call.

## 7. References

- `scripts/eval/b0-1-probe-results.md` — B-0.1 PASS verdict.
- `scripts/eval/probe_open_ended_suites.py` — the probe.
- `scripts/eval/test_b0_capability_probe.py` — 26 tests, 0 skip after the
  venv reinstall.
- `scripts/eval/run_openrouter_e2e.py` — the harness with the new
  `--cap-per-pair` flag and `PairBudget` class.
- `docs/adr/ADR-8-agentdyn-open-ended-frontier.md` — the decision.
