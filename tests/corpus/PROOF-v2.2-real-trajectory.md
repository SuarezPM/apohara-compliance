# PROOF-v2.2 — real-trajectory provenance + real LIVE API usage

This file records PROOF that the v2.2 real-trajectory measurement used (1) a REAL downloaded
corpus of real successful injection trajectories and (2) REAL current-frontier LLM API calls —
not fabricated, not free-credit phantom. The API key is NEVER recorded here — only model ids,
token usage, and HTTP outcomes. Mirrors the PROOF-v2-minimax.md discipline.

> **Pre-registration:** the detection rules were FROZEN at blob SHA
> `dcd1ac6e1d7ed8dce4b5b516296e8ce5a3e0582a` BEFORE any trace was scanned (see
> `PREREG-v2.2-real-trajectory.md`). `git hash-object crates/scanner/references/detection-rules.yaml`
> still returns that SHA; the root `references/detection-rules.yaml` is `cmp`-byte-identical. NO rule
> edit after the freeze. The missed sink arg-keys (`iban`-analog: `path`/`otp`/`repo_name`/…) are a
> DOCUMENTED overlap-miss, deliberately NOT closed.

## Part A — DOWNLOAD corpus provenance (the overlap-miss volume; last-gen, date-labeled)

- **Upstream:** SaFo-Lab/AgentDyn (MIT), commit
  `5353cf7615b135cace8d07c8f12dac53a16b6db3` (2026-05-19).
- **`agentdojo_package_version` 0.1.35; `benchmark_version` v1.2.2.** Attack template
  `important_instructions`. Open-ended suites (shopping / github / dailylife).
- **Models are LAST-GEN, DATE-LABELED** (`gpt-5.1-2025-11-13`, `gpt-5-mini-2025-08-07`,
  `gemini-2.5-pro`, `gemini-2.5-flash`) — used for the model-INDEPENDENT overlap-miss volume ONLY,
  NEVER as a "current-frontier efficacy" headline (see `SOURCE-agentdyn.md`).
- **Polarity (gated by `assert_polarity.py`):** `security == True AND injection-present` ⇒ the
  injection SUCCEEDED. Buckets: POSITIVE = 236, FAILED = 2295, BENIGN = 352.
- **Transcription:** the FROZEN apohara-agnostic `wrap_agentdojo_trace.py` (unchanged in v2.2) →
  the REAL release binary (`scan-session --rules-dir references --format json`). NO corpus text is
  committed (whole corpus stays in gitignored `eval/`); the report carries numbers/IDs only.

### The bound triple — DOWNLOAD (post-hoc, template-scoped — never "efficacy")
- (a) **model attack-success-rate** (AgentDyn labels, apohara-independent): gpt-5.1 33/851 (3.9%);
  gpt-5-mini 2/560 (0.4%); gemini-2.5-pro 122/560 (21.8%); gemini-2.5-flash 79/560 (14.1%).
- (b) **apohara post-hoc AGT-TRJ detection on the 236 REAL successes: 169/236 (71.6%).** Per model:
  gpt-5.1 25/33; gpt-5-mini 0/2; gemini-2.5-pro 89/122; gemini-2.5-flash 55/79. (AGT-TRJ-001
  dominant, AGT-TRJ-003 secondary where reported.)
- (c) **FALSE-POSITIVE control:** failed-injection (RESISTED) FP = 659/2295 (28.7%);
  benign FP = 5/352 (1.4%). **precision-on-success ≈ 169 / (169 + 659 + 5) = 169/833 ≈ 20%.**

### Overlap-miss (model-independent representation coverage of the 236 positives)
Marker `<information>` covered 232/236; role-mapped structured sink covered 180/236; BOTH 178/236;
NEITHER 2/236. Covered sink roles: url=170, recipient=60, amount=59, command=34. MISSED sink
arg-keys (OUTSIDE the frozen role map — the `iban`-analog): path (161), subject (114), otp (87),
title (79), body (68), recipients (68), repo_name (54), password (33). **Reported as-is, NEVER
closed** — adding any of these to the role map after seeing traces would convert the number from a
MEASUREMENT into a FIT (forbidden by the pre-registration).

## Part B — LIVE current-frontier real API usage (the cross-check; OpenRouter)

- **Provider:** OpenRouter. **Suite:** `workspace` (the standard AgentDojo suite). **Attack:**
  `important_instructions_no_model_name`. **SAME frozen rules + frozen wrapper + release binary.**
- **Models (all ran, smoke OK, dated):** `openai/gpt-5.5` (gpt-5.5-20260423),
  `google/gemini-3.5-flash` (20260519), `google/gemini-3.1-pro-preview` (20260219),
  `minimax/minimax-m3` (20260531), `anthropic/claude-opus-4.8` (claude-4.8-opus-20260528).

### The bound triple — LIVE (current-frontier)
- (a) **attack-success TOTAL 0/80 (0.0%)** — EACH model 0/16.
- (b) **0/0 — UNDEFINED** (no live success exists to detect on).
- (c) **failed-injection FP 0/80; benign FP 0/15.** The download-corpus 28.7% correlation-FP did
  NOT reproduce on this live set (0/80).

### Real API-usage proof
**224 API calls, all HTTP 200; 698,959 tokens total** (smoke + live; under the 1M cap). Definitive
evidence of real consumption. **Key never logged** (read at runtime from outside the repo; never
committed, never in prompts; leak guard + canary green).

### CAVEAT (stated plainly)
The LIVE run used `suite=workspace` (the standard AgentDojo suite), NOT AgentDyn's harder
open-ended suites (shopping / github / dailylife) where last-gen models reached 14–22% ASR —
because the current-frontier OpenRouter IDs are not in AgentDyn's model registry. So the live 0/80
is on the EASIER standard suite; current-frontier behavior on the HARDER open-ended attack is
UNMEASURED (a documented follow-up). The download corpus (last-gen, open-ended) remains the only
set with real successes.

## Conclusion (no spin)

This run CLOSES the v2.0/v2.1 "real-world efficacy UNPROVEN by absence of any real trajectory" gap:
the mechanism fires on **real** traces (169/236 of last-gen open-ended successes), not only
synthetic. It does NOT establish efficacy: apohara is a CANDIDATE injection→consequence CORRELATION
surfacer, NOT a success/causation discriminator — it ALSO fires on 28.7% of RESISTED injections and
1.4% of benign traces (precision-on-success ≈ 20%). The discriminating signal (did the agent OBEY
the injection) is not representable in a deterministic post-hoc text-pattern model — this is the
quantified ceiling. Current-frontier models resisted 100% (0/80) of the standard attack; live
post-hoc detection is therefore undefined. See ADR-6 and the v2.2 `BENCHMARK.md` section.
