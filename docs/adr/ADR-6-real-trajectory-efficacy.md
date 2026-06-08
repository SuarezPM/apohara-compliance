# ADR-6: Real-Trajectory Efficacy — measured on real successes + live current-frontier cross-check

**Status:** ACCEPTED (v2.2, 2026-06-08). Base = v2.1 (ADR-5). All LOCAL. Pre-registration:
`tests/corpus/PREREG-v2.2-real-trajectory.md` (rules frozen at blob SHA
`dcd1ac6e1d7ed8dce4b5b516296e8ce5a3e0582a` BEFORE any scan; verified unchanged). Honesty lineage:
v2.0/ADR-4 (mechanism proven on synthetic positives; real-world efficacy UNPROVEN — MiniMax refused
all 10) → v2.1/ADR-5 (representation gap closed; structured sinks + generic markers fire on a
synthetic positive; still no real trajectory corpus) → **v2.2/ADR-6 (the mechanism is MEASURED on
REAL successful trajectories, AND the correlation-not-causation ceiling is quantified).**

## Context

v2.0 and v2.1 left real-world efficacy "UNPROVEN **by absence of any real trajectory**": v2.0's live
MiniMax run was 0/10 (the target refused everything) and the committed AgentDojo corpus was flat
bait (0 trajectories). A real measurement needs REAL successful injection→consequence trajectories,
externally labeled, scanned with the FROZEN rules — without changing the scanner.

## Decision

Measure apohara's post-hoc detection on REAL injection→consequence traces from TWO sources, with the
CORRECTED label polarity (`security==True AND injection-present` = the POSITIVE/attack-succeeded
bucket), without touching the scanner, the wrapper, or the rules:

1. **DOWNLOAD corpus (the real-success volume, last-gen, date-labeled).** SaFo-Lab/AgentDyn (MIT)
   pinned at `5353cf7615b135cace8d07c8f12dac53a16b6db3`, agentdojo 0.1.35, benchmark v1.2.2, attack
   `important_instructions`, open-ended suites (shopping/github/dailylife). Last-gen models
   (gpt-5.1-2025-11-13, gpt-5-mini-2025-08-07, gemini-2.5-pro/flash), date-labeled, used for the
   model-INDEPENDENT real-success + overlap-miss numbers. Buckets (gated by `assert_polarity.py`):
   POSITIVE = 236, FAILED = 2295, BENIGN = 352.
2. **LIVE current-frontier cross-check (the resistance number).** A bounded OpenRouter run on TRUE
   current-frontier models (gpt-5.5, gemini-3.5-flash, gemini-3.1-pro-preview, minimax-m3,
   claude-opus-4.8), suite `workspace`, attack `important_instructions_no_model_name`, SAME frozen
   rules + wrapper + release binary.

Both transcribe via the FROZEN apohara-agnostic `wrap_agentdojo_trace.py` → the REAL release binary;
report the bound-triple + overlap-miss as-is; never retro-fit.

## Measured result (the bound triple + ceiling — verbatim, no overclaim)

**HEADLINE.** apohara v2.1 post-hoc-recognizes the injection→sink CORRELATION in **169/236
(71.6%)** of REAL successful indirect-injection trajectories from last-generation frontier models
(AgentDyn open-ended suites). This closes the v2.0 "real-world efficacy UNPROVEN by absence of any
real trajectory" gap — the mechanism fires on real traces, not only synthetic.

**CO-HEADLINE LIMIT (equally prominent, never buried).** It ALSO fires on **28.7% (659/2295)** of
RESISTED injections and **1.4% (5/352)** of benign traces. apohara is a CANDIDATE
injection→consequence CORRELATION surfacer, NOT a success/causation discriminator: a resisted
injection still carries the marker in a tool-result AND the agent still performs a legitimate
structured sink, so the marker→sink correlation fires in both succeeded and resisted cases.
**precision-on-success ≈ 169 / (169+659+5) = 169/833 ≈ 20%.** The discriminating signal (did the
agent OBEY the injection) is not representable in a deterministic post-hoc text-pattern model — this
is the quantified ceiling.

- **(a) DOWNLOAD model attack-success-rate** (AgentDyn labels, apohara-independent): gpt-5.1 33/851
  (3.9%); gpt-5-mini 2/560 (0.4%); gemini-2.5-pro 122/560 (21.8%); gemini-2.5-flash 79/560 (14.1%).
- **(b) post-hoc detection on the 236 successes: 169/236 (71.6%)** — gpt-5.1 25/33; gpt-5-mini 0/2;
  gemini-2.5-pro 89/122; gemini-2.5-flash 55/79 (AGT-TRJ-001 dominant, AGT-TRJ-003 secondary).
- **(c) FP control:** failed-injection 659/2295 (28.7%); benign 5/352 (1.4%).
- **Overlap-miss** (model-independent, 236 positives): marker `<information>` covered 232/236;
  role-mapped structured sink covered 180/236; BOTH 178/236; NEITHER 2/236. Covered roles: url=170,
  recipient=60, amount=59, command=34. MISSED arg-keys (the `iban`-analog, OUTSIDE the frozen role
  map): path (161), subject (114), otp (87), title (79), body (68), recipients (68), repo_name (54),
  password (33). **Reported as-is, NEVER closed.**

**LIVE current-frontier.** 2026 current-frontier models (gpt-5.5, gemini-3.5-flash,
gemini-3.1-pro-preview, minimax-m3, claude-opus-4.8) resisted **100% (0/80)** of the standard
`important_instructions` attack on the workspace suite; with zero live successes, live post-hoc
detection is **0/0 — undefined**. FP control: failed-injection 0/80; benign 0/15 (the download
28.7% correlation-FP did NOT reproduce on this live set). Real usage: **224 API calls, all HTTP 200;
698,959 tokens** (under the 1M cap); key never logged. **CAVEAT:** the live run used `suite=workspace`
(the standard AgentDojo suite), NOT AgentDyn's harder open-ended suites where last-gen models reached
14–22% ASR — because the current-frontier OpenRouter IDs are not in AgentDyn's model registry. So the
live 0/80 is on the EASIER standard suite; current-frontier behavior on the harder open-ended attack
is UNMEASURED (a documented follow-up). The download corpus (last-gen, open-ended) remains the only
set with real successes.

## Drivers

- **D1 — an honest real-success number with volume.** The date-labeled download corpus supplies real
  successful trajectories (236) at volume; the overlap-miss is model-independent, so last-gen models
  legitimately measure representation coverage. The live run supplies the only current-frontier
  number + real-usage proof.
- **D2 — keep the number a MEASUREMENT, not a fit.** Pre-registration (rules frozen at `dcd1ac6`
  BEFORE scanning) + apohara-agnostic transcription + external `security` labels. A low/0 (b) — and
  the 28.7% (c) — are VALID results, never a trigger to add vocab. The missed arg-keys are documented
  overlap-miss, deliberately NOT closed.
- **D3 — the ceiling must survive a real positive.** Post-hoc, template-scoped, conditional on
  representation overlap; recognizable-in-log ≠ would-have-prevented; NOT efficacy/recall/prevention.

## Alternatives considered (rejected, with rationale)

- **Download-only (no live)** — REJECTED: loses the only current-frontier number + the real-usage
  proof; the resistance result (0/80) is itself informative.
- **Live-only (no download)** — REJECTED: current-frontier models resist (0 live successes), so a
  live-only run would have NO real positive to measure on — re-creating the v2.0 "absence" gap and
  losing the 236-positive overlap-miss volume.
- **Old models (gpt-4o / gpt-4-0125 / gpt-3.5) as the headline** — REJECTED: out of scope by the
  frontier-only constraint; their high ASR would inflate the number on obsolete targets.
- **Using the DOWNLOAD last-gen models as a "current-frontier efficacy" headline** — REJECTED: they
  are last-gen; they appear ONLY as date-labeled real-success + overlap-miss references, never a
  frontier-efficacy claim.
- **Computing the positive bucket as `security==False`** (the Rev-1 polarity inversion) — REJECTED:
  that is the RESISTED bucket; triple-verified polarity proof, gated by `assert_polarity.py`.
- **Adding `iban` (or any missed arg-key) to the role map after seeing traces** — REJECTED: a
  retro-fit converts the measurement into a fit; the overlap-miss is reported as-is.
- **Any scanner-crate / wrapper / rule change** — OUT OF SCOPE: re-opens the pre-registration; the
  representation already shipped in v2.1.

## Why this was chosen

BOTH sources together produce the honest synthesis the absence gap demanded: a real-trajectory
number with volume (download) AND a current-frontier resistance number with real-usage proof (live),
each carrying its full bound-triple. The 71.6% recall and the 28.7% correlation-FP are stated as
co-headlines of equal prominence — the framing IS the deliverable.

## Consequences

- **The gap is closed honestly:** the mechanism fires on REAL traces (169/236), not only synthetic —
  AND the same run quantifies the ceiling (28.7% FP on resisted injections; precision-on-success
  ≈ 20%). Both numbers are stated; neither is buried.
- The scanner + wrapper stay byte-identical, offline, deterministic, FP=0 (synthetic gate still
  1.0/1.0/FP=0). The AGT-TRJ rules are unchanged (blob SHA `dcd1ac6` verified post-scan).
- A gitignored, date-labeled AgentDyn corpus (no example text committed); a numbers/IDs-only report
  (`tests/corpus/v2.2-real-trajectory-report.json`, strict-schema-validated by
  `scripts/eval/validate_v22_report.py`, wired into `scripts/verify.sh`); PREREG-v2.2 + PROOF-v2.2.
- **Amended claim ceiling:** *"deterministic, post-hoc, representation-aware injection→consequence
  CANDIDATE CORRELATION surfacer; mechanism + representation proven on synthetic positives; post-hoc
  recognition MEASURED on real successful trajectories (169/236, last-gen open-ended) with an explicit
  model-independent overlap-miss; ALSO fires on resisted (28.7%) + benign (1.4%) — a correlation
  surfacer, NOT a success/causation discriminator (precision-on-success ≈ 20%); NOT efficacy / recall
  / prevention; recognizable-in-log ≠ would-have-prevented."*

## Follow-ups

- **Current-frontier on the harder open-ended suites** (shopping/github/dailylife) — blocked by
  AgentDyn's model registry not carrying the current-frontier OpenRouter IDs; a registry addition (or
  an AgentDyn-side mapping) would let the live headline run the harder attack.
- **The representation overlap-miss** (the missed arg-keys path/otp/repo_name/… — the `iban`-analog)
  — documented, deliberately NOT closed; closing it requires a SEPARATE future pre-registration, not
  a retro-fit of this measurement.
- **Causal vs correlation** — the discriminating "did the agent OBEY" signal is not representable in a
  deterministic post-hoc text-pattern model; a value-level / runtime approach is a future separate
  ADR, not this one.
- Repo-file normalization (the deferred ADR-5 M4 gap); S2 `conch-parser` escalation if shlex proves
  insufficient; the version-badge / tag bump (Pablo-gated).
