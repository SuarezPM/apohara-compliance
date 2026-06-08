# AgentDyn — EVAL-ONLY corpus source (no example trace text committed)

## Source & license

- **Upstream:** [SaFo-Lab/AgentDyn](https://github.com/SaFo-Lab/AgentDyn) — a dynamic
  agentic-security benchmark built on top of AgentDojo (arXiv 2602.03117).
  (`leolee99/AgentDyn` 301-redirects to the same repo.)
- **License:** **MIT** (Copyright (c) 2024 Edoardo Debenedetti, Jie Zhang, Mislav
  Balunović, Luca Beurer-Kellner, Marc Fischer, Florian Tramèr — the AgentDojo authors,
  inherited by AgentDyn). Redistribution is permitted under MIT, but per this project's
  eval-only posture (matching SOURCE-agentharm.md) **no example trace text is committed.**
- **Pinned provenance:**
  - AgentDyn commit `5353cf7615b135cace8d07c8f12dac53a16b6db3` (2026-05-19).
  - `agentdojo_package_version` **0.1.35** (recorded in each trace).
  - `benchmark_version` **v1.2.2** (recorded in each trace).
  - The committed `runs/` `.gitignore` strips the 4 ORIGINAL AgentDojo suites
    (banking / slack / travel / workspace); only AgentDyn's NEW suites are committed:
    **shopping, github, dailylife**.

## Models used — DATE-LABELED, overlap-miss reference ONLY (NOT current frontier)

The committed AgentDyn `runs/` were produced by **LAST-GEN / OLD** models. They are used
**ONLY** for the model-INDEPENDENT overlap-miss (representation-coverage) analysis, and
are **NEVER** presented as a current-frontier efficacy headline. The overlap-miss is a
property of the benchmark's attack template + the tool field-name schemas, not of which
model executed — which is why a last-gen corpus is legitimate for THIS analysis.

| no-defense model dir | date label | currency posture |
|---|---|---|
| `gpt-5.1-2025-11-13` | gpt-5.1, Nov-2025 | **LAST-GEN** (per Pablo's June-2026 frontier line) |
| `gpt-5-mini-2025-08-07` | gpt-5-mini, Aug-2025 | **LAST-GEN** (only 2 positives — too thin to use) |
| `google_gemini-2.5-pro` | gemini-2.5-pro | **OLD** — explicitly NOT current frontier |
| `google_gemini-2.5-flash` | gemini-2.5-flash | **OLD** — explicitly NOT current frontier |

> The June-2026 current frontier is GPT-5.5 / Gemini 3.1 Pro / Gemini 3.5 Flash /
> MiniMax-M3 / Claude Opus 4.8. None of the AgentDyn committed models are current-frontier;
> they appear here strictly as date-labeled overlap-miss references.

## What is captured (and why nothing under `eval/` is committed)

The whole AgentDyn corpus is cloned into the **gitignored** `eval/agentdyn/` tree
(`.gitignore: /eval/`); the `scripts/verify.sh` leak guard asserts **nothing under
`eval/` is ever tracked**. Concretely:

- The corpus + the derived bucket manifests (`eval/v22-buckets/{positive,failed,benign}.txt`)
  and the scan results (`eval/v22-scan-results.json`) all live under gitignored `eval/`.
- The only committed AgentDyn-derived artifacts are **tooling/provenance** under
  `scripts/eval/` (this file, `extract_agentdyn_positives.py`, `count_agentdyn_positives.py`,
  `assert_polarity.py`) and a **numbers/IDs-only** pre-registration + report under
  `tests/corpus/` (`PREREG-v2.2-real-trajectory.md`). No example trace text, no marker
  strings copied from traces, no key.

## Bucket polarity (Critic-verified — the corrected polarity)

```
POSITIVE = security == True  AND  injection-present (attack_type not in {None,"none"}
                                  AND injections non-empty AND basename != none.json)
FAILED   = security == False AND  injection-present
BENIGN   = no injection present  (ALWAYS security==True via AgentDojo's no-injection
                                  early-return default -> partition by attack-present,
                                  NEVER by security)
```

`security == True` ⇒ the injection SUCCEEDED (the agent executed the attacker's target
action). This is empirically gated by `scripts/eval/assert_polarity.py`
(`security==True ⟺ delivered to the attacker's recipient/account`). AgentDyn's own
results table renames the `security` column to "Targeted ASR" (higher = more success),
corroborating the polarity.

## Honesty caveat

apohara is a deterministic, OFFLINE, POST-HOC scanner. Firing on a real successful-
injection trace is **post-hoc recognizability** on a benchmark template, template-scoped,
and conditional on the pre-registered marker/sink vocab overlapping the attack's markers +
the tool field-name schema. It is **NOT efficacy / recall / prevention** —
recognizable-in-log ≠ would-have-prevented. The reported numbers always carry the bound
triple (model attack-success / apohara post-hoc detection / failed+benign FP) and the
explicit overlap-miss. The overlap-miss is reported **as-is** and is **NEVER** closed by
editing the frozen detection rules.

## Reproduce (local only; requires the gitignored clone)

```
git clone https://github.com/SaFo-Lab/AgentDyn eval/agentdyn        # gitignored
git -C eval/agentdyn checkout 5353cf7615b135cace8d07c8f12dac53a16b6db3
python3 scripts/eval/assert_polarity.py            # polarity HARD GATE (must PASS)
python3 scripts/eval/count_agentdyn_positives.py   # confirm 236 positives
python3 scripts/eval/extract_agentdyn_positives.py # write gitignored bucket manifests
```
