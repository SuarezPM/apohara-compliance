# AgentHarm — EVAL-ONLY source (no examples committed)

## Source & license

- **Upstream:** [ai-safety-institute/AgentHarm](https://huggingface.co/datasets/ai-safety-institute/AgentHarm)
  — "AgentHarm: A Benchmark for Measuring Harmfulness of LLM Agents"
  (Andriushchenko et al., 2024). Config `harmful`, split `test_public` (176 augmented
  prompts over 44 public base behaviors).
- **License:** MIT **with an additional clause**: the dataset may be used **solely to
  improve the safety and security of AI systems**, and the authors **request no use of
  the examples for training** — evaluation only. The dataset **carries a canary GUID**.

## Why nothing from AgentHarm is committed

Because of the eval-only / no-redistribution posture and the canary, **no AgentHarm
example text is ever committed to this repository.** Concretely:

- The dataset is downloaded on demand into the **gitignored** `eval/agentharm/.cache`
  (HuggingFace cache); it never enters git.
- The canary GUID is stored **only** in the gitignored `eval/agentharm/.canary` — it is
  the pattern the `scripts/verify.sh` leak guard greps for over **tracked** files. It is
  **not reproduced here by policy** (this file is committed).
- The only committed artifact derived from AgentHarm is a **numbers/IDs-only report**
  at `tests/corpus/agentharm-report.json`: aggregate counts, per-category coverage
  rates, fired-AGT-code counts, and bare behavior identifiers (`id` / `id_original`,
  which match a strict `^[0-9]+(-[0-9]+)*$` pattern). It contains **no** prompt text,
  no behavior `name`, no `detailed_prompt`, no `grading_function`, and no canary. A
  schema validator (`scripts/eval/validate_report_schema.py`) enforces this.

## What the report measures (honesty caveat)

The same bait-keyword surface-coverage caveat as the AgentDojo corpus applies: an
AgentHarm prompt is the attacker's instruction, represented to the scanner as an action
input. The number is **surface coverage of harmful-agentic vocabulary**, not
injection-consequence detection. AgentHarm's content-harm categories (e.g. fraud,
cybercrime) are **not** apohara `AGT-*` tool-abuse codes, so the metric is "fraction of
AgentHarm harmful prompts on which apohara surfaces ≥1 candidate," broken down by
AgentHarm category and by which AGT codes fire.

## Reproduce (local only; requires the gitignored eval/.venv)

```
HF_HOME=$PWD/eval/agentharm/.cache \
  eval/.venv/bin/python scripts/eval/run_agentharm_eval.py     # -> tests/corpus/agentharm-report.json
eval/.venv/bin/python scripts/eval/validate_report_schema.py    # enforces numbers/IDs-only
```
