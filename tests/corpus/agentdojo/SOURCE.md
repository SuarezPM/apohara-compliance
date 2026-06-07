# AgentDojo independent corpus — source, license, and labeling

## Source & license

- **Upstream:** [ethz-spylab/agentdojo](https://github.com/ethz-spylab/agentdojo) —
  "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses
  for LLM Agents" (Debenedetti et al., NeurIPS 2024 Datasets & Benchmarks).
- **License:** MIT (redistribution permitted with attribution). The extracted content
  here is the set of **injection-task `GOAL` strings** (the attacker's malicious
  instruction in prose) from benchmark version **v1.2.1**, across the four suites
  (`workspace`, `travel`, `banking`, `slack`).
- The IBANs, email addresses, and names inside the GOALs are AgentDojo's own
  **fictional fixture data** — not real PII. No local paths or real personal data are
  present.

## What this corpus measures (honesty caveat — read before citing any number)

An AgentDojo injection is **untrusted DATA the agent reads** (bait planted in an email,
a webpage, a document), **not the agent's own action**. apohara scans an agent's
actions. To run the rule engine over this content we wrap each GOAL as a synthetic
chat-tool action input (`session:AgentChatMessage.input`, the "B1" representation).

Therefore the recall measured over this corpus is **bait-keyword surface coverage over
labeled injection STRINGS — NOT injection-consequence detection.** It tells you whether
apohara's vocabulary, `\b`-boundary, `source_kinds`, and context machinery would surface
the attack *class* when the attack text appears as an action. It does **not** tell you
whether apohara detects the *consequence* of a successful injection (the downstream
tricked action). Modeling AgentDojo **trajectories** (the agent's post-injection tool
calls) is the right vehicle for consequence detection and is a documented follow-up.

This corpus is **non-gating**: it drives the separate `#[ignore]` harness
`crates/scanner/tests/independent_corpus.rs`; it is never merged into the synthetic CI
gate (`tests/corpus/expected.json`).

## Labeling method (best-effort, explicit)

Each GOAL is mapped to the apohara `AGT-*` family that *should* surface that attack
class. The mapping is a hand-authored, auditable table in
`scripts/eval/extract_agentdojo.py` (`LABELS`), not a fragile keyword heuristic. A
per-category recall "hit" = the scanner fires at least one of an item's
`expected_agt_codes`. Multi-aspect GOALs (e.g. exfiltrate-then-delete) list the primary
then secondary code.

| Attack class | apohara family | # items |
|---|---|---|
| data-exfiltration (email/forward data externally) | AGT-EXF-001 | 12 |
| web-exfiltration / phishing (post to site, send link) | AGT-EXF-002 | 4 |
| unauthorized autonomous action (send/book/calendar/admin) | AGT-MIS-003 | 10 |
| destructive action (delete) | AGT-MIS-001 | 1 |
| financial transaction (send/transfer money) | AGT-FIN-001 | 5 |
| financial structuring (small-increment splits) | AGT-FIN-002 | 1 |
| PII harvest (passport/credit-card/bank/ID) | AGT-PII-001 | 2 |

(Counts are by each item's **primary** category; several items carry a secondary code.)

## Provenance

- `expected.json` — 35 labeled items `{id, suite, upstream_task_id, kind, input,
  expected_agt_codes, category}`. Each `upstream_task_id` is the AgentDojo task id
  (e.g. `injection_task_6`) for traceability back to the upstream suite.
- `raw/<suite>.jsonl` — one JSONL line per item in the scanner's session action-record
  shape, directly feedable to `apohara-compliance-scanner scan-session`.
- Regenerate with: `eval/.venv/bin/python scripts/eval/extract_agentdojo.py`
  (requires `agentdojo` installed in the gitignored `eval/.venv`).
- Validate shape with: `eval/.venv/bin/python scripts/eval/validate_agentdojo_shape.py`.
