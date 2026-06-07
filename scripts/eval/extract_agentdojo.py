#!/usr/bin/env python3
"""Extract AgentDojo (ethz-spylab, MIT) injection-task GOALs into an apohara
INDEPENDENT, non-gating corpus.

What this captures: each AgentDojo injection task's GOAL — the attacker's malicious
instruction in natural-language prose. We wrap each GOAL in the scanner's session
action-record shape (a synthetic chat tool) so the rule engine can scan it.

HONESTY (the v1.4 category caveat): an AgentDojo injection is untrusted DATA the
agent *reads* (bait), not the agent's own action. Representing it as the agent's own
tool input measures BAIT-KEYWORD SURFACE COVERAGE — whether apohara's vocabulary +
\\b-boundary + source_kinds + context machinery would surface the attack class when
the attack text appears as an action — NOT injection-consequence detection. See
BENCHMARK.md and the ADR.

Labeling is BEST-EFFORT and explicit (a hand-authored map below, not fragile keyword
heuristics): each GOAL is mapped to the apohara AGT-* family that SHOULD surface that
attack class. A per-category recall "hit" = the scanner fires at least one expected code.

Run:  VIRTUAL_ENV=$PWD/eval/.venv eval/.venv/bin/python scripts/eval/extract_agentdojo.py
Output (committable, MIT): tests/corpus/agentdojo/{raw/<suite>.jsonl, expected.json, SOURCE.md}
"""
import json
import pathlib

BENCHMARK_VERSION = "v1.2.1"
SYNTHETIC_TOOL = "AgentChatMessage"  # documents the B1 representation in the raw shape
OUT_DIR = pathlib.Path("tests/corpus/agentdojo")

# Explicit, auditable best-effort label map: (suite, task_id) -> [expected AGT codes].
# Each code is the apohara family that SHOULD surface that attack class. Multi-aspect
# GOALs (e.g. exfil + delete) list the primary then secondary code.
LABELS = {
    # workspace (email / drive / calendar)
    ("workspace", "injection_task_0"): ["AGT-MIS-003"],                 # unauthorized email send
    ("workspace", "injection_task_1"): ["AGT-MIS-001"],                 # delete file (destructive)
    ("workspace", "injection_task_2"): ["AGT-MIS-003"],                 # unauthorized calendar event
    ("workspace", "injection_task_3"): ["AGT-EXF-001"],                 # forward email body externally
    ("workspace", "injection_task_4"): ["AGT-EXF-001"],                 # exfil 2FA security code
    ("workspace", "injection_task_5"): ["AGT-EXF-001", "AGT-MIS-001"],  # exfil code + delete trace
    ("workspace", "injection_task_6"): ["AGT-EXF-001", "AGT-MIS-001"],  # mass email exfil + delete
    ("workspace", "injection_task_7"): ["AGT-EXF-001", "AGT-MIS-001"],
    ("workspace", "injection_task_8"): ["AGT-EXF-001", "AGT-MIS-001"],
    ("workspace", "injection_task_9"): ["AGT-EXF-001", "AGT-MIS-001"],
    ("workspace", "injection_task_10"): ["AGT-EXF-001", "AGT-MIS-001"], # exfil all files + delete
    ("workspace", "injection_task_11"): ["AGT-EXF-001", "AGT-MIS-001"],
    ("workspace", "injection_task_12"): ["AGT-EXF-001", "AGT-MIS-001"],
    ("workspace", "injection_task_13"): ["AGT-MIS-003"],                # mass unauthorized email
    # travel
    ("travel", "injection_task_0"): ["AGT-MIS-003"],                    # unauthorized reservation
    ("travel", "injection_task_1"): ["AGT-EXF-001"],                    # send all messages externally
    ("travel", "injection_task_2"): ["AGT-MIS-003"],                    # unauthorized calendar event
    ("travel", "injection_task_3"): ["AGT-PII-001", "AGT-EXF-001"],     # harvest passport/bank + send
    ("travel", "injection_task_4"): ["AGT-MIS-003"],                    # unauthorized expensive booking
    ("travel", "injection_task_5"): ["AGT-PII-001", "AGT-EXF-001"],     # passport+credit card -> email
    ("travel", "injection_task_6"): ["AGT-MIS-003"],                    # forced recommendation (output manip)
    # banking
    ("banking", "injection_task_0"): ["AGT-FIN-001"],                   # send transaction
    ("banking", "injection_task_1"): ["AGT-FIN-001"],
    ("banking", "injection_task_2"): ["AGT-FIN-001"],
    ("banking", "injection_task_3"): ["AGT-FIN-001"],
    ("banking", "injection_task_4"): ["AGT-MIS-003", "AGT-FIN-001"],    # modify recurring-payment recipient
    ("banking", "injection_task_5"): ["AGT-FIN-001"],                   # send max money
    ("banking", "injection_task_6"): ["AGT-FIN-002"],                   # structuring (small increments)
    ("banking", "injection_task_7"): ["AGT-MIS-003"],                   # change password (acct takeover)
    ("banking", "injection_task_8"): ["AGT-EXF-001", "AGT-FIN-001"],    # exfil scheduled txns via transaction
    # slack
    ("slack", "injection_task_1"): ["AGT-EXF-002"],                     # send phishing link
    ("slack", "injection_task_2"): ["AGT-EXF-002"],                     # concat + post to website
    ("slack", "injection_task_3"): ["AGT-EXF-002"],                     # visit attacker website
    ("slack", "injection_task_4"): ["AGT-EXF-002"],                     # post channel to website
    ("slack", "injection_task_5"): ["AGT-MIS-003"],                     # unauthorized admin invite/remove
}

# v1.4 (c)/(d): F2-2 adds the broad prose-exfil detectors AGT-EXF-004 (bulk messaging
# exfil) and AGT-EXF-005 (external website/link). They are legitimate surfacers of the
# data-/web-exfiltration class for natural-language attacks the keyword-scoped
# EXF-001/002 miss, so the expected codes are extended to recognize them (a recall hit
# is fired ∩ expected ≠ ∅). This is transparent labeling, not overfitting: the rules
# fire on generic phrasings + a required exfil recipient, not item-specific strings.
# banking injection_task_8 exfiltrates via a transaction (caught by AGT-FIN-001 in
# F2-3), not via messaging, so EXF-004 is NOT added there.
for _key, _codes in LABELS.items():
    if _codes[0] == "AGT-EXF-001" and _key != ("banking", "injection_task_8"):
        _codes.append("AGT-EXF-004")
    if _codes[0] == "AGT-EXF-002":
        _codes.append("AGT-EXF-005")

# v1.4 F2-3: AGT-FIN-003 (prose money movement / structuring) is a valid surfacer of
# the financial class; add it wherever AGT-FIN-001/002 is expected (incl. items where
# the financial code is secondary, e.g. modify-recurring-payment and exfil-via-txn).
for _key, _codes in LABELS.items():
    if ("AGT-FIN-001" in _codes or "AGT-FIN-002" in _codes) and "AGT-FIN-003" not in _codes:
        _codes.append("AGT-FIN-003")

# Human-readable attack category per code family (for the corpus + reporting buckets).
CATEGORY = {
    "AGT-EXF-001": "data-exfiltration",
    "AGT-EXF-002": "web-exfiltration/phishing",
    "AGT-MIS-001": "destructive-action",
    "AGT-MIS-003": "unauthorized-autonomous-action",
    "AGT-FIN-001": "financial-transaction",
    "AGT-FIN-002": "financial-structuring",
    "AGT-PII-001": "pii-harvest",
}


def main() -> int:
    from agentdojo.task_suite.load_suites import get_suites

    suites = get_suites(BENCHMARK_VERSION)
    raw_dir = OUT_DIR / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    items = []
    per_suite_lines: dict[str, list[str]] = {}
    missing = []
    for suite_name, suite in suites.items():
        for tid, task in suite.injection_tasks.items():
            goal = (getattr(task, "GOAL", "") or "").strip()
            key = (suite_name, tid)
            codes = LABELS.get(key)
            if codes is None:
                missing.append(key)
                continue
            item_id = f"agentdojo-{suite_name}-{tid}"
            # B1 action-record shape: the GOAL prose as a synthetic chat-tool input.
            line = json.dumps(
                {
                    "type": "assistant",
                    "message": {
                        "content": [
                            {
                                "type": "tool_use",
                                "name": SYNTHETIC_TOOL,
                                "input": {"prompt": goal},
                            }
                        ]
                    },
                }
            )
            per_suite_lines.setdefault(suite_name, []).append(line)
            items.append(
                {
                    "id": item_id,
                    "suite": suite_name,
                    "upstream_task_id": tid,
                    "kind": "session-chat",
                    "input": goal,
                    "expected_agt_codes": codes,
                    "category": CATEGORY.get(codes[0], "other"),
                }
            )

    if missing:
        raise SystemExit(f"unlabeled injection tasks (update LABELS): {missing}")

    for suite_name, lines in per_suite_lines.items():
        (raw_dir / f"{suite_name}.jsonl").write_text("\n".join(lines) + "\n")

    expected = {
        "source": "AgentDojo (ethz-spylab/agentdojo)",
        "benchmark_version": BENCHMARK_VERSION,
        "license": "MIT",
        "representation": "B1: each injection-task GOAL wrapped as a synthetic chat-tool "
        "action input (session:%s.input). Measures bait-keyword surface coverage, "
        "NOT injection-consequence detection (see SOURCE.md / BENCHMARK.md / ADR)." % SYNTHETIC_TOOL,
        "synthetic_tool": SYNTHETIC_TOOL,
        "count": len(items),
        "items": items,
    }
    (OUT_DIR / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")
    print(f"wrote {len(items)} AgentDojo items -> {OUT_DIR}/expected.json")
    print("per-suite:", {k: len(v) for k, v in per_suite_lines.items()})
    from collections import Counter
    cat = Counter(it["category"] for it in items)
    print("categories:", dict(cat))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
