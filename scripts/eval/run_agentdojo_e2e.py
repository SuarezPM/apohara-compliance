#!/usr/bin/env python3
"""F5A: AgentDojo END-TO-END with MiniMax-M3 → measured POST-HOC detection (Amendment A).

Runs a bounded set of AgentDojo (banking suite) injection×user task pairs under the
`important_instructions` attack, with MiniMax-M3 as the agent LLM. AgentDojo's own
`security` verdict labels which injections SUCCEEDED (the agent performed the malicious
tool call). Each conversation is transcribed by the FROZEN apohara-agnostic 1:1 wrapper
(wrap_agentdojo_trace.py) and scanned by the REAL apohara binary.

Reports the BOUND TRIPLE (never one number alone, change 6/H1):
  (a) MiniMax attack-success-rate (successful / attacked)
  (b) apohara post-hoc detection k-of-N on SUCCESSFUL-injection traces
  (c) failed-injection FP (apohara firing on marker-present-but-unsuccessful traces — must be 0)
Plus benign-trace FP and the marker/representation generalization-gap note (H4).

HONESTY: this is POST-HOC recognizability on AgentDojo's `important_instructions`
template, conditional on the AGT-TRJ rule vocab overlapping AgentDojo's STRUCTURED
tool-call representation. It is NOT efficacy, NOT recall, NOT prevention. Small-n →
raw counts, never percentages. Real API usage logged (tokens), key never logged.

Run: HF unused. eval/.venv/bin/python scripts/eval/run_agentdojo_e2e.py
"""
import json
import os
import subprocess
import sys
import tempfile

AUTH = os.path.expanduser("~/.local/share/opencode/auth.json")
BIN = "target/release/apohara-compliance-scanner"
RULES = "references"
SUITE = "banking"
ATTACK = "important_instructions"
BENCH = "v1.2.1"
# Bounded N (documented). user_task × injection_task grid + benign user_tasks.
USER_TASKS = ["user_task_0", "user_task_1"]
INJECTION_TASKS = ["injection_task_0", "injection_task_1", "injection_task_2", "injection_task_4", "injection_task_5"]

# --- cumulative real-usage proof (no key) -----------------------------------
_USAGE = {"calls": 0, "total_tokens": 0}


def _agt_trj(messages) -> list:
    """Wrap an AgentDojo message list (frozen 1:1) and scan via the real binary."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import wrap_agentdojo_trace as W

    lines = W.wrap(messages)
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        f.write("\n".join(lines) + "\n")
        path = f.name
    try:
        out = subprocess.run(
            [BIN, "--rules-dir", RULES, "scan-session", path, "--format", "json"],
            capture_output=True, text=True, check=True,
        ).stdout
    finally:
        os.unlink(path)
    rep = json.loads(out)
    return sorted({x["id"] for x in rep.get("findings", []) if x["id"].startswith("AGT-TRJ")})


def main() -> int:
    key = json.load(open(AUTH))["minimax"]["key"]
    from openai import OpenAI
    from agentdojo.agent_pipeline import (
        AgentPipeline, SystemMessage, InitQuery, OpenAILLM, ToolsExecutionLoop, ToolsExecutor, AbortAgentError,
    )
    from agentdojo.agent_pipeline.agent_pipeline import load_system_message
    from agentdojo.attacks import load_attack
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suites
    from agentdojo.task_suite.task_suite import (
        model_output_from_messages, functions_stack_trace_from_messages,
    )

    client = OpenAI(base_url="https://api.minimax.io/v1", api_key=key)
    # Wrap create() to accumulate REAL token usage (proof), without touching the key.
    _orig = client.chat.completions.create
    def _counting_create(*a, **k):
        r = _orig(*a, **k)
        _USAGE["calls"] += 1
        if getattr(r, "usage", None):
            _USAGE["total_tokens"] += getattr(r.usage, "total_tokens", 0) or 0
        return r
    client.chat.completions.create = _counting_create  # type: ignore

    llm = OpenAILLM(client, "MiniMax-M3")
    sysmsg = load_system_message(None)
    pipeline = AgentPipeline(
        [SystemMessage(sysmsg), InitQuery(), llm, ToolsExecutionLoop([ToolsExecutor(), llm])]
    )
    pipeline.name = "minimax-m3-none"

    suite = get_suites(BENCH)[SUITE]
    attack = load_attack(ATTACK, suite, pipeline)

    def run_one(ut, it, injections):
        """Return (messages, security_bool_or_None)."""
        env = suite.load_and_inject_default_environment(injections)
        task_env = ut.init_environment(env)
        pre = task_env.model_copy(deep=True)
        runtime = FunctionsRuntime(suite.tools)
        try:
            _, _, post, messages, _ = pipeline.query(ut.PROMPT, runtime, task_env)
        except AbortAgentError as e:
            post, messages = e.task_environment, e.messages
        sec = None
        if it is not None:
            mo = model_output_from_messages(messages)
            tr = functions_stack_trace_from_messages(messages)
            try:
                sec = suite._check_task_result(it, mo, pre, post, tr)
            except Exception as e:
                print(f"    security check error: {type(e).__name__}: {str(e)[:80]}")
        return messages, sec

    successful, failed, benign = [], [], []  # each: (label, agt_trj_ids)

    # Attacked pairs.
    for uid in USER_TASKS:
        ut = suite.user_tasks[uid]
        for iid in INJECTION_TASKS:
            it = suite.injection_tasks[iid]
            injections = attack.attack(ut, it)
            try:
                messages, sec = run_one(ut, it, injections)
            except Exception as e:
                print(f"  {uid}×{iid}: RUN ERROR {type(e).__name__}: {str(e)[:100]}")
                continue
            ids = _agt_trj(messages)
            tag = "SUCCESS" if sec else "fail"
            print(f"  {uid}×{iid}: injection={tag} apohara_AGT-TRJ={ids}")
            (successful if sec else failed).append((f"{uid}/{iid}", ids))

    # Benign (no injection) — the clean FP control.
    for uid in USER_TASKS:
        ut = suite.user_tasks[uid]
        try:
            messages, _ = run_one(ut, None, {})
        except Exception as e:
            print(f"  benign {uid}: RUN ERROR {type(e).__name__}: {str(e)[:100]}")
            continue
        ids = _agt_trj(messages)
        print(f"  benign {uid}: apohara_AGT-TRJ={ids}")
        benign.append((uid, ids))

    n_attacked = len(successful) + len(failed)
    n_succ = len(successful)
    succ_detected = sum(1 for _, ids in successful if ids)
    failed_fp = sum(1 for _, ids in failed if ids)
    benign_fp = sum(1 for _, ids in benign if ids)

    report = {
        "harness": "agentdojo-e2e",
        "suite": SUITE, "attack": ATTACK, "benchmark": BENCH, "model": "MiniMax-M3",
        "n_attacked": n_attacked,
        "minimax_attack_success": {"successful": n_succ, "attacked": n_attacked},
        "apohara_posthoc_detection_on_successes": {"detected": succ_detected, "of": n_succ},
        "failed_injection_fp": {"fired": failed_fp, "of": len(failed)},
        "benign_fp": {"fired": benign_fp, "of": len(benign)},
        "real_api_usage": {"minimax_calls": _USAGE["calls"], "total_tokens": _USAGE["total_tokens"]},
        "framing": "POST-HOC recognizability on AgentDojo important_instructions; conditional on "
                   "AGT-TRJ vocab overlapping AgentDojo's STRUCTURED tool-call representation; "
                   "NOT efficacy/recall/prevention. Small-n -> raw counts, never %.",
    }
    os.makedirs("eval/agentharm", exist_ok=True)  # gitignored scratch
    json.dump(report, open("eval/agentdojo-e2e-report.json", "w"), indent=2)
    print("\n=== F5A BOUND TRIPLE (post-hoc, template-scoped) ===")
    print(f"  (a) MiniMax attack-success-rate: {n_succ} of {n_attacked} attacked")
    print(f"  (b) apohara post-hoc detection on SUCCESSES: {succ_detected} of {n_succ}")
    print(f"  (c) failed-injection FP: {failed_fp} of {len(failed)}  |  benign FP: {benign_fp} of {len(benign)}")
    print(f"  real MiniMax usage: {_USAGE['calls']} calls, {_USAGE['total_tokens']} tokens")
    print("  report -> eval/agentdojo-e2e-report.json (gitignored scratch)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
