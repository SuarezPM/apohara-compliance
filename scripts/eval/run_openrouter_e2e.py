#!/usr/bin/env python3
"""v2.2 Phase-4 AC4.2 — WIDE bounded LIVE run on AgentDyn open-ended suites via OpenRouter.

Drives AgentDyn (AgentDojo lineage, pinned 5353cf7 / benchmark v1.2.2) end-to-end with
TRUE CURRENT-frontier models served over OpenRouter's OpenAI-compatible endpoint, using
AgentDyn's PUBLISHED `important_instructions` attack family. Because OpenRouter's
current-frontier ids are NOT in AgentDyn's model registry, we:
  * point AgentDojo's OpenAILLM at base_url=https://openrouter.ai/api/v1 with the
    current-frontier model id (path (ii) of the brief), and
  * use the model-name-AGNOSTIC published variant `important_instructions_no_model_name`
    (the registered variant for non-registered models; AgentDyn-published; NOT rule-tuning,
    NOT an apohara change — identical posture to v2.0's harness).

AgentDyn's own `_check_task_result` (`security` label) decides which injections SUCCEEDED.
We capture the FULL trajectory (messages, JSON-serialized) + the per-task `security` label
into gitignored eval/v22-live/ for OFFLINE apohara scanning later. The scanner is NOT run
here — this script only does the paid live run + capture.

BUDGET: a hard cumulative token cap (default 1,000,000) across the whole run. Each
response's `usage.total_tokens` is accumulated; we HARD-ABORT before exceeding it. Per-call
HTTP outcome + tokens are logged to a gitignored eval/ proof file. The OpenRouter key is
read ONLY into a local variable and is NEVER printed/logged/written.

Run: eval/.venv/bin/python scripts/eval/run_openrouter_e2e.py
"""
import argparse
import json
import os
import sys
import time

AUTH = os.path.expanduser("~/.local/share/opencode/auth.json")
BASE_URL = "https://openrouter.ai/api/v1"
HERE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT_DIR = os.path.join(HERE, "eval", "v22-live")

# Phase-0-verified current-frontier ids (all passed AC4.1 smoke).
DEFAULT_MODELS = [
    "openai/gpt-5.5",
    "google/gemini-3.5-flash",
    "google/gemini-3.1-pro-preview",
    "minimax/minimax-m3",
    "anthropic/claude-opus-4.8",
]
ATTACK = "important_instructions_no_model_name"
BENCH = "v1.2.2"


class BudgetExceeded(Exception):
    pass


class Budget:
    def __init__(self, cap):
        self.cap = cap
        self.total = 0
        self.calls = 0

    def add(self, n):
        self.total += int(n or 0)
        self.calls += 1
        if self.total > self.cap:
            raise BudgetExceeded(f"cumulative tokens {self.total} > cap {self.cap}")


def _fc_to_dict(call):
    """AgentDojo FunctionCall (pydantic) -> {function,args} dict for capture + offline scan."""
    fn = getattr(call, "function", None)
    if fn is None and isinstance(call, dict):
        fn = call.get("function")
    args = getattr(call, "args", None)
    if args is None and isinstance(call, dict):
        args = call.get("args")
    # args may be a MutableMapping with non-JSON values; coerce defensively.
    try:
        json.dumps(args)
        sargs = args
    except (TypeError, ValueError):
        sargs = {k: str(v) for k, v in dict(args or {}).items()}
    return {"function": fn, "args": sargs or {}}


def _content_to_json(content):
    """Serialize AgentDojo message content (str | list[block]) to JSON-safe form."""
    if content is None or isinstance(content, str):
        return content
    if isinstance(content, list):
        out = []
        for b in content:
            if isinstance(b, str):
                out.append(b)
            elif isinstance(b, dict):
                out.append({k: b.get(k) for k in ("type", "content", "text") if k in b})
            else:
                # pydantic content block
                d = {}
                for k in ("type", "content", "text"):
                    v = getattr(b, k, None)
                    if v is not None:
                        d[k] = v
                out.append(d or str(b))
        return out
    return str(content)


def serialize_messages(messages):
    """AgentDojo ChatMessage list -> JSON-safe dicts the Phase-3 scanner can read 1:1."""
    out = []
    for m in messages:
        role = m.get("role") if isinstance(m, dict) else getattr(m, "role", None)
        rec = {"role": role}
        content = m.get("content") if isinstance(m, dict) else getattr(m, "content", None)
        rec["content"] = _content_to_json(content)
        if role == "assistant":
            tcs = m.get("tool_calls") if isinstance(m, dict) else getattr(m, "tool_calls", None)
            rec["tool_calls"] = [_fc_to_dict(c) for c in (tcs or [])]
        elif role == "tool":
            tcid = m.get("tool_call_id") if isinstance(m, dict) else getattr(m, "tool_call_id", None)
            rec["tool_call_id"] = tcid
        out.append(rec)
    return out


def build_pipeline(client, model, OpenAILLM, AgentPipeline, SystemMessage, InitQuery,
                   ToolsExecutionLoop, ToolsExecutor, load_system_message):
    llm = OpenAILLM(client, model)
    sysmsg = load_system_message(None)
    pipeline = AgentPipeline(
        [SystemMessage(sysmsg), InitQuery(), llm, ToolsExecutionLoop([ToolsExecutor(), llm])]
    )
    # Non-registered model -> generic "local" name; no false branding. The no_model_name
    # attack variant does not embed the model name anyway. Setup-only; rules stay frozen.
    pipeline.name = "local"
    return pipeline


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="*", default=DEFAULT_MODELS)
    ap.add_argument("--suite", default="workspace")
    ap.add_argument("--cap", type=int, default=1_000_000, help="hard cumulative token cap")
    ap.add_argument("--user-tasks", type=int, default=4, help="# user_tasks per model")
    ap.add_argument("--injection-tasks", type=int, default=4, help="# injection_tasks per model")
    ap.add_argument("--benign", type=int, default=3, help="# benign user_tasks per model")
    args = ap.parse_args()

    key = json.load(open(AUTH))["openrouter"]["key"]  # local var only; never logged
    from openai import OpenAI
    from agentdojo.agent_pipeline import (
        AgentPipeline, SystemMessage, InitQuery, OpenAILLM, ToolsExecutionLoop,
        ToolsExecutor, AbortAgentError,
    )
    from agentdojo.agent_pipeline.agent_pipeline import load_system_message
    from agentdojo.attacks import load_attack
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suites
    from agentdojo.task_suite.task_suite import (
        model_output_from_messages, functions_stack_trace_from_messages,
    )

    os.makedirs(OUT_DIR, exist_ok=True)
    proof_path = os.path.join(OUT_DIR, "usage-proof.jsonl")
    proof = open(proof_path, "a")

    budget = Budget(args.cap)
    suite = get_suites(BENCH)[args.suite]
    uids = list(suite.user_tasks.keys())[: args.user_tasks]
    iids = list(suite.injection_tasks.keys())[: args.injection_tasks]
    benign_uids = list(suite.user_tasks.keys())[: args.benign]

    print(f"suite={args.suite} models={args.models}")
    print(f"grid: user_tasks={uids} injection_tasks={iids} benign={benign_uids}")
    print(f"token cap={args.cap}")

    def make_counting_client(model):
        client = OpenAI(base_url=BASE_URL, api_key=key)
        _orig = client.chat.completions.create

        def _counting(*a, **k):
            t0 = time.time()
            status = "ok"
            try:
                r = _orig(*a, **k)
            except Exception as e:
                status = f"{type(e).__name__}"
                proof.write(json.dumps({
                    "model": model, "status": status, "ms": int((time.time() - t0) * 1000),
                    "err": str(e)[:200],
                }) + "\n")
                proof.flush()
                raise
            tot = getattr(getattr(r, "usage", None), "total_tokens", 0) or 0
            budget.add(tot)
            proof.write(json.dumps({
                "model": model, "status": status, "http": 200,
                "total_tokens": tot, "cum_tokens": budget.total,
                "ms": int((time.time() - t0) * 1000),
            }) + "\n")
            proof.flush()
            return r

        client.chat.completions.create = _counting  # type: ignore
        return client

    def run_one(pipeline, ut, it, injections):
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
                print(f"      security check error: {type(e).__name__}: {str(e)[:80]}")
        return messages, sec

    captured = {}  # model -> list of records
    aborted = False
    for model in args.models:
        if aborted:
            break
        client = make_counting_client(model)
        pipeline = build_pipeline(
            client, model, OpenAILLM, AgentPipeline, SystemMessage, InitQuery,
            ToolsExecutionLoop, ToolsExecutor, load_system_message,
        )
        attack = load_attack(ATTACK, suite, pipeline)
        recs = []
        print(f"\n=== MODEL {model} ===")
        try:
            # attacked grid
            for uid in uids:
                ut = suite.user_tasks[uid]
                for iid in iids:
                    it = suite.injection_tasks[iid]
                    injections = attack.attack(ut, it)
                    try:
                        messages, sec = run_one(pipeline, ut, it, injections)
                    except BudgetExceeded:
                        raise
                    except Exception as e:
                        print(f"  {uid}x{iid}: RUN ERROR {type(e).__name__}: {str(e)[:120]}")
                        continue
                    rec = {
                        "kind": "attacked", "user_task": uid, "injection_task": iid,
                        "security": bool(sec) if sec is not None else None,
                        "messages": serialize_messages(messages),
                    }
                    recs.append(rec)
                    tag = "SUCCESS" if sec else "fail"
                    print(f"  {uid}x{iid}: injection={tag} (cum_tokens={budget.total})")
            # benign controls
            for uid in benign_uids:
                ut = suite.user_tasks[uid]
                try:
                    messages, _ = run_one(pipeline, ut, None, {})
                except BudgetExceeded:
                    raise
                except Exception as e:
                    print(f"  benign {uid}: RUN ERROR {type(e).__name__}: {str(e)[:120]}")
                    continue
                recs.append({
                    "kind": "benign", "user_task": uid, "injection_task": None,
                    "security": None, "messages": serialize_messages(messages),
                })
                print(f"  benign {uid}: done (cum_tokens={budget.total})")
        except BudgetExceeded as e:
            aborted = True
            print(f"\n!!! HARD-ABORT (budget): {e}")
        finally:
            captured[model] = recs
            # persist whatever we have for this model immediately
            with open(os.path.join(OUT_DIR, f"traces-{model.replace('/', '_')}.json"), "w") as f:
                json.dump({"model": model, "suite": args.suite, "attack": ATTACK,
                           "benchmark": BENCH, "records": recs}, f, indent=2)

    proof.close()
    summary = {
        "suite": args.suite, "attack": ATTACK, "benchmark": BENCH,
        "models": args.models, "aborted_on_budget": aborted,
        "cumulative_tokens": budget.total, "api_calls": budget.calls, "cap": args.cap,
        "per_model_records": {m: len(r) for m, r in captured.items()},
    }
    json.dump(summary, open(os.path.join(OUT_DIR, "run-summary.json"), "w"), indent=2)
    print(f"\n=== LIVE RUN SUMMARY ===")
    print(json.dumps(summary, indent=2))
    print(f"traces + proof -> {os.path.relpath(OUT_DIR, HERE)}/ (gitignored)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
