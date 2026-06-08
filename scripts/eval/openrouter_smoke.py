#!/usr/bin/env python3
"""v2.2 Phase-4 AC4.1 — OpenRouter real-usage SMOKE for CURRENT-frontier models.

For each model id passed on argv (or the default current-frontier set), issue ONE
tool-call request (the `send_money` tool) against OpenRouter's OpenAI-compatible
endpoint and confirm the model returns parseable `tool_calls` + a finish_reason. This
gates the end-to-end live run (AgentDojo's OpenAILLM needs parseable tool_calls):
a model that cannot return them is DROPPED (noted), no fabricated traces.

apohara-agnostic. The OpenRouter key is read ONLY into a local variable from
~/.local/share/opencode/auth.json["openrouter"]["key"] and is NEVER printed, logged,
or written anywhere. PROOF logged = model id + usage tokens + tool_call name only.

Run: eval/.venv/bin/python scripts/eval/openrouter_smoke.py [model_id ...]
"""
import json
import os
import sys

AUTH = os.path.expanduser("~/.local/share/opencode/auth.json")
BASE_URL = "https://openrouter.ai/api/v1"

# Phase-0-verified current-frontier ids (tools=True). FORBIDDEN: gpt-4o/gpt-5.1/
# gemini-2.5/gpt-3.5 (old). Override via argv.
DEFAULT_MODELS = [
    "openai/gpt-5.5",
    "google/gemini-3.5-flash",
    "google/gemini-3.1-pro-preview",
    "minimax/minimax-m3",
    "anthropic/claude-opus-4.8",
]

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "send_money",
            "description": "Send money to a recipient IBAN.",
            "parameters": {
                "type": "object",
                "properties": {
                    "iban": {"type": "string"},
                    "amount": {"type": "number"},
                },
                "required": ["iban", "amount"],
            },
        },
    }
]


def smoke_one(client, model: str) -> dict:
    """One tool-call request. Returns a PROOF dict (no key, no trajectory text)."""
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are an agent. Use the provided tool when asked."},
                {"role": "user", "content": "Send 100 to IBAN US12345678901234567. Call the send_money tool."},
            ],
            tools=TOOLS,
            max_tokens=4000,
        )
    except Exception as e:
        return {"model": model, "ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}"}

    msg = resp.choices[0].message
    tc = msg.tool_calls or []
    usage = resp.usage
    rec = {
        "model": model,
        "resolved_model": resp.model,
        "finish_reason": resp.choices[0].finish_reason,
        "tool_calls_count": len(tc),
        "prompt_tokens": getattr(usage, "prompt_tokens", None) if usage else None,
        "completion_tokens": getattr(usage, "completion_tokens", None) if usage else None,
        "total_tokens": getattr(usage, "total_tokens", None) if usage else None,
        "ok": bool(tc),
    }
    if tc:
        rec["tool_call_name"] = tc[0].function.name
    return rec


def main() -> int:
    key = json.load(open(AUTH))["openrouter"]["key"]  # local var only; never logged
    from openai import OpenAI

    client = OpenAI(base_url=BASE_URL, api_key=key)
    models = sys.argv[1:] or DEFAULT_MODELS

    lines = []

    def pr(s=""):
        print(s)
        lines.append(s)

    pr("=" * 72)
    pr("v2.2 Phase-4 AC4.1 OpenRouter SMOKE (current-frontier, tools=True)")
    pr("=" * 72)
    feasible, dropped = [], []
    for m in models:
        rec = smoke_one(client, m)
        if rec["ok"]:
            feasible.append(m)
            pr(f"[OK]   {m}")
            pr(f"         resolved={rec['resolved_model']} finish={rec['finish_reason']} "
               f"tool_calls={rec['tool_calls_count']} name={rec.get('tool_call_name')}")
            pr(f"         usage: prompt={rec['prompt_tokens']} completion={rec['completion_tokens']} "
               f"total={rec['total_tokens']}")
        else:
            dropped.append(m)
            why = rec.get("error") or f"no tool_calls (finish={rec.get('finish_reason')})"
            pr(f"[DROP] {m}: {why}")

    pr("")
    pr(f"FEASIBLE (parseable tool_calls): {feasible}")
    pr(f"DROPPED: {dropped}")
    with open("/tmp/v22-p4-smoke.txt", "w") as f:
        f.write("\n".join(lines) + "\n")
    # Exit 0 if at least the 3 minimum models are feasible enough to proceed; the
    # caller decides. We never hard-fail here so a partial set can still run.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
