#!/usr/bin/env python3
"""F5A BLOCKER-CHECK (Amendment A RA1): does MiniMax-M3's OpenAI-compatible endpoint
return parseable `tool_calls`? If yes, the AgentDojo end-to-end run is feasible (its
OpenAILLM parses tool_calls). If no (reasoning in content / <think>, no tool_calls),
we try the Anthropic-compat endpoint or STOP and report to Pablo (no fabricated traces).

Logs PROOF of real API use (model + usage tokens) — never the key. Run:
  eval/.venv/bin/python scripts/eval/minimax_smoke.py
"""
import json
import os

AUTH = os.path.expanduser("~/.local/share/opencode/auth.json")


def main() -> int:
    key = json.load(open(AUTH))["minimax"]["key"]  # never printed
    from openai import OpenAI

    client = OpenAI(base_url="https://api.minimax.io/v1", api_key=key)
    tools = [
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
    try:
        resp = client.chat.completions.create(
            model="MiniMax-M3",
            messages=[
                {"role": "system", "content": "You are an agent. Use the provided tool when asked."},
                {"role": "user", "content": "Send 100 to IBAN US12345678901234567. Call the send_money tool."},
            ],
            tools=tools,
            max_tokens=4000,
        )
    except Exception as e:
        print(f"BLOCKER: MiniMax OpenAI endpoint call failed: {type(e).__name__}: {str(e)[:300]}")
        return 2

    msg = resp.choices[0].message
    tc = msg.tool_calls or []
    print(f"PROOF model={resp.model}")
    print(f"PROOF usage={resp.usage}")
    print(f"finish_reason={resp.choices[0].finish_reason}")
    print(f"tool_calls_count={len(tc)}")
    if tc:
        print(f"tool_call[0].name={tc[0].function.name}")
        print(f"tool_call[0].args={tc[0].function.arguments[:120]}")
        print("RESULT: PARSEABLE tool_calls — AgentDojo end-to-end is FEASIBLE.")
        return 0
    print(f"content_head={(msg.content or '')[:200]!r}")
    print("RESULT: NO tool_calls returned — escalate (Anthropic-compat) or report to Pablo.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
