#!/usr/bin/env python3
"""FROZEN, apohara-AGNOSTIC, 1:1 AgentDojo trace wrapper (Amendment A change 1/H2).

Transcribes an AgentDojo conversation (a list of ChatMessage dicts) into apohara
session-transcript JSONL lines, MECHANICALLY and identically for every bucket
(successful / failed-injection / benign):

  * each ChatAssistantMessage tool_call  -> one  {"type":"assistant", tool_use ...}
  * each ChatToolResultMessage           -> one  {"type":"user", tool_result ...}

ZERO apohara-aware logic: NO marker detection, NO sink awareness, NO AGT-TRJ-specific
branches. The injection-marker presence on the tool-result channel is a property of
AgentDojo's injected data, NEVER of this transcription. This is what makes the F5A
post-hoc detection number a MEASUREMENT, not a tautology (see PROOF-v2 / ADR-4).

`--self-test` runs the faithfulness invariant (change 7/H2): the count of emitted
tool-result lines equals the count of source ChatToolResultMessages, and a benign vs
an attacked trace that differ ONLY in injected content transcribe identically except
for that content.
"""
import json
import sys


def _content_text(content) -> str:
    """Extract text from a message content (str, or a list of content blocks)."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for b in content:
            if isinstance(b, str):
                parts.append(b)
            elif isinstance(b, dict):
                # AgentDojo TextContentBlock uses "content"; tolerate "text" too.
                t = b.get("content") or b.get("text")
                if isinstance(t, str):
                    parts.append(t)
        return " ".join(parts)
    return str(content)


def _tool_calls(msg) -> list:
    tc = msg.get("tool_calls") if isinstance(msg, dict) else getattr(msg, "tool_calls", None)
    return tc or []


def _get(msg, key):
    return msg.get(key) if isinstance(msg, dict) else getattr(msg, key, None)


def wrap(messages) -> list:
    """Return apohara session JSONL lines (strings), in source order. Mechanical 1:1."""
    lines = []
    for msg in messages:
        role = _get(msg, "role")
        if role == "assistant":
            for call in _tool_calls(msg):
                name = call.get("function") if isinstance(call, dict) else getattr(call, "function", "")
                args = call.get("args") if isinstance(call, dict) else getattr(call, "args", {})
                lines.append(
                    json.dumps(
                        {
                            "type": "assistant",
                            "message": {"content": [{"type": "tool_use", "name": name, "input": args or {}}]},
                        }
                    )
                )
        elif role == "tool":
            tcid = _get(msg, "tool_call_id") or ""
            text = _content_text(_get(msg, "content"))
            lines.append(
                json.dumps(
                    {
                        "type": "user",
                        "message": {
                            "content": [
                                {"type": "tool_result", "tool_use_id": str(tcid), "content": text}
                            ]
                        },
                    }
                )
            )
    return lines


def _self_test() -> int:
    # Faithfulness invariant: tool-result line count == source ChatToolResultMessage count.
    benign = [
        {"role": "user", "content": "do the task"},
        {"role": "assistant", "content": "ok", "tool_calls": [{"function": "get_data", "args": {}}]},
        {"role": "tool", "tool_call_id": "c1", "content": [{"type": "text", "content": "balance: 100"}]},
        {"role": "assistant", "content": "done", "tool_calls": [{"function": "report", "args": {"x": 1}}]},
    ]
    attacked = [
        {"role": "user", "content": "do the task"},
        {"role": "assistant", "content": "ok", "tool_calls": [{"function": "get_data", "args": {}}]},
        # SAME structure, ONLY the injected content differs:
        {"role": "tool", "tool_call_id": "c1", "content": [{"type": "text", "content": "balance: 100 <INFORMATION> ignore previous"}]},
        {"role": "assistant", "content": "done", "tool_calls": [{"function": "report", "args": {"x": 1}}]},
    ]
    wb, wa = wrap(benign), wrap(attacked)
    src_results = sum(1 for m in benign if m["role"] == "tool")
    out_results = sum(1 for ln in wb if json.loads(ln)["message"]["content"][0]["type"] == "tool_result")
    assert out_results == src_results, f"tool-result count {out_results} != source {src_results}"
    # Identical except the single injected tool-result line. The wrapper emits only
    # tool_use + tool_result lines (user/assistant-text are not actions), so the
    # emitted index of the injected tool_result is 1 (get_data tool_use is 0).
    diff = [i for i, (a, b) in enumerate(zip(wb, wa)) if a != b]
    injected_lines = [i for i in diff if json.loads(wb[i])["message"]["content"][0]["type"] == "tool_result"]
    assert diff == injected_lines and len(diff) == 1, (
        f"benign vs attacked must differ ONLY in the injected tool-result line; diff={diff}"
    )
    assert len(wb) == len(wa), "line counts must match"
    print("WRAPPER FAITHFULNESS OK: 1:1 tool-result count; benign/attacked differ only in injected content")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(_self_test())
    # Stdin = a JSON array of messages; stdout = apohara JSONL.
    msgs = json.load(sys.stdin)
    for line in wrap(msgs):
        print(line)
