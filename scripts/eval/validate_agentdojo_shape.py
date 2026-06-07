#!/usr/bin/env python3
"""Validate the committed AgentDojo corpus shape (US-F0-2 AC).

Asserts every tests/corpus/agentdojo/expected.json item is a dict with the required
keys/types and that each item's raw JSONL representation round-trips through json.loads
into the B1 synthetic-chat-tool action shape. Exits 0 on success, non-zero on any
violation. No network, no AgentDojo import — pure structural check over committed files.

Run: eval/.venv/bin/python scripts/eval/validate_agentdojo_shape.py  (or any python3)
"""
import json
import pathlib
import sys

CORPUS = pathlib.Path("tests/corpus/agentdojo")
EXPECTED = CORPUS / "expected.json"
SYNTHETIC_TOOL = "AgentChatMessage"
REQUIRED = {"id": str, "kind": str, "input": str, "expected_agt_codes": list}
KNOWN_CODE_PREFIXES = ("AGT-",)


def fail(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    print(f"SHAPE INVALID: {msg}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    if not EXPECTED.exists():
        fail(f"{EXPECTED} missing")
    doc = json.loads(EXPECTED.read_text())
    items = doc.get("items")
    if not isinstance(items, list) or not items:
        fail("expected.json has no non-empty 'items' list")

    # Build the set of raw-line prompts per suite to confirm round-trip linkage.
    raw_prompts: set[str] = set()
    for jl in sorted((CORPUS / "raw").glob("*.jsonl")):
        for ln, line in enumerate(jl.read_text().splitlines(), 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                fail(f"{jl}:{ln} not valid JSON ({e})")
            try:
                block = rec["message"]["content"][0]
                assert rec["type"] == "assistant"
                assert block["type"] == "tool_use"
                assert block["name"] == SYNTHETIC_TOOL
                prompt = block["input"]["prompt"]
                assert isinstance(prompt, str) and prompt
            except (KeyError, IndexError, AssertionError):
                fail(f"{jl}:{ln} is not the B1 synthetic-chat-tool shape")
            raw_prompts.add(prompt)

    seen_ids: set[str] = set()
    for i, it in enumerate(items):
        if not isinstance(it, dict):
            fail(f"item[{i}] is not a dict")
        for key, typ in REQUIRED.items():
            if key not in it:
                fail(f"item[{i}] ({it.get('id','?')}) missing key '{key}'")
            if not isinstance(it[key], typ):
                fail(f"item[{i}] ({it.get('id','?')}) key '{key}' is {type(it[key]).__name__}, want {typ.__name__}")
        if it["id"] in seen_ids:
            fail(f"duplicate id {it['id']}")
        seen_ids.add(it["id"])
        if not it["expected_agt_codes"]:
            fail(f"{it['id']} has empty expected_agt_codes (every item must label its attack class)")
        for code in it["expected_agt_codes"]:
            if not isinstance(code, str) or not code.startswith(KNOWN_CODE_PREFIXES):
                fail(f"{it['id']} bad code {code!r}")
        if it["input"] not in raw_prompts:
            fail(f"{it['id']} input prose has no matching raw/<suite>.jsonl line (round-trip broken)")

    print(f"SHAPE OK: {len(items)} items, all keys/types valid, all inputs round-trip to raw B1 lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
