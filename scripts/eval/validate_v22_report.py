#!/usr/bin/env python3
"""Strict numbers/IDs-only schema validator for tests/corpus/v2.2-real-trajectory-report.json.

Mirrors the AgentHarm-report discipline (scripts/eval/validate_report_schema.py): the committed
v2.2 real-trajectory report must carry NO free-text / example / trace content and NO API key.
Every leaf is a number, a boolean control flag, an enum/metadata string from a fixed allowlist, a
SHA, a model id, a sink-role key, a sink arg-key, or an AGT code. Anything else (a prompt, a trace,
a key, a free-prose sentence) fails the schema.

Exit 0 = report is numbers/IDs-only. Non-zero = a free-text/unexpected field present.
"""
import json
import pathlib
import re
import sys

REPORT = pathlib.Path("tests/corpus/v2.2-real-trajectory-report.json")

SHA_RE = re.compile(r"^[0-9a-f]{40}$")              # git blob / corpus commit SHA
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,79}$")  # model ids / dated tags
KEY_RE = re.compile(r"^[a-z0-9_]{1,40}$")           # short controlled-vocab map keys
# OpenRouter key shape — must NEVER appear anywhere as a value.
OR_KEY_RE = re.compile(r"sk-or-v1-[0-9a-f]{20,}")

# Top-level + nested metadata strings must be EXACT allow-listed values (no free text).
META_ALLOW = {
    "schema": {"apohara-v2.2-real-trajectory/1"},
    "measures": {
        "post-hoc injection-sink correlation surfacing on real successful trajectories "
        "(NOT efficacy/recall/prevention)"
    },
    "source": {"SaFo-Lab/AgentDyn"},
    "agentdojo_package_version": {"0.1.35"},
    "benchmark_version": {"v1.2.2"},
    "attack": {"important_instructions", "important_instructions_no_model_name"},
    "model_currency": {"last-gen", "current-frontier"},
    "provider": {"openrouter"},
    "suite": {"workspace"},
}


def fail(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    print(f"V2.2 REPORT SCHEMA INVALID: {msg}", file=sys.stderr)
    raise SystemExit(1)


def is_num(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def check_scalar(path: str, v) -> None:
    """A leaf must be a number, a bool control flag, a SHA, a model id, or an allow-listed enum."""
    if is_num(v) or isinstance(v, bool):
        return
    if not isinstance(v, str):
        fail(f"{path}: leaf is neither number/bool/string (free-text leak?): {v!r}")
    if OR_KEY_RE.search(v):
        fail(f"{path}: an OpenRouter key shape appears in a value (KEY LEAK)")
    if SHA_RE.match(v) or MODEL_RE.match(v):
        return
    fail(f"{path}: string leaf {v!r} is not a SHA / model id / dated tag (free-text leak?)")


def walk(path: str, node) -> None:
    """Recursively validate. Object keys must be controlled vocab; leaves via check_scalar."""
    if isinstance(node, dict):
        if len(node) > 40:
            fail(f"{path}: object has {len(node)} keys (>40 — suspicious)")
        for k, v in node.items():
            if not isinstance(k, str):
                fail(f"{path}: non-string key {k!r}")
            # Keys are short controlled-vocab tokens: snake_case, model ids, AGT codes, roles.
            if not (KEY_RE.match(k) or MODEL_RE.match(k) or re.match(r"^AGT-[A-Z]+-[0-9]+$", k)):
                fail(f"{path}: key {k!r} is not a controlled-vocab token (free-text leak?)")
            child = f"{path}.{k}"
            if k in META_ALLOW:
                if v not in META_ALLOW[k]:
                    fail(f"{child}: metadata {v!r} not in allow-list {META_ALLOW[k]}")
                continue
            walk(child, v)
    elif isinstance(node, list):
        if len(node) > 100:
            fail(f"{path}: list has {len(node)} entries (>100 — suspicious)")
        for i, v in enumerate(node):
            walk(f"{path}[{i}]", v)
    else:
        check_scalar(path, node)


def main() -> int:
    if not REPORT.exists():
        fail(f"{REPORT} missing")
    raw = REPORT.read_text()
    if OR_KEY_RE.search(raw):
        fail("an OpenRouter key shape appears in the report text (KEY LEAK)")
    try:
        d = json.loads(raw)
    except json.JSONDecodeError as e:
        fail(f"not valid JSON: {e}")
    if not isinstance(d, dict):
        fail("top level is not an object")
    if d.get("schema") != "apohara-v2.2-real-trajectory/1":
        fail("missing/incorrect schema tag")

    walk("$", d)

    # Cross-checks: the bound-triple denominators are internally consistent.
    dl = d["download"]
    assert dl["buckets"]["positive"] == 236
    assert dl["posthoc_detection_on_success"]["total"]["n"] == 236
    assert dl["precision_on_success_denominator"] == (
        dl["posthoc_detection_on_success"]["total"]["fired"]
        + dl["false_positive_control"]["failed_injection"]["fired"]
        + dl["false_positive_control"]["benign"]["fired"]
    ), "precision-on-success denominator must equal posthoc + failed-FP + benign-FP"
    live = d["live"]
    assert live["attack_success"]["total"]["success"] == 0
    assert live["usage"]["key_logged"] is False

    print(
        "V2.2 REPORT SCHEMA OK: numbers/IDs only; no key; "
        f"download positives={dl['buckets']['positive']}, "
        f"posthoc={dl['posthoc_detection_on_success']['total']['fired']}/"
        f"{dl['posthoc_detection_on_success']['total']['n']}, "
        f"live={live['attack_success']['total']['success']}/"
        f"{live['attack_success']['total']['n']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
