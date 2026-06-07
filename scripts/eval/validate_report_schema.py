#!/usr/bin/env python3
"""Strict numbers/IDs-only schema validator for tests/corpus/agentharm-report.json.

This is the RELEASE-BLOCKER control (critic item 7c): it guarantees the committed
AgentHarm report carries NO free-text / example content (which would leak eval-only
data even though it isn't the canary GUID). Every leaf is a number, an enum/metadata
string from a fixed allowlist, an AGT code, a short category label, or a bare behavior
id. Anything else (a prompt, a behavior name, a description) fails the schema.

Exit 0 = report is numbers/IDs-only. Non-zero = a free-text/unexpected field present.
"""
import json
import pathlib
import re
import sys

REPORT = pathlib.Path("tests/corpus/agentharm-report.json")

ID_RE = re.compile(r"^[0-9]+(-[0-9]+)*$")          # behavior ids: 1, 1-2, 12-3
AGT_RE = re.compile(r"^AGT-[A-Z]+-[0-9]+$")        # fired codes
CAT_RE = re.compile(r"^[A-Za-z0-9 /&_-]{1,40}$")   # short controlled-vocab category labels
# Top-level metadata strings must be EXACT allow-listed values (no free text).
META_ALLOW = {
    "source": {"ai-safety-institute/AgentHarm"},
    "config": {"harmful", "harmless_benign", "chat"},
    "split": {"test_public", "validation"},
    "license": {"MIT + eval-only clause (no examples committed)"},
    "measures": {"bait-keyword surface coverage (NOT injection-consequence detection)"},
}
NUMERIC_KEYS = {"n", "base_behaviors", "candidate_only_violations"}


def fail(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    print(f"REPORT SCHEMA INVALID: {msg}", file=sys.stderr)
    raise SystemExit(1)


def is_num(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def main() -> int:
    if not REPORT.exists():
        fail(f"{REPORT} missing")
    try:
        d = json.loads(REPORT.read_text())
    except json.JSONDecodeError as e:
        fail(f"not valid JSON: {e}")
    if not isinstance(d, dict):
        fail("top level is not an object")

    allowed_top = set(META_ALLOW) | NUMERIC_KEYS | {
        "coverage", "by_category", "by_fired_code", "behavior_ids",
    }
    extra = set(d) - allowed_top
    if extra:
        fail(f"unexpected top-level keys (possible free-text leak): {sorted(extra)}")

    for k, allow in META_ALLOW.items():
        if k not in d:
            fail(f"missing metadata key {k}")
        if d[k] not in allow:
            fail(f"metadata {k}={d[k]!r} not in allow-list {allow}")
    for k in NUMERIC_KEYS:
        if k in d and not is_num(d[k]):
            fail(f"{k} must be numeric, got {d[k]!r}")

    cov = d.get("coverage", {})
    if not isinstance(cov, dict) or set(cov) - {"prompts_with_any_candidate", "rate"}:
        fail(f"coverage has unexpected keys: {cov}")
    for v in cov.values():
        if not is_num(v):
            fail(f"coverage leaf not numeric: {v!r}")

    bycat = d.get("by_category", {})
    if not isinstance(bycat, dict):
        fail("by_category not an object")
    if len(bycat) > 20:
        fail(f"by_category has {len(bycat)} keys (>20 — suspicious)")
    for cat, stats in bycat.items():
        if not CAT_RE.match(cat):
            fail(f"by_category key {cat!r} is not a short controlled-vocab label (free-text leak?)")
        if not isinstance(stats, dict) or set(stats) - {"n", "with_candidate"}:
            fail(f"by_category[{cat}] unexpected shape: {stats}")
        for v in stats.values():
            if not is_num(v):
                fail(f"by_category[{cat}] leaf not numeric: {v!r}")

    for code, cnt in d.get("by_fired_code", {}).items():
        if not AGT_RE.match(code):
            fail(f"by_fired_code key {code!r} is not an AGT code")
        if not is_num(cnt):
            fail(f"by_fired_code[{code}] not numeric: {cnt!r}")

    ids = d.get("behavior_ids", [])
    if not isinstance(ids, list):
        fail("behavior_ids not a list")
    for x in ids:
        if not (isinstance(x, str) and ID_RE.match(x)):
            fail(f"behavior_ids entry {x!r} is not a bare numeric id (free-text leak?)")

    print(f"REPORT SCHEMA OK: numbers/IDs only; {len(bycat)} categories, "
          f"{len(d.get('by_fired_code', {}))} codes, {len(ids)} behavior ids")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
