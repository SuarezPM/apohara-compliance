#!/usr/bin/env python3
"""US-006 / B-0.1 — Capability probe for AgentDyn open-ended suites.

DRY-RUN. Does NOT call any LLM API. Reads ONLY the local AgentDyn installation
to confirm which of {shopping, github, dailylife} are registered in
get_suites(BENCH) for the benchmark version the harness actually uses
(BENCH = "v1.2.2").

Why this script exists
----------------------
The v2.2 live run (PR #10, 9a8bf64) used suite=workspace because the
open-ended AgentDyn suites were UNMEASURED on current frontier. ADR-8
(B-0) decides whether to close that gap with B-1 (the live run) or
document it as DEFERRED. The decision pivots on a single fact: are
{shopping, github, dailylife} actually registered in the AgentDyn
build the harness imports at run time?

What the probe does
-------------------
1. Imports the same `agentdojo.task_suite.load_suites.get_suites` the
   harness imports (no sitecustomize, no monkey-patching, no model
   registry override).
2. Resolves BENCH = "v1.2.2" (same constant as run_openrouter_e2e.py:46).
3. Iterates over the three open-ended suite names and asks
   get_suites(BENCH)[name] for each.
4. Reports which resolve and which raise KeyError, plus the full
   registered-set for context.

What the probe does NOT do
--------------------------
* Does NOT load or call any LLM client.
* Does NOT touch `~/.local/share/opencode/auth.json`.
* Does NOT require MINIMAX_API_KEY or any other secret.
* Does NOT modify state. The module imports are pure.

Usage
-----
    eval/.venv/bin/python scripts/eval/probe_open_ended_suites.py
    eval/.venv/bin/python scripts/eval/probe_open_ended_suites.py \\
        --bench v1.2.2 --json

Exit codes
----------
    0  — every requested suite resolved
    2  — at least one requested suite did NOT resolve
    3  — probe could not import agentdojo (env not provisioned)
"""
from __future__ import annotations

import argparse
import importlib
import json
import sys
import traceback

# Same benchmark constant the harness uses. The harness at
# run_openrouter_e2e.py:46 hard-codes "v1.2.2"; we mirror it here so the
# probe and the harness always look at the same row in _SUITES.
DEFAULT_BENCH = "v1.2.2"
OPEN_ENDED_SUITES = ("shopping", "github", "dailylife")


def _load_get_suites():
    """Import get_suites from the same path the harness uses.

    No sitecustomize, no monkey-patch, no PYTHONPATH override. If the
    agentdojo installed in the venv is the one the harness will see at
    run time, the probe answers for that exact build.
    """
    try:
        mod = importlib.import_module("agentdojo.task_suite.load_suites")
        return getattr(mod, "get_suites")
    except Exception as e:
        print(f"PROBE ERROR: cannot import agentdojo.task_suite.load_suites: "
              f"{type(e).__name__}: {e}", file=sys.stderr)
        print(traceback.format_exc(), file=sys.stderr)
        return None


def probe(bench: str) -> dict:
    """Run the probe and return a structured result."""
    get_suites = _load_get_suites()
    if get_suites is None:
        return {
            "bench": bench,
            "agentdojo_import_ok": False,
            "registered": None,
            "open_ended": {s: None for s in OPEN_ENDED_SUITES},
            "summary": "agentdojo import failed; env not provisioned",
        }

    suites_by_version = get_suites(bench)
    registered = sorted(suites_by_version.keys())

    open_ended = {}
    for name in OPEN_ENDED_SUITES:
        try:
            suite = suites_by_version[name]
            open_ended[name] = {
                "registered": True,
                "n_user_tasks": len(getattr(suite, "user_tasks", {}) or {}),
                "n_injection_tasks": len(getattr(suite, "injection_tasks", {}) or {}),
                "n_tools": len(getattr(suite, "tools", []) or []),
            }
        except KeyError:
            open_ended[name] = {"registered": False}

    return {
        "bench": bench,
        "agentdojo_import_ok": True,
        "registered": registered,
        "open_ended": open_ended,
        "summary": _summarize(open_ended, registered),
    }


def _summarize(open_ended: dict, registered: list) -> str:
    hits = [n for n, info in open_ended.items()
            if info.get("registered") is True]
    misses = [n for n, info in open_ended.items()
              if info.get("registered") is False]
    if len(hits) == len(open_ended):
        return (f"PASS — all open-ended suites registered for {registered!r} "
                f"benchmark: {hits}")
    if len(misses) == len(open_ended):
        return (f"DEFER — none of the open-ended suites are registered. "
                f"Registered set: {registered}. "
                f"B-1 must be DEFERRED per ADR-8 §'If B-0.1 fails'.")
    return (f"PARTIAL — registered: {hits}; missing: {misses}. "
            f"Full registered set: {registered}.")


def _print_human(result: dict) -> None:
    print(f"bench: {result['bench']}")
    print(f"agentdojo import ok: {result['agentdojo_import_ok']}")
    if result["registered"] is not None:
        print(f"all suites registered for this bench: {result['registered']}")
    print()
    print(f"{'suite':<12} {'registered':<12} {'user_tasks':<12} "
          f"{'injection_tasks':<16} {'tools':<6}")
    print("-" * 60)
    for name, info in result["open_ended"].items():
        if info is None:
            print(f"{name:<12} {'error':<12}")
            continue
        reg = info.get("registered")
        if reg is True:
            print(f"{name:<12} {'yes':<12} {info['n_user_tasks']:<12} "
                  f"{info['n_injection_tasks']:<16} {info['n_tools']:<6}")
        else:
            print(f"{name:<12} {'NO':<12}")
    print()
    print(f"summary: {result['summary']}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1] if __doc__ else "")
    ap.add_argument("--bench", default=DEFAULT_BENCH,
                    help=f"benchmark version (default: {DEFAULT_BENCH})")
    ap.add_argument("--json", action="store_true",
                    help="emit machine-readable JSON only")
    args = ap.parse_args()

    result = probe(args.bench)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_human(result)

    # Exit code: 0 if all resolve, 2 if any miss, 3 if env not provisioned.
    if not result["agentdojo_import_ok"]:
        return 3
    misses = [n for n, info in result["open_ended"].items()
              if info.get("registered") is False]
    return 2 if misses else 0


if __name__ == "__main__":
    raise SystemExit(main())
