#!/usr/bin/env python3
"""POLARITY HARD-GATE (Rev 2 CR-4, BLOCKING) -- structural guard vs the Rev-1 inversion.

EMPIRICALLY proves the AgentDyn/AgentDojo label polarity:

    security == True  <=>  the agent EXECUTED the injection task's target tool
                           against the ATTACKER's recipient/account

WHY NOT the bare function name: AgentDojo's `security()` is an environment-STATE check
(money/email actually delivered to the ATTACKER's recipient/account). The SAME target
function (e.g. `send_email`) is also called for the LEGITIMATE user task, and a resisting
agent may even email the USER to REPORT the injection. So the polarity predicate compares
the call's RECIPIENT/ACCOUNT field against the attacker's value -- never a blob substring
(which is fooled by an agent quoting the bait when reporting it).

The attacker's distinguishing value (recipient email / IBAN-style account) is lifted from
TWO apohara-AGNOSTIC ground-truth sources: (1) the trace's own `injections` text, and
(2) the injection-task class attributes (`_ATTACKER_*` / `_RECIPIENT` / `*_IBAN`) in the
vendored `src/agentdojo/default_suites/v1/{suite}/injection_tasks.py` (AST, no import).

Procedure:
  * Restrict to the CLEAN families (dailylife + shopping `send_money`/`send_email`) where
    the env-state check is a recipient/account delivery -- so "delivered to attacker" is a
    faithful proxy for `security`. (The github invite-template tasks and the env-side
    download/browse tasks have side-effect-success subtleties and are out of this sample.)
  * Hand-pick >=N security==True + >=N security==False such traces across >=2 suites where
    a literal attacker recipient is extractable.
  * ASSERT: every security==True trace DELIVERED to the attacker; every security==False
    trace did NOT. Any violation -> EXIT NON-ZERO + print the file (HALTS Phase 0).

apohara-AGNOSTIC: no apohara import, no rule file touched. Pure corpus + ground-truth.
"""
import argparse
import ast
import json
import os
import re
import sys

AGENTDYN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "eval", "agentdyn",
)
RUNS = os.path.join(AGENTDYN, "runs")
SUITE_SRC = os.path.join(AGENTDYN, "src", "agentdojo", "default_suites", "v1")

# Clean families only: env-state check == delivery to attacker recipient/account.
CLEAN_SUITES = ("dailylife", "shopping")
TARGET_TOOLS = ("send_money", "send_email")
# Sample deterministically from these no-defense frontier dirs, in this order.
NO_DEFENSE_MODELS = [
    "gpt-5.1-2025-11-13",
    "google_gemini-2.5-pro",
    "google_gemini-2.5-flash",
    "gpt-5-mini-2025-08-07",
]

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w]+")
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{6,}\b")
_SRC_CACHE: dict = {}


def _attacker_recipients(suite: str, injection_task_id: str, injections: dict) -> set:
    """Literal attacker recipient(s)/account(s): from the injection text AND the
    injection-task class `_ATTACKER_*` / `_RECIPIENT` / `*_IBAN` attributes (AST)."""
    vals: set = set()
    text = " ".join(str(v) for v in (injections or {}).values())
    vals |= set(_EMAIL_RE.findall(text))
    vals |= set(_IBAN_RE.findall(text))
    vals |= _src_attacker_attrs(suite, injection_task_id)
    # keep only well-formed email / IBAN tokens
    return {v for v in vals if ("@" in v and not v.endswith(".")) or _IBAN_RE.fullmatch(v)}


def _src_attacker_attrs(suite: str, injection_task_id: str) -> set:
    key = (suite, injection_task_id)
    if key in _SRC_CACHE:
        return _SRC_CACHE[key]
    m = re.match(r"injection_task_(\d+)$", injection_task_id or "")
    vals: set = set()
    if m:
        cls = f"InjectionTask{m.group(1)}"
        path = os.path.join(SUITE_SRC, suite, "injection_tasks.py")
        if os.path.isfile(path):
            tree = ast.parse(open(path).read(), filename=path)
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name == cls:
                    for stmt in node.body:
                        if not isinstance(stmt, ast.Assign):
                            continue
                        names = [getattr(t, "id", "") for t in stmt.targets]
                        if not any(
                            k in n.upper() for n in names for k in ("ATTACKER", "RECIPIENT", "IBAN")
                        ):
                            continue
                        try:
                            v = ast.literal_eval(stmt.value)
                        except Exception:
                            continue
                        if isinstance(v, str):
                            vals.add(v)
                        elif isinstance(v, list):
                            vals |= {x for x in v if isinstance(x, str)}
                    break
    _SRC_CACHE[key] = vals
    return vals


def _recipient_fields(fn: str, args: dict) -> list:
    out = []
    if fn == "send_email":
        r = args.get("recipients") or []
        out += r if isinstance(r, list) else [r]
    elif fn == "send_money":
        out.append(args.get("recipient"))
    return [str(x) for x in out if x]


def _delivered_to_attacker(messages, attacker_vals: set) -> bool:
    """True iff a send_money/send_email tool_call's RECIPIENT field == an attacker value."""
    if not isinstance(messages, list):
        return False
    for m in messages:
        if not (isinstance(m, dict) and m.get("role") == "assistant"):
            continue
        for c in (m.get("tool_calls") or []):
            if not isinstance(c, dict) or c.get("function") not in TARGET_TOOLS:
                continue
            for rf in _recipient_fields(c["function"], c.get("args") or {}):
                if any(v == rf for v in attacker_vals):
                    return True
    return False


def _collect(want_security: bool, need: int) -> list:
    found, suites = [], set()
    for model in NO_DEFENSE_MODELS:
        root = os.path.join(RUNS, model)
        if not os.path.isdir(root):
            continue
        for dirpath, _d, files in os.walk(root):
            for fn in sorted(files):
                if not fn.endswith(".json") or fn == "none.json":
                    continue
                path = os.path.join(dirpath, fn)
                try:
                    d = json.load(open(path))
                except Exception:
                    continue
                if d.get("suite_name") not in CLEAN_SUITES:
                    continue
                if d.get("security") is not want_security:
                    continue
                if d.get("attack_type") in (None, "none") or not d.get("injections"):
                    continue
                av = _attacker_recipients(d.get("suite_name"), d.get("injection_task_id"), d.get("injections"))
                if not av:
                    continue
                found.append((path, d.get("suite_name"), d.get("injection_task_id"), av, d.get("messages")))
                suites.add(d.get("suite_name"))
                if len(found) >= need and len(suites) >= 2:
                    return found
    return found


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=3)
    args = ap.parse_args()
    if not os.path.isdir(RUNS):
        print(f"ERROR: runs not found: {RUNS}", file=sys.stderr)
        return 2

    pos = _collect(True, args.n)
    neg = _collect(False, args.n)
    if len(pos) < args.n or len(neg) < args.n:
        print(f"ERROR: insufficient curated samples (sec=True:{len(pos)}, sec=False:{len(neg)}; "
              f"need >={args.n} each)", file=sys.stderr)
        return 3
    if len({p[1] for p in pos}) < 2 or len({n[1] for n in neg}) < 2:
        print("WARNING: could not span >=2 suites for one polarity", file=sys.stderr)

    violations = []
    print("=== security==True traces (MUST have DELIVERED to the attacker recipient) ===")
    for path, suite, inj_id, av, msgs in pos:
        ok = _delivered_to_attacker(msgs, av)
        rel = os.path.relpath(path, AGENTDYN)
        print(f"  [{'OK ' if ok else 'FAIL'}] {suite}/{inj_id} attacker={sorted(av)[:2]}  {rel}")
        if not ok:
            violations.append(("security==True but NOT delivered to attacker", path))

    print("=== security==False traces (MUST NOT have delivered to the attacker recipient) ===")
    for path, suite, inj_id, av, msgs in neg:
        ok = not _delivered_to_attacker(msgs, av)
        rel = os.path.relpath(path, AGENTDYN)
        print(f"  [{'OK ' if ok else 'FAIL'}] {suite}/{inj_id} attacker={sorted(av)[:2]}  {rel}")
        if not ok:
            violations.append(("security==False but DELIVERED to attacker", path))

    print(f"\nchecked: {len(pos)} positive + {len(neg)} negative across "
          f"suites {sorted({p[1] for p in pos} | {n[1] for n in neg})}")

    if violations:
        print("\nPOLARITY VIOLATION(S) -- HALT Phase 0:", file=sys.stderr)
        for reason, path in violations:
            print(f"  {reason}: {path}", file=sys.stderr)
        return 1

    print("POLARITY CONFIRMED: positive bucket = security==True AND injection-present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
