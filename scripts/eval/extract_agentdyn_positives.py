#!/usr/bin/env python3
"""Extract AgentDyn buckets into gitignored manifests (v2.2 Phase 1 / AC1.1).

apohara-AGNOSTIC. Enumerates the NO-DEFENSE model dirs under the gitignored AgentDyn
corpus (`eval/agentdyn/runs/`) and writes three bucket MANIFESTS (lists of trace-file
paths) under a gitignored output dir (default `eval/v22-buckets/`), under the Critic-
verified label polarity (see scripts/eval/assert_polarity.py for the empirical proof):

  POSITIVE = security == True  AND  an injection was actually present
           = security == True  AND  attack_type not in (None, "none")
                               AND  injections is a non-empty dict
                               AND  basename != "none.json"
  FAILED   = security == False AND  an injection was actually present
  BENIGN   = no injection present (attack_type in (None,"none") / none.json /
             empty injections) -- ALWAYS security==True via AgentDojo's no-injection
             early-return default, so the benign bucket is partitioned by attack-present,
             NEVER by security.

This script NEVER imports apohara, NEVER detects a marker, NEVER emits a `sink:` action.
It only partitions trace FILES by the EXTERNAL `security` label + injection presence,
so the downstream (b) post-hoc detection number stays a MEASUREMENT, not a tautology.

The output manifests live under gitignored eval/ and are NEVER committed.

Usage:  python3 scripts/eval/extract_agentdyn_positives.py [--runs PATH] [--out PATH]
"""
import argparse
import json
import os
import sys

# Bare NO-DEFENSE model dirs (NOT the `-drift`/`-piguard_detector`/... defended dirs,
# and NOT the old gpt-4o* dirs which are excluded by the frontier-only constraint).
# These are the same dirs counted by count_agentdyn_positives.py.
NO_DEFENSE_MODELS = [
    "gpt-5.1-2025-11-13",
    "gpt-5-mini-2025-08-07",
    "google_gemini-2.5-pro",
    "google_gemini-2.5-flash",
]


def _is_injection_file(path: str, d: dict) -> bool:
    """True iff an injection was actually present in this trace."""
    if os.path.basename(path) == "none.json":
        return False
    atk = d.get("attack_type")
    if atk in (None, "none"):
        return False
    inj = d.get("injections")
    return isinstance(inj, dict) and len(inj) > 0


def classify(path: str, d: dict) -> str:
    """Return 'positive' | 'failed' | 'benign' for one trace dict."""
    if not _is_injection_file(path, d):
        return "benign"
    sec = d.get("security")
    if sec is True:
        return "positive"
    if sec is False:
        return "failed"
    # security is None/missing on an injection trace: treat as failed (no success proof).
    return "failed"


def main() -> int:
    ap = argparse.ArgumentParser()
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--runs", default=os.path.join(here, "eval", "agentdyn", "runs"))
    ap.add_argument("--out", default=os.path.join(here, "eval", "v22-buckets"))
    args = ap.parse_args()

    if not os.path.isdir(args.runs):
        print(f"ERROR: runs dir not found: {args.runs}", file=sys.stderr)
        return 2
    os.makedirs(args.out, exist_ok=True)

    buckets = {"positive": [], "failed": [], "benign": []}
    per_model = {m: {"positive": 0, "failed": 0, "benign": 0} for m in NO_DEFENSE_MODELS}

    for model in NO_DEFENSE_MODELS:
        root = os.path.join(args.runs, model)
        if not os.path.isdir(root):
            print(f"WARNING: model dir missing: {root}", file=sys.stderr)
            continue
        for dirpath, _dirs, files in os.walk(root):
            for fn in sorted(files):
                if not fn.endswith(".json"):
                    continue
                path = os.path.join(dirpath, fn)
                try:
                    d = json.load(open(path))
                except Exception:
                    continue
                bucket = classify(path, d)
                buckets[bucket].append(path)
                per_model[model][bucket] += 1

    for name, paths in buckets.items():
        out_path = os.path.join(args.out, f"{name}.txt")
        with open(out_path, "w") as f:
            f.write("\n".join(sorted(paths)) + ("\n" if paths else ""))
        print(f"wrote {len(paths):>5} paths -> {out_path}")

    print("\nper-model (no-defense):")
    print(f"  {'model':<28} {'POSITIVE':>9} {'FAILED':>8} {'BENIGN':>8}")
    tp = tf = tb = 0
    for m in NO_DEFENSE_MODELS:
        c = per_model[m]
        print(f"  {m:<28} {c['positive']:>9} {c['failed']:>8} {c['benign']:>8}")
        tp += c["positive"]
        tf += c["failed"]
        tb += c["benign"]
    print(f"  {'TOTAL':<28} {tp:>9} {tf:>8} {tb:>8}")
    print(f"\nPOSITIVE bucket = {tp} (expected 236: gpt-5.1=33, gpt-5-mini=2, "
          f"gemini-2.5-pro=122, gemini-2.5-flash=79)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
