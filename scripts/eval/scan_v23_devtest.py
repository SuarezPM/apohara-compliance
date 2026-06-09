#!/usr/bin/env python3
"""v2.3 Phase 2 — re-measure the AgentDyn corpus with the v2.3 binary (which
ships BOTH the v2.2 AGT-TRJ-* rules AND the new AGT-TRJ-*-P provenance-gated
variants). Report the v2.2 (correlation) number and the v2.3 (-P) number
SIDE-BY-SIDE per model+suite, on the FROZEN dev/test split from
.eval/v23/split.json (44 dev / 192 test; deterministic SHA-256 seed; see
PREREG-v2.3.md for the anti-fit guard). Headline is the TEST split (192);
DEV is for sanity checks only.

Same FROZEN wrap_agentdojo_trace.py + the v2.3 release binary
(`scan-session --rules-dir references --format json`) — apohara-AGNOSTIC
transcription, no LLM, no network.

Bound triple (per PREREG-v2.3.md):
  (a) model attack-success-rate — same as v2.2 (AgentDyn `security` label).
  (b) apohara correlation post-hoc — k-of-N AGT-TRJ-* on the 236 positives
      (v2.2 number, restated; the v2.2 rules are byte-identical in the
      new binary because empty require_value_from_source = passthrough).
  (c) apohara provenance-gated post-hoc (NEW) — k'-of-N AGT-TRJ-*-P on the
      same 236 positives. Reported side-by-side with (b).
  (d) FP controls: FAILED + BENIGN. -P should REDUCE (b)'s 28.7% correlation
      FP; the honest number is reported whatever it is.

FROZEN inputs (PREREG-v2.3.md):
  - rules: crates/scanner/references/detection-rules.yaml @ SHA dcd1ac6e (PRE-edit)
           + appended -P rules (the ONLY post-freeze change to the rules file).
  - binary: target/release/apohara-compliance-scanner (this build).
  - split: eval/v23/split.json (44 dev / 192 test, deterministic).
  - buckets: eval/v22-buckets/{positive,failed,benign}.txt (FROZEN at v2.2 scan).

Output: eval/v23/scan-results.json (gitignored).
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter

HERE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(HERE, "scripts", "eval"))
import wrap_agentdojo_trace as W  # noqa: E402

BIN = os.path.join(HERE, "target", "release", "apohara-compliance-scanner")
RULES = "references"


def scan(messages) -> dict:
    """Frozen 1:1 wrap + real-binary scan -> {corr_codes, p_codes} sorted."""
    lines = W.wrap(messages)
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        f.write("\n".join(lines) + "\n")
        path = f.name
    try:
        out = subprocess.run(
            [BIN, "--rules-dir", RULES, "scan-session", path, "--format", "json"],
            capture_output=True, text=True, check=True,
        ).stdout
    finally:
        os.unlink(path)
    rep = json.loads(out)
    corr = set()
    pvar = set()
    for x in rep.get("findings", []):
        if not x["id"].startswith("AGT-TRJ"):
            continue
        if x["id"].endswith("-P"):
            pvar.add(x["id"])
        else:
            corr.add(x["id"])
    return {"corr": sorted(corr), "p": sorted(pvar)}


def model_of(path: str) -> str:
    parts = path.split(os.sep)
    i = parts.index("runs")
    return parts[i + 1]


def suite_of(path: str) -> str:
    parts = path.split(os.sep)
    i = parts.index("runs")
    return parts[i + 2]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default=os.path.join(HERE, "eval", "v23", "split.json"))
    ap.add_argument("--buckets", default=os.path.join(HERE, "eval", "v22-buckets"))
    ap.add_argument("--out", default=os.path.join(HERE, "eval", "v23", "scan-results.json"))
    args = ap.parse_args()

    split = json.load(open(args.split))
    # Normalize the split paths to the same form the scanner produces
    # (relative to HERE, the repo root). The split file stores absolute paths.
    def _norm(p: str) -> str:
        return os.path.relpath(p, HERE)
    dev_paths = {_norm(p) for v in split["dev"].values() for p in v}
    test_paths = {_norm(p) for v in split["test"].values() for p in v}
    print(f"split: dev={len(dev_paths)} test={len(test_paths)}", file=sys.stderr)

    def load_bucket(name):
        p = os.path.join(args.buckets, f"{name}.txt")
        return [l for l in open(p).read().splitlines() if l]

    positives = load_bucket("positive")
    failed = load_bucket("failed")
    benign = load_bucket("benign")

    def scan_one(bucket_name, path):
        d = json.load(open(path))
        r = scan(d["messages"])
        return {
            "path": os.path.relpath(path, HERE),
            "model": model_of(path),
            "suite": suite_of(path),
            "agt_trj_corr": r["corr"],
            "agt_trj_p": r["p"],
            "fired_corr": bool(r["corr"]),
            "fired_p": bool(r["p"]),
        }

    results = {"positive": [], "failed": [], "benign": []}

    for p in positives:
        results["positive"].append(scan_one("positive", p))
    for p in failed:
        results["failed"].append(scan_one("failed", p))
    for p in benign:
        results["benign"].append(scan_one("benign", p))

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    json.dump(results, open(args.out, "w"), indent=2)

    # --- summary ---
    summary = []
    def pr(s=""):
        print(s)
        summary.append(s)

    models = sorted({r["model"] for r in results["positive"]})
    test_pos = [r for r in results["positive"] if r["path"] in test_paths]
    dev_pos = [r for r in results["positive"] if r["path"] in dev_paths]

    pr("=" * 78)
    pr("v2.3 BOUND TRIPLE over the AgentDyn corpus (date-labeled last-gen models)")
    pr("=" * 78)
    pr(f"split: dev={len(dev_pos)} test={len(test_pos)}  (total positives = {len(positives)})")
    pr("Headline is the TEST split (192); DEV is for sanity checks only.")

    pr(f"\n(b) v2.2 correlation post-hoc AGT-TRJ-* on the {len(test_pos)} TEST positives")
    pr(f"    {'model':<30} {'corr fired':>11} {'of':>4}   per-code")
    tot_corr = 0
    for mdl in models:
        rs = [r for r in test_pos if r["model"] == mdl]
        fired = sum(1 for r in rs if r["fired_corr"])
        tot_corr += fired
        codes = Counter()
        for r in rs:
            for c in r["agt_trj_corr"]:
                codes[c] += 1
        cs = ", ".join(f"{k}={v}" for k, v in sorted(codes.items())) or "-"
        pr(f"    {mdl:<30} {fired:>11} {len(rs):>4}   {cs}")
    pct = f" ({100*tot_corr/len(test_pos):.1f}%)" if len(test_pos) >= 5 else ""
    pr(f"    {'TOTAL':<30} {tot_corr:>11} {len(test_pos):>4}{pct}")

    pr(f"\n(c) v2.3 -P provenance-gated AGT-TRJ-*-P on the {len(test_pos)} TEST positives")
    pr(f"    {'model':<30} {'-P fired':>9} {'of':>4}   per-code")
    tot_p = 0
    for mdl in models:
        rs = [r for r in test_pos if r["model"] == mdl]
        fired = sum(1 for r in rs if r["fired_p"])
        tot_p += fired
        codes = Counter()
        for r in rs:
            for c in r["agt_trj_p"]:
                codes[c] += 1
        cs = ", ".join(f"{k}={v}" for k, v in sorted(codes.items())) or "-"
        pr(f"    {mdl:<30} {fired:>9} {len(rs):>4}   {cs}")
    pct = f" ({100*tot_p/len(test_pos):.1f}%)" if len(test_pos) >= 5 else ""
    pr(f"    {'TOTAL':<30} {tot_p:>9} {len(test_pos):>4}{pct}")

    pr(f"\n    >>> (b) corr: {tot_corr} of {len(test_pos)}    (c) -P: {tot_p} of {len(test_pos)}")
    pr(f"    >>> delta = -{(tot_corr - tot_p)} candidates (the FP-killer result, honest number).")

    pr(f"\n(d) FP controls (full buckets, FROZEN at v2.2):")
    fl_corr = sum(1 for r in results["failed"] if r["fired_corr"])
    fl_p = sum(1 for r in results["failed"] if r["fired_p"])
    bn_corr = sum(1 for r in results["benign"] if r["fired_corr"])
    bn_p = sum(1 for r in results["benign"] if r["fired_p"])
    pr(f"    FAILED-injection: corr={fl_corr}/{len(failed)}   -P={fl_p}/{len(failed)}")
    pr(f"    BENIGN:           corr={bn_corr}/{len(benign)}   -P={bn_p}/{len(benign)}")

    pr(f"\nDEV split sanity check (44 positives; not a headline — just verification):")
    dev_corr = sum(1 for r in dev_pos if r["fired_corr"])
    dev_p = sum(1 for r in dev_pos if r["fired_p"])
    pr(f"    corr={dev_corr}/{len(dev_pos)}  -P={dev_p}/{len(dev_pos)}")

    pr(f"\nresults -> {os.path.relpath(args.out, HERE)} (gitignored)")

    with open("/tmp/v23-p2-summary.txt", "w") as f:
        f.write("\n".join(summary) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
