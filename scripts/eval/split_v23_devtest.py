#!/usr/bin/env python3
"""
v2.3 dev/test split — stratified 20/80 by (model, suite), deterministic.

Frozen pre-registration parameters (see .omc/prereg/PREREG-v2.3.md):
  - input: eval/v22-buckets/positive.txt (236 lines from v2.2 corpus)
  - split ratio: 20% DEV, 80% TEST per (model, suite) bucket
  - determinism: SHA-256 of the file path; the integer prefix of the digest hex
    modulo 100 is the bucket's pseudo-random number; < 20 -> DEV, >= 20 -> TEST
  - output: eval/v23/split.json (per-bucket file lists + counts + total)

This script is FROZEN at this SHA. Any post-scan change to it invalidates the
split, which is a fit, not a measurement. Re-runs MUST produce the same output
(verified by `make test-eval` after the v2.3 implementation step).
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

# Frozen pre-registration parameters.
SEED_SALT = "v2.3-argument-value-provenance"
DEV_FRACTION = 0.20
BUCKETS_FILE = Path("eval/v22-buckets/positive.txt")
OUTPUT_FILE = Path("eval/v23/split.json")


def bucket_key(path: str) -> tuple[str, str] | None:
    """Path shape: eval/agentdyn/runs/<model>/<suite>/..."""
    parts = path.strip().split("/")
    if "runs" not in parts:
        return None
    i = parts.index("runs")
    if i + 2 >= len(parts):
        return None
    return (parts[i + 1], parts[i + 2])


def deterministic_assign(path: str) -> bool:
    """Return True if this path is DEV, False if TEST.

    Determinism: SHA-256 of (seed_salt + path) → first 8 hex chars → modulo 100.
    < DEV_FRACTION * 100 → DEV. No global RNG, no time, no PID.
    """
    h = hashlib.sha256(f"{SEED_SALT}{path}".encode("utf-8")).hexdigest()[:8]
    bucket = int(h, 16) % 100
    return bucket < int(DEV_FRACTION * 100)


def main() -> int:
    if not BUCKETS_FILE.exists():
        print(f"missing input: {BUCKETS_FILE}", file=sys.stderr)
        return 2

    dev: dict[tuple[str, str], list[str]] = defaultdict(list)
    test: dict[tuple[str, str], list[str]] = defaultdict(list)
    skipped: list[str] = []
    total = 0
    for line in BUCKETS_FILE.read_text().splitlines():
        path = line.strip()
        if not path:
            continue
        total += 1
        key = bucket_key(path)
        if key is None:
            skipped.append(path)
            continue
        if deterministic_assign(path):
            dev[key].append(path)
        else:
            test[key].append(path)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "prereg": ".omc/prereg/PREREG-v2.3.md",
        "input": str(BUCKETS_FILE),
        "seed_salt": SEED_SALT,
        "dev_fraction": DEV_FRACTION,
        "total_positives": total,
        "skipped_unparseable": len(skipped),
        "counts": {
            "dev": {f"{m}|{s}": len(v) for (m, s), v in sorted(dev.items())},
            "test": {f"{m}|{s}": len(v) for (m, s), v in sorted(test.items())},
            "dev_total": sum(len(v) for v in dev.values()),
            "test_total": sum(len(v) for v in test.values()),
        },
        "dev": {f"{m}|{s}": sorted(v) for (m, s), v in sorted(dev.items())},
        "test": {f"{m}|{s}": sorted(v) for (m, s), v in sorted(test.items())},
    }
    OUTPUT_FILE.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    print(f"total positives: {total}")
    print(f"dev: {manifest['counts']['dev_total']}  test: {manifest['counts']['test_total']}")
    print(f"skipped: {len(skipped)}")
    print(f"wrote: {OUTPUT_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
