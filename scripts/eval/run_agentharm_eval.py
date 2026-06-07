#!/usr/bin/env python3
"""AgentHarm EVAL-ONLY runner -> tests/corpus/agentharm-report.json (numbers/IDs only).

Loads AgentHarm harmful/test_public (gitignored HF cache), runs each prompt through the
REAL apohara binary as a synthetic chat-tool action, and writes an aggregate report that
contains NO example text (no prompt, no name, no detailed_prompt, no grading_function,
no canary) — only counts, per-category coverage rates, fired-AGT-code counts, and bare
behavior identifiers. scripts/eval/validate_report_schema.py enforces this.

HONESTY: measures bait-keyword surface coverage of harmful-agentic vocabulary, NOT
injection-consequence detection. See scripts/eval/SOURCE-agentharm.md.

Run: HF_HOME=$PWD/eval/agentharm/.cache eval/.venv/bin/python scripts/eval/run_agentharm_eval.py
"""
import json
import os
import pathlib
import re
import subprocess
import tempfile
from collections import Counter

REPO = "ai-safety-institute/AgentHarm"
CONFIG, SPLIT = "harmful", "test_public"
BIN = pathlib.Path("target/release/apohara-compliance-scanner")
RULES = pathlib.Path("references")
OUT = pathlib.Path("tests/corpus/agentharm-report.json")
SYNTHETIC_TOOL = "AgentChatMessage"
ID_RE = re.compile(r"^[0-9]+(-[0-9]+)*$")


def fired_codes(prompt: str) -> tuple[list[str], bool]:
    """Run the binary on one prompt-as-action; return (fired AGT codes, all-candidate)."""
    line = json.dumps(
        {
            "type": "assistant",
            "message": {"content": [{"type": "tool_use", "name": SYNTHETIC_TOOL, "input": {"prompt": prompt}}]},
        }
    )
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        f.write(line + "\n")
        path = f.name
    try:
        out = subprocess.run(
            [str(BIN), "--rules-dir", str(RULES), "scan-session", path, "--format", "json"],
            capture_output=True, text=True, check=True,
        ).stdout
    finally:
        os.unlink(path)
    rep = json.loads(out)
    findings = rep.get("findings", [])
    codes = sorted({f["id"] for f in findings})
    all_cand = all(f.get("is_candidate", False) for f in findings) if findings else True
    return codes, all_cand


def main() -> int:
    if not BIN.exists():
        raise SystemExit(f"binary missing: {BIN} (cargo build --release first)")
    from datasets import load_dataset

    ds = load_dataset(REPO, CONFIG, split=SPLIT)
    n = len(ds)
    with_any = 0
    by_cat: dict[str, dict[str, int]] = {}
    fired = Counter()
    base_ids: set[str] = set()
    candidate_violation = 0

    for row in ds:
        prompt = row.get("prompt") or row.get("detailed_prompt") or ""
        cat = str(row.get("category", "uncategorized")).strip()
        codes, all_cand = fired_codes(prompt)
        if not all_cand:
            candidate_violation += 1
        hit = bool(codes)
        with_any += int(hit)
        slot = by_cat.setdefault(cat, {"n": 0, "with_candidate": 0})
        slot["n"] += 1
        slot["with_candidate"] += int(hit)
        for c in codes:
            fired[c] += 1
        ido = str(row.get("id_original", row.get("id", ""))).strip()
        if ID_RE.match(ido):
            base_ids.add(ido)

    report = {
        "source": REPO,
        "config": CONFIG,
        "split": SPLIT,
        "license": "MIT + eval-only clause (no examples committed)",
        "measures": "bait-keyword surface coverage (NOT injection-consequence detection)",
        "n": n,
        "base_behaviors": len(base_ids),
        "coverage": {
            "prompts_with_any_candidate": with_any,
            "rate": round(with_any / n, 4) if n else 0.0,
        },
        "candidate_only_violations": candidate_violation,
        "by_category": dict(sorted(by_cat.items())),
        "by_fired_code": dict(sorted(fired.items())),
        "behavior_ids": sorted(base_ids),
    }
    OUT.write_text(json.dumps(report, indent=2) + "\n")
    print(f"wrote {OUT}: n={n} coverage={report['coverage']['rate']:.4f} "
          f"({with_any}/{n}) base_behaviors={len(base_ids)} codes={dict(fired)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
