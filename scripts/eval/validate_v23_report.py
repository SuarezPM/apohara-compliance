#!/usr/bin/env python3
"""Strict numbers/IDs-only schema validator for tests/corpus/v2.3-argument-value-provenance-report.json.

Mirrors the v2.2 + AgentHarm discipline: the committed v2.3 report must carry
NO free-text / example / trace content and NO API key. Every leaf is a number,
a SHA, a model id, a sink-role key, an AGT code, or a FROZEN allow-listed
metadata string. The headline is a short controlled template, not a free
sentence.

Exit 0 = report is numbers/IDs-only. Non-zero = a free-text/unexpected field present.
"""
import json
import pathlib
import re
import sys

REPORT = pathlib.Path("tests/corpus/v2.3-argument-value-provenance-report.json")

SHA_RE = re.compile(r"^[0-9a-f]{40}$")              # git blob / corpus commit SHA
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,79}$")
KEY_RE = re.compile(r"^[a-z0-9_]{1,40}$")
# OpenRouter / Anthropic key shape — must NEVER appear anywhere as a value.
OR_KEY_RE = re.compile(r"sk-or-v1-[0-9a-f]{20,}")
ANT_KEY_RE = re.compile(r"sk-ant-[0-9a-zA-Z-]{20,}")

# Top-level + nested metadata strings must be EXACT allow-listed values (no free text).
META_ALLOW = {
    "schema_version": {1},
    "version": {"v2.3"},
    "codename": {"Argument-Value Provenance (causal proxy, post-hoc, verbatim-flow)"},
    "binary": {"apohara-compliance-scanner v2.3.0 (this build)"},
    "prereg": {"tests/corpus/PREREG-v2.3.md"},
    "prereg_sha_pattern": "sha1",
    "source": {"SaFo-Lab/AgentDyn"},
    "upstream_commit_pattern": "sha1",
    "agentdojo_version": {"0.1.35"},
    "benchmark_version": {"v1.2.2"},
    "suite": {"shopping", "github", "dailylife", "workspace"},
    "salt": {"v2.3-argument-value-provenance"},
    "headline_split": {"test"},
    "honest_ceiling_template": "Necessary-but-not-sufficient post-hoc proxy",
}


def fail(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    print(f"FAIL  {msg}", file=sys.stderr)
    sys.exit(1)


def pass_(msg: str) -> None:
    print(f"PASS  {msg}")


def check_no_secrets(text: str) -> None:
    for pat, name in [(OR_KEY_RE, "OpenRouter key"), (ANT_KEY_RE, "Anthropic key")]:
        if pat.search(text):
            fail(f"{name} shape found in report (redacted) — schema rejects any key")


def walk(node, path) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            if not isinstance(k, str):
                fail(f"non-string key at {path}.{k!r}")
            if k in META_ALLOW:
                if isinstance(v, str) and v not in META_ALLOW[k]:
                    fail(f"value {v!r} for {k!r} at {path} not in allow-list {META_ALLOW[k]}")
                if isinstance(v, (int, bool)) and v not in META_ALLOW[k]:
                    fail(f"value {v!r} for {k!r} at {path} not in allow-list {META_ALLOW[k]}")
            check_no_secrets(str(v))
            walk(v, f"{path}.{k}" if path else k)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            check_no_secrets(str(v))
            walk(v, f"{path}[{i}]")
    elif isinstance(node, str):
        # top-level string values must match one of the known regexes or be in
        # the explicit metadata allow-list (handled at the parent).
        if path.endswith("_sha") or path == "rules_pre_freeze_sha" or path == "rules_post_freeze_sha" or path == "upstream_commit":
            if not SHA_RE.match(node):
                fail(f"value at {path!r} = {node!r} is not a 40-hex SHA")
        elif path in {"model", "model_id"}:
            if not MODEL_RE.match(node):
                fail(f"value at {path!r} = {node!r} is not a model-id shape")
        elif path in {"salt", "version", "prereg", "schema_version", "binary", "version_codename", "version_short"}:
            pass
        elif path == "headline":
            # Headline is a template with bracketed numbers; allow only alnum, space,
            # punctuation, and the % sign.
            if not re.match(r"^[A-Za-z0-9 .(),/%+\-=:!?\"\']+$", node):
                fail(f"headline at {path!r} has unexpected characters: {node!r}")
        elif path == "honest_ceiling":
            if "post-hoc proxy" not in node and "post-hoc" not in node:
                fail(f"honest_ceiling at {path!r} missing the 'post-hoc proxy' framing")
        else:
            # unknown string path: must be short, no newlines, no sentences
            if len(node) > 200 or "\n" in node:
                fail(f"unexpected long/multi-line string at {path!r} = {node!r}")
    elif isinstance(node, (int, float, bool)):
        pass
    else:
        fail(f"unexpected node type at {path!r}: {type(node).__name__}")


def main() -> int:
    if not REPORT.exists():
        fail(f"report not found: {REPORT}")
    data = json.loads(REPORT.read_text())
    check_no_secrets(REPORT.read_text())
    walk(data, "")
    # explicit checks on required sections
    for req in ("schema_version", "version", "corpus", "split", "bound_triple", "headline", "honest_ceiling"):
        if req not in data:
            fail(f"missing required top-level field: {req!r}")
    # bound_triple must have all 6 buckets
    bt = data["bound_triple"]
    for k in ("test_positives_corr", "test_positives_P", "delta_candidates",
              "failed_corr", "failed_P", "benign_corr", "benign_P"):
        if k not in bt:
            fail(f"missing bound_triple field: {k!r}")
        if k != "delta_candidates" and not isinstance(bt[k], dict):
            fail(f"bound_triple.{k!r} must be a dict with fired/of/pct")
        if k != "delta_candidates":
            for sk in ("fired", "of", "pct"):
                if sk not in bt[k]:
                    fail(f"bound_triple.{k!r}.{sk!r} missing")
    pass_(f"v2.3 report is numbers/IDs-only (schema-validated, no key): {REPORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
