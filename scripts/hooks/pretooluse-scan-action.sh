#!/usr/bin/env bash
# PreToolUse live hook (US-F3-2 / Step 3.2): surface compliance CANDIDATES for a
# pending Bash command BEFORE it executes, using the apohara-compliance scanner's
# lightweight `scan-action` mode (matches ONE string, reads no file or session).
#
# WARN-not-block by default: it prints any candidate to stderr and exits 0, so the
# action still runs — a candidate is a "please review", NEVER a verdict that the
# command is malicious. Set APOHARA_BLOCK_ON (to any non-empty value) to opt into
# blocking the tool call for human review instead.
#
# Install (Claude Code .claude/settings.json):
#   "hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [ { "type": "command",
#     "command": "/abs/path/to/scripts/hooks/pretooluse-scan-action.sh" } ] } ] }
#
# Optional env:
#   APOHARA_SCANNER   path/name of the scanner binary (default: on PATH).
#   APOHARA_RULES_DIR canonical references/ dir (passed through to the scanner).
#   APOHARA_BLOCK_ON  if set, block (exit 2) when any candidate is surfaced.
set -euo pipefail

SCANNER="${APOHARA_SCANNER:-apohara-compliance-scanner}"
# Scanner not installed → no-op. The hook must never break the agent loop.
command -v "$SCANNER" >/dev/null 2>&1 || exit 0

# The PreToolUse hook receives the tool call as JSON on stdin; pull the Bash
# command out of tool_input.command (empty for non-Bash tools → no-op).
payload="$(cat)"
cmd="$(printf '%s' "$payload" \
  | python3 -c 'import sys,json
try:
    d=json.load(sys.stdin)
    print(d.get("tool_input",{}).get("command",""))
except Exception:
    print("")' 2>/dev/null || true)"
[ -z "$cmd" ] && exit 0

rules_arg=()
[ -n "${APOHARA_RULES_DIR:-}" ] && rules_arg=(--rules-dir "$APOHARA_RULES_DIR")

report="$("$SCANNER" "${rules_arg[@]}" scan-action "$cmd" --kind session:Bash.input --format md 2>/dev/null || true)"
if printf '%s' "$report" | grep -q 'CANDIDATE —'; then
  echo "apohara-compliance: candidate(s) to review before running this command:" >&2
  printf '%s\n' "$report" | grep 'CANDIDATE —' >&2
  if [ -n "${APOHARA_BLOCK_ON:-}" ]; then
    echo "apohara-compliance: APOHARA_BLOCK_ON set -> blocking this tool call for human review." >&2
    exit 2
  fi
fi
exit 0
