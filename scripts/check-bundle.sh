#!/usr/bin/env bash
#
# Marketplace bundle-integrity check (consensus plan Step 5, "MARKETPLACE BUNDLE
# INTEGRITY", BLOCKING acceptance).
#
# The skill points the scanner at canonical rules via --rules-dir /
# APOHARA_RULES_DIR, which resolve to a `references/` dir living INSIDE the
# installed skill subtree (skills/apohara-compliance/references/). If the
# packaged plugin bundle does not ship those YAML files where the skill points,
# installs silently fall through the scanner's resolution ladder to the embedded
# copy — re-opening the silent-drift hole via distribution.
#
# This script asserts the bundle ships the resolvable references/*.yaml. If the
# bundler would drop the root-level references/, it copies them into the skill
# subtree at build time so the bundle is self-contained.
#
# Usage:
#   scripts/check-bundle.sh           # check + fix-up (copy refs into skill subtree)
#   scripts/check-bundle.sh --check   # check only, never mutate (fail if missing)
set -euo pipefail

# Resolve repo root from this script's location so it works from any cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

CHECK_ONLY=0
if [[ "${1:-}" == "--check" ]]; then
  CHECK_ONLY=1
fi

# The exact YAML files the scanner loads (crates/scanner/src/rules.rs).
# detection-rules.yaml is the marker file is_rules_dir() looks for.
RULE_FILES=(
  asi-2026.yaml
  ast-2026.yaml
  controls-49.yaml
  crosswalk-asi-llm.yaml
  detection-rules.yaml
)

CANONICAL_REFS="${ROOT}/references"
SKILL_DIR="${ROOT}/skills/apohara-compliance"
SKILL_REFS="${SKILL_DIR}/references"

fail() { echo "BUNDLE_INTEGRITY: FAIL — $*" >&2; exit 1; }

# Canonical references must exist at the repo root.
for f in "${RULE_FILES[@]}"; do
  [[ -f "${CANONICAL_REFS}/${f}" ]] || fail "canonical references/${f} is missing at repo root"
done

# Ensure the skill subtree carries a resolvable references/ (a real dir or a
# symlink to one). If it doesn't, either fix it up or fail in --check mode.
needs_fixup=0
if [[ ! -e "${SKILL_REFS}" ]]; then
  needs_fixup=1
else
  for f in "${RULE_FILES[@]}"; do
    [[ -f "${SKILL_REFS}/${f}" ]] || { needs_fixup=1; break; }
  done
fi

if [[ "${needs_fixup}" -eq 1 ]]; then
  if [[ "${CHECK_ONLY}" -eq 1 ]]; then
    fail "skills/apohara-compliance/references/*.yaml not resolvable; bundle would fall through to embedded rules"
  fi
  echo "BUNDLE_INTEGRITY: references missing in skill subtree — copying canonical references into the bundle"
  # Resolve through a symlink target if present, else copy the real files.
  rm -rf "${SKILL_REFS}"
  mkdir -p "${SKILL_REFS}"
  for f in "${RULE_FILES[@]}"; do
    cp "${CANONICAL_REFS}/${f}" "${SKILL_REFS}/${f}"
  done
fi

# Final assertion: every rule file resolves to a readable file inside the skill
# subtree (following symlinks).
for f in "${RULE_FILES[@]}"; do
  [[ -f "${SKILL_REFS}/${f}" ]] || fail "skills/apohara-compliance/references/${f} still not resolvable after fix-up"
done

echo "BUNDLE_INTEGRITY: OK — all ${#RULE_FILES[@]} references/*.yaml resolvable in the skill subtree"
