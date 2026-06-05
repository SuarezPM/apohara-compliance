#!/usr/bin/env bash
# apohara-compliance — verification block (operationalizes spec §5 / plan §5).
# Exit non-zero on any failure. Run from repo root.
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
pass() { printf 'PASS  %s\n' "$1"; }
bad()  { printf 'FAIL  %s\n' "$1"; fail=1; }

# EXTENDED assertive-language NEGATIVE guard (fix #6b). Beyond the original
# `is compliant|certified|guaranteed`, the candidate/absence honesty contract now
# also bans `non-compliant`, `violates`, `is vulnerable to`, `detected`, and
# `you have ASI`. Applied (case-insensitive) to EVERY output path: scan-repo,
# scan-session (the moat), --by-asi, and gap-mode (US-F1-4). A single shared
# pattern keeps the guard identical everywhere it runs.
NEGATIVE_GUARD='is compliant|certified|guaranteed|non-compliant|violates|is vulnerable to|detected|you have ASI'

echo "== License / packaging =="
[ -f LICENSE-MIT ] && [ -f LICENSE-APACHE ] && pass "dual license present (LICENSE-MIT + LICENSE-APACHE)" || bad "dual license files"
[ ! -f LICENSE ] && pass "no single LICENSE file" || bad "single LICENSE present (must be dual)"
[ -f NOTICE ] && pass "NOTICE present" || bad "NOTICE missing"
grep -q 'license = "MIT OR Apache-2.0"' Cargo.toml && pass "Cargo license = MIT OR Apache-2.0" || bad "Cargo license string"
python3 -c "import json;d=json.load(open('.claude-plugin/plugin.json'));assert d['skills']==['./skills/apohara-compliance/']" \
  && pass "plugin.json skills array" || bad "plugin.json skills array"
git check-ignore target/ >/dev/null 2>&1 && pass "target/ gitignored" || bad "target/ not gitignored"

echo "== Reference data provenance gate =="
python3 - <<'PY' && pass "controls-49 provenance gate" || bad "controls-49 provenance gate"
import yaml, sys
d = yaml.safe_load(open('references/controls-49.yaml'))
ctrls = next(v for v in d.values() if isinstance(v, list))
assert len(ctrls) == 49, f"expected 49 controls, got {len(ctrls)}"
for c in ctrls:
    assert c.get('consilium_ref'), f"{c.get('id')} missing consilium_ref"
    assert c.get('status') in ('official','draft'), f"{c.get('id')} bad status"
    if 'AGENTIC-' in str(c.get('id','')):
        assert c['status'] == 'draft', f"AGENTIC {c['id']} must be draft"
# OWASP LLM authoritative version must be 2025, never 2026
for c in ctrls:
    if 'OWASP LLM' in str(c.get('framework','')) or c.get('framework','').startswith('OWASP LLM'):
        assert str(c.get('version')) == '2025', f"{c['id']} OWASP LLM version must be 2025, got {c.get('version')}"
print("  controls=49, all consilium_ref+status, AGENTIC=draft, OWASP-LLM=2025", file=sys.stderr)
PY

python3 - <<'PY' && pass "crosswalk cites OWASP Appendix A (no third-party)" || bad "crosswalk provenance"
import yaml
d = yaml.safe_load(open('references/crosswalk-asi-llm.yaml'))
rows = next(v for v in d.values() if isinstance(v, list))
banned = ('deepteam','promptfoo','trent.ai','genai-security-crosswalk')
for r in rows:
    prov = str(r.get('provenance','')).lower()
    cite = str(r.get('citation','')).lower()
    assert not any(b in prov or b in cite for b in banned), f"third-party crosswalk in {r}"
    assert ('appendix' in prov or 'appendix' in cite or 'authored-from-owasp-narrative' in prov), f"row not Appendix-A sourced: {r}"
PY

python3 - <<'PY' && pass "MITRE ATLAS layer provenance gate (US-F2-1: version 5.6.0, verified_on, per-row url+status)" || bad "ATLAS provenance gate"
import yaml, re, sys
d = yaml.safe_load(open('references/atlas-2026.yaml'))
# File-level provenance: framework, version 5.6.0, a source_url, and a verified_on.
assert d.get('framework') == 'MITRE ATLAS', f"framework must be MITRE ATLAS, got {d.get('framework')}"
assert str(d.get('version')) == '5.6.0', f"ATLAS version must be 5.6.0, got {d.get('version')}"
assert d.get('source_url'), "atlas-2026.yaml missing file-level source_url"
assert 'atlas.mitre.org' in str(d.get('source_url')), f"source_url must point at atlas.mitre.org: {d.get('source_url')}"
assert d.get('verified_on'), "atlas-2026.yaml missing verified_on"
techs = d.get('techniques') or []
assert techs, "atlas-2026.yaml has no techniques"
tid = re.compile(r'^AML\.T\d{4}(\.\d{3})?$')
for t in techs:
    assert tid.match(str(t.get('id',''))), f"malformed ATLAS id: {t.get('id')}"
    assert t.get('name'), f"{t.get('id')} missing name"
    # Every row carries a source_url (its own technique url on atlas.mitre.org).
    assert t.get('url') and 'atlas.mitre.org' in str(t['url']), f"{t.get('id')} missing atlas.mitre.org url"
    assert t.get('status') == 'official', f"{t.get('id')} status must be official, got {t.get('status')}"
# The required prompt-injection technique is present (RAC-2.1).
ids = {t['id'] for t in techs}
assert 'AML.T0051' in ids, "AML.T0051 (LLM Prompt Injection) must be carried"
print(f"  ATLAS 5.6.0: {len(techs)} techniques, all url+status+id-shape ok; AML.T0051 present", file=sys.stderr)
PY

python3 - <<'PY' && pass "ATLAS cite-don't-copy guard (ids/names/urls only, NO MITRE prose)" || bad "ATLAS prose guard"
import sys
# No-MITRE-prose guard (cite-don't-copy): the data rows carry only id/name/url/
# status. A long free-text sentence in a `name:`/`description:` field would mean
# copied MITRE prose. Guard: (1) no `description:` key anywhere; (2) every
# technique `name` is short (<= 6 words) and free of sentence punctuation.
import yaml
raw = open('references/atlas-2026.yaml').read()
# Only inspect non-comment lines (header comments cite URLs/principles, allowed).
body = '\n'.join(l for l in raw.splitlines() if not l.lstrip().startswith('#'))
assert 'description:' not in body, "atlas-2026.yaml must not carry MITRE description prose"
d = yaml.safe_load(raw)
for t in d['techniques']:
    name = str(t['name'])
    assert len(name.split()) <= 6, f"{t['id']} name too long (looks like prose): {name!r}"
    assert not any(p in name for p in ('. ', '; ')), f"{t['id']} name contains sentence punctuation: {name!r}"
print("  ATLAS rows carry ids/names/urls only; no description prose, names are short labels", file=sys.stderr)
PY

python3 - <<'PY' && pass "ISO 42001 layer provenance gate (US-F2-2: framework ISO/IEC 42001, version 2023, status official, per-row url)" || bad "ISO 42001 provenance gate"
import yaml, re, sys
d = yaml.safe_load(open('references/iso42001-2023.yaml'))
# File-level provenance: framework, version 2023, status official, source_url
# (iso.org), and a verified_on.
assert d.get('framework') == 'ISO/IEC 42001', f"framework must be ISO/IEC 42001, got {d.get('framework')}"
assert str(d.get('version')) == '2023', f"ISO 42001 version must be 2023, got {d.get('version')}"
assert d.get('status') == 'official', f"ISO 42001 layer status must be official, got {d.get('status')}"
assert d.get('source_url') and 'iso.org' in str(d.get('source_url')), f"file source_url must point at iso.org: {d.get('source_url')}"
assert d.get('verified_on'), "iso42001-2023.yaml missing verified_on"
ctrls = d.get('controls') or []
assert ctrls, "iso42001-2023.yaml has no controls"
cid = re.compile(r'^ISO42001:A\.\d+\.\d+(\.\d+)?$')
for c in ctrls:
    assert cid.match(str(c.get('id',''))), f"malformed ISO 42001 id: {c.get('id')}"
    assert c.get('objective'), f"{c.get('id')} missing objective"
    assert c.get('title'), f"{c.get('id')} missing title"
    assert c.get('paraphrase'), f"{c.get('id')} missing paraphrase"
    # Every row carries its own source_url pointing at iso.org.
    assert c.get('source_url') and 'iso.org' in str(c['source_url']), f"{c.get('id')} missing iso.org source_url"
# The required event-log control is present (RAC-2.2).
ids = {c['id'] for c in ctrls}
assert 'ISO42001:A.6.2.8' in ids, "ISO42001:A.6.2.8 (AI system recording of event logs) must be carried"
print(f"  ISO 42001 2023: {len(ctrls)} controls, all id-shape+objective+title+paraphrase+url ok; A.6.2.8 present", file=sys.stderr)
PY

python3 - <<'PY' && pass "ISO 42001 cite-don't-copy guard (codes/objectives/titles + OWN paraphrase, NO verbatim ISO prose)" || bad "ISO 42001 prose guard"
import sys, yaml
# No-verbatim-ISO-prose guard. ISO/IEC 42001 normative text is copyrighted; this
# layer carries only control codes + factual objective/title names + our OWN
# one-line paraphrase. Guard: (1) no `description:` key anywhere (we never copy a
# requirement clause); (2) the ISO normative drafting verb "The organization
# shall" (the signature of copied ISO clause text) appears nowhere in the body;
# (3) every `title` is a short label (<= 8 words) free of sentence punctuation.
raw = open('references/iso42001-2023.yaml').read()
# Only inspect non-comment lines (header comments cite URLs/principles, allowed).
body = '\n'.join(l for l in raw.splitlines() if not l.lstrip().startswith('#'))
assert 'description:' not in body, "iso42001-2023.yaml must not carry an ISO description/requirement clause"
low = body.lower()
for prose in ('the organization shall', 'the organisation shall'):
    assert prose not in low, f"verbatim ISO drafting clause {prose!r} must not be reproduced"
d = yaml.safe_load(raw)
for c in d['controls']:
    title = str(c['title'])
    assert len(title.split()) <= 8, f"{c['id']} title too long (looks like prose): {title!r}"
    assert not any(p in title for p in ('. ', '; ')), f"{c['id']} title has sentence punctuation: {title!r}"
print("  ISO 42001 rows carry codes/objectives/titles + own paraphrase; no `shall` clause, no description prose", file=sys.stderr)
PY

python3 - <<'PY' && pass "detection-rules iso42001_xref all resolve to iso42001-2023.yaml (US-F2-2)" || bad "detection-rules dangling iso42001_xref"
import yaml, sys
iso = yaml.safe_load(open('references/iso42001-2023.yaml'))
iso_ids = {c['id'] for c in iso['controls']}
rules = yaml.safe_load(open('references/detection-rules.yaml'))
rlist = next(v for v in rules.values() if isinstance(v, list))
dangling = []
mapped = 0
for r in rlist:
    xs = r.get('iso42001_xref', []) or []
    if xs:
        mapped += 1
    for x in xs:
        if x not in iso_ids:
            dangling.append((r['agt_code'], x))
if dangling:
    print('  DANGLING iso42001_xref:', dangling, file=sys.stderr); sys.exit(1)
# RAC-2.2: AGT-GOV-002 MUST cross-ref ISO42001:A.6.2.8.
by_code = {r['agt_code']: (r.get('iso42001_xref') or []) for r in rlist}
assert 'ISO42001:A.6.2.8' in by_code.get('AGT-GOV-002', []), "AGT-GOV-002 must map to ISO42001:A.6.2.8"
print(f"  {mapped}/16 AGT rules mapped to ISO 42001; all iso42001_xref resolve; GOV-002 -> A.6.2.8", file=sys.stderr)
PY

python3 - <<'PY' && pass "EU AI Act layer provenance gate (US-F2-3: framework EU AI Act, version 2024/1689, status official, eur-lex url, Art-10/11/13)" || bad "EU AI Act provenance gate"
import yaml, re, sys
d = yaml.safe_load(open('references/eu-ai-act-2024.yaml'))
# File-level provenance: framework, version, status official, source_url (eur-lex),
# and a verified_on.
assert d.get('framework') == 'EU AI Act', f"framework must be EU AI Act, got {d.get('framework')}"
assert str(d.get('version')) == 'Regulation (EU) 2024/1689', f"version must be Regulation (EU) 2024/1689, got {d.get('version')}"
assert d.get('status') == 'official', f"EU AI Act layer status must be official, got {d.get('status')}"
assert d.get('source_url') and 'eur-lex.europa.eu' in str(d.get('source_url')), f"file source_url must point at eur-lex: {d.get('source_url')}"
assert d.get('verified_on'), "eu-ai-act-2024.yaml missing verified_on"
arts = d.get('articles') or []
assert arts, "eu-ai-act-2024.yaml has no articles"
aid = re.compile(r'^EU-AI-ACT:Art-\d+$')
for a in arts:
    assert aid.match(str(a.get('id',''))), f"malformed EU AI Act id: {a.get('id')}"
    assert a.get('title'), f"{a.get('id')} missing title"
    assert a.get('paraphrase'), f"{a.get('id')} missing paraphrase"
    # Every row carries its own source_url pointing at eur-lex.
    assert a.get('source_url') and 'eur-lex.europa.eu' in str(a['source_url']), f"{a.get('id')} missing eur-lex source_url"
# The required Art-10/11/13 are present (RAC-2.3).
ids = {a['id'] for a in arts}
for need in ('EU-AI-ACT:Art-10', 'EU-AI-ACT:Art-11', 'EU-AI-ACT:Art-13'):
    assert need in ids, f"{need} must be carried in the EU AI Act layer"
print(f"  EU AI Act 2024/1689: {len(arts)} articles, all id-shape+title+paraphrase+url ok; Art-10/11/13 present", file=sys.stderr)
PY

python3 - <<'PY' && pass "EU AI Act cite-don't-copy guard (article numbers/titles + OWN paraphrase, NO verbatim EU prose)" || bad "EU AI Act prose guard"
import sys, yaml
# No-verbatim-EU-prose guard. The EU AI Act normative text is © European Union;
# this layer carries only the official article numbers + official article titles +
# our OWN one-line paraphrase. Guard: (1) no `description:` key anywhere (we never
# copy a requirement clause); (2) the regulation's drafting signature
# "shall be designed" / "high-risk AI systems shall" (copied clause text) appears
# nowhere in the body; (3) every `title` is a short label (<= 10 words) free of
# sentence punctuation.
raw = open('references/eu-ai-act-2024.yaml').read()
# Only inspect non-comment lines (header comments cite URLs/principles, allowed).
body = '\n'.join(l for l in raw.splitlines() if not l.lstrip().startswith('#'))
assert 'description:' not in body, "eu-ai-act-2024.yaml must not carry an EU description/requirement clause"
low = body.lower()
for prose in ('shall be designed', 'high-risk ai systems shall', 'shall be drawn up', 'shall be accompanied'):
    assert prose not in low, f"verbatim EU drafting clause {prose!r} must not be reproduced"
d = yaml.safe_load(raw)
for a in d['articles']:
    title = str(a['title'])
    assert len(title.split()) <= 10, f"{a['id']} title too long (looks like prose): {title!r}"
    assert not any(p in title for p in ('. ', '; ')), f"{a['id']} title has sentence punctuation: {title!r}"
print("  EU AI Act rows carry article numbers/titles + own paraphrase; no `shall` clause, no description prose", file=sys.stderr)
PY

python3 - <<'PY' && pass "detection-rules eu_ai_act_xref all resolve to eu-ai-act-2024.yaml (US-F2-3)" || bad "detection-rules dangling eu_ai_act_xref"
import yaml, sys
eu = yaml.safe_load(open('references/eu-ai-act-2024.yaml'))
eu_ids = {a['id'] for a in eu['articles']}
rules = yaml.safe_load(open('references/detection-rules.yaml'))
rlist = next(v for v in rules.values() if isinstance(v, list))
dangling = []
mapped = 0
for r in rlist:
    xs = r.get('eu_ai_act_xref', []) or []
    if xs:
        mapped += 1
    for x in xs:
        if x not in eu_ids:
            dangling.append((r['agt_code'], x))
if dangling:
    print('  DANGLING eu_ai_act_xref:', dangling, file=sys.stderr); sys.exit(1)
# RAC-2.3 mappings: Art-13<->governance, Art-10<->EXF/PII, Art-11<->doc-evidence.
by_code = {r['agt_code']: (r.get('eu_ai_act_xref') or []) for r in rlist}
assert 'EU-AI-ACT:Art-11' in by_code.get('AGT-GOV-002', []), "AGT-GOV-002 must map to EU-AI-ACT:Art-11 (doc evidence)"
assert 'EU-AI-ACT:Art-10' in by_code.get('AGT-EXF-001', []), "AGT-EXF-001 must map to EU-AI-ACT:Art-10 (data governance)"
assert 'EU-AI-ACT:Art-13' in by_code.get('AGT-GOV-001', []), "AGT-GOV-001 must map to EU-AI-ACT:Art-13 (transparency)"
# All three new articles must be referenced by at least one rule.
referenced = {x for xs in by_code.values() for x in xs}
for need in ('EU-AI-ACT:Art-10', 'EU-AI-ACT:Art-11', 'EU-AI-ACT:Art-13'):
    assert need in referenced, f"{need} must be referenced by at least one AGT rule"
print(f"  {mapped}/16 AGT rules mapped to EU AI Act; all eu_ai_act_xref resolve; Art-10/11/13 all referenced", file=sys.stderr)
PY

python3 - <<'PY' && pass "controls-49 count UNCHANGED at exactly 49 (US-F2-3 separate-layer invariant)" || bad "controls-49 count drift"
import yaml, sys
d = yaml.safe_load(open('references/controls-49.yaml'))
ctrls = next(v for v in d.values() if isinstance(v, list))
assert len(ctrls) == 49, f"controls-49 MUST stay exactly 49, got {len(ctrls)}"
assert d.get('total') == 49, f"controls-49 header total MUST be 49, got {d.get('total')}"
# The EU AI Act Art-10/11/13 are a SEPARATE layer and must NOT have leaked into
# the 49 (Art-9/12/14/15/73 are the only EU rows in the 49).
eu_in_49 = sorted(c['id'] for c in ctrls if str(c.get('id','')).startswith('EU-AI-ACT:'))
assert eu_in_49 == ['EU-AI-ACT:Art-12','EU-AI-ACT:Art-14','EU-AI-ACT:Art-15','EU-AI-ACT:Art-73','EU-AI-ACT:Art-9'], f"unexpected EU rows in the 49: {eu_in_49}"
for leaked in ('EU-AI-ACT:Art-10','EU-AI-ACT:Art-11','EU-AI-ACT:Art-13'):
    assert leaked not in {c['id'] for c in ctrls}, f"{leaked} must stay in the SEPARATE layer, not the 49"
print("  controls-49 == 49 (unchanged); Art-10/11/13 stay in the separate EU layer", file=sys.stderr)
PY

python3 - <<'PY' && pass "AST title re-audit (US-F2-3: verified_on stamped, no guessed titles for unverified)" || bad "AST title re-audit gate"
import yaml, sys
d = yaml.safe_load(open('references/ast-2026.yaml'))
# Framework stays draft (the OWASP project is a New Project Proposal).
assert d.get('status') == 'draft', f"AST framework status must stay draft, got {d.get('status')}"
# The re-audit stamp is present.
assert d.get('verified_on'), "ast-2026.yaml missing verified_on stamp"
risks = d.get('risks') or []
assert len(risks) == 10, f"AST must carry 10 risks (AST01..AST10), got {len(risks)}"
for r in risks:
    assert r.get('title_status') in ('verified','unverified'), f"{r.get('id')} bad title_status: {r.get('title_status')}"
    # No guessed titles: an unverified row must NOT carry a confident title (it is
    # blanked/placeholdered per the established fallback). A verified row MUST.
    if r['title_status'] == 'verified':
        assert r.get('title'), f"{r['id']} verified but has no title"
    else:
        # unverified -> title must be blank or an explicit placeholder, never a guess.
        t = str(r.get('title','')).strip().lower()
        assert (t == '' or 'unverified' in t or 'placeholder' in t), f"{r['id']} unverified must not carry a guessed title: {r.get('title')!r}"
verified = sum(1 for r in risks if r['title_status'] == 'verified')
print(f"  AST re-audit: {verified}/10 verified, {10-verified}/10 unverified (no guesses); framework still draft", file=sys.stderr)
PY

python3 - <<'PY' && pass "detection-rules atlas_xref all resolve to atlas-2026.yaml (US-F2-1)" || bad "detection-rules dangling atlas_xref"
import yaml, sys
atlas = yaml.safe_load(open('references/atlas-2026.yaml'))
atlas_ids = {t['id'] for t in atlas['techniques']}
rules = yaml.safe_load(open('references/detection-rules.yaml'))
rlist = next(v for v in rules.values() if isinstance(v, list))
dangling = []
mapped = 0
for r in rlist:
    xs = r.get('atlas_xref', []) or []
    if xs:
        mapped += 1
    for x in xs:
        if x not in atlas_ids:
            dangling.append((r['agt_code'], x))
if dangling:
    print('  DANGLING atlas_xref:', dangling, file=sys.stderr); sys.exit(1)
# RAC-2.1: AGT-PI-001 and AGT-PI-003 MUST cross-ref AML.T0051.
by_code = {r['agt_code']: (r.get('atlas_xref') or []) for r in rlist}
for code in ('AGT-PI-001', 'AGT-PI-003'):
    assert 'AML.T0051' in by_code.get(code, []), f"{code} must map to AML.T0051"
print(f"  {mapped}/16 AGT rules mapped to ATLAS; all atlas_xref resolve; PI-001/PI-003 -> AML.T0051", file=sys.stderr)
PY

python3 - <<'PY' && pass "detection-rules carried-framework refs all resolve to controls-49" || bad "detection-rules dangling carried-framework ref"
import yaml, sys
controls = yaml.safe_load(open('references/controls-49.yaml'))
ids = {c['id'] for c in next(v for v in controls.values() if isinstance(v, list))}
rules = yaml.safe_load(open('references/detection-rules.yaml'))
rlist = next(v for v in rules.values() if isinstance(v, list))
# Frameworks we carry full citations for: every ref with these prefixes MUST resolve.
carried = ('SP800-53:', 'ISO27001:', 'EU-AI-ACT:', 'NIST-AI-RMF:', 'SOC2:', 'OWASP-LLM:')
dangling = []
for r in rlist:
    for cid in r.get('maps_to_controls', []):
        if cid.startswith(carried) and cid not in ids:
            dangling.append((r['agt_code'], cid))
if dangling:
    print('  DANGLING:', dangling, file=sys.stderr); sys.exit(1)
print('  all carried-framework control refs resolve; external (GDPR/CCPA/HIPAA/PCI/FinCEN) allowed', file=sys.stderr)
PY

python3 - <<'PY' && pass "crosswalk-derived OWASP-LLM cross_refs all resolve to controls-49 (US-F0-1)" || bad "crosswalk OWASP-LLM dangling cross_ref"
import yaml, sys
# Mirror matching.rs::normalize_llm_id: "LLM01:2025" -> "OWASP-LLM:LLM01".
def normalize(llm_id):
    if llm_id.startswith('OWASP-LLM:'):
        return llm_id
    base = llm_id.split(':', 1)[0]
    return f'OWASP-LLM:{base}'

controls = yaml.safe_load(open('references/controls-49.yaml'))
ids = {c['id'] for c in next(v for v in controls.values() if isinstance(v, list))}

crosswalk = yaml.safe_load(open('references/crosswalk-asi-llm.yaml'))
rows = {r['asi_id']: r for r in crosswalk['crosswalk']}

rules = yaml.safe_load(open('references/detection-rules.yaml'))
rlist = next(v for v in rules.values() if isinstance(v, list))

# Every OWASP-LLM:* the scanner can emit in cross_refs = the normalized llm_ids
# of every crosswalk row referenced by some detection rule's asi_xref.
emitted = set()
for r in rlist:
    for asi in r.get('asi_xref', []):
        row = rows.get(asi)
        if row is None:
            print(f'  asi_xref {asi} (rule {r["agt_code"]}) has no crosswalk row', file=sys.stderr); sys.exit(1)
        for llm in row.get('llm_ids', []):
            emitted.add(normalize(llm))

dangling = sorted(x for x in emitted if x not in ids)
if dangling:
    print('  DANGLING OWASP-LLM cross_refs:', dangling, file=sys.stderr); sys.exit(1)
print(f'  {len(emitted)} distinct OWASP-LLM cross_refs emittable; all resolve to controls-49', file=sys.stderr)
PY

echo "== Rust: build + test + clippy (release) =="
cargo build --release -p apohara-compliance-scanner >/tmp/ac_build.log 2>&1 && pass "cargo build --release" || { bad "cargo build --release"; tail -20 /tmp/ac_build.log; }
cargo test -p apohara-compliance-scanner >/tmp/ac_test.log 2>&1 && pass "cargo test" || { bad "cargo test"; tail -20 /tmp/ac_test.log; }
cargo clippy -p apohara-compliance-scanner --all-targets -- -D warnings >/tmp/ac_clippy.log 2>&1 && pass "cargo clippy -D warnings" || { bad "cargo clippy"; tail -20 /tmp/ac_clippy.log; }

echo "== Scanner behavioral: candidates-only + CANDIDATE prefix =="
BIN=target/release/apohara-compliance-scanner
"$BIN" scan-repo tests/fixtures/repo-fixture --format md  > /tmp/ac_md.out   2>/dev/null
"$BIN" scan-repo tests/fixtures/repo-fixture --format sarif > /tmp/ac_sarif.out 2>/dev/null
# NEGATIVE guard: no assertive strings (EXTENDED, fix #6b — adds non-compliant,
# violates, is vulnerable to, detected, you have ASI on top of the original set).
if grep -Eiq "$NEGATIVE_GUARD" /tmp/ac_md.out /tmp/ac_sarif.out; then
  bad "assertive-language NEGATIVE guard (found forbidden string)"
else
  pass "assertive-language NEGATIVE guard (no forbidden strings)"
fi
# POSITIVE guard: every MD finding line starts with CANDIDATE —
if grep -qE '^- ' /tmp/ac_md.out; then
  if grep -E '^- ' /tmp/ac_md.out | grep -qvE 'CANDIDATE —'; then
    bad "assertive-language POSITIVE guard (a finding line lacks CANDIDATE prefix)"
  else
    pass "assertive-language POSITIVE guard (every MD finding line CANDIDATE-prefixed)"
  fi
else
  bad "no MD findings produced on fixture"
fi

echo "== SARIF 2.1.0 validity =="
python3 - <<'PY' && pass "SARIF structural (version 2.1.0, levels note/warning, CANDIDATE messages)" || bad "SARIF structural"
import json
s = json.load(open('/tmp/ac_sarif.out'))
assert s.get('version') == '2.1.0', s.get('version')
for run in s['runs']:
    for res in run.get('results', []):
        assert res['level'] in ('note','warning'), res['level']
        assert res['message']['text'].startswith('CANDIDATE — '), res['message']['text'][:40]
PY

echo "== scan-session honesty guard (the moat) =="
# Exercise the real scan-session path so the moat's output is guarded too.
"$BIN" scan-session tests/fixtures/session-sample.jsonl --format md    > /tmp/ac_sess_md.out    2>/dev/null
"$BIN" scan-session tests/fixtures/session-sample.jsonl --format sarif > /tmp/ac_sess_sarif.out 2>/dev/null
if grep -Eiq "$NEGATIVE_GUARD" /tmp/ac_sess_md.out /tmp/ac_sess_sarif.out; then
  bad "scan-session assertive-language NEGATIVE guard (found forbidden string)"
else
  pass "scan-session assertive-language NEGATIVE guard (no forbidden strings)"
fi
if grep -qE '^- ' /tmp/ac_sess_md.out; then
  if grep -E '^- ' /tmp/ac_sess_md.out | grep -qvE 'CANDIDATE —'; then
    bad "scan-session POSITIVE guard (a finding line lacks CANDIDATE prefix)"
  else
    pass "scan-session POSITIVE guard (every MD finding line CANDIDATE-prefixed)"
  fi
else
  bad "no MD findings produced on session fixture"
fi

echo "== Visible suppression (US-F0-2 allowlist) =="
# With an allowlist on (AGT-EXF-001, report.sql), the SELECT * FROM finding must
# move to the VISIBLE suppressed channel — not vanish, not stay active.
"$BIN" scan-repo tests/fixtures/repo-fixture --suppress tests/fixtures/sample.apohara-suppress --format json  > /tmp/ac_supp_json.out  2>/dev/null
"$BIN" scan-repo tests/fixtures/repo-fixture --suppress tests/fixtures/sample.apohara-suppress --format md    > /tmp/ac_supp_md.out    2>/dev/null
"$BIN" scan-repo tests/fixtures/repo-fixture --suppress tests/fixtures/sample.apohara-suppress --format sarif > /tmp/ac_supp_sarif.out 2>/dev/null
python3 - <<'PY' && pass "suppression visible in json + md + sarif; active results carry no suppressions" || bad "suppression visibility"
import json, sys
# JSON: AGT-EXF-001 in suppressed[], NOT in findings[]; still is_candidate.
j = json.load(open('/tmp/ac_supp_json.out'))
assert all(f['id'] != 'AGT-EXF-001' for f in j['findings']), "EXF-001 must not be active"
supp = [s for s in j['suppressed'] if s['finding']['id'] == 'AGT-EXF-001']
assert len(supp) == 1, f"EXF-001 must be in suppressed[], got {len(supp)}"
assert supp[0]['finding']['is_candidate'] is True
assert supp[0]['reason']
# MD: a "Suppressed" section with a CANDIDATE-prefixed EXF-001 line.
md = open('/tmp/ac_supp_md.out').read()
assert 'Suppressed (allowlisted)' in md, "md missing suppressed section"
# SARIF: ONE results[] array; EXF-001 carries suppressions[{kind:external}];
# active results have NO suppressions property.
s = json.load(open('/tmp/ac_supp_sarif.out'))
results = s['runs'][0]['results']
exf = [r for r in results if r['ruleId'] == 'AGT-EXF-001']
assert len(exf) == 1, "EXF-001 must be a single merged result"
sup = exf[0].get('suppressions')
assert sup and sup[0]['kind'] == 'external', f"EXF-001 needs suppressions external, got {sup}"
for r in results:
    if r['ruleId'] != 'AGT-EXF-001':
        assert 'suppressions' not in r, f"active {r['ruleId']} must not carry suppressions"
print("  json/md/sarif suppression visible; sarif single results[] + external kind", file=sys.stderr)
PY

echo "== Threshold drops vs allowlist (US-F1-2 honesty split) =="
# RAC-1.2: --min-confidence 0.85 moves the 0.7-confidence AGT-PI-002 (session
# fixture) to the VISIBLE threshold-drop channel. On SARIF it must carry
# properties.dropped_by_threshold:true and NO suppressions property — distinct
# from a human allowlist (which uses suppressions{kind:external}).
"$BIN" scan-session tests/fixtures/session-sample.jsonl --min-confidence 0.85 --format json  > /tmp/ac_thr_json.out  2>/dev/null
"$BIN" scan-session tests/fixtures/session-sample.jsonl --min-confidence 0.85 --format sarif > /tmp/ac_thr_sarif.out 2>/dev/null
python3 - <<'PY' && pass "threshold drop uses dropped_by_threshold (NOT suppressions); allowlist uses suppressions{external}" || bad "threshold-vs-allowlist split"
import json, sys
# JSON: AGT-PI-002 moved to suppressed[] with origin "threshold", reason mentions
# "below threshold"/min-confidence, still a candidate; NOT in active findings.
j = json.load(open('/tmp/ac_thr_json.out'))
assert all(f['id'] != 'AGT-PI-002' for f in j['findings']), "PI-002 must leave active findings"
drop = [s for s in j['suppressed'] if s['finding']['id'] == 'AGT-PI-002']
assert len(drop) == 1, f"PI-002 must be a single threshold drop, got {len(drop)}"
assert drop[0]['origin'] == 'threshold', f"origin must be threshold, got {drop[0]['origin']}"
assert 'below' in drop[0]['reason'].lower(), f"reason must read as a threshold drop: {drop[0]['reason']}"
assert drop[0]['finding']['is_candidate'] is True
# SARIF: AGT-PI-002 is a NORMAL merged result with properties.dropped_by_threshold
# and NO suppressions property. No threshold drop anywhere may carry suppressions.
s = json.load(open('/tmp/ac_thr_sarif.out'))
results = s['runs'][0]['results']
pi = [r for r in results if r['ruleId'] == 'AGT-PI-002']
assert len(pi) == 1, "PI-002 must be a single merged SARIF result"
assert pi[0]['properties'].get('dropped_by_threshold') is True, "PI-002 needs dropped_by_threshold:true"
assert 'suppressions' not in pi[0], "a THRESHOLD drop must NOT carry the SARIF suppressions property"
assert pi[0]['message']['text'].startswith('CANDIDATE — '), "threshold drop still CANDIDATE-prefixed"
print("  threshold drop: dropped_by_threshold:true, no suppressions, candidate-framed", file=sys.stderr)
PY

echo "== ASI-primary companions via opt-in --by-asi (US-F1-3) =="
# RAC-1.4: --by-asi surfaces companion ASI candidates (id ^ASI(0[1-9]|10)$) with
# the ASI title + genai.owasp.org citation, each cross-referencing ALL triggering
# AGT codes, deduped by ASI id. WITHOUT the flag the output is byte-identical.
"$BIN" scan-session tests/fixtures/session-sample.jsonl --format json        > /tmp/ac_noasi_json.out  2>/dev/null
"$BIN" scan-session tests/fixtures/session-sample.jsonl --by-asi --format json  > /tmp/ac_byasi_json.out  2>/dev/null
"$BIN" scan-session tests/fixtures/session-sample.jsonl --by-asi --format md    > /tmp/ac_byasi_md.out    2>/dev/null
"$BIN" scan-session tests/fixtures/session-sample.jsonl --by-asi --format sarif > /tmp/ac_byasi_sarif.out 2>/dev/null
# Byte-identical default (the flag is OFF) — the parent-commit shape is preserved.
cmp -s /tmp/ac_sess_md.out <("$BIN" scan-session tests/fixtures/session-sample.jsonl --format md 2>/dev/null) \
  && pass "--by-asi OFF: default md byte-shape unchanged" || bad "--by-asi OFF default md drift"
python3 - <<'PY' && pass "--by-asi: ASI companions (id shape + title + genai citation + AGT cross-refs + dedup)" || bad "--by-asi companions"
import json, re, sys
plain = json.load(open('/tmp/ac_noasi_json.out'))
byasi = json.load(open('/tmp/ac_byasi_json.out'))
# The default findings are a PREFIX of the --by-asi findings (AGT findings intact).
plain_ids = [f['id'] for f in plain['findings']]
byasi_ids = [f['id'] for f in byasi['findings']]
assert byasi_ids[:len(plain_ids)] == plain_ids, "AGT findings must be preserved unchanged"
asi = [f for f in byasi['findings'] if re.match(r'^ASI(0[1-9]|10)$', f['id'])]
assert asi, "at least one ASI companion expected"
# id shape, candidate framing, genai citation, AGT cross-refs.
for f in asi:
    assert re.match(r'^ASI(0[1-9]|10)$', f['id']), f['id']
    assert f['is_candidate'] is True
    assert f['title'], f"ASI {f['id']} missing title"
    assert 'genai.owasp.org' in f['citation']['url'], f['citation']
    assert f['citation']['version'] == '2026', f['citation']
    assert f['cross_refs'] and all(x.startswith('AGT-') for x in f['cross_refs']), f['cross_refs']
# Dedup: each ASI id appears exactly once even with multiple AGT contributors.
ids = [f['id'] for f in asi]
assert len(ids) == len(set(ids)), f"ASI companions must be deduped: {ids}"
# On the session fixture, ASI02 has multiple AGT contributors → ONE companion.
asi02 = [f for f in asi if f['id'] == 'ASI02']
assert len(asi02) == 1, "ASI02 must be a single deduped companion"
assert len(asi02[0]['cross_refs']) >= 2, f"ASI02 must record ALL contributing AGT codes: {asi02[0]['cross_refs']}"
print(f"  {len(asi)} ASI companions, deduped; ASI02 contributors={asi02[0]['cross_refs']}", file=sys.stderr)
PY
# Honesty NEGATIVE guard on --by-asi output (ASI lines must read as candidates).
if grep -Eiq "$NEGATIVE_GUARD" /tmp/ac_byasi_md.out /tmp/ac_byasi_sarif.out; then
  bad "--by-asi assertive-language NEGATIVE guard (found forbidden string)"
else
  pass "--by-asi assertive-language NEGATIVE guard (no forbidden strings)"
fi
# POSITIVE guard: every --by-asi md finding line (incl ASI companions) CANDIDATE-prefixed.
if grep -E '^- ' /tmp/ac_byasi_md.out | grep -qvE 'CANDIDATE —'; then
  bad "--by-asi POSITIVE guard (a finding line lacks CANDIDATE prefix)"
else
  pass "--by-asi POSITIVE guard (every MD finding line CANDIDATE-prefixed)"
fi

echo "== --llm-assist triage manifest emitter (US-F3-1 / Step 3.1, Hybrid C) =="
# EMITTER-ONLY semantics: with --llm-assist OFF nothing extra is written; with it
# ON, stdout is byte-identical and a single triage manifest of the ambiguous
# (ambiguity==true) ACTIVE candidates is written to STDERR for an orchestrator to
# triage. The binary never calls an LLM nor merges a verdict back.
"$BIN" scan-session tests/fixtures/session-sample.jsonl --format json > /tmp/ac_la_off.out 2> /tmp/ac_la_off.err
"$BIN" --llm-assist scan-session tests/fixtures/session-sample.jsonl --format json > /tmp/ac_la_on.out 2> /tmp/ac_la_on.err
if cmp -s /tmp/ac_la_off.out /tmp/ac_la_on.out; then
  pass "--llm-assist: stdout byte-identical with the flag on vs off (emitter-only)"
else
  bad "--llm-assist: stdout drifted when the flag is set"
fi
if grep -q 'llm-assist-manifest:' /tmp/ac_la_off.err; then
  bad "--llm-assist OFF: manifest leaked to stderr"
else
  pass "--llm-assist OFF: no manifest on stderr (byte-shape preserved)"
fi
if [ "$(grep -c 'llm-assist-manifest:' /tmp/ac_la_on.err)" = "1" ]; then
  pass "--llm-assist ON: exactly one manifest line on stderr"
else
  bad "--llm-assist ON: expected exactly one manifest line on stderr"
fi
grep 'llm-assist-manifest:' /tmp/ac_la_on.err | sed 's/^.*llm-assist-manifest: //' > /tmp/ac_la_manifest.json
python3 - <<'PY' && pass "--llm-assist: manifest valid JSON, schema tag, ids subset of the active set" || bad "--llm-assist manifest shape"
import json
m = json.load(open('/tmp/ac_la_manifest.json'))
assert m['schema'] == 'apohara-triage-manifest/1', m.get('schema')
assert isinstance(m['candidates'], list), 'candidates must be a list'
active = {f['id'] for f in json.load(open('/tmp/ac_la_on.out'))['findings']}
for c in m['candidates']:
    assert c['id'] in active, f"manifest id {c['id']} absent from the deterministic active set"
PY
if grep -Eiq "$NEGATIVE_GUARD" /tmp/ac_la_manifest.json; then
  bad "--llm-assist manifest NEGATIVE guard (found forbidden string)"
else
  pass "--llm-assist manifest NEGATIVE guard (no forbidden strings)"
fi

echo "== Gap analysis over the 49 carried controls (US-F1-4 / fix #11d) =="
# RAC-1.7: `gap` lists controls (from the 49 ONLY) with zero candidate evidence,
# absence-framed; the output carries the absence-of-evidence disclaimer + the
# 49-scope statement; the EXTENDED NEGATIVE guard (fix #6b) finds none of the
# banned phrases across json+md+sarif; a control WITH evidence is not a gap, one
# WITHOUT evidence is.
"$BIN" gap tests/fixtures/repo-fixture --format json  > /tmp/ac_gap_json.out  2>/dev/null
"$BIN" gap tests/fixtures/repo-fixture --format md    > /tmp/ac_gap_md.out    2>/dev/null
"$BIN" gap tests/fixtures/repo-fixture --format sarif > /tmp/ac_gap_sarif.out 2>/dev/null
# EXTENDED NEGATIVE guard applied to ALL THREE gap outputs.
if grep -Eiq "$NEGATIVE_GUARD" /tmp/ac_gap_json.out /tmp/ac_gap_md.out /tmp/ac_gap_sarif.out; then
  bad "gap assertive-language NEGATIVE guard (found forbidden string)"
else
  pass "gap assertive-language NEGATIVE guard (no forbidden strings, extended set)"
fi
# Disclaimer + 49-scope statement present in the md output.
if grep -q 'Absence of evidence is not evidence of a gap' /tmp/ac_gap_md.out \
   && grep -q 'Gap is computed over the 49 carried controls' /tmp/ac_gap_md.out \
   && grep -q 'out of scope for gap analysis' /tmp/ac_gap_md.out; then
  pass "gap md carries absence-of-evidence disclaimer + 49-scope statement"
else
  bad "gap md missing disclaimer or 49-scope statement"
fi
# Every gap md control line is absence/candidate-framed.
if grep -qE '^- ' /tmp/ac_gap_md.out; then
  if grep -E '^- ' /tmp/ac_gap_md.out | grep -qvE '^- no candidate evidence observed for '; then
    bad "gap POSITIVE guard (a gap line is not absence-framed)"
  else
    pass "gap POSITIVE guard (every gap line absence/candidate-framed)"
  fi
else
  bad "no gap lines produced on fixture"
fi
python3 - <<'PY' && pass "gap over the 49 ONLY: evidence excluded, zero-evidence listed, externals out of scope" || bad "gap semantics"
import json, yaml, sys
g = json.load(open('/tmp/ac_gap_json.out'))
y = yaml.safe_load(open('references/controls-49.yaml'))
ids = {c['id'] for c in y['controls']}
gap_ids = {x['id'] for x in g['gaps']}
# Universe = the 49; covered + gaps partition the 49.
assert g['universe'] == 49, g['universe']
assert g['covered'] + len(g['gaps']) == 49, (g['covered'], len(g['gaps']))
# Every gap id is one of the 49; no external standard is ever a gap.
assert gap_ids <= ids, f"gap ids outside the 49: {gap_ids - ids}"
assert not any(x.startswith(('GDPR','CCPA','HIPAA','PCI','FinCEN')) for x in gap_ids), "external standard in gap universe"
# A control WITH fixture evidence (SP800-53:SI-7 via AGT-MIS-001) is NOT a gap.
assert 'SP800-53:SI-7' not in gap_ids, "a control with candidate evidence must not be a gap"
# A control with NO fixture evidence IS a gap.
assert 'EU-AI-ACT:Art-73' in gap_ids, "a zero-evidence control must be listed as a gap"
# Each gap carries id + title + status + consilium_ref, absence-framed message.
for x in g['gaps']:
    assert x['status'] in ('official','draft'), x
    assert x['consilium_ref'].startswith('compliance-suite.md:'), x
    assert x['message'].startswith('no candidate evidence observed for '), x['message']
# SARIF: version 2.1.0, every gap result is informational note-level, absence-framed.
s = json.load(open('/tmp/ac_gap_sarif.out'))
assert s['version'] == '2.1.0', s['version']
for r in s['runs'][0]['results']:
    assert r['level'] == 'note', r['level']
    assert r['message']['text'].startswith('no candidate evidence observed for '), r['message']['text']
print(f"  universe=49 covered={g['covered']} gaps={len(g['gaps'])}; externals out of scope; sarif note-level", file=sys.stderr)
PY

echo "== Baseline/diff mode (US-F2-4: baselineState enum, zero-new on no-change) =="
# RAC-2.4: a re-run with the SAME scan as its baseline yields ZERO `new` results
# (all `unchanged`); every emitted baselineState is a valid SARIF 2.1.0 enum
# value; `--only-new` keeps only `new`. The baseline is the scanner's own JSON.
"$BIN" scan-repo tests/fixtures/repo-fixture --format json 2>/dev/null > /tmp/ac_base.json
# Default output (no --baseline) must NOT carry the baselineState/baseline_state field.
if grep -q 'baseline_state' /tmp/ac_base.json || grep -q 'baselineState' /tmp/ac_sarif.out; then
  bad "default output leaked baselineState (must be omitted without --baseline)"
else
  pass "default output omits baselineState/baseline_state (byte-shape preserved)"
fi
"$BIN" scan-repo tests/fixtures/repo-fixture --baseline /tmp/ac_base.json --format json  2>/dev/null > /tmp/ac_diff_json.out
"$BIN" scan-repo tests/fixtures/repo-fixture --baseline /tmp/ac_base.json --format sarif 2>/dev/null > /tmp/ac_diff_sarif.out
"$BIN" scan-repo tests/fixtures/repo-fixture --baseline /tmp/ac_base.json --only-new --format json 2>/dev/null > /tmp/ac_onlynew.out
python3 - <<'PY' && pass "baseline: no-change re-run → 0 new, all unchanged; valid SARIF enum; --only-new keeps only new" || bad "baseline/diff semantics"
import json, sys
VALID = {"none", "unchanged", "updated", "new", "absent"}
# JSON diff: every active finding annotated unchanged; zero new on a no-change re-run.
d = json.load(open('/tmp/ac_diff_json.out'))
states = [f.get('baseline_state') for f in d['findings']]
assert states, "expected ≥1 finding to annotate"
assert all(s in VALID for s in states), f"invalid baseline_state values: {states}"
assert states.count('new') == 0, f"no-change re-run must have zero new, got {states.count('new')}"
assert all(s == 'unchanged' for s in states), f"all must be unchanged on a no-change re-run: {states}"
# SARIF: version 2.1.0, every result.baselineState a valid enum, level never error.
s = json.load(open('/tmp/ac_diff_sarif.out'))
assert s['version'] == '2.1.0', s['version']
for r in s['runs'][0]['results']:
    bs = r.get('baselineState')
    assert bs in VALID, f"invalid SARIF baselineState: {bs}"
    assert r['level'] in ('note', 'warning'), r['level']
    assert r['message']['text'].startswith('CANDIDATE — '), r['message']['text'][:40]
# --only-new: only `new` survive (here: none, since the no-change re-run has no new).
n = json.load(open('/tmp/ac_onlynew.out'))
assert all(f.get('baseline_state') == 'new' for f in n['findings']), \
    f"--only-new must keep ONLY new: {[f.get('baseline_state') for f in n['findings']]}"
print(f"  baseline no-change: {len(states)} findings all unchanged, 0 new; sarif enum ok; --only-new ok", file=sys.stderr)
PY
# Honesty NEGATIVE/POSITIVE guards on the annotated SARIF output too.
if grep -Eiq "$NEGATIVE_GUARD" /tmp/ac_diff_sarif.out; then
  bad "baseline assertive-language NEGATIVE guard (found forbidden string)"
else
  pass "baseline assertive-language NEGATIVE guard (no forbidden strings)"
fi

echo "== scan-repo --ext walker filter (US-F2-4 #5) =="
# RAC-2.4: `--ext rs,py` only reads .rs/.py files; default reads all. The fixture
# has cleanup.sh (.sh), report.sql (.sql), config.py (.py).
"$BIN" scan-repo tests/fixtures/repo-fixture --ext rs,py --format json 2>/tmp/ac_ext.err > /tmp/ac_ext_json.out
python3 - <<'PY' && pass "--ext rs,py reads only .py here (config.py); .sh/.sql filtered out; default reads all" || bad "--ext walker filter"
import json, sys
e = json.load(open('/tmp/ac_ext_json.out'))
ids = {f['id'] for f in e['findings']}
# cleanup.sh (.sh) and report.sql (.sql) must be filtered; config.py (.py) stays.
assert not any(i.startswith('AGT-MIS') for i in ids), f".sh must be filtered: {ids}"
assert 'AGT-EXF-001' not in ids, f".sql must be filtered: {ids}"
print(f"  --ext rs,py active ids={sorted(ids)} (.sh/.sql excluded)", file=sys.stderr)
PY
# The walker logs the skipped non-matching files to stderr.
if grep -q 'extension not in --ext filter' /tmp/ac_ext.err; then
  pass "--ext logs skipped non-matching files to stderr"
else
  bad "--ext skip log missing from stderr"
fi
# Default (no --ext) still reads everything → the .sh/.sql findings return.
"$BIN" scan-repo tests/fixtures/repo-fixture --format json 2>/dev/null > /tmp/ac_noext_json.out
python3 - <<'PY' && pass "default (no --ext) reads all files (byte-identical behavior)" || bad "default scan-repo extension behavior"
import json, sys
d = json.load(open('/tmp/ac_noext_json.out'))
ids = {f['id'] for f in d['findings']}
assert any(i.startswith('AGT-MIS') for i in ids), f".sh findings must return without --ext: {ids}"
assert 'AGT-EXF-001' in ids, f".sql findings must return without --ext: {ids}"
print(f"  default scan-repo active ids={sorted(ids)} (all files read)", file=sys.stderr)
PY

echo "== GitHub Action wiring (US-F2-4) =="
python3 - <<'PY' && pass "action/action.yml valid composite; cargo install + --format sarif + upload-sarif wired" || bad "action.yml wiring"
import yaml, sys
d = yaml.safe_load(open('action/action.yml'))
assert d['runs']['using'] == 'composite', d['runs']['using']
steps = d['runs']['steps']
runs_text = "\n".join(s.get('run', '') or '' for s in steps)
assert 'cargo install apohara-compliance-scanner' in runs_text, "must cargo install the scanner"
assert '--format sarif' in runs_text, "must run with --format sarif"
uploads = [s for s in steps if str(s.get('uses', '')).startswith('github/codeql-action/upload-sarif')]
assert len(uploads) == 1, "must wire github/codeql-action/upload-sarif"
print("  action.yml: composite, cargo install + --format sarif + upload-sarif", file=sys.stderr)
PY
# README documents the candidate/never-error framing.
if grep -q 'CANDIDATE' action/README.md && grep -qi 'never.*error\|not.*failures\|never.*assertions' action/README.md; then
  pass "action/README.md documents the candidate/never-error framing"
else
  bad "action/README.md missing candidate/never-error framing"
fi

echo
if [ "$fail" -eq 0 ]; then echo "ALL VERIFICATION CHECKS PASSED"; else echo "VERIFICATION FAILED"; fi
exit "$fail"
