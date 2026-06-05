# apohara-compliance — demo script (re-recordable)

This is a **re-recordable terminal walkthrough**, not a recorded asset. The
published asciinema cast / GIF is deferred to **end-of-Fase-1** (after the
regex + context detection engine and the precision lift), so the hero shows the
**tuned** scanner rather than today's noisier substring matcher. Until then,
this script is the source of truth: an operator can run it verbatim and record
it later.

> **Honesty (carried from the README and SKILL):** every line of output below
> is a **CANDIDATE** for a human to review — never a verdict, an attestation, or
> an audit conclusion. The narration says "candidate to review", never any
> assertion of compliance. A false positive here is a "please confirm", not a
> wrong answer.

## What this demo shows

The moat is `scan-session`: it audits **what a coding agent actually *did*** (its
session transcript — `Bash` commands, file reads/writes), and maps those
observed actions to the **OWASP Top 10 for Agentic Applications (2026)** plus a
cross-referenced control set (NIST SP 800-53, SOC 2, ISO 27001, EU AI Act,
OWASP LLM Top 10 2025). `scan-repo` does the same for a repository's contents.
Every finding carries a citation (framework ID + version + URL) and the exact
triggering signal.

This is **v0.1**. Scanner precision is still improving — Fase 1 adds
word-boundary + context rules to cut false positives. The demo deliberately uses
small, sanitized fixtures so the output is stable and reproducible.

## Recording with asciinema (intended recorder)

The intended recorder is [asciinema](https://asciinema.org/). When the time
comes (end-of-Fase-1, against the tuned engine), record the exact commands in
the steps below:

```sh
# Start a cast; run the steps; press Ctrl-D (or `exit`) to stop.
asciinema rec apohara-compliance-demo.cast

# Optional: convert the cast to a GIF for the README hero (Step 1.6).
# e.g. `agg apohara-compliance-demo.cast apohara-compliance-demo.gif`
```

Keep the recording short: build once off-camera (it's slow and uninteresting),
then record only Steps 2–4.

---

## Step 1 — Build the scanner from source

The lowest-trust-assumption path: compile the deterministic scanner on your own
machine. (Do this off-camera when recording — only the result matters.)

```sh
cargo build --release
```

The binary lands at `target/release/apohara-compliance-scanner`. The rest of this
script invokes it as `./target/release/apohara-compliance-scanner` from the repo
root. On the steady-state install path (`cargo install
apohara-compliance-scanner`) you'd just call `apohara-compliance-scanner`, and
its build-time-embedded rules are the normal source (`rules_source:
embedded-fallback` — expected, not an anomaly).

## Step 2 — `scan-session`: map an agent's actions to candidates (the moat)

Point `scan-session` at an AI coding-agent session transcript (newline-delimited JSON,
normally under `~/.claude/projects/**/*.jsonl`). Here we use the sanitized
fixture `tests/fixtures/session-sample.jsonl`, which contains a handful of tool
calls an agent "performed".

```sh
./target/release/apohara-compliance-scanner \
  scan-session tests/fixtures/session-sample.jsonl --format md
```

### Expected output (captured from the real binary)

The report goes to **stdout**; diagnostics (which `rules_source` resolved, which
transcript objects were skipped and why, the session `version`/`gitBranch`/`cwd`
evidence) go to **stderr**, so the report stays cleanly pipeable.

```markdown
# apohara-compliance — candidate findings

_Guidance/mapping only — these are CANDIDATES for review, not assertions of compliance, certification, or audit conclusions._

**Rules source:** `embedded-fallback` · **Findings:** 5 · **Suppressed:** 0

## Findings

- CANDIDATE — **AGT-MIS-001** Destructive Tool Invocation — status: `official`, confidence: 0.90
  - triggering_signal: `rm -rf`
  - suggested_controls: SP800-53:SI-7, EU-AI-ACT:Art-9, ISO27001:A.12.1
  - cross_refs: ASI02, ASI05, OWASP-LLM:LLM06, OWASP-LLM:LLM01, OWASP-LLM:LLM05
  - citation: <https://doi.org/10.6028/NIST.SP.800-53r5> (version Rev 5)
- CANDIDATE — **AGT-MIS-002** Privilege Escalation Attempt — status: `official`, confidence: 0.90
  - triggering_signal: `sudo`
  - suggested_controls: SP800-53:AC-6, SOC2:CC6.1, EU-AI-ACT:Art-14
  - cross_refs: ASI03, OWASP-LLM:LLM01, OWASP-LLM:LLM06, OWASP-LLM:LLM02
  - citation: <https://doi.org/10.6028/NIST.SP.800-53r5> (version Rev 5)
- CANDIDATE — **AGT-EXF-002** Unauthorized Outbound Network Call — status: `official`, confidence: 0.90
  - triggering_signal: `curl http`
  - suggested_controls: SP800-53:SC-7, SOC2:CC6.6, ISO27001:A.8.16, OWASP-LLM:LLM02
  - cross_refs: ASI02, ASI04, OWASP-LLM:LLM06, OWASP-LLM:LLM03
  - citation: <https://doi.org/10.6028/NIST.SP.800-53r5> (version Rev 5)
- CANDIDATE — **AGT-EXF-001** Database Dump Request — status: `official`, confidence: 0.90
  - triggering_signal: `SELECT * FROM`
  - suggested_controls: SP800-53:AC-3, SOC2:CC6.1, GDPR:Art-32, OWASP-LLM:LLM02
  - cross_refs: ASI02, ASI03, OWASP-LLM:LLM06, OWASP-LLM:LLM01, OWASP-LLM:LLM02
  - citation: <https://doi.org/10.6028/NIST.SP.800-53r5> (version Rev 5)
- CANDIDATE — **AGT-PI-002** Roleplay Persona Manipulation — status: `draft`, confidence: 0.70
  - triggering_signal: `act as`
  - suggested_controls: OWASP-LLM:LLM01, NIST-AI-RMF:AGENTIC-MAP-PROMPT-SURFACE, EU-AI-ACT:Art-9
  - cross_refs: ASI01, OWASP-LLM:LLM01, OWASP-LLM:LLM06
  - citation: <https://genai.owasp.org/llm-top-10/> (version 2025)
```

### What to narrate

- Each line is **`CANDIDATE — `** prefixed (the em dash). Nothing here asserts
  compliance.
- The agent *did* something (e.g. ran `sudo rm -rf`, a `SELECT * FROM`, a `curl
  http`); the scanner maps that observed **action** to an `AGT-*` rule, then to
  OWASP Agentic (`ASI*`) cross-refs and concrete suggested controls, each with a
  **citation** (URL + version).
- Read `status`: `AGT-PI-002` is `status: draft` (lower confidence, 0.70) — a
  draft control is never presented as settled guidance.
- The chain `signal → AGT rule → mapped control → published source` is the audit
  trail to preserve when summarizing.

> **Honesty caveat (v0.1):** today's matcher is substring-based, so signals like
> `act as` can over-fire. That is exactly why the published GIF waits for
> Fase 1's context engine. Present borderline candidates as "please confirm".

## Step 3 — `scan-repo` with SARIF output (→ CI code scanning)

The same engine over a repository's contents. SARIF 2.1.0 is ingestible by CI /
code-scanning UIs (e.g. GitHub code scanning), so candidate findings can surface
in a pull request. The walker respects `.gitignore`.

```sh
./target/release/apohara-compliance-scanner \
  scan-repo tests/fixtures/repo-fixture --format sarif
```

### Expected output (shape; captured from the real binary)

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "properties": { "rules_source": "embedded-fallback" },
      "results": [
        {
          "level": "warning",
          "message": {
            "text": "CANDIDATE — Database Dump Request (signal: SELECT * FROM). Review suggested control(s): SP800-53:AC-3, SOC2:CC6.1, GDPR:Art-32, OWASP-LLM:LLM02. Source provenance: official."
          },
          "properties": {
            "citation": { "url": "https://doi.org/10.6028/NIST.SP.800-53r5", "version": "Rev 5" },
            "confidence": 0.8999999761581421,
            "is_candidate": true,
            "status": "official"
          },
          "ruleId": "AGT-EXF-001"
        }
        // … further results for AGT-EXF-002 (curl http), AGT-MIS-001 (rm -rf),
        //    AGT-MIS-002 (sudo) — four findings total on this fixture.
      ]
    }
  ]
}
```

### What to narrate

- Every `result.message.text` is **`CANDIDATE — `** prefixed and `level` is
  `note` or `warning` — **never `error`** — so a CI surface cannot misread a
  candidate as a failing assertion.
- `is_candidate: true` is structural in every result.
- `secret.env` in the fixture trips signals too, but it is `.gitignore`d, so the
  walker skips it and it produces **no** finding — proving gitignore-respect.

To pipe SARIF into a file for upload, use stdout (diagnostics stay on stderr):

```sh
./target/release/apohara-compliance-scanner \
  scan-repo tests/fixtures/repo-fixture --format sarif > apohara.sarif
```

## Step 4 — Suppression flow with `.apohara-suppress` (visible, never dropped)

An operator can allowlist a known candidate. Critically, a suppressed candidate
is **never dropped** — it moves to a **visible** `suppressed` channel and stays
`is_candidate: true`. The sample allowlist
`tests/fixtures/sample.apohara-suppress` allowlists the `AGT-EXF-001`
(`SELECT * FROM`) hit in `report.sql`:

```text
AGT-EXF-001:SELECT * FROM:repo-file:*report.sql   # known scan-repo test fixture
```

Run the same `scan-repo`, now with `--suppress`:

```sh
./target/release/apohara-compliance-scanner \
  scan-repo tests/fixtures/repo-fixture --format md \
  --suppress tests/fixtures/sample.apohara-suppress
```

### Expected output (captured from the real binary)

```markdown
# apohara-compliance — candidate findings

_Guidance/mapping only — these are CANDIDATES for review, not assertions of compliance, certification, or audit conclusions._

**Rules source:** `embedded-fallback` · **Findings:** 3 · **Suppressed:** 1

## Findings

- CANDIDATE — **AGT-EXF-002** Unauthorized Outbound Network Call — status: `official`, confidence: 0.90
  - triggering_signal: `curl http`
  - suggested_controls: SP800-53:SC-7, SOC2:CC6.6, ISO27001:A.8.16, OWASP-LLM:LLM02
  - cross_refs: ASI02, ASI04, OWASP-LLM:LLM06, OWASP-LLM:LLM03
  - citation: <https://doi.org/10.6028/NIST.SP.800-53r5> (version Rev 5)
- CANDIDATE — **AGT-MIS-001** Destructive Tool Invocation — status: `official`, confidence: 0.90
  - triggering_signal: `rm -rf`
  - suggested_controls: SP800-53:SI-7, EU-AI-ACT:Art-9, ISO27001:A.12.1
  - cross_refs: ASI02, ASI05, OWASP-LLM:LLM06, OWASP-LLM:LLM01, OWASP-LLM:LLM05
  - citation: <https://doi.org/10.6028/NIST.SP.800-53r5> (version Rev 5)
- CANDIDATE — **AGT-MIS-002** Privilege Escalation Attempt — status: `official`, confidence: 0.90
  - triggering_signal: `sudo`
  - suggested_controls: SP800-53:AC-6, SOC2:CC6.1, EU-AI-ACT:Art-14
  - cross_refs: ASI03, OWASP-LLM:LLM01, OWASP-LLM:LLM06, OWASP-LLM:LLM02
  - citation: <https://doi.org/10.6028/NIST.SP.800-53r5> (version Rev 5)

## Suppressed (allowlisted)

_These candidates were moved here by your allowlist — not dropped. They remain CANDIDATES for review._

- CANDIDATE — **AGT-EXF-001** Database Dump Request — status: `official`, confidence: 0.90
  - triggering_signal: `SELECT * FROM`
  - suggested_controls: SP800-53:AC-3, SOC2:CC6.1, GDPR:Art-32, OWASP-LLM:LLM02
  - cross_refs: ASI02, ASI03, OWASP-LLM:LLM06, OWASP-LLM:LLM01, OWASP-LLM:LLM02
  - citation: <https://doi.org/10.6028/NIST.SP.800-53r5> (version Rev 5)
  - suppressed: known scan-repo test fixture (by `AGT-EXF-001:SELECT * FROM:repo-file:*report.sql`)
```

### What to narrate

- `AGT-EXF-001` moved out of **Findings** and into the **Suppressed
  (allowlisted)** section — it did not vanish. The header counts reflect it:
  **Findings: 3 · Suppressed: 1**.
- The suppressed line records the human justification (`known scan-repo test
  fixture`) and the matching allowlist rule, preserving the audit trail.
- In SARIF, the same candidate stays in a single `results[]` array carrying
  `result.suppressions[{ "kind": "external" }]` — visible to a code-scanning UI,
  not deleted. It is still `is_candidate: true`.

---

## Reproducibility checklist

The captured outputs above are from a real run of the release binary against the
committed fixtures (`tests/fixtures/session-sample.jsonl`,
`tests/fixtures/repo-fixture/`, `tests/fixtures/sample.apohara-suppress`). To
re-verify before recording:

```sh
cargo build --release
./target/release/apohara-compliance-scanner scan-session tests/fixtures/session-sample.jsonl --format md
./target/release/apohara-compliance-scanner scan-repo    tests/fixtures/repo-fixture       --format sarif
./target/release/apohara-compliance-scanner scan-repo    tests/fixtures/repo-fixture       --format md --suppress tests/fixtures/sample.apohara-suppress
```

If the matcher changes (e.g. the Fase-1 context engine), re-capture the
"Expected output" blocks before recording the asciinema cast.
