# Adoption metrics (US-F3-3 / Step 3.3)

How adoption of `apohara-compliance` is tracked — **privacy-respecting and
out-of-band**. The scanner is an offline, lowest-trust-assumption tool: it reads
transcripts and repositories from disk and **phones nothing home**. Adoption is
measured from public counters the maintainer reads manually; the binary itself
emits no telemetry and opens no network connection.

## Non-negotiable: no telemetry in the binary

The published crate has **no outbound-HTTP dependency and no network code** in
the core scan path. This is enforced, not merely promised:

- the dependency set is `serde`, `serde_norway`, `serde_json`, `clap`, `ignore`,
  `regex`, `toml` — none is an HTTP/async-network client;
- `scripts/verify.sh` greps `Cargo.toml` and `crates/scanner/src/` for
  `reqwest|ureq|hyper|isahc|surf|attohttpc|std::net::|TcpStream` and fails the
  build on any match.

A tool whose whole thesis is surfacing the ASI04 / AST02 supply-chain and
exfiltration surface cannot itself open an unannounced socket. Adoption tracking
therefore stays entirely outside the binary.

## What is tracked, and how (all out-of-band)

| Signal | Source | How it is read (manually, by the maintainer) |
|--------|--------|------------------------------------------------|
| crates.io downloads | crates.io | `https://crates.io/api/v1/crates/apohara-compliance-scanner` (browser/`curl`), **not** the binary |
| GitHub Release download counts | GitHub Releases API | `gh api repos/SuarezPM/apohara-compliance/releases --jq '.[].assets[] | {name, download_count}'` |
| GitHub stars / forks | GitHub repo | `gh repo view SuarezPM/apohara-compliance --json stargazerCount,forkCount` |
| Precision/recall trend across releases | `references/validation-log.md` | recorded per release from the CI P/R gate (no user data) |

These are read on demand, off the user's machine, from public endpoints. None of
them is collected by the scanner, and none requires the user to opt into any
data collection.

## Optional, local-only counters

If a per-run local count is ever wanted, it must remain a **local, opt-in**
counter (e.g. an incrementing file the user owns) with **no network egress** —
consistent with the offline thesis. None ships today; this section records the
constraint so a future addition cannot quietly become telemetry.

## Honesty framing

Adoption numbers describe interest in the tool — never a claim about any user's
compliance posture. Every scanner finding remains a CANDIDATE for human review,
not an assertion; downloads and stars say nothing about whether any scanned
system meets any control.
