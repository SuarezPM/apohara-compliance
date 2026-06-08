# Open questions

Gated / deferred decisions tracked outside the ADRs. Each entry names the gate and the
trigger that closes it.

## Version badge (Pablo-gated)

`README.md:10` version badge = `version-1.1.0`. v1.4 + v2.0 + v2.1 are on `main` with no new
tag, so the badge lags the codebase. The badge tracks the last **release tag**, and
tagging/release is Pablo-gated — bump the badge to whatever tag v2.1 eventually cuts. No
badge edit lands until that tag exists.

## Real-positive trajectory trace (deferred — closes the UNPROVEN gap)

v2.1 closes the representation gap in the engine's vocabulary (structured `sink:` + generic markers
fire on a synthetic trajectory) but real-world efficacy stays UNPROVEN: there is no committed REAL
trajectory where an injection succeeded and a sensitive sink followed. **Gate to close:** a
reproducibly-jailbreakable, in-domain (coding/shell-agent) target + corpus. v2.0 spent 65.5k
MiniMax tokens for 0/10 (the target refused all), so live capture is fully deferred (A10) until
such a target exists. NEVER iterate a live run to manufacture a positive (that is fitting).

## S2 — full shell AST escalation (deferred)

WS2-b ships S1 (`shlex` tokenizer: argv + flag-set, no pipeline/subshell structure). If structural
coverage proves insufficient (e.g. pipelines, command substitution, here-docs), escalate to
`conch-parser` (pure-Rust, no runtime) — **gated** on a green `cargo tree -e no-dev` + `cargo audit`.
NOT `brush-parser`/`flash` (the disqualifier is a transitive `tokio` on the dep-graph denylist).
