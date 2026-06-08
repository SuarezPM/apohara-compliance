# Open questions

Gated / deferred decisions tracked outside the ADRs. Each entry names the gate and the
trigger that closes it.

## Version badge (Pablo-gated)

`README.md:10` version badge = `version-1.1.0`. v1.4 + v2.0 + v2.1 are on `main` with no new
tag, so the badge lags the codebase. The badge tracks the last **release tag**, and
tagging/release is Pablo-gated — bump the badge to whatever tag v2.1 eventually cuts. No
badge edit lands until that tag exists.
