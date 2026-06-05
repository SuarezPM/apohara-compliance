// Output formatters. Three views over the same `Report`:
//   * json  — the scanner's own pretty JSON (carries status + rules_source).
//   * sarif — SARIF 2.1.0 for CI consumers.
//   * md    — a human Markdown summary.
//
// The literal `"CANDIDATE — "` prefix on every SARIF result message and every
// Markdown finding line is the honesty thesis made textual (plan fix 8): a SARIF
// `warning` and a Markdown bullet must never read as a compliance assertion.

pub mod gap;
pub mod json;
pub mod md;
pub mod sarif;

/// The mandatory candidate prefix, shared by SARIF + Markdown emitters.
pub const CANDIDATE_PREFIX: &str = "CANDIDATE — ";
