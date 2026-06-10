//! `#[sensitive(dual)]` with only `derive(Sensitive)` must fail to compile:
//! dual makes `Sensitive` skip its redacted `Debug` impl on the assumption
//! that `SensitiveDisplay` provides it. Without the pairing this used to
//! compile with no `Debug` at all, and a hand-added `#[derive(Debug)]`
//! printed raw secrets in production.

use redactable::Sensitive;

// Debug and Serialize keep the generated slog bounds satisfied under
// --all-features, so the only error is the dual pairing assertion in every
// feature configuration. The hand-written Debug here is exactly the dangerous
// pattern the guard exists for: it would print raw secrets in production.
#[derive(Clone, Debug, Sensitive, serde::Serialize)]
#[sensitive(dual)]
struct ApiKey(#[sensitive(redactable::Token)] String);

fn main() {}
