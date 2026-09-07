//! Legacy `#[sensitive(dual)]` with `Sensitive` is rejected outright.
//! The supported combined derive is `SensitiveDual`. Historically, unmatched
//! coordination could omit the generated redacted `Debug` implementation.
//! A hand-added `#[derive(Debug)]` then printed raw secrets in production.
//! The current guard rejects the legacy syntax before expansion.

use redactable::{RedactableWithFormatter, Sensitive};
use std::fmt::{Formatter, Result as FmtResult};

// Debug and Serialize keep the generated slog bounds satisfied under
// --all-features, so the only error is legacy syntax rejection in every
// feature configuration. The explicit `Debug` derive here is exactly the dangerous
// pattern the guard exists for: it would print raw secrets in production.
#[derive(Clone, Debug, Sensitive, serde::Serialize)]
#[sensitive(dual)]
struct ApiKey(#[sensitive(redactable::Token)] String);

// A public capability impl is not proof that SensitiveDisplay generated the
// matching half of the dual contract.
impl RedactableWithFormatter for ApiKey {
    fn fmt_redacted(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str("manual formatter")
    }
}

fn main() {}
