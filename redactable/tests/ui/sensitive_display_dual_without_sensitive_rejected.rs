//! `#[sensitive(dual)]` with only `derive(SensitiveDisplay)` must fail to
//! compile: dual makes `SensitiveDisplay` skip its slog/tracing impls on the
//! assumption that `Sensitive` provides them. Without the pairing the type
//! silently lost its logging integration.

use redactable::SensitiveDisplay;

/// {0}
#[derive(SensitiveDisplay)]
#[sensitive(dual)]
struct ApiKey(#[sensitive(redactable::Token)] String);

fn main() {}
