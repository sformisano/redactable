//! `#[sensitive(dual)]` with only `derive(SensitiveDisplay)` must fail to
//! compile: dual makes `SensitiveDisplay` skip its slog/tracing impls on the
//! assumption that `Sensitive` provides them. Without the pairing the type
//! silently lost its logging integration.

use redactable::SensitiveDisplay;

/// {0}
#[derive(SensitiveDisplay)]
#[sensitive(dual)]
struct ApiKey(#[sensitive(redactable::Token)] String);

// A public capability impl is not proof that Sensitive generated the matching
// half of the dual contract.
impl redactable::RedactableWithMapper for ApiKey {
    fn redact_with<M: redactable::RedactableMapper>(self, _mapper: &M) -> Self {
        self
    }
}

fn main() {}
