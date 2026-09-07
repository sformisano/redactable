//! Legacy `#[sensitive(dual)]` with `SensitiveDisplay` is rejected outright.
//! The supported combined derive is `SensitiveDual`. Historically, unmatched
//! legacy coordination skipped slog/tracing implementations and silently lost
//! logging integration; the current guard rejects that syntax before expansion.

use redactable::{RedactableMapper, RedactableWithMapper, SensitiveDisplay};

/// {0}
#[derive(SensitiveDisplay)]
#[sensitive(dual)]
struct ApiKey(#[sensitive(redactable::Token)] String);

// A public capability impl is not proof that Sensitive generated the matching
// half of the dual contract.
impl RedactableWithMapper for ApiKey {
    fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
        self
    }
}

fn main() {}
