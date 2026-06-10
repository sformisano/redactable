//! Variant-level `#[sensitive(...)]` must be a compile error for
//! `SensitiveDisplay` too: it used to be silently ignored, so the template
//! formatted the variant's fields without redaction.

use redactable::SensitiveDisplay;

#[derive(SensitiveDisplay)]
enum AuthError {
    #[sensitive(redactable::Secret)]
    #[error("login failed for {user} with {password}")]
    InvalidCredentials { user: String, password: String },
}

fn main() {}
