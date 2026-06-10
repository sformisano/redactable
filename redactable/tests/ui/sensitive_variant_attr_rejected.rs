//! Variant-level `#[sensitive(...)]` must be a compile error: it used to be
//! silently ignored, leaving the variant's fields unredacted.

use redactable::Sensitive;

#[derive(Clone, Sensitive)]
enum AuthEvent {
    #[sensitive(redactable::Secret)]
    Login { password: String },
}

fn main() {}
