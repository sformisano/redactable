//! Variant-level `#[not_sensitive]` must be rejected on `NotSensitive` types,
//! matching the existing container- and field-level rejections.

use redactable::NotSensitive;

#[derive(Clone, NotSensitive)]
enum Status {
    #[not_sensitive]
    Ready,
    Stopped,
}

fn main() {}
