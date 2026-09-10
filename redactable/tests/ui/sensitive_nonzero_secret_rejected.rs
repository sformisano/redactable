use std::num::NonZeroU32;

use redactable::Sensitive;

#[derive(serde::Serialize, Clone, Sensitive)]
struct Counter {
    #[sensitive(redactable::Secret)]
    value: NonZeroU32,
}

fn main() {}
