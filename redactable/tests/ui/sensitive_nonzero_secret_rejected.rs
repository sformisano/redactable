use std::num::NonZeroU32;

use redactable::Sensitive;

#[derive(Clone, Sensitive)]
struct Counter {
    #[sensitive(redactable::Secret)]
    value: NonZeroU32,
}

fn main() {}
