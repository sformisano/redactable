use std::num::NonZeroU32;

use redactable::{Secret, Sensitive};

#[derive(Clone, Sensitive, serde::Serialize)]
struct Counter {
    #[sensitive(Secret)]
    value: NonZeroU32,
}

fn main() {}
