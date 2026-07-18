use std::num::NonZeroU32 as ImportedNonZero;

use redactable::SensitiveDisplay;

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct Invalid {
    #[sensitive(redactable::Secret)]
    value: ImportedNonZero,
}

fn main() {}
