use redactable::{SensitiveDisplay, Secret, __private::PolicyField};
#[derive(SensitiveDisplay)]
#[error("{value}")]
struct Envelope<T: PolicyField<Secret>> { #[sensitive(Secret)] value: T }

fn main() {}
