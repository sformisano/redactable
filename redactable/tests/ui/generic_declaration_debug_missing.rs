use redactable::{SensitiveDisplay, Secret, PolicyDisplay};
#[derive(SensitiveDisplay)]
#[error("{value:?}")]
struct Envelope<T: PolicyDisplay<Secret>> { #[sensitive(Secret)] value: T }

fn main() {}
