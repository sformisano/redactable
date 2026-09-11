use redactable::{SensitiveDisplay, Secret, PolicyDebug};
#[derive(SensitiveDisplay)]
#[error("{value} {value:?}")]
struct Envelope<T: PolicyDebug<Secret>> { #[sensitive(Secret)] value: T }

fn main() {}
