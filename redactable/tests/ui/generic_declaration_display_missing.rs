use redactable::{SensitiveDisplay, Secret};
#[derive(SensitiveDisplay)]
#[error("{value}")]
struct Envelope<T> { #[sensitive(Secret)] value: T }

fn main() {}
