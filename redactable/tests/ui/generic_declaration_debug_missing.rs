use redactable::{SensitiveDisplay, Secret, PolicyDisplay};
#[derive(SensitiveDisplay)]
#[error("{value:?}")]
struct Debug<T: std::fmt::Debug + PolicyDisplay<Secret>> { #[sensitive(Secret)] value: T }

fn main() {}
