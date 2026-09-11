use std::fmt::Debug;
use redactable::Sensitive;
#[derive(Sensitive)]
struct Envelope<T: Debug> { #[redactable(recursive)] value: T }

fn main() {}
