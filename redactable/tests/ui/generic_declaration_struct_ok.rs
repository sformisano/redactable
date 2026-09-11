use redactable::{Redactable, Sensitive};
#[derive(Sensitive)]
struct Envelope<T: Redactable> { value: T }

fn main() {}
