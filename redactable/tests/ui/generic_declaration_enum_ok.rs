use redactable::{Redactable, Sensitive};
#[derive(Sensitive)]
enum Envelope<T: Redactable> { Value(T), Empty }

fn main() {}
