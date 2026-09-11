use redactable::{Redactable, Sensitive};
#[derive(Sensitive)]
struct Envelope<T: Redactable> { value: Option<Vec<T>> }

fn main() {}
