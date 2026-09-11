use redactable::{Redactable, Sensitive};
#[derive(Sensitive)]
struct Envelope<T: Redactable>(T);

fn main() {}
