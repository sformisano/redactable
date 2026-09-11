use redactable::Sensitive;
#[derive(Sensitive)]
enum Envelope<T> { Value(T), Empty }

fn main() {}
