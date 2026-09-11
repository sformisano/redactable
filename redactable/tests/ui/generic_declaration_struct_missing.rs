use redactable::Sensitive;
#[derive(Sensitive)]
struct Envelope<T> { value: T }

fn main() {}
