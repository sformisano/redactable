use redactable::Sensitive;
#[derive(Sensitive)]
struct Envelope<T> { value: Option<Vec<T>> }

fn main() {}
