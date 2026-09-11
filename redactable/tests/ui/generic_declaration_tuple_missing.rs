use redactable::Sensitive;
#[derive(Sensitive)]
struct Envelope<T>(T);

fn main() {}
