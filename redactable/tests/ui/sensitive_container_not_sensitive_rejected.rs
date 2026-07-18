use redactable::Sensitive;

#[derive(Sensitive)]
#[not_sensitive]
struct Event {
    value: String,
}

fn main() {}
