use redactable::Sensitive;

#[derive(Clone, serde::Serialize, Sensitive)]
#[not_sensitive]
struct Event {
    value: String,
}

fn main() {}
