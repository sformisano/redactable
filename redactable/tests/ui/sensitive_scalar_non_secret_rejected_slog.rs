use redactable::Sensitive;

#[derive(Clone, Sensitive, serde::Serialize)]
struct Counter {
    #[sensitive(redactable::Pii)]
    value: u64,
}

fn main() {}
