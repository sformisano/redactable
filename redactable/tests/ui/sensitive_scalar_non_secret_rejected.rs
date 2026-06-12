use redactable::Sensitive;

#[derive(Clone, Sensitive)]
struct Counter {
    #[sensitive(redactable::Pii)]
    value: u64,
}

fn main() {}
