use redactable::NotSensitive;

#[derive(serde::Serialize, NotSensitive)]
struct Invalid {
    #[sensitive(redactable::Secret)]
    value: String,
}

fn main() {}
