use redactable::NotSensitive;

#[derive(NotSensitive)]
struct Invalid {
    #[sensitive(redactable::Secret)]
    value: String,
}

fn main() {}
