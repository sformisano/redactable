use redactable::SensitiveDisplay;

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct Event {
    #[redactable(legacy_formatting)]
    value: String,
}

fn main() {}
