use redactable::SensitiveDisplay;

#[derive(SensitiveDisplay)]
#[error("{value}")]
#[redactable(recursive)]
struct Event {
    value: String,
}

fn main() {}
