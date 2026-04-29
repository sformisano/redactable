use redactable::SensitiveDisplay;

#[derive(SensitiveDisplay)]
#[error("value {value:.*}")]
struct DynamicWidth {
    value: String,
}

fn main() {}
