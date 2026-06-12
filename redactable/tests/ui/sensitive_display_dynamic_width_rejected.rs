use redactable::SensitiveDisplay;

#[derive(SensitiveDisplay)]
#[error("value {value:.*}")]
struct DynamicPrecision {
    value: String,
}

#[derive(SensitiveDisplay)]
#[error("value {value:width$}")]
struct DynamicWidth {
    value: String,
}

fn main() {}
