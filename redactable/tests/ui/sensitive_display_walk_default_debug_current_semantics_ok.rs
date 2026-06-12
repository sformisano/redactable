use redactable::{RedactableWithFormatter, SensitiveDisplay};

// Documents current generated behavior: `:?` on an unannotated walk-default
// field still formats through the redacted-display wrapper, not raw `Debug`.
#[derive(SensitiveDisplay)]
#[error("value {value:?}")]
struct DebugTemplate {
    value: String,
}

fn main() {
    let value = DebugTemplate {
        value: "plain".to_string(),
    };
    assert_eq!(value.redacted_display().to_string(), "value plain");
}
