use redactable::{Redactable, RedactableWithFormatter, Secret, SensitiveDual};

#[derive(SensitiveDual)]
#[error("{value}")]
struct Combined {
    #[sensitive(Secret)]
    #[redactable(recursive, legacy_formatting)]
    value: Option<String>,
}

fn main() {
    let value = Combined {
        value: Some(String::from("secret")),
    };
    assert_eq!(value.redacted_display().to_string(), "Some([REDACTED])");
    let _ = value.redact();
}
