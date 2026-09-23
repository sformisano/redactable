use redactable::{Redactable, RedactableWithFormatter, Secret, SensitiveDual};

#[derive(Clone, serde::Serialize, SensitiveDual)]
#[error("{value}")]
struct Combined {
    #[sensitive(Secret)]
    #[redactable(recursive)]
    value: Option<String>,
}

fn main() {
    let value = Combined {
        value: Some(String::from("secret")),
    };
    assert_eq!(value.redacted_display().to_string(), "Some([REDACTED])");
    let _ = value.redact();
}
