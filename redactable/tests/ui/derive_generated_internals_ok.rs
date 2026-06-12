use redactable::{Redactable, RedactableWithFormatter, Sensitive, SensitiveDisplay};

#[derive(Clone, serde::Serialize, Sensitive)]
struct CollisionSensitive {
    f: String,
    mapper: String,
    debug: String,
}

#[derive(serde::Serialize, SensitiveDisplay)]
#[error("value {f}")]
struct CollisionDisplay {
    f: String,
    mapper: String,
    debug: String,
}

fn main() {
    let sensitive = CollisionSensitive {
        f: "field".to_string(),
        mapper: "mapper".to_string(),
        debug: "debug".to_string(),
    };
    let redacted = sensitive.redact();
    assert_eq!(redacted.f, "field");
    assert_eq!(redacted.mapper, "mapper");
    assert_eq!(redacted.debug, "debug");

    let display = CollisionDisplay {
        f: "field".to_string(),
        mapper: "mapper".to_string(),
        debug: "debug".to_string(),
    };
    assert_eq!(display.redacted_display().to_string(), "value field");
    let _ = format!("{display:?}");
}
