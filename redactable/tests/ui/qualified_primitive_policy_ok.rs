use redactable::{Redactable, Secret, Sensitive};

#[derive(Clone, Sensitive, serde::Serialize)]
struct QualifiedPrimitives {
    #[sensitive(Secret)]
    attempts: std::primitive::u32,
    #[sensitive(redactable::Secret)]
    enabled: std::primitive::bool,
    #[sensitive(::redactable::Secret)]
    marker: std::primitive::char,
}

fn main() {
    let redacted = QualifiedPrimitives {
        attempts: 7,
        enabled: true,
        marker: 'x',
    }
    .redact();

    assert_eq!(redacted.attempts, 0);
    assert!(!redacted.enabled);
    assert_eq!(redacted.marker, '*');
}
