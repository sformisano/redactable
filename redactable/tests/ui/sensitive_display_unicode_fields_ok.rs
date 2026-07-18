use redactable::{RedactableWithFormatter, SensitiveDisplay};

const CANARY: &str = "unicode-field-secret-canary";

#[derive(SensitiveDisplay)]
#[error("{café} {café:?} {jalapeño} {jalapeño:?} {公開} {公開:?}")]
struct UnicodeStruct {
    #[sensitive(redactable::Secret)]
    café: String,
    jalapeño: String,
    #[not_sensitive]
    公開: String,
}

#[derive(SensitiveDisplay)]
enum UnicodeEnum {
    #[error("{café} {café:?} {jalapeño} {jalapeño:?} {公開} {公開:?}")]
    Value {
        #[sensitive(redactable::Secret)]
        café: String,
        jalapeño: String,
        #[not_sensitive]
        公開: String,
    },
}

fn assert_rendered<T: RedactableWithFormatter>(value: &T) {
    let rendered = value.redacted_display().to_string();
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains(CANARY));
}

fn main() {
    assert_rendered(&UnicodeStruct {
        café: CANARY.into(),
        jalapeño: "walked".into(),
        公開: "public".into(),
    });
    assert_rendered(&UnicodeEnum::Value {
        café: CANARY.into(),
        jalapeño: "walked".into(),
        公開: "public".into(),
    });
}
