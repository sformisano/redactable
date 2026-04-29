use redactable::{RedactableWithFormatter, Secret, SensitiveDisplay};

#[derive(SensitiveDisplay)]
#[error("value {value}")]
struct OptionalSecret {
    #[sensitive(Secret)]
    value: Option<String>,
}

#[derive(SensitiveDisplay)]
#[error("values {values}")]
struct SecretList {
    #[sensitive(Secret)]
    values: Vec<String>,
}

#[derive(SensitiveDisplay)]
#[error("debug {values:?}")]
struct DebugSecretList {
    #[sensitive(Secret)]
    values: Vec<String>,
}

fn main() {
    let optional = OptionalSecret {
        value: Some(String::from("hidden")),
    };
    assert_eq!(
        optional.redacted_display().to_string(),
        "value Some([REDACTED])"
    );

    let list = SecretList {
        values: vec![String::from("alpha"), String::from("beta")],
    };
    assert_eq!(
        list.redacted_display().to_string(),
        "values [[REDACTED], [REDACTED]]"
    );

    let debug_list = DebugSecretList {
        values: vec![String::from("alpha"), String::from("beta")],
    };
    assert_eq!(
        debug_list.redacted_display().to_string(),
        "debug [\"[REDACTED]\", \"[REDACTED]\"]"
    );
}
