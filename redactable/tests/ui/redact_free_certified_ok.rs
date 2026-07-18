use redactable::{
    NotSensitive, Secret, Sensitive, SensitiveValue, apply_policy, redact,
};

#[derive(Clone, serde::Serialize, Sensitive)]
struct SensitiveRecord {
    #[sensitive(Secret)]
    value: String,
}

#[derive(Clone, serde::Serialize, NotSensitive)]
struct PublicRecord {
    value: String,
}

fn main() {
    let sensitive = redact(SensitiveRecord {
        value: "secret".into(),
    });
    assert_eq!(sensitive.value, "[REDACTED]");

    let public = redact(PublicRecord {
        value: "public".into(),
    });
    assert_eq!(public.value, "public");

    let wrapped = redact(SensitiveValue::<String, Secret>::from(String::from(
        "secret",
    )));
    assert_eq!(wrapped.redacted(), "[REDACTED]");

    let certified = redact(vec![SensitiveRecord {
        value: "secret".into(),
    }]);
    assert_eq!(certified[0].value, "[REDACTED]");

    assert_eq!(
        apply_policy::<Secret, _>(String::from("secret")),
        "[REDACTED]"
    );
}
