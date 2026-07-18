use super::*;

#[test]
fn passes_through_all_fields_unchanged() {
    #[derive(Clone, NotSensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct PublicInfo {
        id: u64,
        label: String,
    }

    let value = PublicInfo {
        id: 42,
        label: "ok".to_string(),
    };

    let redacted = value.clone().redact();
    assert_eq!(redacted.id, value.id);
    assert_eq!(redacted.label, value.label);
}

#[test]
fn does_not_walk_nested_sensitive_fields() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Inner {
        #[sensitive(Secret)]
        secret: String,
    }

    #[derive(Clone, NotSensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Outer {
        inner: Inner,
    }

    let value = Outer {
        inner: Inner {
            secret: "top_secret".into(),
        },
    };

    let redacted = value.clone().redact();
    assert_eq!(redacted.inner.secret, value.inner.secret);
}
