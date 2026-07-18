use super::*;

#[test]
fn passes_through_foreign_types_in_struct() {
    #[derive(Clone, Debug, PartialEq)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct ForeignType {
        data: String,
    }

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Container {
        #[not_sensitive]
        foreign: ForeignType,
        #[sensitive(Secret)]
        secret: String,
    }

    let value = Container {
        foreign: ForeignType {
            data: "external".into(),
        },
        secret: "hunter2".into(),
    };

    let redacted = value.clone().redact();

    assert_eq!(redacted.foreign, value.foreign);
    assert_eq!(redacted.secret, "[REDACTED]");
}

#[test]
fn does_not_walk_nested_sensitive_fields() {
    #[derive(Clone, Sensitive, PartialEq)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct InnerSensitive {
        #[sensitive(Secret)]
        password: String,
    }

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Outer {
        #[not_sensitive]
        inner: InnerSensitive,
        #[sensitive(Secret)]
        api_key: String,
    }

    let value = Outer {
        inner: InnerSensitive {
            password: "secret123".into(),
        },
        api_key: "sk_live_abc".into(),
    };

    let redacted = value.clone().redact();

    assert_eq!(redacted.inner.password, "secret123");
    assert_eq!(redacted.api_key, "[REDACTED]");
}

#[test]
fn works_on_enum_variant_fields() {
    #[derive(Clone, Debug, PartialEq)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Metadata {
        version: u32,
    }

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    enum Event {
        Success {
            #[not_sensitive]
            meta: Metadata,
            #[sensitive(Secret)]
            token: String,
        },
        Failure {
            #[not_sensitive]
            code: u32,
            message: String,
        },
    }

    let success = Event::Success {
        meta: Metadata { version: 1 },
        token: "secret_token".into(),
    };

    let failure = Event::Failure {
        code: 500,
        message: "error".into(),
    };

    let redacted_success = success.clone().redact();
    let redacted_failure = failure.clone().redact();

    match redacted_success {
        Event::Success { meta, token } => {
            assert_eq!(meta, Metadata { version: 1 });
            assert_eq!(token, "[REDACTED]");
        }
        _ => panic!("wrong variant"),
    }

    match redacted_failure {
        Event::Failure { code, message } => {
            assert_eq!(code, 500);
            assert_eq!(message, "error");
        }
        _ => panic!("wrong variant"),
    }
}
