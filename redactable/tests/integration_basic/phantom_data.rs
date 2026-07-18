use std::marker::PhantomData;

use super::*;

/// External type that does NOT implement RedactableWithMapper.
/// This simulates types like `chrono::DateTime<Utc>` or other third-party types.
#[derive(Clone, Debug, PartialEq)]
struct ExternalType;

#[test]
fn phantom_data_field_passes_through_without_bounds() {
    // This test verifies that PhantomData<T> fields work without
    // requiring T: RedactableWithMapper. If this compiles, the fix works.
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct TypedId<T> {
        id: String,
        #[sensitive(Secret)]
        secret: String,
        _marker: PhantomData<T>,
    }

    // ExternalType does NOT implement RedactableWithMapper.
    // If PhantomData wasn't handled specially, this would fail to compile.
    let typed_id: TypedId<ExternalType> = TypedId {
        id: "user_123".into(),
        secret: "hunter2".into(),
        _marker: PhantomData,
    };

    let redacted = typed_id.redact();

    // PhantomData passes through unchanged
    assert_eq!(redacted._marker, PhantomData);
    // Other fields work normally
    assert_eq!(redacted.id, "user_123");
    assert_eq!(redacted.secret, "[REDACTED]");
}

#[test]
fn phantom_data_with_qualified_path() {
    // Test with fully qualified std::marker::PhantomData
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Wrapper<T> {
        value: String,
        _phantom: std::marker::PhantomData<T>,
    }

    let wrapper: Wrapper<ExternalType> = Wrapper {
        value: "test".into(),
        _phantom: std::marker::PhantomData,
    };

    let redacted = wrapper.redact();
    assert_eq!(redacted.value, "test");
}

#[test]
fn multiple_phantom_data_fields() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct MultiPhantom<A, B, C> {
        #[sensitive(Secret)]
        data: String,
        _a: PhantomData<A>,
        _b: PhantomData<B>,
        _c: PhantomData<C>,
    }

    // None of A, B, C implement RedactableWithMapper
    let multi: MultiPhantom<ExternalType, ExternalType, ExternalType> = MultiPhantom {
        data: "secret".into(),
        _a: PhantomData,
        _b: PhantomData,
        _c: PhantomData,
    };

    let redacted = multi.redact();
    assert_eq!(redacted.data, "[REDACTED]");
}

#[test]
fn phantom_data_in_enum_variant() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    enum TypedEvent<T> {
        Created {
            #[sensitive(Secret)]
            token: String,
            _marker: PhantomData<T>,
        },
        Deleted(PhantomData<T>),
    }

    let created: TypedEvent<ExternalType> = TypedEvent::Created {
        token: "secret_token".into(),
        _marker: PhantomData,
    };

    let redacted = created.redact();
    match redacted {
        TypedEvent::Created { token, _marker } => {
            assert_eq!(token, "[REDACTED]");
        }
        _ => panic!("wrong variant"),
    }

    let deleted: TypedEvent<ExternalType> = TypedEvent::Deleted(PhantomData);
    let redacted = deleted.redact();
    match redacted {
        TypedEvent::Deleted(_) => {}
        _ => panic!("wrong variant"),
    }
}
