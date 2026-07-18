use super::*;

#[test]
fn applies_user_defined_policy() {
    #[derive(Clone, Copy)]
    struct InternalId;

    impl RedactionPolicy for InternalId {
        type Kind = TextPolicyKind;

        fn policy() -> TextRedactionPolicy {
            TextRedactionPolicy::keep_last(2)
        }
    }

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Record {
        #[sensitive(InternalId)]
        id: String,
        name: String,
    }

    let record = Record {
        id: "user_abc123".into(),
        name: "Test".into(),
    };

    let redacted = record.redact();
    assert_eq!(redacted.id, "*********23");
    assert_eq!(redacted.name, "Test");
}
