use redactable::{Redactable, RedactionPolicy, Sensitive, TextPolicyKind, TextRedactionPolicy};

#[test]
fn applies_user_defined_policy() {
    #[derive(Clone, Copy)]
    struct CardSuffix;

    impl RedactionPolicy for CardSuffix {
        type Kind = TextPolicyKind;

        fn policy() -> TextRedactionPolicy {
            TextRedactionPolicy::keep_last(4)
        }
    }

    #[derive(Clone, Sensitive, serde::Serialize)]
    struct Record {
        // Support matches payment cards by their final four digits.
        #[sensitive(CardSuffix)]
        payment_card: String,
        #[not_sensitive]
        name: String,
    }

    let record = Record {
        payment_card: "4111111111110123".into(),
        name: "Test".into(),
    };

    let redacted = record.redact();
    assert_eq!(redacted.payment_card, "************0123");
    assert_eq!(redacted.name, "Test");
}
