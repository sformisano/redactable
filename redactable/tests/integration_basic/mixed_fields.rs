use super::*;

#[test]
fn applies_correct_policy_to_each_field() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct MixedRecord {
        id: u64,
        #[sensitive(Secret)]
        ssn: String,
        name: String,
        #[sensitive(Secret)]
        internal_score: i32,
        #[sensitive(Token)]
        api_key: String,
        public_data: String,
    }

    let record = MixedRecord {
        id: 12345,
        ssn: "123-45-6789".into(),
        name: "John Doe".into(),
        internal_score: 95,
        api_key: "sk_test_abc123456789".into(),
        public_data: "visible".into(),
    };

    let redacted = record.redact();

    assert_eq!(redacted.id, 12345);
    assert_eq!(redacted.ssn, "[REDACTED]");
    assert_eq!(redacted.name, "John Doe");
    assert_eq!(redacted.internal_score, 0);
    assert_eq!(redacted.api_key, "****************6789");
    assert_eq!(redacted.public_data, "visible");
}
