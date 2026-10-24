use redactable::{Redactable, Secret, Sensitive};

#[test]
fn applies_correct_policy_to_each_field() {
    #[derive(Clone, Sensitive, serde::Serialize)]
    struct MixedRecord {
        #[not_sensitive]
        id: u64,
        #[sensitive(Secret)]
        ssn: String,
        #[not_sensitive]
        name: String,
        #[sensitive(Secret)]
        recovery_pin: u32,
        #[sensitive(Secret)]
        api_key: String,
        #[not_sensitive]
        public_data: String,
    }

    let record = MixedRecord {
        id: 12345,
        ssn: "123-45-6789".into(),
        name: "John Doe".into(),
        recovery_pin: 428731,
        api_key: "sk_test_abc123456789".into(),
        public_data: "visible".into(),
    };

    let redacted = record.redact();

    assert_eq!(redacted.id, 12345);
    assert_eq!(redacted.ssn, "[REDACTED]");
    assert_eq!(redacted.name, "John Doe");
    assert_eq!(redacted.recovery_pin, 0);
    assert_eq!(redacted.api_key, "[REDACTED]");
    assert_eq!(redacted.public_data, "visible");
}
