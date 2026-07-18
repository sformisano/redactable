use super::*;

#[test]
fn passes_through_unchanged_when_implementing_redactable_container() {
    #[derive(Clone, PartialEq, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct ExternalTimestamp(u64);

    #[derive(Clone, PartialEq, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct ExternalDecimal(f64);

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Transaction {
        #[sensitive(Secret)]
        account_number: String,
        timestamp: ExternalTimestamp,
        amount: ExternalDecimal,
        description: String,
    }

    let tx = Transaction {
        account_number: "1234567890".into(),
        timestamp: ExternalTimestamp(1704067200),
        amount: ExternalDecimal(99.99),
        description: "Coffee".into(),
    };

    let redacted = tx.redact();

    assert_eq!(redacted.account_number, "[REDACTED]");
    assert_eq!(redacted.timestamp, ExternalTimestamp(1704067200));
    assert_eq!(redacted.amount, ExternalDecimal(99.99));
    assert_eq!(redacted.description, "Coffee");
}

#[test]
fn redacts_via_sensitive_wrapper() {
    #[derive(Clone, Debug, PartialEq)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct ExternalId(String);

    impl SensitiveWithPolicy<Secret> for ExternalId {
        fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self {
            Self(policy.apply_to(&self.0))
        }

        fn redacted_string(&self, policy: &TextRedactionPolicy) -> String {
            policy.apply_to(&self.0)
        }
    }

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Record {
        #[sensitive(Secret)]
        token: String,
        external_id: SensitiveValue<ExternalId, Secret>,
    }

    let record = Record {
        token: "secret".to_string(),
        external_id: SensitiveValue::from(ExternalId("external".to_string())),
    };

    let redacted = record.redact();
    assert_eq!(redacted.token, "[REDACTED]");
    assert_eq!(
        redacted.external_id.expose(),
        &ExternalId("[REDACTED]".to_string())
    );
}

#[test]
fn redacts_via_policy_trait() {
    #[derive(Clone, Debug, PartialEq)]
    #[cfg_attr(feature = "json", derive(serde::Serialize))]
    struct ExternalType(String);

    #[derive(Clone, Copy)]
    struct ExternalTypePolicy;

    impl RedactionPolicy for ExternalTypePolicy {
        type Kind = TextPolicyKind;

        fn policy() -> TextRedactionPolicy {
            TextRedactionPolicy::keep_last(2)
        }
    }

    impl SensitiveWithPolicy<ExternalTypePolicy> for ExternalType {
        fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self {
            Self(policy.apply_to(&self.0))
        }

        fn redacted_string(&self, policy: &TextRedactionPolicy) -> String {
            policy.apply_to(&self.0)
        }
    }

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "json", derive(serde::Serialize))]
    struct Record {
        id: SensitiveValue<ExternalType, ExternalTypePolicy>,
    }

    let record = Record {
        id: SensitiveValue::from(ExternalType("external".into())),
    };

    let redacted = record.clone().redact();
    assert_eq!(redacted.id.expose(), &ExternalType("******al".to_string()));
    assert_eq!(
        log_redacted(&record.id),
        RedactedOutput::Text("******al".to_string())
    );
}

#[test]
fn chooses_trait_based_on_wrapper_usage() {
    #[derive(Clone, PartialEq, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct UserId {
        prefix: String,
        #[sensitive(Secret)]
        value: String,
    }

    impl SensitiveWithPolicy<Token> for UserId {
        fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self {
            Self {
                prefix: "redacted".into(),
                value: policy.apply_to(&self.value),
            }
        }

        fn redacted_string(&self, policy: &TextRedactionPolicy) -> String {
            policy.apply_to(&self.value)
        }
    }

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct AccountTraversed {
        user_id: UserId,
    }

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct AccountAsLeaf {
        user_id: SensitiveValue<UserId, Token>,
    }

    let user_id = UserId {
        prefix: "usr".into(),
        value: "12345678".into(),
    };

    // Unannotated field uses Sensitive (traverses fields)
    let account_traversed = AccountTraversed {
        user_id: user_id.clone(),
    };
    let redacted_traversed = account_traversed.redact();
    assert_eq!(redacted_traversed.user_id.prefix, "usr");
    assert_eq!(redacted_traversed.user_id.value, "[REDACTED]");

    // SensitiveValue<T, Policy> wrapper uses SensitiveWithPolicy (redacts as unit)
    let account_as_leaf = AccountAsLeaf {
        user_id: SensitiveValue::from(user_id.clone()),
    };
    let redacted_as_leaf = account_as_leaf.redact();
    assert_eq!(redacted_as_leaf.user_id.expose().prefix, "redacted");
    assert_eq!(redacted_as_leaf.user_id.expose().value, "****5678");
}
