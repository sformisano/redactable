use crate::log_redacted;
use redactable::{
    Redactable, RedactionPolicy, Secret, Sensitive, SensitiveValue, SensitiveWithPolicy,
    TextPolicyKind, TextRedactionPolicy,
};

#[test]
fn passes_through_unchanged_when_implementing_redactable_container() {
    #[derive(Clone, PartialEq, Sensitive, serde::Serialize)]
    struct ExternalTimestamp(#[not_sensitive] u64);

    #[derive(Clone, PartialEq, Sensitive, serde::Serialize)]
    struct ExternalDecimal(#[not_sensitive] f64);

    #[derive(Clone, Sensitive, serde::Serialize)]
    struct Transaction {
        #[sensitive(Secret)]
        account_number: String,
        timestamp: ExternalTimestamp,
        amount: ExternalDecimal,
        #[not_sensitive]
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
    #[derive(Clone, Debug, PartialEq, serde::Serialize)]
    struct ExternalRecoveryCode(String);

    impl SensitiveWithPolicy<Secret> for ExternalRecoveryCode {
        fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self {
            Self(policy.apply_to(&self.0))
        }

        fn redacted_string(&self, policy: &TextRedactionPolicy) -> String {
            policy.apply_to(&self.0)
        }
    }

    #[derive(Clone, Sensitive, serde::Serialize)]
    struct Record {
        #[sensitive(Secret)]
        token: String,
        recovery_code: SensitiveValue<ExternalRecoveryCode, Secret>,
    }

    let record = Record {
        token: "secret".to_string(),
        recovery_code: SensitiveValue::from(ExternalRecoveryCode(
            "recovery-code-canary".to_string(),
        )),
    };

    let redacted = record.redact();
    assert_eq!(redacted.token, "[REDACTED]");
    assert_eq!(
        redacted.recovery_code.expose(),
        &ExternalRecoveryCode("[REDACTED]".to_string())
    );
}

#[test]
fn redacts_via_policy_trait() {
    #[derive(Clone, Debug, PartialEq, serde::Serialize)]
    struct ExternalAccountNumber(String);

    #[derive(Clone, Copy)]
    struct AccountNumberPolicy;

    impl RedactionPolicy for AccountNumberPolicy {
        type Kind = TextPolicyKind;

        fn policy() -> TextRedactionPolicy {
            TextRedactionPolicy::keep_last(4)
        }
    }

    impl SensitiveWithPolicy<AccountNumberPolicy> for ExternalAccountNumber {
        fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self {
            Self(policy.apply_to(&self.0))
        }

        fn redacted_string(&self, policy: &TextRedactionPolicy) -> String {
            policy.apply_to(&self.0)
        }
    }

    #[derive(Clone, Sensitive, serde::Serialize)]
    struct Record {
        account_number: SensitiveValue<ExternalAccountNumber, AccountNumberPolicy>,
    }

    let record = Record {
        account_number: SensitiveValue::from(ExternalAccountNumber("123456789012".into())),
    };

    let redacted = record.clone().redact();
    assert_eq!(
        redacted.account_number.expose(),
        &ExternalAccountNumber("********9012".to_string())
    );
    assert_eq!(log_redacted(&record.account_number).text(), "********9012");
}

#[test]
fn chooses_trait_based_on_wrapper_usage() {
    #[derive(Clone, PartialEq, Sensitive, serde::Serialize)]
    struct AccountNumber {
        #[not_sensitive]
        scheme: String,
        #[sensitive(Secret)]
        value: String,
    }

    // Support diagnostics correlate accounts by their final four digits.
    #[derive(Clone, Copy)]
    struct SupportAccountNumber;
    impl RedactionPolicy for SupportAccountNumber {
        type Kind = TextPolicyKind;

        fn policy() -> TextRedactionPolicy {
            TextRedactionPolicy::keep_last(4)
        }
    }

    impl SensitiveWithPolicy<SupportAccountNumber> for AccountNumber {
        fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self {
            Self {
                scheme: "support-last-four".into(),
                value: policy.apply_to(&self.value),
            }
        }

        fn redacted_string(&self, policy: &TextRedactionPolicy) -> String {
            policy.apply_to(&self.value)
        }
    }

    #[derive(Clone, Sensitive, serde::Serialize)]
    struct AccountTraversed {
        account_number: AccountNumber,
    }

    #[derive(Clone, Sensitive, serde::Serialize)]
    struct AccountAsLeaf {
        account_number: SensitiveValue<AccountNumber, SupportAccountNumber>,
    }

    let account_number = AccountNumber {
        scheme: "customer-account".into(),
        value: "12345678".into(),
    };

    // Structural traversal preserves the scheme and applies the number's full mask.
    let account_traversed = AccountTraversed {
        account_number: account_number.clone(),
    };
    let redacted_traversed = account_traversed.redact();
    assert_eq!(redacted_traversed.account_number.scheme, "customer-account");
    assert_eq!(redacted_traversed.account_number.value, "[REDACTED]");

    // The leaf policy selects its own scheme and last-four representation.
    let account_as_leaf = AccountAsLeaf {
        account_number: SensitiveValue::from(account_number.clone()),
    };
    let redacted_as_leaf = account_as_leaf.redact();
    assert_eq!(
        redacted_as_leaf.account_number.expose().scheme,
        "support-last-four"
    );
    assert_eq!(redacted_as_leaf.account_number.expose().value, "****5678");
}
