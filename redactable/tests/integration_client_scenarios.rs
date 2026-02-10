//! Client scenario tests - simulating real-world adoption patterns.
//!
//! These tests verify that the issues encountered during library adoption are fixed.
//! Each test is documented with the original problem and expected behavior.

#![allow(clippy::redundant_locals, clippy::box_collection)]

use std::marker::PhantomData;

use redactable::{
    Email, PhoneNumber, Pii, Redactable, RedactionPolicy, Secret, Sensitive, TextRedactionPolicy,
};

/// Custom policy that fully redacts (for testing custom policies)
#[derive(Clone, Copy)]
struct FullRedact;
impl RedactionPolicy for FullRedact {
    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::default_full()
    }
}

/// Custom policy that keeps last 4 characters (like a token)
#[derive(Clone, Copy)]
struct PartiallyVisible;
impl RedactionPolicy for PartiallyVisible {
    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(4)
    }
}

/// Issue 1: Wrapper types with #[sensitive(Policy)]
///
/// Original problem: Users were forced to create newtypes like `PiiString`
/// just to wrap optional strings because Option<String> didn't implement
/// `SensitiveWithPolicy`.
///
/// Expected behavior: `#[sensitive(Policy)]` should work on Option<T>,
/// Vec<T>, Box<T> and apply the policy to the inner value(s).
mod wrapper_types_with_policy {
    use super::*;

    #[test]
    fn applies_policy_to_option_string() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct UserProfile {
            username: String,
            #[sensitive(Email)]
            email: Option<String>,
            #[sensitive(PhoneNumber)]
            phone: Option<String>,
        }

        let profile = UserProfile {
            username: "johndoe".into(),
            email: Some("john@example.com".into()),
            phone: Some("+1-555-123-4567".into()),
        };

        let redacted = profile.redact();
        assert_eq!(redacted.username, "johndoe");
        assert_eq!(redacted.email, Some("jo**@example.com".into()));
        assert_eq!(redacted.phone, Some("***********4567".into()));

        let profile_no_contact = UserProfile {
            username: "janedoe".into(),
            email: None,
            phone: None,
        };

        let redacted = profile_no_contact.redact();
        assert_eq!(redacted.username, "janedoe");
        assert_eq!(redacted.email, None);
        assert_eq!(redacted.phone, None);
    }

    #[test]
    fn applies_policy_to_vec_string() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct AuditLog {
            event_type: String,
            #[sensitive(FullRedact)]
            affected_users: Vec<String>,
            #[sensitive(PartiallyVisible)]
            ip_addresses: Vec<String>,
        }

        let log = AuditLog {
            event_type: "login_attempt".into(),
            affected_users: vec![
                "user@email.com".into(),
                "admin@corp.com".into(),
                "guest@example.org".into(),
            ],
            ip_addresses: vec!["192.168.1.100".into(), "10.0.0.50".into()],
        };

        let redacted = log.redact();
        assert_eq!(redacted.event_type, "login_attempt");
        assert_eq!(
            redacted.affected_users,
            vec!["[REDACTED]", "[REDACTED]", "[REDACTED]"]
        );
        assert_eq!(redacted.ip_addresses, vec!["*********.100", "*****0.50"]);

        let empty_log = AuditLog {
            event_type: "system".into(),
            affected_users: vec![],
            ip_addresses: vec![],
        };
        let redacted = empty_log.redact();
        assert!(redacted.affected_users.is_empty());
        assert!(redacted.ip_addresses.is_empty());
    }

    #[test]
    fn applies_policy_to_box_string() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct EncryptedPayload {
            algorithm: String,
            #[sensitive(Secret)]
            key: Box<String>,
            #[sensitive(Secret)]
            iv: Box<String>,
        }

        let payload = EncryptedPayload {
            algorithm: "AES-256-GCM".into(),
            key: Box::new("super_secret_encryption_key_12345".into()),
            iv: Box::new("initialization_vector_abc".into()),
        };

        let redacted = payload.redact();
        assert_eq!(redacted.algorithm, "AES-256-GCM");
        assert_eq!(*redacted.key, "[REDACTED]");
        assert_eq!(*redacted.iv, "[REDACTED]");
    }

    #[test]
    fn handles_mixed_wrapper_types() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct DatabaseConfig {
            host: String,
            port: u16,
            #[sensitive(Secret)]
            password: Option<String>,
            #[sensitive(Secret)]
            ssl_cert: Box<String>,
            #[sensitive(PartiallyVisible)]
            connection_strings: Vec<String>,
        }

        let config = DatabaseConfig {
            host: "db.example.com".into(),
            port: 5432,
            password: Some("super_secret_db_password".into()),
            ssl_cert: Box::new("-----BEGIN CERTIFICATE-----...".into()),
            connection_strings: vec![
                "postgres://user:pass@host1:5432/db".into(),
                "postgres://user:pass@host2:5432/db".into(),
            ],
        };

        let redacted = config.redact();
        assert_eq!(redacted.host, "db.example.com");
        assert_eq!(redacted.port, 5432);
        assert_eq!(redacted.password, Some("[REDACTED]".into()));
        assert_eq!(*redacted.ssl_cert, "[REDACTED]");
        assert_eq!(
            redacted.connection_strings,
            vec![
                "******************************2/db",
                "******************************2/db"
            ]
        );
    }
}

/// Issue 5: PhantomData handling
///
/// Original problem: PhantomData<T> didn't implement RedactionWalker, forcing
/// users to manually implement it or avoid PhantomData.
///
/// Expected behavior: PhantomData<T> should be automatically handled as a
/// pass-through (no redaction needed).
mod phantom_data {
    use super::*;

    #[test]
    fn works_in_generic_struct() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct TypedId<T> {
            #[sensitive(PartiallyVisible)]
            id: String,
            _marker: PhantomData<T>,
        }

        struct User;
        struct Order;

        let user_id: TypedId<User> = TypedId {
            id: "user_abc123456789".into(),
            _marker: PhantomData,
        };

        let order_id: TypedId<Order> = TypedId {
            id: "order_xyz987654321".into(),
            _marker: PhantomData,
        };

        let redacted_user = user_id.redact();
        let redacted_order = order_id.redact();

        assert_eq!(redacted_user.id, "*************6789");
        assert_eq!(redacted_order.id, "**************4321");
    }

    #[test]
    fn works_with_lifetimes() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct BorrowedRef<'a, T> {
            name: String,
            #[sensitive(Secret)]
            secret: String,
            _marker: PhantomData<&'a T>,
        }

        let borrowed: BorrowedRef<'static, String> = BorrowedRef {
            name: "test".into(),
            secret: "confidential_data".into(),
            _marker: PhantomData,
        };

        let redacted = borrowed.redact();
        assert_eq!(redacted.name, "test");
        assert_eq!(redacted.secret, "[REDACTED]");
    }

    #[test]
    fn works_with_multiple_phantom_data() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct MultiPhantom<A, B, C> {
            #[sensitive(Secret)]
            data: String,
            _a: PhantomData<A>,
            _b: PhantomData<B>,
            _c: PhantomData<C>,
        }

        let multi: MultiPhantom<u8, u16, u32> = MultiPhantom {
            data: "secret_value".into(),
            _a: PhantomData,
            _b: PhantomData,
            _c: PhantomData,
        };

        let redacted = multi.redact();
        assert_eq!(redacted.data, "[REDACTED]");
    }
}

/// Combined real-world scenarios
///
/// These tests combine multiple features to simulate realistic usage patterns.
mod real_world_scenarios {
    use super::*;

    #[test]
    fn user_account_model() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct UserAccount<Id: Clone> {
            id: u64,
            username: String,
            is_active: bool,
            #[sensitive(Pii)]
            full_name: String,
            #[sensitive(Email)]
            email: String,
            #[sensitive(PhoneNumber)]
            phone: Option<String>,
            #[sensitive(Secret)]
            password_hash: String,
            #[sensitive(Secret)]
            recovery_codes: Vec<String>,
            _id_type: PhantomData<Id>,
        }

        #[derive(Clone)]
        struct UserId;

        let account: UserAccount<UserId> = UserAccount {
            id: 12345,
            username: "johndoe".into(),
            is_active: true,
            full_name: "John Doe".into(),
            email: "john.doe@example.com".into(),
            phone: Some("+1-555-123-4567".into()),
            password_hash: "$argon2id$v=19$m=65536,t=3,p=4$...".into(),
            recovery_codes: vec!["ABCD-1234".into(), "EFGH-5678".into(), "IJKL-9012".into()],
            _id_type: PhantomData,
        };

        let redacted = account.clone().redact();

        assert_eq!(redacted.id, 12345);
        assert_eq!(redacted.username, "johndoe");
        assert!(redacted.is_active);
        assert_eq!(redacted.full_name, "******oe");
        assert_eq!(redacted.email, "jo******@example.com");
        assert_eq!(redacted.phone, Some("***********4567".into()));
        assert_eq!(redacted.password_hash, "[REDACTED]");
        assert_eq!(
            redacted.recovery_codes,
            vec!["[REDACTED]", "[REDACTED]", "[REDACTED]"]
        );

        // In test builds, Sensitive generates unredacted Debug (shows actual values)
        let debug_output = format!("{:?}", account);
        assert!(
            debug_output.contains("johndoe"),
            "test-mode Debug should show actual values, got: {debug_output}"
        );
    }

    #[test]
    fn api_response_logging() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct BillingAddress {
            #[sensitive(Secret)]
            lines: Vec<String>,
        }

        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct PaymentResponse {
            transaction_id: String,
            status: String,
            amount_cents: i64,
            currency: String,
            #[sensitive(PartiallyVisible)]
            card_number: String,
            #[sensitive(Secret)]
            cvv: Option<String>,
            #[sensitive(Secret)]
            billing_name: String,
            billing_address: Option<BillingAddress>,
        }

        let response = PaymentResponse {
            transaction_id: "txn_abc123".into(),
            status: "completed".into(),
            amount_cents: 9999,
            currency: "USD".into(),
            card_number: "4111111111111111".into(),
            cvv: Some("123".into()),
            billing_name: "John Doe".into(),
            billing_address: Some(BillingAddress {
                lines: vec![
                    "123 Main St".into(),
                    "Apt 4B".into(),
                    "New York, NY 10001".into(),
                ],
            }),
        };

        let safe_to_log = response.redact();

        assert_eq!(safe_to_log.transaction_id, "txn_abc123");
        assert_eq!(safe_to_log.status, "completed");
        assert_eq!(safe_to_log.amount_cents, 9999);
        assert_eq!(safe_to_log.currency, "USD");
        assert_eq!(safe_to_log.card_number, "************1111");
        assert_eq!(safe_to_log.cvv, Some("[REDACTED]".into()));
        assert_eq!(safe_to_log.billing_name, "[REDACTED]");
        assert_eq!(
            safe_to_log.billing_address.unwrap().lines,
            vec!["[REDACTED]", "[REDACTED]", "[REDACTED]"]
        );
    }
}
