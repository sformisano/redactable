//! Client scenario tests - simulating real-world adoption patterns.
//!
//! These tests verify that the issues encountered during library adoption are fixed.
//! Each test is documented with the original problem and expected behavior.

#![allow(clippy::redundant_locals, clippy::box_collection)]

use redactable::{RedactionPolicy, TextPolicyKind, TextRedactionPolicy};

/// Custom policy that fully redacts (for testing custom policies)
#[derive(Clone, Copy)]
struct FullRedact;
impl RedactionPolicy for FullRedact {
    type Kind = TextPolicyKind;

    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::default_full()
    }
}

/// Support payment views retain the last four card digits for transaction matching.
#[derive(Clone, Copy)]
struct CardSuffix;
impl RedactionPolicy for CardSuffix {
    type Kind = TextPolicyKind;

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
    use super::FullRedact;
    use redactable::{Email, PhoneNumber, Redactable, Secret, Sensitive, ToRedacted};

    #[test]
    fn applies_policy_to_option_string() {
        #[derive(Clone, Sensitive, serde::Serialize)]
        struct UserProfile {
            #[not_sensitive]
            username: String,
            // Support uses mailbox and phone fragments to distinguish contact routes.
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
        #[derive(Clone, Sensitive, serde::Serialize)]
        struct AuditLog {
            #[not_sensitive]
            event_type: String,
            #[sensitive(FullRedact)]
            affected_users: Vec<String>,
            #[sensitive(FullRedact)]
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
        assert_eq!(redacted.ip_addresses, vec!["[REDACTED]", "[REDACTED]"]);

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
        #[derive(Clone, Sensitive, serde::Serialize)]
        struct EncryptedPayload {
            #[not_sensitive]
            algorithm: String,
            #[sensitive(Secret)]
            key: Box<String>,
            #[not_sensitive]
            iv: Box<String>,
        }

        let payload = EncryptedPayload {
            algorithm: "AES-256-GCM".into(),
            key: Box::new("super_secret_encryption_key_12345".into()),
            iv: Box::new("000102030405060708090a0b".into()),
        };

        let original = serde_json::to_value(&payload).unwrap();
        let redacted = payload.clone().redact();
        assert_eq!(redacted.algorithm, "AES-256-GCM");
        assert_eq!(*redacted.key, "[REDACTED]");
        assert_eq!(*redacted.iv, "000102030405060708090a0b");
        assert_eq!(
            payload.to_redacted().json(),
            serde_json::json!({
                "algorithm": "AES-256-GCM", "key": "[REDACTED]", "iv": "000102030405060708090a0b"
            })
        );
        assert_eq!(serde_json::to_value(&payload).unwrap(), original);
        assert_eq!(*payload.key, "super_secret_encryption_key_12345");
    }

    #[test]
    fn handles_mixed_wrapper_types() {
        #[derive(Clone, Sensitive, serde::Serialize)]
        struct ConnectionSettings {
            #[not_sensitive]
            host: String,
            #[not_sensitive]
            port: u16,
            #[not_sensitive]
            database: String,
            #[not_sensitive]
            username: String,
            #[sensitive(Secret)]
            password: String,
        }

        #[derive(Clone, Sensitive, serde::Serialize)]
        struct DatabaseConfig {
            #[not_sensitive]
            host: String,
            #[not_sensitive]
            port: u16,
            #[sensitive(Secret)]
            password: Option<String>,
            #[sensitive(Secret)]
            tls_private_key: Box<String>,
            connections: Vec<ConnectionSettings>,
        }

        let config = DatabaseConfig {
            host: "db.example.com".into(),
            port: 5432,
            password: Some("super_secret_db_password".into()),
            tls_private_key: Box::new("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PRIVATE KEY-----".into()),
            connections: vec![
                ConnectionSettings { host: "primary.example.com".into(), port: 5432, database: "reviews".into(), username: "review_service".into(), password: "primary-password-canary".into() },
                ConnectionSettings { host: "replica.example.com".into(), port: 5433, database: "reviews_archive".into(), username: "review_service".into(), password: "replica-password-canary".into() },
            ],
        };

        let original = serde_json::to_value(&config).unwrap();
        let redacted = config.clone().redact();
        assert_eq!(redacted.host, "db.example.com");
        assert_eq!(redacted.port, 5432);
        assert_eq!(redacted.password, Some("[REDACTED]".into()));
        assert_eq!(*redacted.tls_private_key, "[REDACTED]");
        assert_eq!(redacted.connections[0].host, "primary.example.com");
        assert_eq!(redacted.connections[0].database, "reviews");
        assert_eq!(redacted.connections[0].password, "[REDACTED]");
        assert_eq!(redacted.connections[1].host, "replica.example.com");
        assert_eq!(redacted.connections[1].port, 5433);
        assert_eq!(redacted.connections[1].database, "reviews_archive");
        assert_eq!(redacted.connections[1].password, "[REDACTED]");
        let diagnostic = config.to_redacted();
        assert_eq!(
            diagnostic.json(),
            serde_json::json!({
                "host": "db.example.com", "port": 5432, "password": "[REDACTED]", "tls_private_key": "[REDACTED]",
                "connections": [
                    {"host": "primary.example.com", "port": 5432, "database": "reviews", "username": "review_service", "password": "[REDACTED]"},
                    {"host": "replica.example.com", "port": 5433, "database": "reviews_archive", "username": "review_service", "password": "[REDACTED]"}
                ]
            })
        );
        for secret in [
            "super_secret_db_password",
            "BEGIN PRIVATE KEY",
            "primary-password-canary",
            "replica-password-canary",
        ] {
            assert!(!diagnostic.text().contains(secret));
            assert!(!format!("{config:?}").contains(secret));
        }
        assert_eq!(serde_json::to_value(&config).unwrap(), original);
        assert_eq!(config.connections[0].password, "primary-password-canary");
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
    use redactable::{Redactable, Secret, Sensitive};
    use std::marker::PhantomData;

    #[test]
    fn works_in_generic_struct() {
        #[derive(Clone, Sensitive, serde::Serialize)]
        struct TypedId<T> {
            #[not_sensitive]
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

        assert_eq!(redacted_user.id, "user_abc123456789");
        assert_eq!(redacted_order.id, "order_xyz987654321");
    }

    #[test]
    fn works_with_lifetimes() {
        #[derive(Clone, Sensitive, serde::Serialize)]
        struct BorrowedRef<'a, T> {
            #[not_sensitive]
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
        #[derive(Clone, Sensitive, serde::Serialize)]
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
    use super::CardSuffix;
    use redactable::{Redactable, Secret, Sensitive};
    use std::marker::PhantomData;

    #[test]
    fn user_account_model() {
        #[derive(Clone, Sensitive, serde::Serialize)]
        struct UserAccount<Id: Clone> {
            #[not_sensitive]
            id: u64,
            #[not_sensitive]
            username: String,
            #[not_sensitive]
            is_active: bool,
            #[sensitive(Secret)]
            full_name: String,
            #[sensitive(Secret)]
            email: String,
            #[sensitive(Secret)]
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
        assert_eq!(redacted.full_name, "[REDACTED]");
        assert_eq!(redacted.email, "[REDACTED]");
        assert_eq!(redacted.phone, Some("[REDACTED]".into()));
        assert_eq!(redacted.password_hash, "[REDACTED]");
        assert_eq!(
            redacted.recovery_codes,
            vec!["[REDACTED]", "[REDACTED]", "[REDACTED]"]
        );

        // Explicit public fields remain visible; policy fields use full masks.
        let debug_output = format!("{:?}", account);
        assert!(
            debug_output.contains("johndoe"),
            "declared public username should remain visible, got: {debug_output}"
        );
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("John Doe"));
        assert!(!debug_output.contains("john.doe@example.com"));
        assert!(!debug_output.contains("$argon2id$"));
    }

    #[test]
    fn api_response_logging() {
        #[derive(Clone, Sensitive, serde::Serialize)]
        struct BillingAddress {
            #[sensitive(Secret)]
            lines: Vec<String>,
        }

        #[derive(Clone, Sensitive, serde::Serialize)]
        struct PaymentResponse {
            #[not_sensitive]
            transaction_id: String,
            #[not_sensitive]
            status: String,
            #[not_sensitive]
            amount_cents: i64,
            #[not_sensitive]
            currency: String,
            #[sensitive(CardSuffix)]
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
