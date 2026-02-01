//! End-to-end tests for the public redaction API.
//!
//! These tests exercise the integration of:
//! - `Sensitive` derive traversal,
//! - policy-bound redaction selection, and
//! - container traversal for common standard library types.

#![allow(clippy::redundant_locals)]

use std::collections::{BTreeMap, HashMap};

use redactable::{
    Default, NotSensitive, NotSensitiveDebugExt, NotSensitiveExt, Redactable, RedactableLeaf,
    RedactableWithPolicy, RedactedOutput, RedactedOutputExt, RedactionPolicy, SensitiveData,
    SensitiveValue, TextRedactionPolicy, ToRedactedOutput, Token,
};

fn log_redacted<T: ToRedactedOutput>(value: &T) -> RedactedOutput {
    value.to_redacted_output()
}

#[test]
fn test_text_policy_apply() {
    let sensitive = String::from("my_secret_password");
    let policy = TextRedactionPolicy::default_full();
    let redacted = policy.apply_to(&sensitive);
    assert_eq!(redacted, "[REDACTED]");
}

#[test]
fn test_engine_redacts_classified() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Token {
        #[sensitive(Default)]
        value: String,
    }

    let token = Token {
        value: "secret123".to_string(),
    };
    let redacted = token.redact();
    assert_eq!(redacted.value, "[REDACTED]");
}

#[test]
fn test_engine_redacts_nested_maps() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct ApiKeyEntry {
        #[sensitive(Token)]
        key: String,
    }

    let mut map: HashMap<String, ApiKeyEntry> = HashMap::new();
    map.insert(
        "primary".to_string(),
        ApiKeyEntry {
            key: "sk_live_abc123".to_string(),
        },
    );
    let redacted = map.redact();
    // Token keeps last 4
    assert_eq!(redacted.get("primary").unwrap().key, "**********c123");
}

#[test]
fn test_derive_policy_struct() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct User {
        #[sensitive(Default)]
        password: String,
        username: String,
    }

    let user = User {
        password: "my_secret_password".into(),
        username: "john_doe".into(),
    };

    let redacted: User = user.redact();

    assert_eq!(redacted.password, "[REDACTED]");
    assert_eq!(redacted.username, "john_doe");
}

#[test]
fn test_enum_derive() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    enum Credential {
        ApiKey {
            #[sensitive(Token)]
            key: String,
        },
        Password {
            #[sensitive(Default)]
            value: String,
        },
    }

    let api_key = Credential::ApiKey {
        key: "sk_live_abcdef123456".into(),
    };
    let redacted = api_key.redact();

    match &redacted {
        Credential::ApiKey { key } => {
            // Token keeps last 4: "sk_live_abcdef123456" (20 chars) → 16 asterisks + "3456"
            assert_eq!(key, "****************3456");
        }
        _ => panic!("Wrong variant"),
    }

    let password = Credential::Password {
        value: "super_secret".into(),
    };
    let redacted = password.redact();
    match &redacted {
        Credential::Password { value } => {
            assert_eq!(value, "[REDACTED]");
        }
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_redacted_guard_type() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct SensitiveData2 {
        #[sensitive(Default)]
        data: String,
    }

    let secret = SensitiveData2 {
        data: "confidential".into(),
    };

    let guarded = secret.redact();
    assert_eq!(guarded.data, "[REDACTED]");
}

#[test]
fn test_nested_struct_derive() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Address {
        #[sensitive(Default)]
        street: String,
        city: String,
    }

    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Person {
        #[sensitive(Default)]
        name: String,
        address: Address, // Nested containers are walked automatically
    }

    let person = Person {
        name: "John Doe".into(),
        address: Address {
            street: "123 Main Street".into(),
            city: "Springfield".into(),
        },
    };

    let redacted = person.redact();

    assert_eq!(redacted.name, "[REDACTED]");
    assert_eq!(redacted.address.street, "[REDACTED]");
    assert_eq!(redacted.address.city, "Springfield");
}

#[test]
fn test_btreemap_traversal() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct SensitiveValue2 {
        #[sensitive(Default)]
        value: String,
    }

    let mut map: BTreeMap<String, SensitiveValue2> = BTreeMap::new();
    map.insert(
        "key".to_string(),
        SensitiveValue2 {
            value: "value".to_string(),
        },
    );
    let redacted = map.redact();
    assert_eq!(redacted.get("key").unwrap().value, "[REDACTED]");
}

#[test]
fn test_custom_policy() {
    // Users can define their own policy types
    #[derive(Clone, Copy)]
    struct InternalId;

    impl RedactionPolicy for InternalId {
        fn policy() -> TextRedactionPolicy {
            // Custom policy: mask all but last 2 characters
            TextRedactionPolicy::keep_last(2)
        }
    }

    #[derive(Clone, SensitiveData)]
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

// ============================================================================
// Additional coverage tests for edge cases and type variations
// ============================================================================

#[test]
fn test_tuple_struct() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct TupleSensitive(#[sensitive(Default)] String, String);

    let tuple = TupleSensitive("secret_value".into(), "public_value".into());
    let redacted = tuple.redact();

    assert_eq!(redacted.0, "[REDACTED]");
    assert_eq!(redacted.1, "public_value");
}

#[test]
fn test_tuple_struct_multiple_sensitive() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct AuthCredentials(
        #[sensitive(Default)] String, // password
        #[sensitive(Token)] String,   // api_key
        String,                       // username
    );

    let creds = AuthCredentials("hunter2".into(), "sk_live_abc123def".into(), "alice".into());
    let redacted = creds.redact();

    assert_eq!(redacted.0, "[REDACTED]");
    assert_eq!(redacted.1, "*************3def"); // Token keeps last 4
    assert_eq!(redacted.2, "alice");
}

#[test]
fn test_enum_tuple_variant() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    enum Auth {
        ApiKey(#[sensitive(Token)] String),
        Basic(#[sensitive(Default)] String, String),
        None,
    }

    // Test tuple variant with single field
    let api_key = Auth::ApiKey("sk_live_abc123def456ghi".into());
    let redacted = api_key.redact();
    match redacted {
        // "sk_live_abc123def456ghi" is 22 chars, keep_last(4) shows "6ghi"
        Auth::ApiKey(key) => assert_eq!(key, "*******************6ghi"),
        _ => panic!("Wrong variant"),
    }

    // Test tuple variant with multiple fields
    let basic = Auth::Basic("super_secret_password".into(), "alice".into());
    let redacted = basic.redact();
    match redacted {
        Auth::Basic(password, username) => {
            assert_eq!(password, "[REDACTED]");
            assert_eq!(username, "alice");
        }
        _ => panic!("Wrong variant"),
    }

    // Test unit variant
    let none = Auth::None;
    let redacted = none.redact();
    match redacted {
        Auth::None => {}
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_unit_struct() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct UnitMarker;

    let marker = UnitMarker;
    let redacted = marker.redact();
    // Unit structs just return themselves
    let _ = redacted; // Ensure it compiles and doesn't panic
}

#[test]
fn test_box_traversal() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct BoxedSensitive {
        #[sensitive(Default)]
        value: String,
    }

    let boxed: Box<BoxedSensitive> = Box::new(BoxedSensitive {
        value: "secret_in_box".into(),
    });
    let redacted = boxed.redact();

    assert_eq!(redacted.value, "[REDACTED]");
}

#[test]
fn test_nested_box_traversal() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct DeepSensitive {
        #[sensitive(Default)]
        value: String,
    }

    let nested: Box<Box<DeepSensitive>> = Box::new(Box::new(DeepSensitive {
        value: "deeply_nested".into(),
    }));
    let redacted = nested.redact();

    assert_eq!(redacted.value, "[REDACTED]");
}

#[test]
fn test_nested_generics() {
    // Test nested structs with concrete types - walked by default
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Inner {
        #[sensitive(Default)]
        secret: String,
        public: i32,
    }

    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Outer {
        inner: Inner, // Nested containers are walked automatically
        label: String,
    }

    let outer = Outer {
        inner: Inner {
            secret: "inner_secret".into(),
            public: 42,
        },
        label: "test".into(),
    };

    let redacted = outer.redact();

    assert_eq!(redacted.inner.secret, "[REDACTED]");
    assert_eq!(redacted.inner.public, 42);
    assert_eq!(redacted.label, "test");
}

#[test]
fn test_generic_container_with_sensitive() {
    // Test that generic containers work with SensitiveData types
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct SensitiveWrapper {
        #[sensitive(Default)]
        value: String,
    }

    // Vec<T> where T: SensitiveData
    let vec_data = vec![
        SensitiveWrapper {
            value: "secret1".into(),
        },
        SensitiveWrapper {
            value: "secret2".into(),
        },
    ];
    let redacted = vec_data.redact();
    assert_eq!(redacted[0].value, "[REDACTED]");
    assert_eq!(redacted[1].value, "[REDACTED]");

    // Option<T> where T: SensitiveData
    let opt_data = Some(SensitiveWrapper {
        value: "secret".into(),
    });
    let redacted = opt_data.redact();
    assert_eq!(redacted.unwrap().value, "[REDACTED]");

    // HashMap<K, V> where V: SensitiveData
    let mut map_data: HashMap<String, SensitiveWrapper> = HashMap::new();
    map_data.insert(
        "key".into(),
        SensitiveWrapper {
            value: "secret".into(),
        },
    );
    let redacted = map_data.redact();
    assert_eq!(redacted["key"].value, "[REDACTED]");
}

#[test]
fn test_option_vec_nesting() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct SensitiveItem {
        #[sensitive(Default)]
        value: String,
    }

    let data: Option<Vec<SensitiveItem>> = Some(vec![
        SensitiveItem {
            value: "first".into(),
        },
        SensitiveItem {
            value: "second".into(),
        },
    ]);

    let redacted = data.redact();

    let items = redacted.unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].value, "[REDACTED]");
    assert_eq!(items[1].value, "[REDACTED]");
}

#[test]
fn test_scalar_redaction() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct ScalarData {
        #[sensitive(Default)]
        secret_number: i32,
        #[sensitive(Default)]
        secret_flag: bool,
        #[sensitive(Default)]
        secret_char: char,
        public_number: i32,
    }

    let data = ScalarData {
        secret_number: 42,
        secret_flag: true,
        secret_char: '*',
        public_number: 100,
    };

    let redacted = data.redact();

    assert_eq!(redacted.secret_number, 0); // Default for i32
    assert!(!redacted.secret_flag); // Default for bool is false
    assert_eq!(redacted.secret_char, '*'); // char redacts to '*'
    assert_eq!(redacted.public_number, 100); // Non-sensitive unchanged
}

#[test]
fn test_scalar_types_comprehensive() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct AllScalars {
        #[sensitive(Default)]
        i8_val: i8,
        #[sensitive(Default)]
        i16_val: i16,
        #[sensitive(Default)]
        i32_val: i32,
        #[sensitive(Default)]
        i64_val: i64,
        #[sensitive(Default)]
        u8_val: u8,
        #[sensitive(Default)]
        u16_val: u16,
        #[sensitive(Default)]
        u32_val: u32,
        #[sensitive(Default)]
        u64_val: u64,
        #[sensitive(Default)]
        f32_val: f32,
        #[sensitive(Default)]
        f64_val: f64,
        #[sensitive(Default)]
        bool_val: bool,
        #[sensitive(Default)]
        char_val: char,
    }

    let data = AllScalars {
        i8_val: 1,
        i16_val: 2,
        i32_val: 3,
        i64_val: 4,
        u8_val: 5,
        u16_val: 6,
        u32_val: 7,
        u64_val: 8,
        f32_val: 9.5,
        f64_val: 10.5,
        bool_val: true,
        char_val: 'A',
    };

    let redacted = data.redact();

    // All numeric types redact to 0
    assert_eq!(redacted.i8_val, 0);
    assert_eq!(redacted.i16_val, 0);
    assert_eq!(redacted.i32_val, 0);
    assert_eq!(redacted.i64_val, 0);
    assert_eq!(redacted.u8_val, 0);
    assert_eq!(redacted.u16_val, 0);
    assert_eq!(redacted.u32_val, 0);
    assert_eq!(redacted.u64_val, 0);
    assert_eq!(redacted.f32_val, 0.0);
    assert_eq!(redacted.f64_val, 0.0);

    // bool redacts to false (default)
    assert!(!redacted.bool_val);

    // char redacts to '*' (special case)
    assert_eq!(redacted.char_val, '*');
}

#[test]
fn test_mixed_named_and_sensitive_fields() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct MixedRecord {
        id: u64,
        #[sensitive(Default)]
        ssn: String,
        name: String,
        #[sensitive(Default)]
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

    assert_eq!(redacted.id, 12345); // Non-sensitive, unchanged
    assert_eq!(redacted.ssn, "[REDACTED]"); // Default: full redaction
    assert_eq!(redacted.name, "John Doe"); // Non-sensitive, unchanged
    assert_eq!(redacted.internal_score, 0); // Bare sensitive scalar
    assert_eq!(redacted.api_key, "****************6789"); // Token: keep last 4 (20 - 4 = 16 asterisks)
    assert_eq!(redacted.public_data, "visible"); // Non-sensitive, unchanged
}

// ============================================================================
// Nested wrapper policy tests (PolicyApplicable)
// ============================================================================

#[test]
fn test_nested_wrapper_option_vec() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct NestedWrappers {
        #[sensitive(Default)]
        addresses: Option<Vec<String>>,
    }

    let n = NestedWrappers {
        addresses: Some(vec!["123 Main St".into(), "456 Oak Ave".into()]),
    };
    let redacted = n.redact();

    let addrs = redacted.addresses.unwrap();
    assert_eq!(addrs[0], "[REDACTED]");
    assert_eq!(addrs[1], "[REDACTED]");
}

#[test]
fn test_nested_wrapper_vec_option() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct NestedWrappers {
        #[sensitive(Default)]
        values: Vec<Option<String>>,
    }

    let n = NestedWrappers {
        values: vec![Some("secret1".into()), None, Some("secret2".into())],
    };
    let redacted = n.redact();

    assert_eq!(redacted.values[0], Some("[REDACTED]".into()));
    assert_eq!(redacted.values[1], None);
    assert_eq!(redacted.values[2], Some("[REDACTED]".into()));
}

#[test]
fn test_nested_wrapper_deeply_nested() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct DeepNest {
        #[sensitive(Default)]
        values: Option<Vec<Option<String>>>,
    }

    let n = DeepNest {
        values: Some(vec![Some("secret".into()), None]),
    };
    let redacted = n.redact();

    let values = redacted.values.unwrap();
    assert_eq!(values[0], Some("[REDACTED]".into()));
    assert_eq!(values[1], None);
}

#[test]
fn test_nested_wrapper_hashmap_vec() {
    use std::collections::HashMap;

    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct MapWithVec {
        #[sensitive(Default)]
        data: HashMap<String, Vec<String>>,
    }

    let mut data = HashMap::new();
    data.insert("secrets".into(), vec!["secret1".into(), "secret2".into()]);

    let n = MapWithVec { data };
    let redacted = n.redact();

    assert_eq!(
        redacted.data.get("secrets"),
        Some(&vec!["[REDACTED]".to_string(), "[REDACTED]".to_string()])
    );
}

#[test]
fn test_external_types_pass_through() {
    // Simulate external types that implement RedactableContainer as pass-through
    #[derive(Clone, PartialEq, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct ExternalTimestamp(u64);

    #[derive(Clone, PartialEq, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct ExternalDecimal(f64);

    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Transaction {
        #[sensitive(Default)]
        account_number: String,
        // External types pass through unchanged when they implement RedactableContainer
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
    assert_eq!(redacted.timestamp, ExternalTimestamp(1704067200)); // Unchanged
    assert_eq!(redacted.amount, ExternalDecimal(99.99)); // Unchanged
    assert_eq!(redacted.description, "Coffee"); // Unchanged
}

#[test]
fn test_external_types_with_sensitive_wrapper() {
    #[derive(Clone, Debug, PartialEq)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct ExternalId(String);

    impl RedactableLeaf for ExternalId {
        fn as_str(&self) -> &str {
            self.0.as_str()
        }

        fn from_redacted(redacted: String) -> Self {
            Self(redacted)
        }
    }

    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Record {
        #[sensitive(Default)]
        token: String,
        external_id: SensitiveValue<ExternalId, Default>,
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
fn test_external_types_with_policy_trait() {
    #[derive(Clone, Debug, PartialEq)]
    #[cfg_attr(feature = "json", derive(serde::Serialize))]
    struct ExternalType(String);

    #[derive(Clone, Copy)]
    struct ExternalTypePolicy;

    impl RedactionPolicy for ExternalTypePolicy {
        fn policy() -> TextRedactionPolicy {
            TextRedactionPolicy::keep_last(2)
        }
    }

    impl RedactableWithPolicy<ExternalTypePolicy> for ExternalType {
        fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self {
            Self(policy.apply_to(&self.0))
        }

        fn redacted_string(&self, policy: &TextRedactionPolicy) -> String {
            policy.apply_to(&self.0)
        }
    }

    #[derive(Clone, SensitiveData)]
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
fn test_not_sensitive_derives_sensitive_type() {
    #[derive(Clone, NotSensitive)]
    struct PublicInfo {
        id: u64,
        label: String,
    }

    let value = PublicInfo {
        id: 42,
        label: "ok".to_string(),
    };

    let redacted = value.clone().redact();
    assert_eq!(redacted.id, value.id);
    assert_eq!(redacted.label, value.label);
}

#[test]
fn test_not_sensitive_does_not_walk_nested() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Inner {
        #[sensitive(Default)]
        secret: String,
    }

    #[derive(Clone, NotSensitive)]
    struct Outer {
        inner: Inner,
    }

    let value = Outer {
        inner: Inner {
            secret: "top_secret".into(),
        },
    };

    let redacted = value.clone().redact();
    assert_eq!(redacted.inner.secret, value.inner.secret);
}

#[test]
fn test_not_sensitive_debug_wrapper() {
    #[derive(Debug)]
    #[allow(dead_code)]
    struct DebugOnly {
        id: u64,
    }

    let value = DebugOnly { id: 7 };
    let redacted = log_redacted(&value.not_sensitive_debug());
    assert_eq!(
        redacted,
        RedactedOutput::Text("DebugOnly { id: 7 }".to_string())
    );
}

#[test]
fn test_log_redacted_bound_accepts_escape_hatches() {
    #[derive(Clone)]
    #[cfg_attr(feature = "json", derive(serde::Serialize))]
    struct ExternalId(String);

    impl RedactableLeaf for ExternalId {
        fn as_str(&self) -> &str {
            self.0.as_str()
        }

        fn from_redacted(redacted: String) -> Self {
            Self(redacted)
        }
    }

    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "json", derive(serde::Serialize))]
    struct Event {
        id: SensitiveValue<ExternalId, Default>,
        status: String,
    }

    let event = Event {
        id: SensitiveValue::from(ExternalId("abc".into())),
        status: "ok".into(),
    };

    assert_eq!(
        log_redacted(&event.id),
        RedactedOutput::Text("[REDACTED]".to_string())
    );
    assert_eq!(
        log_redacted(&event.status.not_sensitive()),
        RedactedOutput::Text("ok".to_string())
    );

    let debug_output = log_redacted(&event.status.not_sensitive_debug());
    assert_eq!(debug_output, RedactedOutput::Text("\"ok\"".to_string()));

    let structured = log_redacted(&event.redacted_output());
    assert_eq!(
        structured,
        RedactedOutput::Text(
            "Event { id: SensitiveValue(\"[REDACTED]\"), status: \"ok\" }".to_string()
        )
    );
}

#[test]
fn test_redacted_output_wrapper_for_sensitive_data() {
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Event {
        #[sensitive(Default)]
        token: String,
        name: String,
    }

    let event = Event {
        token: "secret".into(),
        name: "alpha".into(),
    };

    let redacted_output = log_redacted(&event.redacted_output());
    assert_eq!(
        redacted_output,
        RedactedOutput::Text("Event { token: \"[REDACTED]\", name: \"alpha\" }".to_string())
    );
}

#[test]
fn test_nested_struct_walks_by_default() {
    // Nested structs that derive SensitiveData are walked by default.
    #[derive(Clone, SensitiveData, PartialEq)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    #[sensitive(skip_debug)]
    struct Credentials {
        #[sensitive(Default)]
        password: String,
        username: String,
    }

    impl std::fmt::Debug for Credentials {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Credentials")
                .field("password", &self.password)
                .field("username", &self.username)
                .finish()
        }
    }

    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct UserWithAnnotation {
        creds: Credentials, // Nested containers are walked automatically
    }

    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct UserWithoutAnnotation {
        creds: Credentials,
    }

    let creds = Credentials {
        password: "secret123".into(),
        username: "alice".into(),
    };

    // With #[sensitive], the inner struct is walked
    let user_annotated = UserWithAnnotation {
        creds: creds.clone(),
    };
    let redacted_annotated = user_annotated.redact();
    assert_eq!(redacted_annotated.creds.password, "[REDACTED]");
    assert_eq!(redacted_annotated.creds.username, "alice");

    // Without annotation, the inner struct is still walked
    let user_unannotated = UserWithoutAnnotation {
        creds: creds.clone(),
    };
    let redacted_unannotated = user_unannotated.redact();
    assert_eq!(redacted_unannotated.creds.password, "[REDACTED]");
    assert_eq!(redacted_unannotated.creds.username, "alice");
}

#[test]
fn test_type_with_both_redactable_leaf_and_sensitive_container() {
    // A type can implement both RedactableLeaf and derive Sensitive.
    // Which trait is used depends on how the field is declared:
    // - SensitiveValue<T, Policy> wrapper uses RedactableLeaf (redacts as a unit)
    // - Bare type (unannotated or #[sensitive]) uses RedactableContainer (traverses fields)
    //
    // Note: #[sensitive(Policy)] only works on String/Cow<str> via PolicyApplicable.
    // Custom RedactableLeaf types must use the SensitiveValue<T, Policy> wrapper.

    #[derive(Clone, PartialEq, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    #[sensitive(skip_debug)]
    struct UserId {
        prefix: String,
        #[sensitive(Default)]
        value: String,
    }

    impl std::fmt::Debug for UserId {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("UserId")
                .field("prefix", &self.prefix)
                .field("value", &self.value)
                .finish()
        }
    }

    // Also implement RedactableLeaf so it can be used with SensitiveValue<T, Policy>
    impl RedactableLeaf for UserId {
        fn as_str(&self) -> &str {
            // When treated as a leaf, we expose the value for redaction
            &self.value
        }

        fn from_redacted(redacted: String) -> Self {
            Self {
                prefix: "redacted".into(),
                value: redacted,
            }
        }
    }

    // When used as an unannotated field, Sensitive is used (fields are traversed)
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct AccountTraversed {
        user_id: UserId, // No annotation -> walks into UserId's fields
    }

    // When wrapped in SensitiveValue<T, Policy>, RedactableLeaf is used (redacted as unit)
    #[derive(Clone, SensitiveData)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct AccountAsLeaf {
        user_id: SensitiveValue<UserId, Token>, // SensitiveValue wrapper -> treats UserId as a leaf
    }

    let user_id = UserId {
        prefix: "usr".into(),
        value: "12345678".into(),
    };

    // Test 1: Unannotated field uses Sensitive (traverses fields)
    let account_traversed = AccountTraversed {
        user_id: user_id.clone(),
    };
    let redacted_traversed = account_traversed.redact();
    // The inner #[sensitive(Default)] on `value` is applied
    assert_eq!(redacted_traversed.user_id.prefix, "usr"); // unchanged
    assert_eq!(redacted_traversed.user_id.value, "[REDACTED]"); // redacted by inner annotation

    // Test 2: SensitiveValue<T, Policy> wrapper uses RedactableLeaf (redacts as unit)
    let account_as_leaf = AccountAsLeaf {
        user_id: SensitiveValue::from(user_id.clone()),
    };
    let redacted_as_leaf = account_as_leaf.redact();
    // The Token policy is applied to the whole UserId via RedactableLeaf
    assert_eq!(redacted_as_leaf.user_id.expose().prefix, "redacted"); // from_redacted was called
    assert_eq!(redacted_as_leaf.user_id.expose().value, "****5678"); // Token keeps last 4
}
