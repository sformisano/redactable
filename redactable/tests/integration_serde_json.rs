//! Integration tests for serde_json::Value support.
//!
//! serde_json::Value is treated as an opaque leaf type. Any policy application
//! fully redacts it to Value::String("[REDACTED]"). This is safe-by-default.

#![cfg(feature = "json")]

use redactable::{Default, Redactable, RedactableDisplay, Sensitive, Token};
use serde_json::{Value, json};

// =============================================================================
// Basic Policy Application
// =============================================================================

#[test]
fn test_value_with_default_policy() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Payload {
        #[sensitive(Default)]
        data: Value,
    }

    let payload = Payload {
        data: json!({"secret": "password123", "nested": {"key": "value"}}),
    };

    let redacted = payload.redact();
    assert_eq!(redacted.data, Value::String("[REDACTED]".to_string()));
}

#[test]
fn test_value_with_token_policy() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Payload {
        #[sensitive(Token)]
        data: Value,
    }

    let payload = Payload {
        data: json!({"api_key": "sk_live_abc123"}),
    };

    let redacted = payload.redact();
    // Token policy should still fully redact Value (it's opaque)
    assert_eq!(redacted.data, Value::String("[REDACTED]".to_string()));
}

#[test]
fn test_value_with_custom_policy() {
    use redactable::{RedactionPolicy, TextRedactionPolicy};

    #[derive(Clone, Copy)]
    struct CustomPolicy;

    impl RedactionPolicy for CustomPolicy {
        fn policy() -> TextRedactionPolicy {
            TextRedactionPolicy::keep_last(4)
        }
    }

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Payload {
        #[sensitive(CustomPolicy)]
        data: Value,
    }

    let payload = Payload {
        data: json!({"anything": "here"}),
    };

    let redacted = payload.redact();
    // Any policy should fully redact Value (it's opaque)
    assert_eq!(redacted.data, Value::String("[REDACTED]".to_string()));
}

// =============================================================================
// Unannotated Value Fields (Safe-by-Default)
// =============================================================================

#[test]
fn test_unannotated_value_field_redacts_by_default() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Payload {
        // No annotation - should redact by default for Value type
        data: Value,
    }

    let payload = Payload {
        data: json!({"potentially_sensitive": "data"}),
    };

    let redacted = payload.redact();
    // Unannotated Value fields are fully redacted (safe-by-default)
    assert_eq!(redacted.data, Value::String("[REDACTED]".to_string()));
}

#[test]
fn test_mixed_fields_with_unannotated_value() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Record {
        id: u64,
        name: String,
        // Unannotated Value field
        metadata: Value,
        #[sensitive(Default)]
        password: String,
    }

    let record = Record {
        id: 123,
        name: "test".to_string(),
        metadata: json!({"key": "value"}),
        password: "secret".to_string(),
    };

    let redacted = record.redact();
    assert_eq!(redacted.id, 123); // Non-sensitive, unchanged
    assert_eq!(redacted.name, "test"); // Non-sensitive, unchanged
    assert_eq!(redacted.metadata, Value::String("[REDACTED]".to_string())); // Redacted by default
    assert_eq!(redacted.password, "[REDACTED]"); // Explicitly redacted
}

// =============================================================================
// Option<Value> Support
// =============================================================================

#[test]
fn test_option_value_some() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Payload {
        #[sensitive(Default)]
        data: Option<Value>,
    }

    let payload = Payload {
        data: Some(json!({"secret": "data"})),
    };

    let redacted = payload.redact();
    assert_eq!(redacted.data, Some(Value::String("[REDACTED]".to_string())));
}

#[test]
fn test_option_value_none() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Payload {
        #[sensitive(Default)]
        data: Option<Value>,
    }

    let payload = Payload { data: None };

    let redacted = payload.redact();
    assert_eq!(redacted.data, None);
}

#[test]
fn test_option_value_unannotated() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Payload {
        // Unannotated Option<Value>
        data: Option<Value>,
    }

    let payload = Payload {
        data: Some(json!({"key": "value"})),
    };

    let redacted = payload.redact();
    assert_eq!(redacted.data, Some(Value::String("[REDACTED]".to_string())));
}

// =============================================================================
// Vec<Value> Support
// =============================================================================

#[test]
fn test_vec_value() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Payload {
        #[sensitive(Default)]
        items: Vec<Value>,
    }

    let payload = Payload {
        items: vec![json!({"a": 1}), json!({"b": 2}), json!({"c": 3})],
    };

    let redacted = payload.redact();
    assert_eq!(redacted.items.len(), 3);
    for item in &redacted.items {
        assert_eq!(item, &Value::String("[REDACTED]".to_string()));
    }
}

#[test]
fn test_vec_value_empty() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Payload {
        #[sensitive(Default)]
        items: Vec<Value>,
    }

    let payload = Payload { items: vec![] };

    let redacted = payload.redact();
    assert!(redacted.items.is_empty());
}

// =============================================================================
// Deeply Nested Structures
// =============================================================================

#[test]
fn test_option_vec_value() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Payload {
        #[sensitive(Default)]
        data: Option<Vec<Value>>,
    }

    let payload = Payload {
        data: Some(vec![json!({"a": 1}), json!({"b": 2})]),
    };

    let redacted = payload.redact();
    let items = redacted.data.unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0], Value::String("[REDACTED]".to_string()));
    assert_eq!(items[1], Value::String("[REDACTED]".to_string()));
}

#[test]
fn test_vec_option_value() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Payload {
        #[sensitive(Default)]
        data: Vec<Option<Value>>,
    }

    let payload = Payload {
        data: vec![Some(json!({"a": 1})), None, Some(json!({"b": 2}))],
    };

    let redacted = payload.redact();
    assert_eq!(redacted.data.len(), 3);
    assert_eq!(
        redacted.data[0],
        Some(Value::String("[REDACTED]".to_string()))
    );
    assert_eq!(redacted.data[1], None);
    assert_eq!(
        redacted.data[2],
        Some(Value::String("[REDACTED]".to_string()))
    );
}

// =============================================================================
// HashMap/BTreeMap with Value
// =============================================================================

#[test]
fn test_hashmap_with_value_values() {
    use std::collections::HashMap;

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Payload {
        #[sensitive(Default)]
        data: HashMap<String, Value>,
    }

    let mut data = HashMap::new();
    data.insert("key1".to_string(), json!({"secret": "value1"}));
    data.insert("key2".to_string(), json!({"secret": "value2"}));

    let payload = Payload { data };

    let redacted = payload.redact();
    // Keys are preserved, values are redacted
    assert!(redacted.data.contains_key("key1"));
    assert!(redacted.data.contains_key("key2"));
    assert_eq!(
        redacted.data.get("key1"),
        Some(&Value::String("[REDACTED]".to_string()))
    );
    assert_eq!(
        redacted.data.get("key2"),
        Some(&Value::String("[REDACTED]".to_string()))
    );
}

#[test]
fn test_btreemap_with_value_values() {
    use std::collections::BTreeMap;

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Payload {
        #[sensitive(Default)]
        data: BTreeMap<String, Value>,
    }

    let mut data = BTreeMap::new();
    data.insert("alpha".to_string(), json!({"a": 1}));
    data.insert("beta".to_string(), json!({"b": 2}));

    let payload = Payload { data };

    let redacted = payload.redact();
    assert_eq!(
        redacted.data.get("alpha"),
        Some(&Value::String("[REDACTED]".to_string()))
    );
    assert_eq!(
        redacted.data.get("beta"),
        Some(&Value::String("[REDACTED]".to_string()))
    );
}

// =============================================================================
// RedactableDisplay Tests
// =============================================================================

#[test]
fn test_value_redactable_display() {
    let value = json!({"secret": "password", "nested": {"key": "value"}});

    // RedactableDisplay should always show "[REDACTED]"
    let display = format!("{}", value.redacted_display());
    assert_eq!(display, "[REDACTED]");
}

#[test]
fn test_value_redactable_display_various_types() {
    // Test with different JSON value types - all should display as "[REDACTED]"
    let test_cases = vec![
        json!(null),
        json!(true),
        json!(false),
        json!(42),
        json!(3.5),
        json!("string"),
        json!([1, 2, 3]),
        json!({"key": "value"}),
    ];

    for value in test_cases {
        let display = format!("{}", value.redacted_display());
        assert_eq!(display, "[REDACTED]", "Failed for value: {value}");
    }
}

// =============================================================================
// Enum Variants with Value
// =============================================================================

#[test]
fn test_enum_with_value_field() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    #[allow(dead_code)]
    enum Event {
        Payload {
            #[sensitive(Default)]
            data: Value,
        },
        Empty,
    }

    let event = Event::Payload {
        data: json!({"event": "data"}),
    };

    let redacted = event.redact();
    match redacted {
        Event::Payload { data } => {
            assert_eq!(data, Value::String("[REDACTED]".to_string()));
        }
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_enum_tuple_variant_with_value() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    #[allow(dead_code)]
    enum Message {
        Json(#[sensitive(Default)] Value),
        Text(String),
    }

    let msg = Message::Json(json!({"type": "notification"}));

    let redacted = msg.redact();
    match redacted {
        Message::Json(data) => {
            assert_eq!(data, Value::String("[REDACTED]".to_string()));
        }
        _ => panic!("Wrong variant"),
    }
}

// =============================================================================
// Box<Value> Support
// =============================================================================

#[test]
fn test_boxed_value() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Payload {
        #[sensitive(Default)]
        data: Box<Value>,
    }

    let payload = Payload {
        data: Box::new(json!({"secret": "boxed"})),
    };

    let redacted = payload.redact();
    assert_eq!(*redacted.data, Value::String("[REDACTED]".to_string()));
}

// =============================================================================
// Nested Struct with Value
// =============================================================================

#[test]
fn test_nested_struct_with_value() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Inner {
        #[sensitive(Default)]
        secret_data: Value,
        public_id: u64,
    }

    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Outer {
        inner: Inner,
        name: String,
    }

    let outer = Outer {
        inner: Inner {
            secret_data: json!({"key": "secret"}),
            public_id: 42,
        },
        name: "test".to_string(),
    };

    let redacted = outer.redact();
    assert_eq!(
        redacted.inner.secret_data,
        Value::String("[REDACTED]".to_string())
    );
    assert_eq!(redacted.inner.public_id, 42);
    assert_eq!(redacted.name, "test");
}

// =============================================================================
// Complex Real-World Scenarios
// =============================================================================

#[test]
fn test_api_response_with_dynamic_payload() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct ApiResponse {
        status: u16,
        message: String,
        // Dynamic payload that could contain anything
        payload: Option<Value>,
        #[sensitive(Token)]
        request_id: String,
    }

    let response = ApiResponse {
        status: 200,
        message: "Success".to_string(),
        payload: Some(json!({
            "user": {
                "email": "user@example.com",
                "ssn": "123-45-6789"
            },
            "token": "secret_token"
        })),
        request_id: "req_abc123def456".to_string(),
    };

    let redacted = response.redact();
    assert_eq!(redacted.status, 200);
    assert_eq!(redacted.message, "Success");
    assert_eq!(
        redacted.payload,
        Some(Value::String("[REDACTED]".to_string()))
    );
    assert_eq!(redacted.request_id, "************f456"); // Token keeps last 4 (16 - 4 = 12 asterisks)
}

#[test]
fn test_webhook_event() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct WebhookEvent {
        event_type: String,
        timestamp: u64,
        // Webhook payload is dynamic and could contain sensitive data
        #[sensitive(Default)]
        payload: Value,
    }

    let event = WebhookEvent {
        event_type: "user.created".to_string(),
        timestamp: 1704067200,
        payload: json!({
            "user_id": "usr_123",
            "email": "sensitive@example.com",
            "metadata": {
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0..."
            }
        }),
    };

    let redacted = event.redact();
    assert_eq!(redacted.event_type, "user.created");
    assert_eq!(redacted.timestamp, 1704067200);
    assert_eq!(redacted.payload, Value::String("[REDACTED]".to_string()));
}
