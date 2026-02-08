//! Integration tests for serde_json::Value support.
//!
//! serde_json::Value is treated as an opaque leaf type. Any policy application
//! fully redacts it to Value::String("[REDACTED]"). This is safe-by-default.

#![cfg(feature = "json")]

use redactable::{Redactable, RedactableWithFormatter, Secret, Sensitive, Token};
use serde_json::{Value, json};

mod policy_application {
    use super::*;

    #[test]
    fn redacts_with_default_policy() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Payload {
            #[sensitive(Secret)]
            data: Value,
        }

        let payload = Payload {
            data: json!({"secret": "password123", "nested": {"key": "value"}}),
        };

        let redacted = payload.redact();
        assert_eq!(redacted.data, Value::String("[REDACTED]".to_string()));
    }

    #[test]
    fn redacts_with_token_policy() {
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
        assert_eq!(redacted.data, Value::String("[REDACTED]".to_string()));
    }

    #[test]
    fn redacts_with_custom_policy() {
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
        assert_eq!(redacted.data, Value::String("[REDACTED]".to_string()));
    }
}

mod unannotated_fields {
    use super::*;

    #[test]
    fn redacts_by_default() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Payload {
            data: Value,
        }

        let payload = Payload {
            data: json!({"potentially_sensitive": "data"}),
        };

        let redacted = payload.redact();
        assert_eq!(redacted.data, Value::String("[REDACTED]".to_string()));
    }

    #[test]
    fn works_alongside_other_fields() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Record {
            id: u64,
            name: String,
            metadata: Value,
            #[sensitive(Secret)]
            password: String,
        }

        let record = Record {
            id: 123,
            name: "test".to_string(),
            metadata: json!({"key": "value"}),
            password: "secret".to_string(),
        };

        let redacted = record.redact();
        assert_eq!(redacted.id, 123);
        assert_eq!(redacted.name, "test");
        assert_eq!(redacted.metadata, Value::String("[REDACTED]".to_string()));
        assert_eq!(redacted.password, "[REDACTED]");
    }
}

mod option_value {
    use super::*;

    #[test]
    fn redacts_some() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Payload {
            #[sensitive(Secret)]
            data: Option<Value>,
        }

        let payload = Payload {
            data: Some(json!({"secret": "data"})),
        };

        let redacted = payload.redact();
        assert_eq!(redacted.data, Some(Value::String("[REDACTED]".to_string())));
    }

    #[test]
    fn preserves_none() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Payload {
            #[sensitive(Secret)]
            data: Option<Value>,
        }

        let payload = Payload { data: None };

        let redacted = payload.redact();
        assert_eq!(redacted.data, None);
    }

    #[test]
    fn redacts_unannotated() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Payload {
            data: Option<Value>,
        }

        let payload = Payload {
            data: Some(json!({"key": "value"})),
        };

        let redacted = payload.redact();
        assert_eq!(redacted.data, Some(Value::String("[REDACTED]".to_string())));
    }
}

mod vec_value {
    use super::*;

    #[test]
    fn redacts_all_elements() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Payload {
            #[sensitive(Secret)]
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
    fn preserves_empty() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Payload {
            #[sensitive(Secret)]
            items: Vec<Value>,
        }

        let payload = Payload { items: vec![] };

        let redacted = payload.redact();
        assert!(redacted.items.is_empty());
    }
}

mod deeply_nested {
    use super::*;

    #[test]
    fn redacts_option_vec_value() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Payload {
            #[sensitive(Secret)]
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
    fn redacts_vec_option_value() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Payload {
            #[sensitive(Secret)]
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
}

mod maps {
    use super::*;

    #[test]
    fn redacts_hashmap_values() {
        use std::collections::HashMap;

        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Payload {
            #[sensitive(Secret)]
            data: HashMap<String, Value>,
        }

        let mut data = HashMap::new();
        data.insert("key1".to_string(), json!({"secret": "value1"}));
        data.insert("key2".to_string(), json!({"secret": "value2"}));

        let payload = Payload { data };

        let redacted = payload.redact();
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
    fn redacts_btreemap_values() {
        use std::collections::BTreeMap;

        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Payload {
            #[sensitive(Secret)]
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
}

mod redactable_display {
    use super::*;

    #[test]
    fn always_shows_redacted() {
        let value = json!({"secret": "password", "nested": {"key": "value"}});

        let display = format!("{}", value.redacted_display());
        assert_eq!(display, "[REDACTED]");
    }

    #[test]
    fn works_for_all_value_types() {
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
}

mod enums {
    use super::*;

    #[test]
    fn redacts_struct_variant_field() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        #[allow(dead_code)]
        enum Event {
            Payload {
                #[sensitive(Secret)]
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
    fn redacts_tuple_variant_field() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        #[allow(dead_code)]
        enum Message {
            Json(#[sensitive(Secret)] Value),
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
}

mod box_value {
    use super::*;

    #[test]
    fn redacts_boxed_value() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Payload {
            #[sensitive(Secret)]
            data: Box<Value>,
        }

        let payload = Payload {
            data: Box::new(json!({"secret": "boxed"})),
        };

        let redacted = payload.redact();
        assert_eq!(*redacted.data, Value::String("[REDACTED]".to_string()));
    }
}

mod nested_structs {
    use super::*;

    #[test]
    fn redacts_in_nested_struct() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Inner {
            #[sensitive(Secret)]
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
}

mod real_world_scenarios {
    use super::*;

    #[test]
    fn api_response_with_dynamic_payload() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct ApiResponse {
            status: u16,
            message: String,
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
        assert_eq!(redacted.request_id, "************f456");
    }

    #[test]
    fn webhook_event() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct WebhookEvent {
            event_type: String,
            timestamp: u64,
            #[sensitive(Secret)]
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
}
