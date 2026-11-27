//! Integration tests for serde_json::Value support.
//!
//! serde_json::Value is treated as an opaque leaf type. Supported recursive policy application
//! replaces it with Value::String("[REDACTED]"). Typed diagnostic views retain selected fields.

mod policy_application {
    use redactable::{Redactable, Secret, Sensitive, Token};
    use serde_json::{Value, json};

    #[test]
    fn low_level_traversal_still_masks_a_bare_value() {
        assert_eq!(
            redactable::redact(json!({"token": "private-value"})),
            json!("[REDACTED]")
        );
    }

    #[test]
    fn redacts_with_default_policy() {
        #[derive(Clone, Sensitive, serde::Serialize)]
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
        #[derive(Clone, Sensitive, serde::Serialize)]
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
        use redactable::{RedactionPolicy, TextPolicyKind, TextRedactionPolicy};

        #[derive(Clone, Copy)]
        struct CustomPolicy;

        impl RedactionPolicy for CustomPolicy {
            type Kind = TextPolicyKind;

            fn policy() -> TextRedactionPolicy {
                TextRedactionPolicy::keep_last(4)
            }
        }

        #[derive(Clone, Sensitive, serde::Serialize)]
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

mod field_declarations {
    use redactable::{Redactable, Secret, Sensitive, ToRedacted};
    use serde_json::{Value, json};

    #[test]
    fn explicit_json_declarations_apply_to_debug_and_structured_output() {
        type Dynamic = Value;

        #[derive(Clone, Sensitive, serde::Serialize)]
        struct Payload {
            #[sensitive(Secret)]
            private: Option<Vec<Dynamic>>,
            #[not_sensitive]
            public: Dynamic,
        }

        let payload = Payload {
            private: Some(vec![json!({"token": "private-json-29"})]),
            public: json!(["approved-label", 42]),
        };
        let debug = format!("{payload:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("approved-label"));
        assert!(!debug.contains("private-json-29"));
        assert_eq!(
            payload.to_redacted().json(),
            json!({"private":["[REDACTED]"],"public":["approved-label",42]})
        );
        assert_eq!(payload.private.unwrap()[0]["token"], "private-json-29");
    }

    #[test]
    fn works_alongside_other_fields() {
        #[derive(Clone, Sensitive, serde::Serialize)]
        struct Record {
            #[not_sensitive]
            id: u64,
            #[not_sensitive]
            name: String,
            #[sensitive(Secret)]
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
    use redactable::{Redactable, Secret, Sensitive};
    use serde_json::{Value, json};

    #[test]
    fn redacts_some() {
        #[derive(Clone, Sensitive, serde::Serialize)]
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
        #[derive(Clone, Sensitive, serde::Serialize)]
        struct Payload {
            #[sensitive(Secret)]
            data: Option<Value>,
        }

        let payload = Payload { data: None };

        let redacted = payload.redact();
        assert_eq!(redacted.data, None);
    }

    #[test]
    fn explicitly_public_optional_payload_is_preserved() {
        #[derive(Clone, Sensitive, serde::Serialize)]
        struct Payload {
            #[not_sensitive]
            data: Option<Value>,
        }

        let data = Some(json!({"approved-count": 12}));
        let payload = Payload { data: data.clone() };
        assert_eq!(payload.redact().data, data);
    }
}

mod vec_value {
    use redactable::{Redactable, Secret, Sensitive};
    use serde_json::{Value, json};

    #[test]
    fn redacts_all_elements() {
        #[derive(Clone, Sensitive, serde::Serialize)]
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
        #[derive(Clone, Sensitive, serde::Serialize)]
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
    use redactable::{Redactable, Secret, Sensitive};
    use serde_json::{Value, json};

    #[test]
    fn redacts_option_vec_value() {
        #[derive(Clone, Sensitive, serde::Serialize)]
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
        #[derive(Clone, Sensitive, serde::Serialize)]
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
    use redactable::{Redactable, Secret, Sensitive};
    use serde_json::{Value, json};

    #[test]
    fn custom_and_json_string_map_keys_follow_the_key_masking_feature() {
        use std::collections::HashMap;

        use redactable::ToRedacted;
        use serde::Serialize;

        #[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
        enum Source {
            Api,
        }

        #[derive(Clone, Serialize, Sensitive)]
        struct Entry {
            #[not_sensitive]
            count: u32,
            #[sensitive(Secret)]
            details: Value,
        }

        #[derive(Clone, Serialize, Sensitive)]
        struct Report {
            sources: HashMap<Source, HashMap<Value, Entry>>,
        }

        let entry = Entry {
            count: 7,
            details: json!({"token": "private-token"}),
        };
        let entries = HashMap::from([(json!("customer-42"), entry)]);
        let report = Report {
            sources: HashMap::from([(Source::Api, entries)]),
        };
        let (source, customer) = if cfg!(feature = "mask-map-keys") {
            ("[REDACTED-KEY-0]", "[REDACTED-KEY-0]")
        } else {
            ("Api", "customer-42")
        };
        assert_eq!(
            report.to_redacted().json(),
            json!({"sources": {source: {customer: {"count": 7, "details": "[REDACTED]"}}}})
        );
    }

    #[test]
    fn redacts_hashmap_values() {
        use std::collections::HashMap;

        #[derive(Clone, Sensitive, serde::Serialize)]
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

        #[derive(Clone, Sensitive, serde::Serialize)]
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
    use redactable::RedactableWithFormatter;
    use serde_json::json;

    #[test]
    fn always_shows_redacted() {
        let value = json!({"secret": "password", "nested": {"key": "value"}});

        let display = format!("{}", value.redacted_display());
        assert_eq!(display, "[REDACTED]");
    }

    #[test]
    fn display_only_derive_can_still_format_a_json_field() {
        use redactable::{SensitiveDisplay, ToRedacted};

        #[derive(SensitiveDisplay)]
        #[error("details {payload}")]
        struct Notice {
            payload: serde_json::Value,
        }

        let notice = Notice {
            payload: json!({"token":"private-value"}),
        };
        assert_eq!(notice.to_redacted().text(), "details [REDACTED]");
        assert_eq!(format!("{notice:?}"), "details [REDACTED]");
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
    use redactable::{Redactable, Secret, Sensitive};
    use serde_json::{Value, json};

    #[test]
    fn redacts_struct_variant_field() {
        #[derive(Clone, Sensitive, serde::Serialize)]
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
        #[derive(Clone, Sensitive, serde::Serialize)]
        #[allow(dead_code)]
        enum Message {
            Json(#[sensitive(Secret)] Value),
            Text(#[not_sensitive] String),
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
    use redactable::{Redactable, Secret, Sensitive};
    use serde_json::{Value, json};

    #[test]
    fn redacts_boxed_value() {
        #[derive(Clone, Sensitive, serde::Serialize)]
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
    use redactable::{Redactable, Secret, Sensitive};
    use serde_json::{Value, json};

    #[test]
    fn unrelated_type_named_value_remains_a_declared_nested_field() {
        use redactable::ToRedacted;
        use std::marker::PhantomData;

        #[derive(Clone, serde::Serialize, Sensitive)]
        struct Value(#[sensitive(Secret)] String);

        #[derive(Clone, serde::Serialize, Sensitive)]
        struct Envelope {
            entries: Vec<Option<Value>>,
            marker: PhantomData<serde_json::Value>,
        }

        let envelope = Envelope {
            entries: vec![Some(Value("private-typed-value".into())), None],
            marker: PhantomData,
        };
        assert_eq!(
            envelope.to_redacted().json(),
            json!({"entries":["[REDACTED]",null],"marker":null})
        );
        assert!(!format!("{envelope:?}").contains("private-typed-value"));
    }

    #[test]
    fn redacts_in_nested_struct() {
        #[derive(Clone, Sensitive, serde::Serialize)]
        struct Inner {
            #[sensitive(Secret)]
            secret_data: Value,
            #[not_sensitive]
            public_id: u64,
        }

        #[derive(Clone, Sensitive, serde::Serialize)]
        struct Outer {
            inner: Inner,
            #[not_sensitive]
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
    use redactable::{Redactable, Secret, Sensitive};
    use serde_json::{Value, json};

    #[test]
    fn api_response_with_dynamic_payload() {
        #[derive(Clone, Sensitive, serde::Serialize)]
        struct ApiResponse {
            #[not_sensitive]
            status: u16,
            #[not_sensitive]
            message: String,
            #[sensitive(Secret)]
            payload: Option<Value>,
            #[not_sensitive]
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

        let original = serde_json::to_value(&response).unwrap();
        let redacted = response.clone().redact();
        assert_eq!(redacted.status, 200);
        assert_eq!(redacted.message, "Success");
        assert_eq!(
            redacted.payload,
            Some(Value::String("[REDACTED]".to_string()))
        );
        assert_eq!(redacted.request_id, "req_abc123def456");
        assert_eq!(
            serde_json::to_value(&redacted).unwrap(),
            json!({
                "status": 200,
                "message": "Success",
                "payload": "[REDACTED]",
                "request_id": "req_abc123def456"
            })
        );
        assert_eq!(serde_json::to_value(&response).unwrap(), original);
    }

    #[test]
    fn webhook_event() {
        #[derive(Clone, Sensitive, serde::Serialize)]
        struct WebhookEvent {
            #[not_sensitive]
            event_type: String,
            #[not_sensitive]
            timestamp: u64,
            #[sensitive(Secret)]
            payload: Value,
        }

        #[derive(Clone, Sensitive, serde::Serialize)]
        struct WebhookDiagnostic {
            #[not_sensitive]
            event_type: String,
            #[not_sensitive]
            timestamp: u64,
            #[not_sensitive]
            user_id: String,
            #[sensitive(Secret)]
            email: String,
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

        let original = serde_json::to_value(&event).unwrap();
        let diagnostic = WebhookDiagnostic {
            event_type: event.event_type.clone(),
            timestamp: event.timestamp,
            user_id: event.payload["user_id"].as_str().unwrap().to_owned(),
            email: event.payload["email"].as_str().unwrap().to_owned(),
        };
        assert_eq!(
            serde_json::to_value(diagnostic.redact()).unwrap(),
            json!({
                "event_type": "user.created",
                "timestamp": 1704067200,
                "user_id": "usr_123",
                "email": "[REDACTED]"
            })
        );
        let redacted = event.clone().redact();
        assert_eq!(redacted.event_type, "user.created");
        assert_eq!(redacted.timestamp, 1704067200);
        assert_eq!(redacted.payload, Value::String("[REDACTED]".to_string()));
        assert_eq!(serde_json::to_value(&event).unwrap(), original);
    }
}
