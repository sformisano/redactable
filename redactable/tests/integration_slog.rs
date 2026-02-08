//! Integration tests for the slog module.
//!
//! These tests verify that:
//! - `slog_redacted_json()` produces correctly redacted JSON values
//! - The `slog::Value` implementation works with slog's serialization API
//! - Nested structures are properly redacted when logged

#![cfg(feature = "slog")]

use std::{cell::RefCell, collections::HashMap, fmt, fmt::Arguments};

use redactable::{
    Email, NotSensitiveJsonExt, PhoneNumber, Pii, RedactableMapper, RedactableWithFormatter,
    RedactableWithMapper, RedactedJsonExt, RedactedOutput, RedactionPolicy, Secret, Sensitive,
    SensitiveDisplay, TextRedactionPolicy, ToRedactedOutput, Token,
    slog::{SlogRedacted, SlogRedactedExt},
};
use serde::Serialize;
use serde_json::Value as JsonValue;

// A test serializer that captures serialized key-value pairs
struct CapturingSerializer {
    captured: RefCell<HashMap<String, CapturedValue>>,
}

#[derive(Debug, Clone, PartialEq)]
enum CapturedValue {
    Str(String),
    Bool(bool),
    I64(i64),
    U64(u64),
    F64(f64),
    Unit,
    None,
    Serde(JsonValue),
}

impl CapturingSerializer {
    fn new() -> Self {
        Self {
            captured: RefCell::new(HashMap::new()),
        }
    }

    fn get(&self, key: &str) -> Option<CapturedValue> {
        self.captured.borrow().get(key).cloned()
    }
}

impl slog::Serializer for CapturingSerializer {
    fn emit_arguments(&mut self, key: slog::Key, val: &Arguments<'_>) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::Str(val.to_string()));
        Ok(())
    }

    fn emit_str(&mut self, key: slog::Key, val: &str) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::Str(val.into()));
        Ok(())
    }

    fn emit_bool(&mut self, key: slog::Key, val: bool) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::Bool(val));
        Ok(())
    }

    fn emit_i64(&mut self, key: slog::Key, val: i64) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::I64(val));
        Ok(())
    }

    fn emit_u64(&mut self, key: slog::Key, val: u64) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::U64(val));
        Ok(())
    }

    fn emit_f64(&mut self, key: slog::Key, val: f64) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::F64(val));
        Ok(())
    }

    fn emit_unit(&mut self, key: slog::Key) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::Unit);
        Ok(())
    }

    fn emit_none(&mut self, key: slog::Key) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::None);
        Ok(())
    }

    fn emit_serde(&mut self, key: slog::Key, val: &dyn slog::SerdeValue) -> slog::Result {
        let json = serde_json::to_value(val.as_serde()).unwrap_or(JsonValue::Null);
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::Serde(json));
        Ok(())
    }
}

fn serialize_to_capture<V: slog::Value, S: slog::Serializer>(
    value: &V,
    key: &'static str,
    serializer: &mut S,
) {
    static RS: slog::RecordStatic<'static> = slog::record_static!(slog::Level::Info, "");
    let args = format_args!("");
    let record = slog::Record::new(&RS, &args, slog::b!());
    value.serialize(&record, key, serializer).unwrap();
}

fn log_redacted<T: ToRedactedOutput>(value: &T) -> RedactedOutput {
    value.to_redacted_output()
}

mod marker_trait {
    use super::*;

    #[test]
    fn sensitive_type_implements_slog_redacted() {
        #[derive(Clone, Sensitive, Serialize)]
        struct Account {
            #[sensitive(Email)]
            email: String,
        }

        fn assert_slog_redacted<T: SlogRedacted>() {}

        assert_slog_redacted::<Account>();
    }
}

mod slog_redacted_json {
    use super::*;

    mod basic {
        use super::*;

        #[test]
        fn redacts_simple_struct() {
            #[derive(Clone, Sensitive, Serialize)]
            struct User {
                username: String,
                #[sensitive(Secret)]
                password: String,
            }

            let user = User {
                username: "alice".into(),
                password: "super_secret_password".into(),
            };

            let redacted = user.slog_redacted_json();

            let mut serializer = CapturingSerializer::new();
            serialize_to_capture(&redacted, "user", &mut serializer);

            if let Some(CapturedValue::Serde(json)) = serializer.get("user") {
                assert_eq!(json["username"], "alice");
                assert_eq!(json["password"], "[REDACTED]");
            } else {
                panic!("Expected Serde value for 'user' key");
            }
        }

        #[test]
        fn applies_different_policies() {
            #[derive(Clone, Sensitive, Serialize)]
            struct Contact {
                #[sensitive(Email)]
                email: String,
                #[sensitive(PhoneNumber)]
                phone: String,
                #[sensitive(Pii)]
                full_name: String,
            }

            let contact = Contact {
                email: "alice@example.com".into(),
                phone: "555-123-4567".into(),
                full_name: "Alice Smith".into(),
            };

            let redacted = contact.slog_redacted_json();

            let mut serializer = CapturingSerializer::new();
            serialize_to_capture(&redacted, "contact", &mut serializer);

            if let Some(CapturedValue::Serde(json)) = serializer.get("contact") {
                assert_eq!(json["email"].as_str().unwrap(), "al***@example.com");
                assert_eq!(json["phone"].as_str().unwrap(), "********4567");
                assert_eq!(json["full_name"].as_str().unwrap(), "*********th");
            } else {
                panic!("Expected Serde value for 'contact' key");
            }
        }
    }

    mod nested {
        use super::*;

        #[test]
        fn redacts_nested_struct() {
            #[derive(Clone, Sensitive, Serialize)]
            struct Address {
                #[sensitive(Pii)]
                street: String,
                city: String,
            }

            #[derive(Clone, Sensitive, Serialize)]
            struct Person {
                name: String,
                #[sensitive(Secret)]
                ssn: String,
                address: Address,
            }

            let person = Person {
                name: "Bob".into(),
                ssn: "123-45-6789".into(),
                address: Address {
                    street: "123 Main Street".into(),
                    city: "Springfield".into(),
                },
            };

            let redacted = person.slog_redacted_json();

            let mut serializer = CapturingSerializer::new();
            serialize_to_capture(&redacted, "person", &mut serializer);

            if let Some(CapturedValue::Serde(json)) = serializer.get("person") {
                assert_eq!(json["name"], "Bob");
                assert_eq!(json["ssn"], "[REDACTED]");
                assert_eq!(
                    json["address"]["street"].as_str().unwrap(),
                    "*************et"
                );
                assert_eq!(json["address"]["city"], "Springfield");
            } else {
                panic!("Expected Serde value for 'person' key");
            }
        }
    }

    mod containers {
        use super::*;

        #[test]
        fn redacts_vec_elements() {
            #[derive(Clone, Sensitive, Serialize)]
            struct ApiKeys {
                #[sensitive(Token)]
                keys: Vec<String>,
            }

            let list = ApiKeys {
                keys: vec![
                    "sk_live_abc123def456".into(),
                    "sk_test_xyz789ghi012".into(),
                    "pk_live_jkl345mno678".into(),
                ],
            };

            let redacted = list.slog_redacted_json();

            let mut serializer = CapturingSerializer::new();
            serialize_to_capture(&redacted, "list", &mut serializer);

            if let Some(CapturedValue::Serde(json)) = serializer.get("list") {
                let keys = json["keys"].as_array().unwrap();
                assert_eq!(keys.len(), 3);
                assert_eq!(keys[0].as_str().unwrap(), "****************f456");
                assert_eq!(keys[1].as_str().unwrap(), "****************i012");
                assert_eq!(keys[2].as_str().unwrap(), "****************o678");
            } else {
                panic!("Expected Serde value for 'list' key");
            }
        }

        #[test]
        fn redacts_option_values() {
            #[derive(Clone, Sensitive, Serialize)]
            struct OptionalSensitive {
                #[sensitive(Secret)]
                secret: Option<String>,
                public: String,
            }

            let with_sensitive = OptionalSensitive {
                secret: Some("my_secret".into()),
                public: "visible".into(),
            };

            let redacted = with_sensitive.slog_redacted_json();
            let mut serializer = CapturingSerializer::new();
            serialize_to_capture(&redacted, "data", &mut serializer);

            if let Some(CapturedValue::Serde(json)) = serializer.get("data") {
                assert_eq!(json["secret"], "[REDACTED]");
                assert_eq!(json["public"], "visible");
            } else {
                panic!("Expected Serde value");
            }

            let without_sensitive = OptionalSensitive {
                secret: None,
                public: "visible".into(),
            };

            let redacted = without_sensitive.slog_redacted_json();
            let mut serializer = CapturingSerializer::new();
            serialize_to_capture(&redacted, "data", &mut serializer);

            if let Some(CapturedValue::Serde(json)) = serializer.get("data") {
                assert!(json["secret"].is_null());
                assert_eq!(json["public"], "visible");
            } else {
                panic!("Expected Serde value");
            }
        }

        #[test]
        fn redacts_hashmap_values() {
            #[derive(Clone, Sensitive, Serialize)]
            struct Config {
                #[sensitive(Secret)]
                secrets: HashMap<String, String>,
            }

            let mut secrets = HashMap::new();
            secrets.insert("api_key".into(), "sk_live_abc123".into());
            secrets.insert("db_password".into(), "p4ssw0rd!".into());

            let config = Config { secrets };
            let redacted = config.slog_redacted_json();

            let mut serializer = CapturingSerializer::new();
            serialize_to_capture(&redacted, "config", &mut serializer);

            if let Some(CapturedValue::Serde(json)) = serializer.get("config") {
                let secrets = json["secrets"].as_object().unwrap();
                for (_key, value) in secrets {
                    assert_eq!(value, "[REDACTED]");
                }
            } else {
                panic!("Expected Serde value");
            }
        }
    }

    mod enums {
        use super::*;

        #[test]
        fn redacts_enum_variants() {
            #[derive(Clone, Sensitive, Serialize)]
            enum Credential {
                ApiKey {
                    #[sensitive(Token)]
                    key: String,
                },
                Password {
                    username: String,
                    #[sensitive(Secret)]
                    password: String,
                },
            }

            let api_key = Credential::ApiKey {
                key: "sk_live_abc123def456".into(),
            };

            let redacted = api_key.slog_redacted_json();
            let mut serializer = CapturingSerializer::new();
            serialize_to_capture(&redacted, "cred", &mut serializer);

            if let Some(CapturedValue::Serde(json)) = serializer.get("cred") {
                let key = json["ApiKey"]["key"].as_str().unwrap();
                assert_eq!(key, "****************f456");
            } else {
                panic!("Expected Serde value");
            }

            let password = Credential::Password {
                username: "admin".into(),
                password: "supersecret".into(),
            };

            let redacted = password.slog_redacted_json();
            let mut serializer = CapturingSerializer::new();
            serialize_to_capture(&redacted, "cred", &mut serializer);

            if let Some(CapturedValue::Serde(json)) = serializer.get("cred") {
                assert_eq!(json["Password"]["username"], "admin");
                assert_eq!(json["Password"]["password"], "[REDACTED]");
            } else {
                panic!("Expected Serde value");
            }
        }
    }

    mod edge_cases {
        use super::*;

        #[test]
        fn handles_empty_string() {
            #[derive(Clone, Sensitive, Serialize)]
            struct Data {
                #[sensitive(Secret)]
                value: String,
            }

            let data = Data { value: "".into() };

            let redacted = data.slog_redacted_json();
            let mut serializer = CapturingSerializer::new();
            serialize_to_capture(&redacted, "data", &mut serializer);

            if let Some(CapturedValue::Serde(json)) = serializer.get("data") {
                assert_eq!(json["value"], "[REDACTED]");
            } else {
                panic!("Expected Serde value");
            }
        }

        #[test]
        fn handles_unicode() {
            #[derive(Clone, Sensitive, Serialize)]
            struct UnicodeData {
                #[sensitive(Pii)]
                name: String,
            }

            let data = UnicodeData {
                name: "田中太郎".into(),
            };

            let redacted = data.slog_redacted_json();
            let mut serializer = CapturingSerializer::new();
            serialize_to_capture(&redacted, "data", &mut serializer);

            if let Some(CapturedValue::Serde(json)) = serializer.get("data") {
                let name = json["name"].as_str().unwrap();
                assert_eq!(name, "**太郎");
            } else {
                panic!("Expected Serde value");
            }
        }

        #[test]
        fn handles_no_sensitive_fields() {
            #[derive(Clone, Sensitive, Serialize)]
            struct PublicData {
                name: String,
                count: i32,
            }

            let data = PublicData {
                name: "test".into(),
                count: 42,
            };

            let redacted = data.slog_redacted_json();
            let mut serializer = CapturingSerializer::new();
            serialize_to_capture(&redacted, "data", &mut serializer);

            if let Some(CapturedValue::Serde(json)) = serializer.get("data") {
                assert_eq!(json["name"], "test");
                assert_eq!(json["count"], 42);
            } else {
                panic!("Expected Serde value");
            }
        }
    }

    mod custom_policy {
        use super::*;

        #[test]
        fn applies_custom_policy() {
            #[derive(Clone, Copy)]
            struct CustomCreditCard;

            impl RedactionPolicy for CustomCreditCard {
                fn policy() -> TextRedactionPolicy {
                    TextRedactionPolicy::keep_last(4).with_mask_char('X')
                }
            }

            #[derive(Clone, Sensitive, Serialize)]
            struct Payment {
                #[sensitive(CustomCreditCard)]
                card_number: String,
                amount: f64,
            }

            let payment = Payment {
                card_number: "4111111111111111".into(),
                amount: 99.99,
            };

            let redacted = payment.slog_redacted_json();
            let mut serializer = CapturingSerializer::new();
            serialize_to_capture(&redacted, "payment", &mut serializer);

            if let Some(CapturedValue::Serde(json)) = serializer.get("payment") {
                let card = json["card_number"].as_str().unwrap();
                assert_eq!(card, "XXXXXXXXXXXX1111");
                assert_eq!(json["amount"], 99.99);
            } else {
                panic!("Expected Serde value");
            }
        }
    }

    mod security {
        use super::*;

        #[test]
        fn redacts_before_serialization() {
            #[derive(Clone, Sensitive, Serialize)]
            struct Canary {
                #[sensitive(Secret)]
                secret: String,
            }

            let canary = Canary {
                secret: "the_actual_secret".into(),
            };

            let redacted = canary.slog_redacted_json();
            let mut serializer = CapturingSerializer::new();
            serialize_to_capture(&redacted, "canary", &mut serializer);

            if let Some(CapturedValue::Serde(json)) = serializer.get("canary") {
                assert_eq!(json["secret"], "[REDACTED]");
            } else {
                panic!("Expected Serde value for 'canary' key");
            }
        }
    }
}

mod not_sensitive_json {
    use super::*;

    #[test]
    fn emits_structured_json() {
        #[derive(Serialize)]
        struct Metadata {
            id: u64,
            label: String,
        }

        let value = Metadata {
            id: 42,
            label: "ok".into(),
        };

        let wrapped = value.not_sensitive_json();
        let mut serializer = CapturingSerializer::new();
        serialize_to_capture(&wrapped, "meta", &mut serializer);

        if let Some(CapturedValue::Serde(json)) = serializer.get("meta") {
            assert_eq!(json["id"], 42);
            assert_eq!(json["label"], "ok");
        } else {
            panic!("Expected Serde value for 'meta' key");
        }
    }

    #[test]
    fn works_with_to_redacted_output() {
        #[derive(Serialize)]
        struct Metadata {
            id: u64,
            label: String,
        }

        let value = Metadata {
            id: 99,
            label: "ok".into(),
        };

        let output = log_redacted(&value.not_sensitive_json());
        if let RedactedOutput::Json(json) = output {
            assert_eq!(json["id"], 99);
            assert_eq!(json["label"], "ok");
        } else {
            panic!("Expected Json output");
        }
    }
}

mod redacted_json {
    use super::*;

    #[test]
    fn produces_json_output() {
        #[derive(Clone, Sensitive, Serialize)]
        struct Event {
            #[sensitive(Secret)]
            token: String,
            user: String,
        }

        let event = Event {
            token: "secret".into(),
            user: "alice".into(),
        };

        let output = log_redacted(&event.redacted_json());
        if let RedactedOutput::Json(json) = output {
            assert_eq!(json["token"], "[REDACTED]");
            assert_eq!(json["user"], "alice");
        } else {
            panic!("Expected Json output");
        }
    }
}

mod sensitive_display {
    use super::*;

    #[test]
    fn emits_redacted_string() {
        #[derive(Debug)]
        struct NonSerializable {
            _detail: String,
        }

        impl RedactableWithMapper for NonSerializable {
            fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
                self
            }
        }

        #[derive(SensitiveDisplay)]
        enum LoginError {
            #[error("invalid login for {username} {password} {context:?} {attempts}")]
            InvalidCredentials {
                #[not_sensitive]
                username: String,
                #[sensitive(Secret)]
                password: String,
                #[not_sensitive]
                context: NonSerializable,
                #[sensitive(Secret)]
                attempts: usize,
            },
        }

        let err = LoginError::InvalidCredentials {
            username: "alice".into(),
            password: "hunter2".into(),
            context: NonSerializable {
                _detail: "remote".into(),
            },
            attempts: 3,
        };

        let mut serializer = CapturingSerializer::new();
        serialize_to_capture(&err, "error", &mut serializer);

        if let Some(CapturedValue::Str(value)) = serializer.get("error") {
            assert_eq!(
                value,
                "invalid login for alice [REDACTED] NonSerializable { _detail: \"remote\" } 0"
            );
        } else {
            panic!("Expected Str value for 'error' key");
        }
    }

    #[test]
    fn works_with_to_redacted_output() {
        #[derive(SensitiveDisplay)]
        enum LoginError {
            #[error("login failed for {user} {password}")]
            Invalid {
                #[not_sensitive]
                user: String,
                #[sensitive(Secret)]
                password: String,
            },
        }

        let err = LoginError::Invalid {
            user: "alice".into(),
            password: "hunter2".into(),
        };

        let output = log_redacted(&err);
        assert_eq!(
            output,
            RedactedOutput::Text("login failed for alice [REDACTED]".to_string())
        );
    }

    #[test]
    fn handles_nested_errors() {
        #[derive(SensitiveDisplay)]
        enum InnerError {
            #[error("invalid api_key {api_key}")]
            InvalidApiKey {
                #[sensitive(Token)]
                api_key: String,
            },
        }

        impl fmt::Display for InnerError {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.fmt_redacted(f)
            }
        }

        #[derive(SensitiveDisplay)]
        enum OuterError {
            #[error("user {user} {inner}")]
            Failure {
                #[not_sensitive]
                user: String,
                #[not_sensitive]
                inner: InnerError,
            },
        }

        let err = OuterError::Failure {
            user: "alice".into(),
            inner: InnerError::InvalidApiKey {
                api_key: "sk_live_abc123def456".into(),
            },
        };

        let mut serializer = CapturingSerializer::new();
        serialize_to_capture(&err, "error", &mut serializer);

        if let Some(CapturedValue::Str(value)) = serializer.get("error") {
            assert_eq!(value, "user alice invalid api_key ****************f456");
        } else {
            panic!("Expected Str value for 'error' key");
        }
    }

    #[test]
    fn handles_raw_opt_out() {
        #[derive(Debug)]
        struct RawContext;

        impl fmt::Display for RawContext {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("raw-context")
            }
        }

        #[derive(SensitiveDisplay)]
        enum RawError {
            #[error("context {context}")]
            Failure {
                #[not_sensitive]
                context: RawContext,
            },
        }

        let err = RawError::Failure {
            context: RawContext,
        };

        let mut serializer = CapturingSerializer::new();
        serialize_to_capture(&err, "error", &mut serializer);

        if let Some(CapturedValue::Str(value)) = serializer.get("error") {
            assert_eq!(value, "context raw-context");
        } else {
            panic!("Expected Str value for 'error' key");
        }
    }

    #[test]
    fn handles_doc_comment_template() {
        #[derive(SensitiveDisplay)]
        enum DocError {
            /// user {user} {secret}
            Variant {
                #[not_sensitive]
                user: String,
                #[sensitive(Secret)]
                secret: String,
            },
        }

        let err = DocError::Variant {
            user: "bob".into(),
            secret: "super_secret".into(),
        };

        let mut serializer = CapturingSerializer::new();
        serialize_to_capture(&err, "error", &mut serializer);

        if let Some(CapturedValue::Str(value)) = serializer.get("error") {
            assert_eq!(value, "user bob [REDACTED]");
        } else {
            panic!("Expected Str value for 'error' key");
        }
    }

    #[test]
    fn handles_debug_specifiers() {
        struct ModeValue;

        impl fmt::Display for ModeValue {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("display")
            }
        }

        impl fmt::Debug for ModeValue {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("debug")
            }
        }

        impl RedactableWithMapper for ModeValue {
            fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
                self
            }
        }

        #[derive(SensitiveDisplay)]
        enum LoginError {
            #[error("user {user} mode {mode} ctx {context:?} secret {password}")]
            Invalid {
                #[not_sensitive]
                user: String,
                #[not_sensitive]
                mode: ModeValue,
                #[not_sensitive]
                context: ModeValue,
                #[sensitive(Secret)]
                password: String,
            },
        }

        let err = LoginError::Invalid {
            user: "alice".into(),
            mode: ModeValue,
            context: ModeValue,
            password: "hunter2".into(),
        };

        let mut serializer = CapturingSerializer::new();
        serialize_to_capture(&err, "error", &mut serializer);

        if let Some(CapturedValue::Str(value)) = serializer.get("error") {
            assert_eq!(value, "user alice mode display ctx debug secret [REDACTED]");
        } else {
            panic!("Expected Str value for 'error' key");
        }
    }

    #[test]
    fn handles_positional_fields_with_error_attr() {
        #[derive(SensitiveDisplay)]
        enum PositionalError {
            #[error("code {0} secret {1}")]
            Invalid(#[not_sensitive] String, #[sensitive(Secret)] String),
        }

        let err = PositionalError::Invalid("E123".into(), "super_secret".into());

        let mut serializer = CapturingSerializer::new();
        serialize_to_capture(&err, "error", &mut serializer);

        if let Some(CapturedValue::Str(value)) = serializer.get("error") {
            assert_eq!(value, "code E123 secret [REDACTED]");
        } else {
            panic!("Expected Str value for 'error' key");
        }
    }

    #[test]
    fn handles_positional_fields_with_doc_comment() {
        #[derive(SensitiveDisplay)]
        enum DocPositionalError {
            /// code {0} name {1:?}
            Invalid(#[not_sensitive] String, #[sensitive(Pii)] String),
        }

        let err = DocPositionalError::Invalid("E42".into(), "John Smith".into());

        let mut serializer = CapturingSerializer::new();
        serialize_to_capture(&err, "error", &mut serializer);

        if let Some(CapturedValue::Str(value)) = serializer.get("error") {
            assert_eq!(value, "code E42 name \"********th\"");
        } else {
            panic!("Expected Str value for 'error' key");
        }
    }
}
