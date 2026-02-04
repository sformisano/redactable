//! Integration tests for the slog module.
//!
//! These tests verify that:
//! - `slog_redacted_json()` produces correctly redacted JSON values
//! - The `slog::Value` implementation works with slog's serialization API
//! - Nested structures are properly redacted when logged

#![cfg(feature = "slog")]

use std::{cell::RefCell, collections::HashMap, fmt, fmt::Arguments};

use redactable::{
    Default, Email, NotSensitiveJsonExt, PhoneNumber, Pii, RedactableContainer, RedactableDisplay,
    RedactableMapper, RedactedJsonExt, RedactedOutput, RedactionPolicy, SensitiveData,
    SensitiveDisplay, TextRedactionPolicy, ToRedactedOutput, Token, slog::SlogRedactedExt,
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
    // For nested serde values, we capture the JSON representation
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
        // Serialize the value to JSON to capture it
        let json = serde_json::to_value(val.as_serde()).unwrap_or(JsonValue::Null);
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::Serde(json));
        Ok(())
    }
}

/// Helper function to serialize a slog::Value into any Serializer.
fn serialize_to_capture<V: slog::Value, S: slog::Serializer>(
    value: &V,
    key: &'static str,
    serializer: &mut S,
) {
    // The record is created and used in a single expression to avoid lifetime issues
    static RS: slog::RecordStatic<'static> = slog::record_static!(slog::Level::Info, "");
    // We need to ensure format_args! result lives long enough
    let args = format_args!("");
    let record = slog::Record::new(&RS, &args, slog::b!());
    value.serialize(&record, key, serializer).unwrap();
}

fn log_redacted<T: ToRedactedOutput>(value: &T) -> RedactedOutput {
    value.to_redacted_output()
}

// ============================================================================
// Basic functionality tests
// ============================================================================

#[test]
fn test_slog_redacted_json_simple_struct() {
    #[derive(Clone, SensitiveData, Serialize)]
    struct User {
        username: String,
        #[sensitive(Default)]
        password: String,
    }

    let user = User {
        username: "alice".into(),
        password: "super_secret_password".into(),
    };

    let redacted = user.slog_redacted_json();

    // Serialize through slog's Value trait
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "user", &mut serializer);

    // Verify the captured value contains redacted password
    if let Some(CapturedValue::Serde(json)) = serializer.get("user") {
        assert_eq!(json["username"], "alice");
        // Password should be fully redacted (Default policy = Full redaction)
        assert_eq!(json["password"], "[REDACTED]");
    } else {
        panic!("Expected Serde value for 'user' key");
    }
}

#[test]
fn test_slog_redacted_json_with_policies() {
    #[derive(Clone, SensitiveData, Serialize)]
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
        // Email policy keeps first 2 chars of local part + domain
        let email = json["email"].as_str().unwrap();
        assert_eq!(email, "al***@example.com");

        // PhoneNumber policy keeps last 4 digits
        let phone = json["phone"].as_str().unwrap();
        assert_eq!(phone, "********4567");

        // Pii policy keeps last 2 chars (for short names)
        let full_name = json["full_name"].as_str().unwrap();
        assert_eq!(full_name, "*********th");
    } else {
        panic!("Expected Serde value for 'contact' key");
    }
}

#[test]
fn test_not_sensitive_json_emits_structured_json() {
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
fn test_log_redacted_bound_accepts_not_sensitive_json() {
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

#[test]
fn test_redacted_json_wrapper_produces_json() {
    #[derive(Clone, SensitiveData, Serialize)]
    struct Event {
        #[sensitive(Default)]
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

#[test]
fn test_sensitive_display_emits_redacted_string() {
    #[derive(Debug)]
    struct NonSerializable {
        _detail: String,
    }

    impl RedactableContainer for NonSerializable {
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
            #[sensitive(Default)]
            password: String,
            #[not_sensitive]
            context: NonSerializable,
            #[sensitive(Default)]
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
fn test_log_redacted_bound_accepts_sensitive_display() {
    #[derive(SensitiveDisplay)]
    enum LoginError {
        #[error("login failed for {user} {password}")]
        Invalid {
            #[not_sensitive]
            user: String,
            #[sensitive(Default)]
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
fn test_sensitive_display_nested_and_policy_display() {
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
        // Token keeps last 4: "sk_live_abc123def456" (20 chars) → 16 asterisks + "f456"
        assert_eq!(value, "user alice invalid api_key ****************f456");
    } else {
        panic!("Expected Str value for 'error' key");
    }
}

#[test]
fn test_sensitive_display_raw_opt_out() {
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
fn test_sensitive_display_doc_comment_template() {
    #[derive(SensitiveDisplay)]
    enum DocError {
        /// user {user} {secret}
        Variant {
            #[not_sensitive]
            user: String,
            #[sensitive(Default)]
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
fn test_sensitive_display_error_attr_named_and_debug_specifiers() {
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

    impl RedactableContainer for ModeValue {
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
            #[sensitive(Default)]
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
fn test_sensitive_display_error_attr_positional_fields() {
    #[derive(SensitiveDisplay)]
    enum PositionalError {
        #[error("code {0} secret {1}")]
        Invalid(#[not_sensitive] String, #[sensitive(Default)] String),
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
fn test_sensitive_display_doc_comment_positional_fields() {
    #[derive(SensitiveDisplay)]
    enum DocPositionalError {
        /// code {0} name {1:?}
        Invalid(#[not_sensitive] String, #[sensitive(Pii)] String),
    }

    let err = DocPositionalError::Invalid("E42".into(), "John Smith".into());

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&err, "error", &mut serializer);

    if let Some(CapturedValue::Str(value)) = serializer.get("error") {
        // Pii keeps last 2 chars: "John Smith" (10 chars) → "********th"
        assert_eq!(value, "code E42 name \"********th\"");
    } else {
        panic!("Expected Str value for 'error' key");
    }
}

#[test]
fn test_slog_redacted_json_nested_struct() {
    #[derive(Clone, SensitiveData, Serialize)]
    struct Address {
        #[sensitive(Pii)]
        street: String,
        city: String,
    }

    #[derive(Clone, SensitiveData, Serialize)]
    struct Person {
        name: String,
        #[sensitive(Default)]
        ssn: String,
        address: Address, // Nested containers are walked automatically
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
        // Name should be unchanged (no policy)
        assert_eq!(json["name"], "Bob");

        // SSN should be fully redacted
        assert_eq!(json["ssn"], "[REDACTED]");

        // Address street should be partially masked (Pii = last 2 visible)
        let street = json["address"]["street"].as_str().unwrap();
        assert_eq!(street, "*************et");

        // City should be unchanged (no policy)
        assert_eq!(json["address"]["city"], "Springfield");
    } else {
        panic!("Expected Serde value for 'person' key");
    }
}

#[test]
fn test_slog_redacted_json_with_vec() {
    #[derive(Clone, SensitiveData, Serialize)]
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

        // Token policy uses Keep(last 4) - shows last 4 chars, masks rest
        assert_eq!(keys[0].as_str().unwrap(), "****************f456");
        assert_eq!(keys[1].as_str().unwrap(), "****************i012");
        assert_eq!(keys[2].as_str().unwrap(), "****************o678");
    } else {
        panic!("Expected Serde value for 'list' key");
    }
}

#[test]
fn test_slog_redacted_json_with_option() {
    #[derive(Clone, SensitiveData, Serialize)]
    struct OptionalSensitive {
        #[sensitive(Default)]
        secret: Option<String>,
        public: String,
    }

    // Test with Some value
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

    // Test with None value
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
fn test_slog_redacted_json_with_hashmap() {
    use std::collections::HashMap;

    #[derive(Clone, SensitiveData, Serialize)]
    struct Config {
        #[sensitive(Default)]
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

        // All values should be redacted
        for (_key, value) in secrets {
            assert_eq!(value, "[REDACTED]");
        }
    } else {
        panic!("Expected Serde value");
    }
}

// ============================================================================
// Enum tests
// ============================================================================

#[test]
fn test_slog_redacted_json_enum() {
    #[derive(Clone, SensitiveData, Serialize)]
    enum Credential {
        ApiKey {
            #[sensitive(Token)]
            key: String,
        },
        Password {
            username: String,
            #[sensitive(Default)]
            password: String,
        },
    }

    // Test ApiKey variant
    let api_key = Credential::ApiKey {
        key: "sk_live_abc123def456".into(),
    };

    let redacted = api_key.slog_redacted_json();
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "cred", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("cred") {
        let key = json["ApiKey"]["key"].as_str().unwrap();
        // Token keeps last 4: "sk_live_abc123def456" (20 chars) → 16 asterisks + "f456"
        assert_eq!(key, "****************f456");
    } else {
        panic!("Expected Serde value");
    }

    // Test Password variant
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

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_slog_redacted_json_empty_string() {
    #[derive(Clone, SensitiveData, Serialize)]
    struct Data {
        #[sensitive(Default)]
        value: String,
    }

    let data = Data { value: "".into() };

    let redacted = data.slog_redacted_json();
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "data", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("data") {
        // Empty string with Full policy should become the placeholder
        assert_eq!(json["value"], "[REDACTED]");
    } else {
        panic!("Expected Serde value");
    }
}

#[test]
fn test_slog_redacted_json_unicode() {
    // Test that unicode characters in PII (like names) are handled correctly
    #[derive(Clone, SensitiveData, Serialize)]
    struct UnicodeData {
        #[sensitive(Pii)]
        name: String,
    }

    let data = UnicodeData {
        name: "田中太郎".into(), // Japanese name "Tanaka Taro" (4 chars)
    };

    let redacted = data.slog_redacted_json();
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "data", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("data") {
        let name = json["name"].as_str().unwrap();
        // Pii keeps last 2 chars, masks the rest
        // The original has 4 characters, so last 2 should be visible
        assert_eq!(name, "**太郎");
    } else {
        panic!("Expected Serde value");
    }
}

#[test]
fn test_slog_redacted_json_no_sensitive_fields() {
    #[derive(Clone, SensitiveData, Serialize)]
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
        // No sensitive fields, so everything should be unchanged
        assert_eq!(json["name"], "test");
        assert_eq!(json["count"], 42);
    } else {
        panic!("Expected Serde value");
    }
}

// ============================================================================
// Custom policy tests
// ============================================================================

#[test]
fn test_slog_redacted_json_custom_policy() {
    // Define a custom policy that shows only last 4 digits with X masking
    #[derive(Clone, Copy)]
    struct CustomCreditCard;

    impl RedactionPolicy for CustomCreditCard {
        fn policy() -> TextRedactionPolicy {
            // Show last 4 digits only, mask rest with X
            TextRedactionPolicy::keep_last(4).with_mask_char('X')
        }
    }

    #[derive(Clone, SensitiveData, Serialize)]
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
        // Should show only last 4 digits
        assert_eq!(card, "XXXXXXXXXXXX1111");
        assert_eq!(json["amount"], 99.99);
    } else {
        panic!("Expected Serde value");
    }
}

// ============================================================================
// Verify redaction happens before serialization (not after)
// ============================================================================

#[test]
fn test_redaction_happens_before_serialization() {
    // This test verifies that the original sensitive data never reaches slog
    #[derive(Clone, SensitiveData, Serialize)]
    struct Canary {
        #[sensitive(Default)]
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
