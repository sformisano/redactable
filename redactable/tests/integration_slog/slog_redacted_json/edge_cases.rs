use crate::slog_capture::{CapturedValue, CapturingSerializer, serialize_to_capture};
use redactable::slog::SlogRedactedExt;
use redactable::{Pii, Secret, Sensitive};
use serde::Serialize;

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
        #[not_sensitive]
        name: String,
        #[not_sensitive]
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
