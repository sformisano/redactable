use crate::log_redacted;
use crate::slog_capture::{CapturedValue, CapturingSerializer, serialize_to_capture};
use redactable::BypassJsonRedaction;
use serde::Serialize;

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

    let wrapped = BypassJsonRedaction(&value);
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
fn works_with_to_redacted() {
    #[derive(Serialize)]
    struct Metadata {
        id: u64,
        label: String,
    }

    let value = Metadata {
        id: 99,
        label: "ok".into(),
    };

    let json = log_redacted(&BypassJsonRedaction(&value)).json();
    assert_eq!(json["id"], 99);
    assert_eq!(json["label"], "ok");
}
