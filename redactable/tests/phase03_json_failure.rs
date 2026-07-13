//! Regression coverage for fail-closed structured JSON serialization.

#![cfg(feature = "slog")]

use redactable::{
    RedactedJsonExt, RedactedOutput, Secret, Sensitive, ToRedactedOutput, slog::SlogRedactedExt,
};
use serde::Serialize;
use serde_json::Value as JsonValue;

mod support {
    pub(crate) mod slog_capture;
}

use support::slog_capture::{CapturedValue, CapturingSerializer, serialize_to_capture};

const CANARY: &str = "phase03-serializer-canary-7fb1";
const ERROR_MARKER: &str = "phase03-deliberate-serialize-error";

#[derive(Clone, Sensitive)]
struct FailingEvent {
    #[sensitive(Secret)]
    secret: String,
}

impl Serialize for FailingEvent {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Err(<S::Error as serde::ser::Error>::custom(format!(
            "{ERROR_MARKER}:{CANARY}"
        )))
    }
}

fn assert_safe_json_string(value: &JsonValue) {
    assert_eq!(value, &JsonValue::String("[REDACTED]".into()));
    for rendered in [value.to_string(), format!("{value:?}")] {
        assert!(!rendered.contains(CANARY));
        assert!(!rendered.contains(ERROR_MARKER));
    }
}

#[test]
fn serialization_errors_stay_json_and_omit_error_canary_across_slog_paths() {
    let event = FailingEvent {
        secret: CANARY.into(),
    };

    let output = event.redacted_json().to_redacted_output();
    let RedactedOutput::Json(json) = output else {
        panic!("redacted_json failure must preserve the Json variant");
    };
    assert_safe_json_string(&json);

    let extension = event.clone().slog_redacted_json();
    let mut extension_capture = CapturingSerializer::new();
    serialize_to_capture(&extension, "extension", &mut extension_capture);
    let Some(CapturedValue::Serde(json)) = extension_capture.get("extension") else {
        panic!("slog extension must emit structured JSON");
    };
    assert_safe_json_string(&json);

    let mut derived_capture = CapturingSerializer::new();
    serialize_to_capture(&event, "derived", &mut derived_capture);
    let Some(CapturedValue::Serde(json)) = derived_capture.get("derived") else {
        panic!("derived slog value must emit structured JSON");
    };
    assert_safe_json_string(&json);
}
