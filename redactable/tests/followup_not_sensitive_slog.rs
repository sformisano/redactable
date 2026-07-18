//! Regressions for explicitly non-sensitive slog boundaries.

#![cfg(feature = "slog")]

use std::cell::RefCell;

use redactable::{
    NotSensitiveExt, NotSensitiveJsonExt, RedactedOutput, ToRedactedOutput, slog::SlogRedacted,
};
use serde::Serialize;

mod support {
    pub(crate) mod slog_capture;
}

use support::slog_capture::{CapturedValue, CapturingSerializer, serialize_to_capture};

const FAILURE_CANARY: &str = "followup-not-sensitive-json-canary-4dc7";
const FAILURE_DETAIL: &str = "followup-not-sensitive-json-serializer-error";

#[derive(Clone, redactable::NotSensitive)]
struct FailingSerialization {
    value: String,
}

impl Serialize for FailingSerialization {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Err(<S::Error as serde::ser::Error>::custom(format!(
            "{FAILURE_DETAIL}:{}",
            self.value
        )))
    }
}

#[derive(Clone, redactable::NotSensitive, Serialize)]
struct SuccessfulSerialization {
    value: String,
}

#[derive(Clone, redactable::NotSensitive, Serialize)]
struct BorrowSensitiveSerialization {
    value: RefCell<String>,
}

fn assert_fixed_json_fallback(value: &serde_json::Value) {
    assert_eq!(value, &serde_json::Value::String("[REDACTED]".into()));
    let rendered = [value.to_string(), format!("{value:?}")];
    for output in rendered {
        assert!(!output.contains(FAILURE_CANARY));
        assert!(!output.contains(FAILURE_DETAIL));
    }
}

#[test]
fn explicitly_non_sensitive_json_failures_stay_json_and_omit_error_details() {
    let value = FailingSerialization {
        value: FAILURE_CANARY.into(),
    };

    let output = value.not_sensitive_json().to_redacted_output();
    let RedactedOutput::Json(json) = output else {
        panic!("not-sensitive JSON failure must preserve the JSON variant");
    };
    assert_fixed_json_fallback(&json);

    let debug = format!("{:?}", value.not_sensitive_json());
    assert!(!debug.contains(FAILURE_CANARY));
    assert!(!debug.contains(FAILURE_DETAIL));

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&value, "value", &mut serializer);
    let Some(CapturedValue::Serde(json)) = serializer.get("value") else {
        panic!("generated NotSensitive slog output must stay structured JSON");
    };
    assert_fixed_json_fallback(&json);
}

#[test]
fn successful_explicitly_non_sensitive_json_and_slog_output_remains_raw() {
    const RAW_VALUE: &str = "declared-public-value-91c2";
    let value = SuccessfulSerialization {
        value: RAW_VALUE.into(),
    };
    let expected = serde_json::json!({"value": RAW_VALUE});

    assert_eq!(
        value.not_sensitive_json().to_redacted_output(),
        RedactedOutput::Json(expected.clone())
    );

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&value, "value", &mut serializer);
    assert_eq!(
        serializer.get("value"),
        Some(CapturedValue::Serde(expected))
    );
}

#[test]
fn not_sensitive_wrapper_is_slog_certified_and_delegates_raw_output() {
    fn assert_slog_certified<T: SlogRedacted>(_: &T) {}

    const RAW_VALUE: &str = "declared-safe-slog-value-b83a";
    let value = RAW_VALUE.to_owned();
    let wrapped = value.not_sensitive();
    assert_slog_certified(&wrapped);

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&wrapped, "value", &mut serializer);
    assert_eq!(
        serializer.get("value"),
        Some(CapturedValue::Str(RAW_VALUE.into()))
    );
}

#[test]
fn generated_not_sensitive_slog_preserves_raw_values_and_fail_closes_borrow_conflicts() {
    const RAW_VALUE: &str = "declared-public-refcell-value-4b19";
    let value = BorrowSensitiveSerialization {
        value: RefCell::new(RAW_VALUE.into()),
    };
    let mut serializer = CapturingSerializer::new();

    serialize_to_capture(&value, "available", &mut serializer);
    assert_eq!(
        serializer.get("available"),
        Some(CapturedValue::Serde(
            serde_json::json!({"value": RAW_VALUE})
        ))
    );

    let _borrow = value.value.borrow_mut();
    serialize_to_capture(&value, "borrowed", &mut serializer);
    assert_eq!(
        serializer.get("borrowed"),
        Some(CapturedValue::Serde(serde_json::Value::String(
            "[REDACTED]".into()
        )))
    );
}
