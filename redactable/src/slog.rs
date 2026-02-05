//! Adapters for emitting redacted values through `slog`.
//!
//! This module exists to connect `crate::redaction::Redactable` with `slog` by
//! providing `slog::Value` implementations that serialize redacted outputs as
//! structured JSON via `slog`'s nested-value support.
//!
//! It is responsible for:
//! - Ensuring the logged representation is derived from `Redactable::redact()`,
//!   not from the original value.
//! - Avoiding fallible logging APIs: serialization failures are represented as
//!   placeholder strings rather than propagated as errors.
//!
//! It does not configure `slog`, define redaction policy, or attempt to validate
//! that a `Redactable` implementation performs correct redaction.

use std::fmt;

use serde::Serialize;
use serde_json::Value as JsonValue;
use slog::{Key, Record, Result as SlogResult, Serializer, Value as SlogValue};

pub use crate::redaction::RedactedJson;
use crate::{
    policy::RedactionPolicy,
    redaction::{
        NotSensitive, NotSensitiveDebug, NotSensitiveDisplay, NotSensitiveJson, Redactable,
        RedactableDisplay, RedactableWithPolicy, RedactedJsonRef, RedactedOutput,
        RedactedOutputRef, SensitiveValue, ToRedactedOutput,
    },
};

/// Marker trait for types whose `slog` integration always emits redacted output.
///
/// This trait requires `slog::Value` so the type can be logged with slog.
/// The marker indicates that the type's `slog::Value` implementation produces
/// redacted output rather than raw values.
///
/// This trait is implemented only for sink adapters and wrappers that redact
/// before logging. It is not a blanket impl for raw types.
///
/// ```compile_fail
/// use redactable::slog::SlogRedacted;
///
/// fn assert_slog_redacted<T: SlogRedacted>() {}
///
/// assert_slog_redacted::<String>();
/// ```
pub trait SlogRedacted: SlogValue {}

impl<T: SlogRedacted + ?Sized> SlogRedacted for &T {}

impl SlogValue for RedactedJson {
    fn serialize(
        &self,
        record: &Record<'_>,
        key: Key,
        serializer: &mut dyn Serializer,
    ) -> SlogResult {
        let nested = slog::Serde(self.value().clone());
        SlogValue::serialize(&nested, record, key, serializer)
    }
}

impl SlogRedacted for RedactedJson {}

fn emit_output(
    output: &RedactedOutput,
    record: &Record<'_>,
    key: Key,
    serializer: &mut dyn Serializer,
) -> SlogResult {
    match output {
        RedactedOutput::Text(text) => serializer.emit_str(key, text),
        #[cfg(feature = "json")]
        RedactedOutput::Json(json) => {
            let nested = slog::Serde(json.clone());
            SlogValue::serialize(&nested, record, key, serializer)
        }
    }
}

impl SlogValue for RedactedOutput {
    fn serialize(
        &self,
        record: &Record<'_>,
        key: Key,
        serializer: &mut dyn Serializer,
    ) -> SlogResult {
        emit_output(self, record, key, serializer)
    }
}

impl SlogRedacted for RedactedOutput {}

/// Extension trait for ergonomic slog logging of redacted values as JSON.
///
/// Calling `slog_redacted_json` consumes the value, computes `self.redact()`,
/// and stores the result as a `serde_json::Value`. The original (unredacted)
/// value is not serialized.
///
/// ## Example
/// ```ignore
/// use redactable::slog::SlogRedactedExt;
///
/// info!(logger, "event"; "data" => event.slog_redacted_json());
/// ```
pub trait SlogRedactedExt: Redactable + fmt::Debug + Serialize + Sized {
    /// Redacts `self` and returns a `slog::Value` that serializes as structured JSON.
    ///
    /// If converting the redacted output into `serde_json::Value` fails, the
    /// returned value stores a JSON string with the message
    /// `"Failed to serialize redacted value"`.
    fn slog_redacted_json(self) -> RedactedJson {
        let redacted = self.redact();
        let json_value = serde_json::to_value(redacted).unwrap_or_else(|err| {
            JsonValue::String(format!("Failed to serialize redacted value: {err}"))
        });
        RedactedJson::new(json_value)
    }
}

impl<T> SlogRedactedExt for T where T: Redactable + fmt::Debug + Serialize {}

// Backward compatibility alias
#[deprecated(since = "0.2.0", note = "Use SlogRedactedExt instead")]
pub trait IntoRedactedJson: SlogRedactedExt {
    /// Deprecated: use `slog_redacted_json` instead.
    #[deprecated(since = "0.2.0", note = "Use slog_redacted_json instead")]
    fn into_redacted_json(self) -> RedactedJson {
        self.slog_redacted_json()
    }
}

#[allow(deprecated)]
impl<T> IntoRedactedJson for T where T: SlogRedactedExt {}

impl<T, P> SlogValue for SensitiveValue<T, P>
where
    T: RedactableWithPolicy<P>,
    P: RedactionPolicy,
{
    fn serialize(
        &self,
        record: &Record<'_>,
        key: Key,
        serializer: &mut dyn Serializer,
    ) -> SlogResult {
        emit_output(&self.to_redacted_output(), record, key, serializer)
    }
}

impl<T, P> SlogRedacted for SensitiveValue<T, P>
where
    T: RedactableWithPolicy<P>,
    P: RedactionPolicy,
{
}

impl<T> SlogValue for NotSensitiveDisplay<T>
where
    T: fmt::Display,
{
    fn serialize(
        &self,
        record: &Record<'_>,
        key: Key,
        serializer: &mut dyn Serializer,
    ) -> SlogResult {
        emit_output(&self.to_redacted_output(), record, key, serializer)
    }
}

impl<T> SlogRedacted for NotSensitiveDisplay<T> where T: fmt::Display {}

impl<T> SlogValue for NotSensitiveDebug<T>
where
    T: fmt::Debug,
{
    fn serialize(
        &self,
        record: &Record<'_>,
        key: Key,
        serializer: &mut dyn Serializer,
    ) -> SlogResult {
        emit_output(&self.to_redacted_output(), record, key, serializer)
    }
}

impl<T> SlogRedacted for NotSensitiveDebug<T> where T: fmt::Debug {}

impl<T> SlogValue for NotSensitive<T>
where
    T: SlogValue,
{
    fn serialize(
        &self,
        record: &Record<'_>,
        key: Key,
        serializer: &mut dyn Serializer,
    ) -> SlogResult {
        self.0.serialize(record, key, serializer)
    }
}

impl<T> SlogRedacted for NotSensitive<T> where T: SlogRedacted {}

impl<T> SlogValue for NotSensitiveJson<'_, T>
where
    T: Serialize + ?Sized,
{
    fn serialize(
        &self,
        record: &Record<'_>,
        key: Key,
        serializer: &mut dyn Serializer,
    ) -> SlogResult {
        emit_output(&self.to_redacted_output(), record, key, serializer)
    }
}

impl<T> SlogRedacted for NotSensitiveJson<'_, T> where T: Serialize + ?Sized {}

impl<T> SlogValue for RedactedOutputRef<'_, T>
where
    T: Redactable + Clone + fmt::Debug,
{
    fn serialize(
        &self,
        record: &Record<'_>,
        key: Key,
        serializer: &mut dyn Serializer,
    ) -> SlogResult {
        emit_output(&self.to_redacted_output(), record, key, serializer)
    }
}

impl<T> SlogRedacted for RedactedOutputRef<'_, T> where T: Redactable + Clone + fmt::Debug {}

impl<T> SlogValue for RedactedJsonRef<'_, T>
where
    T: Redactable + Clone + Serialize,
{
    fn serialize(
        &self,
        record: &Record<'_>,
        key: Key,
        serializer: &mut dyn Serializer,
    ) -> SlogResult {
        emit_output(&self.to_redacted_output(), record, key, serializer)
    }
}

impl<T> SlogRedacted for RedactedJsonRef<'_, T> where T: Redactable + Clone + Serialize {}

/// Wrapper for values that implement `RedactableDisplay` to participate in slog logging.
pub struct RedactedDisplayValue<'a, T: ?Sized>(&'a T);

impl<T> SlogValue for RedactedDisplayValue<'_, T>
where
    T: RedactableDisplay,
{
    fn serialize(
        &self,
        record: &Record<'_>,
        key: Key,
        serializer: &mut dyn Serializer,
    ) -> SlogResult {
        emit_output(&self.0.to_redacted_output(), record, key, serializer)
    }
}
