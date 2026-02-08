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
        RedactableWithFormatter, RedactedJsonRef, RedactedOutput, RedactedOutputRef,
        SensitiveValue, SensitiveWithPolicy, ToRedactedOutput,
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

// =============================================================================
// impl_slog_redacted! — SlogValue + SlogRedacted for ToRedactedOutput types
// =============================================================================
//
// Most types in this module share the same SlogValue body: delegate to
// `emit_output(&self.to_redacted_output(), ...)`. This macro generates both
// the SlogValue and SlogRedacted impls for those types.

macro_rules! impl_slog_redacted {
    // With generics: `@ [T, P] Type<T, P> where Bounds`
    (@ [$($gen:ident),+] $ty:ty where $($bounds:tt)+) => {
        impl<$($gen),+> SlogValue for $ty where $($bounds)+ {
            fn serialize(
                &self,
                record: &Record<'_>,
                key: Key,
                serializer: &mut dyn Serializer,
            ) -> SlogResult {
                emit_output(&self.to_redacted_output(), record, key, serializer)
            }
        }

        impl<$($gen),+> SlogRedacted for $ty where $($bounds)+ {}
    };
    // Without generics: `Type`
    ($ty:ty) => {
        impl SlogValue for $ty {
            fn serialize(
                &self,
                record: &Record<'_>,
                key: Key,
                serializer: &mut dyn Serializer,
            ) -> SlogResult {
                emit_output(&self.to_redacted_output(), record, key, serializer)
            }
        }

        impl SlogRedacted for $ty {}
    };
}

impl_slog_redacted!(RedactedOutput);
impl_slog_redacted!(@ [T, P] SensitiveValue<T, P> where T: SensitiveWithPolicy<P>, P: RedactionPolicy);
impl_slog_redacted!(@ [T] NotSensitiveDisplay<T> where T: fmt::Display);
impl_slog_redacted!(@ [T] NotSensitiveDebug<T> where T: fmt::Debug);
impl_slog_redacted!(@ [T] NotSensitiveJson<'_, T> where T: Serialize + ?Sized);
impl_slog_redacted!(@ [T] RedactedOutputRef<'_, T> where T: Redactable + Clone + fmt::Debug);
impl_slog_redacted!(@ [T] RedactedJsonRef<'_, T> where T: Redactable + Clone + Serialize);

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

// Special cases: these don't use emit_output(&self.to_redacted_output(), ...)

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

/// Helper for `NotSensitive` derive-generated slog impls.
///
/// Serializes the value directly as structured JSON without redaction.
/// Not intended for direct use - called by generated code.
#[doc(hidden)]
pub fn __slog_serialize_not_sensitive<T: Serialize>(
    value: &T,
    record: &Record<'_>,
    key: Key,
    serializer: &mut dyn Serializer,
) -> SlogResult {
    let json_value = serde_json::to_value(value)
        .unwrap_or_else(|err| JsonValue::String(format!("Failed to serialize value: {err}")));
    let nested = slog::Serde(json_value);
    SlogValue::serialize(&nested, record, key, serializer)
}

/// Wrapper for values that implement `RedactableWithFormatter` to participate in slog logging.
///
/// Use [`SlogRedactedDisplayExt::slog_redacted_display`] for ergonomic construction,
/// or call `RedactedDisplayValue::new(&value)` directly.
pub struct RedactedDisplayValue<'a, T: ?Sized>(&'a T);

impl<'a, T: ?Sized> RedactedDisplayValue<'a, T> {
    /// Wraps a reference to a `RedactableWithFormatter` value for slog logging.
    pub fn new(value: &'a T) -> Self {
        Self(value)
    }
}

// Special case: delegates to the inner value's `to_redacted_output`, not `self`.
impl<T> SlogValue for RedactedDisplayValue<'_, T>
where
    T: RedactableWithFormatter,
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

impl<T> SlogRedacted for RedactedDisplayValue<'_, T> where T: RedactableWithFormatter {}

/// Extension trait for logging `RedactableWithFormatter` types through slog.
///
/// This is the display-string counterpart to [`SlogRedactedExt::slog_redacted_json`].
/// Use this when you want redacted display output without JSON serialization overhead.
///
/// ## Example
/// ```ignore
/// use redactable::slog::SlogRedactedDisplayExt;
///
/// info!(logger, "event"; "data" => event.slog_redacted_display());
/// ```
pub trait SlogRedactedDisplayExt: RedactableWithFormatter {
    /// Wraps `&self` for slog logging using `RedactableWithFormatter` formatting.
    fn slog_redacted_display(&self) -> RedactedDisplayValue<'_, Self>
    where
        Self: Sized,
    {
        RedactedDisplayValue::new(self)
    }
}

impl<T> SlogRedactedDisplayExt for T where T: RedactableWithFormatter {}

#[cfg(feature = "tracing")]
impl<T> crate::tracing::TracingRedacted for RedactedDisplayValue<'_, T> where
    T: RedactableWithFormatter
{
}
