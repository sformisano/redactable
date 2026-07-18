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
use slog::{Key, Record, Result as SlogResult, Serializer, Value as SlogValue};

pub use crate::redaction::RedactedJson;
use crate::{
    policy::RedactionPolicy,
    redaction::{
        NotSensitive, NotSensitiveDebug, NotSensitiveDisplay, NotSensitiveJson, Redactable,
        RedactableWithFormatter, RedactedJsonRef, RedactedOutput, RedactedOutputRef,
        SensitiveValue, SensitiveWithPolicy, ToRedactedOutput, serialize_redacted_json,
    },
};

/// Marker trait for types whose `slog` integration always emits logging-safe output.
///
/// This trait requires `slog::Value` so the type can be logged with slog.
/// Implementors are safe because their `slog::Value` implementation either
/// redacts its value or emits a value explicitly declared non-sensitive.
///
/// This trait is implemented only for logging-safe adapters and wrappers. It is
/// not a blanket impl for raw types.
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
/// Requires [`Redactable`], which only types with declared redaction behavior
/// implement - raw passthrough leaves like `String` cannot be certified as
/// redacted slog output. Every `Redactable` shape is accepted, including types
/// using `#[redactable(recursive)]`. `Debug` is not required because this path
/// only redacts and serializes the resulting value.
///
/// # Panics
///
/// The adapter does not clone the value before redacting (unlike the borrowed adapters), but a type's own `.redact()` may clone internally: traversal through
/// [`std::sync::Arc`] or [`std::rc::Rc`] must clone the shared referent because
/// other owners may still hold it, and rebuilding a `HashMap` or `HashSet` clones its `BuildHasher` (a custom hasher whose `Clone` panics or has side effects surfaces here). A live [`std::cell::RefCell`] mutable borrow
/// behind an `Arc`/`Rc` therefore still panics. Prefer unique ownership
/// ([`Box`]) for values you log. (`Arc<RefCell<T>>` is `!Send + !Sync` and an
/// anti-pattern regardless.)
///
/// ## Example
/// ```ignore
/// use redactable::slog::SlogRedactedExt;
///
/// info!(logger, "event"; "data" => event.slog_redacted_json());
/// ```
pub trait SlogRedactedExt: Redactable + Serialize + Sized {
    /// Redacts `self` and returns a `slog::Value` that serializes as structured JSON.
    ///
    /// If converting the redacted output into `serde_json::Value` fails, the
    /// returned value stores the fixed JSON string `"[REDACTED]"`.
    fn slog_redacted_json(self) -> RedactedJson {
        let redacted = self.redact();
        let json_value = serialize_redacted_json(redacted);
        RedactedJson::new(json_value)
    }
}

impl<T> SlogRedactedExt for T where T: Redactable + Serialize {}

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

impl<T> SlogRedacted for NotSensitive<T> where T: SlogValue {}

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
    let json_value = serialize_redacted_json(value);
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

// Special case: formats directly through RedactableWithFormatter. The
// ToRedactedOutput bound keeps raw formatter passthroughs (String, scalars)
// from being certified: `RedactedDisplayValue::new(&raw)` would otherwise emit
// the raw value while carrying the SlogRedacted marker. SensitiveDisplay and
// NotSensitiveDisplay derives generate ToRedactedOutput; passthroughs do not.
impl<T> SlogValue for RedactedDisplayValue<'_, T>
where
    T: RedactableWithFormatter + ToRedactedOutput,
{
    fn serialize(
        &self,
        _record: &Record<'_>,
        key: Key,
        serializer: &mut dyn Serializer,
    ) -> SlogResult {
        let redacted = self.0.redacted_display();
        serializer.emit_arguments(key, &format_args!("{redacted}"))
    }
}

impl<T> SlogRedacted for RedactedDisplayValue<'_, T> where
    T: RedactableWithFormatter + ToRedactedOutput
{
}

/// Extension trait for logging `RedactableWithFormatter` types through slog.
///
/// This is the display-string counterpart to [`SlogRedactedExt::slog_redacted_json`].
/// Use this when you want redacted display output without JSON serialization overhead.
///
/// Requires [`ToRedactedOutput`]: scalar formatter passthroughs like `String`
/// format unchanged, which would let raw values be certified as redacted slog
/// output without any transformation. The display derives generate
/// `ToRedactedOutput`; raw values never implement it.
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

impl<T> SlogRedactedDisplayExt for T where T: RedactableWithFormatter + ToRedactedOutput {}

#[cfg(feature = "tracing")]
impl<T> crate::tracing::TracingRedacted for RedactedDisplayValue<'_, T> where
    T: RedactableWithFormatter + ToRedactedOutput
{
}
