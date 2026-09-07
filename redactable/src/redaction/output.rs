//! Output types for logging boundaries.
//!
//! This module provides types for producing logging-safe output:
//!
//! - [`RedactedOutput`]: Owned output with read-only Text or Json inspection
//! - [`ToRedactedOutput`]: Trait for types that can produce redacted output
//! - [`RedactedOutputRef`]: Wrapper for explicit redacted output
//! - [`IntoRedactedOutputExt`]: Consuming output adapter that redacts via `.redact()`
//! - [`RedactedJson`]: Owned redacted JSON output
//! - [`RedactedJsonRef`]: Wrapper for redacted JSON output

use std::fmt::{Debug, Formatter, Result as FmtResult};

#[cfg(feature = "json")]
use serde::Serialize;
#[cfg(feature = "json")]
use serde_json::Value as JsonValue;

use super::{
    traits::{Redactable, SensitiveWithPolicy},
    wrappers::SensitiveValue,
};
use crate::policy::RedactionPolicy;

/// Serializes an already-redacted value into a structured [`JsonValue`].
///
/// This is the terminal serialization step used by the redacted-JSON logging
/// adapters. It performs **no redaction itself**: whatever `value` serializes
/// to is exactly what ends up in the output, so callers must pass only values
/// whose sensitive content has already been redacted (for example the result
/// of `.redact()`).
///
/// The conversion is fail-closed: if serialization fails (for example a map
/// with unsupported compound keys such as tuples or structs, or a custom
/// [`Serialize`] implementation that errors), the function returns the
/// [`REDACTED_PLACEHOLDER`] string instead of propagating the error or
/// emitting partially serialized data.
///
/// `value` is passed to `serde_json::to_value`. Pass a serializable reference
/// when the original value must remain available.
///
/// [`REDACTED_PLACEHOLDER`]: crate::policy::REDACTED_PLACEHOLDER
#[cfg(feature = "json")]
pub fn serialize_redacted_json<T: Serialize>(value: T) -> JsonValue {
    serde_json::to_value(value)
        .unwrap_or_else(|_| JsonValue::String(crate::policy::REDACTED_PLACEHOLDER.into()))
}

// =============================================================================
// RedactedOutput - Output produced at logging boundaries
// =============================================================================

/// Output produced at a logging boundary.
///
/// Obtain this value from a redacting adapter or a named output declaration.
/// Inspect the selected representation through [`Self::view`].
#[derive(Clone, PartialEq, Eq)]
pub struct RedactedOutput {
    representation: OutputRepresentation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum OutputRepresentation {
    Text(String),
    #[cfg(feature = "json")]
    Json(JsonValue),
}

/// Read-only inspection of the representation selected for logging.
///
/// Downstream matches need a wildcard arm because feature unification can
/// enable JSON and future versions may add representations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RedactedOutputView<'a> {
    /// Redacted text output.
    Text(&'a str),
    /// Redacted structured JSON output (requires the `json` feature).
    #[cfg(feature = "json")]
    Json(&'a JsonValue),
}

impl RedactedOutput {
    /// Borrows the selected output without granting construction or mutation.
    #[must_use]
    pub fn view(&self) -> RedactedOutputView<'_> {
        match &self.representation {
            OutputRepresentation::Text(text) => RedactedOutputView::Text(text),
            #[cfg(feature = "json")]
            OutputRepresentation::Json(json) => RedactedOutputView::Json(json),
        }
    }

    pub(crate) fn text(text: String) -> Self {
        Self {
            representation: OutputRepresentation::Text(text),
        }
    }

    #[cfg(feature = "json")]
    pub(crate) fn json(json: JsonValue) -> Self {
        Self {
            representation: OutputRepresentation::Json(json),
        }
    }

    #[cfg(any(feature = "slog", feature = "tracing"))]
    pub(crate) fn into_text(self) -> String {
        match self.representation {
            OutputRepresentation::Text(text) => text,
            #[cfg(feature = "json")]
            OutputRepresentation::Json(json) => json.to_string(),
        }
    }

    #[cfg(feature = "json")]
    pub(super) fn into_json(self) -> JsonValue {
        match self.representation {
            OutputRepresentation::Text(text) => JsonValue::String(text),
            OutputRepresentation::Json(json) => json,
        }
    }
}

impl Debug for RedactedOutput {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        Debug::fmt(&self.representation, formatter)
    }
}

// =============================================================================
// ToRedactedOutput - Trait for producing logging-safe output
// =============================================================================

/// Produces a logging-safe output representation.
///
/// This trait is intentionally narrower than `RedactableWithFormatter`.
/// Passthrough scalar formatting is useful inside redacted templates, but it
/// does not certify a raw value as safe at a logging boundary.
///
/// For structured values, use [`RedactedOutputExt::redacted_output`] or
/// [`IntoRedactedOutputExt::into_redacted_output`]. With `json`, use
/// `RedactedJsonExt::redacted_json` or
/// `IntoRedactedJsonExt::into_redacted_json`; `Sensitive` and `SensitiveDual`
/// can select that borrowing bridge with `#[redactable(output = json)]`.
/// Borrowing structural bridges require `Clone`; consuming bridges redact
/// the owned value. Their formatting and serialization bounds still apply.
///
/// Handwritten implementations can delegate to those bridges or declare selected
/// output with [`struct@crate::NotSensitiveDisplay`], [`crate::NotSensitiveDebug`],
/// `NotSensitiveJson`, or [`crate::UncheckedRedactedSummary`]. The JSON wrapper
/// is available through `NotSensitiveJsonExt::not_sensitive_json` with
/// `json`. These declarations and user-defined policies remain the author's
/// responsibility; output construction does not prove confidentiality or
/// completeness. Inspect the result through [`RedactedOutput::view`].
#[cfg_attr(
    feature = "json",
    doc = "See [`RedactedJsonExt::redacted_json`], [`IntoRedactedJsonExt::into_redacted_json`], and [`crate::NotSensitiveJsonExt::not_sensitive_json`] for the JSON bridges and explicit escape."
)]
pub trait ToRedactedOutput {
    /// Produces an owned, logging-safe representation of this value.
    ///
    /// The implementing type selects the returned [`RedactedOutput`] through
    /// redaction or an explicit declaration. Logging integrations call this
    /// method at the logging boundary; prefer it over formatting the raw
    /// value with `Display` or `Debug`.
    ///
    /// The method borrows `self` and returns an owned output value, leaving
    /// the original in place. Implementations may clone or otherwise
    /// traverse `self` to build the output and inherit the panics of doing
    /// so; see the documentation of the concrete implementing type for its
    /// panic behavior.
    #[must_use]
    fn to_redacted_output(&self) -> RedactedOutput;
}

impl ToRedactedOutput for RedactedOutput {
    fn to_redacted_output(&self) -> RedactedOutput {
        self.clone()
    }
}

impl<T, P> ToRedactedOutput for SensitiveValue<T, P>
where
    T: SensitiveWithPolicy<P>,
    P: RedactionPolicy,
{
    fn to_redacted_output(&self) -> RedactedOutput {
        RedactedOutput::text(self.redacted())
    }
}

// =============================================================================
// RedactedOutputRef - Wrapper for explicit redacted output
// =============================================================================

/// Wrapper for explicitly redacting structured types.
///
/// Use `.redacted_output()` to opt into logging-safe output for types that
/// implement `Redactable + Clone + Debug`.
///
/// # Panics
///
/// Rendering this wrapper clones the complete value before redacting it and
/// therefore inherits every panic from `Clone`. In particular, cloning a
/// traversed [`std::cell::RefCell`] panics while that cell is mutably borrowed.
/// Use [`IntoRedactedOutputExt::into_redacted_output`] when the original value
/// does not need to be retained.
pub struct RedactedOutputRef<'a, T: ?Sized>(&'a T);

impl<T> ToRedactedOutput for RedactedOutputRef<'_, T>
where
    T: Redactable + Clone + Debug,
{
    fn to_redacted_output(&self) -> RedactedOutput {
        RedactedOutput::text(format!("{:?}", self.0.clone().redact()))
    }
}

/// Extension trait to obtain a redacted output wrapper.
///
/// Requires [`Redactable`], which only types with declared redaction behavior
/// implement - raw passthrough leaves like `String` cannot be certified as
/// redacted output.
pub trait RedactedOutputExt {
    /// Wraps the value for explicit logging-safe output.
    ///
    /// The wrapper is inert until it is rendered or converted with
    /// [`ToRedactedOutput::to_redacted_output`].
    ///
    /// # Panics
    ///
    /// Rendering the returned wrapper inherits panics from cloning `Self`.
    /// A traversed [`std::cell::RefCell`] with a live mutable borrow is one
    /// concrete case. Prefer
    /// [`IntoRedactedOutputExt::into_redacted_output`] when ownership is
    /// available.
    fn redacted_output(&self) -> RedactedOutputRef<'_, Self>
    where
        Self: Sized;
}

/// Consuming extension trait for logging structural redacted output.
///
/// Unlike [`RedactedOutputExt`], this adapter redacts the owned value by calling `.redact()` on it
/// instead of cloning it first. It is the preferred structural logging boundary when
/// the original value does not need to be retained, and it accepts every
/// [`Redactable`] shape, including types using `#[redactable(recursive)]`.
///
/// # Panics
///
/// The adapter does not clone the value before redacting (unlike the borrowed adapters), but a type's own `.redact()` may clone internally: traversal through
/// [`std::sync::Arc`] or [`std::rc::Rc`] must clone the shared referent because
/// other owners may still hold it, and rebuilding a `HashMap` or `HashSet` clones its `BuildHasher` (a custom hasher whose `Clone` panics or has side effects surfaces here). A live [`std::cell::RefCell`] mutable borrow
/// behind an `Arc`/`Rc` therefore still panics. Prefer unique ownership
/// ([`Box`]) for values you log. (`Arc<RefCell<T>>` is `!Send + !Sync` and an
/// anti-pattern regardless.)
pub trait IntoRedactedOutputExt: Redactable + Debug + Sized {
    /// Consumes and redacts the value, then returns its logging-safe Debug text.
    #[must_use]
    fn into_redacted_output(self) -> RedactedOutput {
        RedactedOutput::text(format!("{:?}", self.redact()))
    }
}

impl<T> IntoRedactedOutputExt for T where T: Redactable + Debug {}

impl<T> RedactedOutputExt for T
where
    T: Redactable + Clone + Debug,
{
    fn redacted_output(&self) -> RedactedOutputRef<'_, Self> {
        RedactedOutputRef(self)
    }
}

// =============================================================================
// RedactedJson - Owned redacted JSON output
// =============================================================================

/// Owned redacted JSON output produced at logging boundaries.
#[cfg(feature = "json")]
pub struct RedactedJson {
    value: JsonValue,
}

#[cfg(feature = "json")]
impl RedactedJson {
    #[cfg(feature = "slog")]
    pub(crate) fn new(value: JsonValue) -> Self {
        Self { value }
    }

    #[cfg(feature = "slog")]
    pub(crate) fn value(&self) -> &JsonValue {
        &self.value
    }
}

#[cfg(feature = "json")]
impl ToRedactedOutput for RedactedJson {
    fn to_redacted_output(&self) -> RedactedOutput {
        RedactedOutput::json(self.value.clone())
    }
}

// =============================================================================
// RedactedJsonRef - Wrapper for redacted JSON output
// =============================================================================

/// Wrapper for redacted JSON output from structured types.
///
/// # Panics
///
/// Converting or logging this wrapper clones the complete value before
/// redacting it and therefore inherits every panic from `Clone`. In
/// particular, cloning a traversed [`std::cell::RefCell`] panics while that
/// cell is mutably borrowed. Use
/// [`IntoRedactedJsonExt::into_redacted_json`] when ownership is available.
#[cfg(feature = "json")]
pub struct RedactedJsonRef<'a, T: ?Sized>(&'a T);

#[cfg(feature = "json")]
impl<T> ToRedactedOutput for RedactedJsonRef<'_, T>
where
    T: Redactable + Clone + Serialize,
{
    fn to_redacted_output(&self) -> RedactedOutput {
        let redacted = self.0.clone().redact();
        RedactedOutput::json(serialize_redacted_json(redacted))
    }
}

/// Extension trait to obtain a redacted JSON output wrapper.
///
/// Requires [`Redactable`], which only types with declared redaction behavior
/// implement - raw passthrough leaves like `String` cannot be certified as
/// redacted JSON.
#[cfg(feature = "json")]
pub trait RedactedJsonExt {
    /// Wraps the value for explicit redacted JSON output.
    ///
    /// The wrapper is inert until it is converted or logged.
    ///
    /// # Panics
    ///
    /// Converting or logging the returned wrapper inherits panics from
    /// cloning `Self`, including a traversed [`std::cell::RefCell`] with a live
    /// mutable borrow. Prefer [`IntoRedactedJsonExt::into_redacted_json`] when
    /// ownership is available.
    fn redacted_json(&self) -> RedactedJsonRef<'_, Self>
    where
        Self: Sized;
}

/// Consuming extension trait for logging structural redacted JSON.
///
/// This adapter redacts the owned value by calling `.redact()` on it instead of cloning it first. It accepts
/// every [`Redactable`] shape, including types using `#[redactable(recursive)]`.
///
/// # Panics
///
/// The adapter does not clone the value before redacting (unlike the borrowed adapters), but a type's own `.redact()` may clone internally: traversal through
/// [`std::sync::Arc`] or [`std::rc::Rc`] must clone the shared referent because
/// other owners may still hold it, and rebuilding a `HashMap` or `HashSet` clones its `BuildHasher` (a custom hasher whose `Clone` panics or has side effects surfaces here). A live [`std::cell::RefCell`] mutable borrow
/// behind an `Arc`/`Rc` therefore still panics. Prefer unique ownership
/// ([`Box`]) for values you log. (`Arc<RefCell<T>>` is `!Send + !Sync` and an
/// anti-pattern regardless.)
#[cfg(feature = "json")]
pub trait IntoRedactedJsonExt: Redactable + Serialize + Sized {
    /// Consumes and redacts the value, then serializes only the redacted result.
    #[must_use]
    fn into_redacted_json(self) -> RedactedJson {
        RedactedJson {
            value: serialize_redacted_json(self.redact()),
        }
    }
}

#[cfg(feature = "json")]
impl<T> IntoRedactedJsonExt for T where T: Redactable + Serialize {}

#[cfg(feature = "json")]
impl<T> RedactedJsonExt for T
where
    T: Redactable + Clone + Serialize,
{
    fn redacted_json(&self) -> RedactedJsonRef<'_, Self> {
        RedactedJsonRef(self)
    }
}
