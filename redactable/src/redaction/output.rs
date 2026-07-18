//! Output types for logging boundaries.
//!
//! This module provides types for producing logging-safe output:
//!
//! - [`RedactedOutput`]: The output enum (Text or Json)
//! - [`ToRedactedOutput`]: Trait for types that can produce redacted output
//! - [`RedactedOutputRef`]: Wrapper for explicit redacted output
//! - [`IntoRedactedOutputExt`]: Consuming output adapter that redacts via `.redact()`
//! - [`RedactedJson`]: Owned redacted JSON output
//! - [`RedactedJsonRef`]: Wrapper for redacted JSON output

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
/// `value` is taken by ownership because `serde_json::to_value` consumes it;
/// clone first if the original is still needed.
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
/// Marked `#[non_exhaustive]`: the `Json` variant only exists with the `json`
/// feature, and feature unification means another crate in the build graph can
/// switch it on. Exhaustive matches would break the moment that happens, so
/// downstream matches must carry a wildcard arm.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RedactedOutput {
    /// Redacted text output.
    Text(String),
    /// Redacted structured JSON output (requires the `json` feature).
    #[cfg(feature = "json")]
    Json(JsonValue),
}

// =============================================================================
// ToRedactedOutput - Trait for producing logging-safe output
// =============================================================================

/// Produces a logging-safe output representation.
///
/// This trait is intentionally narrower than `RedactableWithFormatter`.
/// Passthrough scalar formatting is useful inside redacted templates, but it
/// does not certify a raw value as safe at a logging boundary.
pub trait ToRedactedOutput {
    /// Produces an owned, logging-safe representation of this value.
    ///
    /// The implementing type certifies that the returned [`RedactedOutput`]
    /// contains no sensitive data: either redaction has already been applied
    /// or the value was never sensitive. Logging integrations call this
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
        RedactedOutput::Text(self.redacted())
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
    T: Redactable + Clone + std::fmt::Debug,
{
    fn to_redacted_output(&self) -> RedactedOutput {
        RedactedOutput::Text(format!("{:?}", self.0.clone().redact()))
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
pub trait IntoRedactedOutputExt: Redactable + std::fmt::Debug + Sized {
    /// Consumes and redacts the value, then returns its logging-safe Debug text.
    #[must_use]
    fn into_redacted_output(self) -> RedactedOutput {
        RedactedOutput::Text(format!("{:?}", self.redact()))
    }
}

impl<T> IntoRedactedOutputExt for T where T: Redactable + std::fmt::Debug {}

impl<T> RedactedOutputExt for T
where
    T: Redactable + Clone + std::fmt::Debug,
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
        RedactedOutput::Json(self.value.clone())
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
        RedactedOutput::Json(serialize_redacted_json(redacted))
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
