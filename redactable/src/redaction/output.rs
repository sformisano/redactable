//! The sink value produced at logging boundaries.
//!
//! This module provides the two items every logging integration is built on:
//!
//! - [`RedactedValue`]: the eager, opaque value a logging boundary receives
//! - [`ToRedacted`]: the trait that produces one

use std::fmt::{Debug, Formatter, Result as FmtResult};

use serde::Serialize;
use serde_json::{Value as JsonValue, json};

use super::{
    display::RedactedFormatterRef,
    traits::{Redactable, SensitiveWithPolicy},
    wrappers::SensitiveValue,
};
use crate::{
    __private::{DeclaredFormatting, DeclaredNotSensitive},
    policy::RedactionPolicy,
};

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
pub fn serialize_redacted_json<T: Serialize>(value: T) -> JsonValue {
    serde_json::to_value(value)
        .unwrap_or_else(|_| JsonValue::String(crate::policy::REDACTED_PLACEHOLDER.into()))
}

// =============================================================================
// RedactedValue - the sink value produced at logging boundaries
// =============================================================================

/// The value a logging boundary receives.
///
/// Obtain it from [`ToRedacted::to_redacted`]. A value carries redacted text,
/// redacted JSON, or both; which of those a producer builds is decided by the
/// derive that generated it, never by the sink. Both [`Self::text`] and
/// [`Self::json`] always answer, adapting the stored representation when the
/// requested one was not built.
///
/// Redaction finishes when the value is constructed; the accessors only convert
/// the stored result. Nothing here is deferred, so holding a `RedactedValue`
/// never keeps the original value reachable and never runs a policy a second
/// time.
///
/// Construction is crate-private: a `RedactedValue` can only come from a
/// redacting derive, a logging adapter, or a deliberate member of the Bypass
/// family. There is no `From`, no `Deserialize`, and no mutable access.
#[derive(Clone, PartialEq, Eq)]
pub struct RedactedValue {
    text: Option<String>,
    json: Option<JsonValue>,
}

impl RedactedValue {
    /// Returns the redacted text for this value.
    ///
    /// A JSON-only value answers with its JSON rendered as compact text, which
    /// is what a text sink such as `tracing`'s display path emits for it.
    #[must_use]
    pub fn text(&self) -> String {
        match (&self.text, &self.json) {
            (Some(text), _) => text.clone(),
            (None, Some(json)) => json.to_string(),
            // Unreachable: every constructor sets at least one representation.
            (None, None) => String::new(),
        }
    }

    /// Returns the redacted JSON for this value.
    ///
    /// A text-only value answers with `{"message": text}`. The two
    /// representations are never merged into one shape: a value that carries
    /// both returns the JSON its producer built.
    #[must_use]
    pub fn json(&self) -> JsonValue {
        match (&self.json, &self.text) {
            (Some(json), _) => json.clone(),
            (None, Some(text)) => json!({ "message": text }),
            // Unreachable: every constructor sets at least one representation.
            (None, None) => json!({ "message": "" }),
        }
    }

    pub(crate) fn from_text(text: String) -> Self {
        Self {
            text: Some(text),
            json: None,
        }
    }

    pub(crate) fn from_json(json: JsonValue) -> Self {
        Self {
            text: None,
            json: Some(json),
        }
    }

    /// Carries both representations, as `SensitiveDual` producers do.
    pub(crate) fn from_text_and_json(text: String, json: JsonValue) -> Self {
        Self {
            text: Some(text),
            json: Some(json),
        }
    }

    /// Reports the structured representation a sink should prefer.
    ///
    /// This is the crate-private discriminant the logging adapters branch on:
    /// `slog` emits nested Serde when it is `Some` and a string otherwise. It
    /// exists only in that configuration, since `slog` is its one caller.
    #[cfg(feature = "slog")]
    pub(crate) fn structured(&self) -> Option<&JsonValue> {
        self.json.as_ref()
    }
}

impl Debug for RedactedValue {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        let mut shown = formatter.debug_struct("RedactedValue");
        if let Some(text) = &self.text {
            shown.field("text", text);
        }
        if let Some(json) = &self.json {
            shown.field("json", json);
        }
        shown.finish()
    }
}

// =============================================================================
// ToRedacted - the producer trait
// =============================================================================

/// Produces the logging-safe value for this type.
///
/// This trait is intentionally narrower than `RedactableWithFormatter`.
/// Passthrough scalar formatting is useful inside redacted templates, but it
/// does not certify a raw value as safe at a logging boundary: raw leaves such
/// as `String` never implement `ToRedacted`.
///
/// Most implementations are generated. `Sensitive` and `SensitiveDual` require
/// `Clone + Serialize` and produce redacted JSON (`SensitiveDual` also carries
/// its template text); `SensitiveDisplay` produces redacted text;
/// `NotSensitive` requires `Serialize` and produces the raw JSON its author
/// declared public.
///
/// Handwritten implementations are supported and are the route for an exotic
/// projection: build the value from a member of the Bypass family, which is
/// where the author's declaration is recorded. These declarations and
/// user-defined policies remain the author's responsibility; producing a value
/// does not prove confidentiality or completeness.
pub trait ToRedacted {
    /// Produces the logging-safe value for `self`.
    ///
    /// Logging integrations call this method at the logging boundary; prefer
    /// it over formatting the raw value with `Display` or `Debug`.
    ///
    /// The method borrows `self` and returns an owned value, leaving the
    /// original in place. The structural implementations generated by
    /// `Sensitive` and `SensitiveDual` clone `self` before redacting it and
    /// inherit the panics of doing so: cloning a traversed
    /// [`std::cell::RefCell`] panics while that cell is mutably borrowed. The
    /// display and `NotSensitive` implementations format or serialize the
    /// borrowed value instead.
    #[must_use]
    fn to_redacted(&self) -> RedactedValue;
}

impl ToRedacted for RedactedValue {
    fn to_redacted(&self) -> RedactedValue {
        self.clone()
    }
}

impl<T, P> ToRedacted for SensitiveValue<T, P>
where
    T: SensitiveWithPolicy<P>,
    P: RedactionPolicy,
{
    fn to_redacted(&self) -> RedactedValue {
        RedactedValue::from_text(self.redacted())
    }
}

// =============================================================================
// Construction channel for derive-generated producers
// =============================================================================
//
// These functions are reachable only through the doc-hidden `__private` module,
// which is where derive-generated code addresses the runtime. Each one takes a
// borrowed value of a type that carries the matching declaration and performs
// the redaction or serialization itself, so none of them can be handed a raw
// payload: there is no route from an arbitrary `String` or `JsonValue` to a
// `RedactedValue` here. Deliberately raw content goes through the Bypass
// family, which is where an author's declaration is recorded. Being reachable
// does not authenticate the caller; the bounds are what close the channel.

/// Clones, redacts and serializes, leaving the caller's value in place.
fn redacted_json_of<T: Redactable + Clone + Serialize>(value: &T) -> JsonValue {
    serialize_redacted_json(Redactable::redact(Clone::clone(value)))
}

/// Builds the JSON-only sink value a structural producer carries.
///
/// The value is cloned, redacted with its declared behavior, and serialized
/// here. `Sensitive` generates the call.
pub fn generated_redacted_json<T: Redactable + Clone + Serialize>(value: &T) -> RedactedValue {
    RedactedValue::from_json(redacted_json_of(value))
}

/// Builds the text-only sink value a display producer carries.
///
/// The text is rendered through the type's own declared redacted formatting,
/// the same route [`RedactableWithFormatter::redacted_display`] takes.
/// `SensitiveDisplay` and `NotSensitiveDisplay` generate the call.
///
/// [`RedactableWithFormatter::redacted_display`]: super::display::RedactableWithFormatter::redacted_display
pub fn generated_redacted_display<T: DeclaredFormatting + ?Sized>(value: &T) -> RedactedValue {
    RedactedValue::from_text(RedactedFormatterRef::new(value).to_string())
}

/// Builds the dual sink value a `SensitiveDual` producer carries.
///
/// The text comes from the declared template and the JSON from the redacted
/// clone, so both representations describe the same redacted value.
pub fn generated_redacted_dual<T>(value: &T) -> RedactedValue
where
    T: Redactable + Clone + Serialize + DeclaredFormatting,
{
    RedactedValue::from_text_and_json(
        RedactedFormatterRef::new(value).to_string(),
        redacted_json_of(value),
    )
}

/// Builds the raw-JSON sink value a `NotSensitive` producer carries.
///
/// Nothing is redacted: the author declared the whole type public, which is
/// what [`DeclaredNotSensitive`] records. The type's own `Serialize` output is
/// the value.
pub fn generated_declared_json<T: DeclaredNotSensitive + Serialize + ?Sized>(
    value: &T,
) -> RedactedValue {
    RedactedValue::from_json(serialize_redacted_json(value))
}
