//! The sink value produced at logging boundaries.
//!
//! This module provides the two items every logging integration is built on:
//!
//! - [`RedactedValue`]: the eager, opaque value a logging boundary receives
//! - [`ToRedacted`]: the trait that produces one

#[cfg(feature = "mask-map-keys")]
mod map_keys;
#[cfg(test)]
mod tests;

use std::{
    borrow::Cow,
    fmt::{Debug, Formatter, Result as FmtResult},
    rc::Rc,
    sync::Arc,
};

use serde::{Serialize, Serializer};
use serde_json::Value as JsonValue;

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
/// Obtain it from [`ToRedacted::to_redacted`]. The producer chooses whether a
/// value carries redacted text, redacted JSON, or both. Both [`Self::text`] and
/// [`Self::json`] always answer, adapting the stored representation when the
/// requested one was not built.
///
/// Serde borrows this value and serializes the same shape as [`Self::json`]
/// without cloning its stored JSON. Text-only values serialize as
/// `{"message": text}`.
///
/// Redaction finishes when the value is constructed; the accessors only convert
/// the stored result. Nothing here is deferred, so holding a `RedactedValue`
/// never keeps the original value reachable and never runs a policy a second
/// time.
///
/// Construction is crate-private: a `RedactedValue` can only come from a
/// declared producer, a logging adapter, or the built-in null output for
/// `None` and `()`. There is no `From`, no `Deserialize`, and no mutable access.
#[derive(Clone, PartialEq, Eq)]
pub struct RedactedValue {
    text: Option<String>,
    json: Option<JsonValue>,
}

impl RedactedValue {
    const MESSAGE_KEY: &str = "message";

    /// Returns the redacted text for this value.
    ///
    /// A JSON-only value answers with its JSON rendered as compact text, which
    /// is what a text sink such as `tracing`'s display path emits for it.
    #[must_use]
    pub fn text(&self) -> String {
        self.text_view().into_owned()
    }

    pub(crate) fn text_view(&self) -> Cow<'_, str> {
        match (&self.text, &self.json) {
            (Some(text), _) => Cow::Borrowed(text),
            (None, Some(json)) => Cow::Owned(json.to_string()),
            // Unreachable: every constructor sets at least one representation.
            (None, None) => Cow::Borrowed(""),
        }
    }

    /// Returns the redacted JSON for this value.
    ///
    /// A text-only value answers with `{"message": text}`. The two
    /// representations are never merged into one shape: a value that carries
    /// both returns the JSON its producer built.
    #[must_use]
    pub fn json(&self) -> JsonValue {
        self.json
            .clone()
            .unwrap_or_else(|| JsonValue::from_iter([self.message_field()]))
    }

    pub(crate) fn message_field(&self) -> (&'static str, &str) {
        (Self::MESSAGE_KEY, self.text.as_deref().unwrap_or_default())
    }

    /// Returns owned JSON, moving a fresh result or copying the selected JSON of a borrowed value.
    pub(crate) fn json_from<T: ToRedacted + ?Sized>(producer: &T) -> JsonValue {
        match producer.to_redacted_cow() {
            Cow::Borrowed(value) => value.json(),
            Cow::Owned(value) => value.json.unwrap_or_else(|| {
                JsonValue::from_iter([(Self::MESSAGE_KEY, value.text.unwrap_or_default())])
            }),
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

    /// Borrows the stored JSON, if the producer supplied it.
    pub(crate) fn structured(&self) -> Option<&JsonValue> {
        self.json.as_ref()
    }
}

impl Serialize for RedactedValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.structured() {
            Some(json) => json.serialize(serializer),
            None => serializer.collect_map([self.message_field()]),
        }
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

/// Produces the declared diagnostic view for this type.
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
/// With `mask-map-keys`, sensitive JSON producers replace every map key with a
/// positional placeholder. Names emitted through Serde's struct methods stay
/// visible; flattened fields and tags emitted as map keys are masked too.
/// Template text and public producers keep their existing output.
///
/// Handwritten implementations are supported and are the route for an exotic
/// projection: build the value from a member of the Bypass family, which is
/// where the author's declaration is recorded. These declarations and
/// user-defined policies remain the author's responsibility; producing a value
/// does not prove confidentiality or completeness.
///
/// `Option<T>` delegates `Some(value)` to its producer without converting its
/// output. `None` and `()` produce JSON null. There is no variant tag:
/// `Some(())`, `Some(None::<()>)`, and `None::<()>` have the same output.
/// References, `Box`, [`Rc`], and [`Arc`] also delegate to the inner producer,
/// including unsized producers. These implementations require only
/// `ToRedacted`; structural [`Redactable`] implementations do not make a value
/// a producer. Collections require an explicit choice such as
/// [`RedactedList`](super::list::RedactedList), which enforces an item limit.
pub trait ToRedacted {
    /// Produces the declared diagnostic view for `self`.
    ///
    /// Prefer a logging adapter that uses this producer over formatting the
    /// raw value with `Display` or `Debug`.
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

    /// Returns the same diagnostic view as [`Self::to_redacted`], borrowing a
    /// previously produced value when available.
    ///
    /// The default implementation calls the producer once and owns its result.
    /// [`RedactedValue`] borrows itself. References and supported containers
    /// forward the inner producer's choice.
    #[must_use]
    fn to_redacted_cow(&self) -> Cow<'_, RedactedValue> {
        Cow::Owned(self.to_redacted())
    }
}

impl ToRedacted for RedactedValue {
    fn to_redacted(&self) -> RedactedValue {
        self.clone()
    }

    fn to_redacted_cow(&self) -> Cow<'_, RedactedValue> {
        Cow::Borrowed(self)
    }
}

impl<T: ToRedacted> ToRedacted for Option<T> {
    fn to_redacted(&self) -> RedactedValue {
        self.as_ref().map_or_else(
            || RedactedValue::from_json(JsonValue::Null),
            ToRedacted::to_redacted,
        )
    }

    fn to_redacted_cow(&self) -> Cow<'_, RedactedValue> {
        self.as_ref().map_or_else(
            || Cow::Owned(self.to_redacted()),
            ToRedacted::to_redacted_cow,
        )
    }
}

impl ToRedacted for () {
    fn to_redacted(&self) -> RedactedValue {
        RedactedValue::from_json(JsonValue::Null)
    }
}

impl<T: ToRedacted + ?Sized> ToRedacted for &T {
    fn to_redacted(&self) -> RedactedValue {
        T::to_redacted(self)
    }

    fn to_redacted_cow(&self) -> Cow<'_, RedactedValue> {
        T::to_redacted_cow(self)
    }
}

impl<T: ToRedacted + ?Sized> ToRedacted for &mut T {
    fn to_redacted(&self) -> RedactedValue {
        T::to_redacted(self)
    }

    fn to_redacted_cow(&self) -> Cow<'_, RedactedValue> {
        T::to_redacted_cow(self)
    }
}

impl<T: ToRedacted + ?Sized> ToRedacted for Box<T> {
    fn to_redacted(&self) -> RedactedValue {
        T::to_redacted(self)
    }

    fn to_redacted_cow(&self) -> Cow<'_, RedactedValue> {
        T::to_redacted_cow(self)
    }
}

impl<T: ToRedacted + ?Sized> ToRedacted for Rc<T> {
    fn to_redacted(&self) -> RedactedValue {
        T::to_redacted(self)
    }

    fn to_redacted_cow(&self) -> Cow<'_, RedactedValue> {
        T::to_redacted_cow(self)
    }
}

impl<T: ToRedacted + ?Sized> ToRedacted for Arc<T> {
    fn to_redacted(&self) -> RedactedValue {
        T::to_redacted(self)
    }

    fn to_redacted_cow(&self) -> Cow<'_, RedactedValue> {
        T::to_redacted_cow(self)
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
    let redacted = Redactable::redact(Clone::clone(value));
    #[cfg(feature = "mask-map-keys")]
    let redacted = map_keys::MaskMapKeys(&redacted);
    serialize_redacted_json(redacted)
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
