//! The Bypass family: deliberate escapes from redaction at a logging boundary.
//!
//! Every member is named for the action its author is taking. Constructing one
//! is the declaration that the complete value it carries is safe to log:
//!
//! - [`BypassRedactionMarker`]: no formatting opinion; certifies a value for
//!   `slog`'s native typed emitter, and the only member that accepts a type
//!   with neither `Display` nor `Debug`
//! - [`BypassDisplayRedaction`]: log the value's `Display` form as is
//! - [`BypassDebugRedaction`]: log the value's `Debug` form as is
//! - [`BypassJsonRedaction`]: log the value's `Serialize` form as is
//! - [`BypassTextRedaction`]: log author-composed text
//!
//! Every member is a tuple struct with a public field, so construction is
//! `BypassDebugRedaction(&value)`. There is no eligibility bound and no reason
//! argument: the declaration is the construction.
//!
//! `BypassDisplayRedaction` and `BypassDebugRedaction` can own their values.
//! Their Serde implementations preserve the raw inner wire value and do not
//! redact it.
//!
//! A foreign field inside a struct you own is not a job for this family:
//! annotate it `#[not_sensitive]`. Reach for [`crate::BypassRedaction`] only
//! when an API demands `Redactable` on a value you do not own.

use std::{
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    ops::{Deref, DerefMut},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::output::{RedactedValue, ToRedacted, serialize_redacted_json};

// =============================================================================
// BypassRedactionMarker - generic wrapper with no formatting preference
// =============================================================================

/// Declares a value non-sensitive without selecting a logging format.
///
/// This is the member to reach for when the sink already knows how to render
/// the value: `slog`'s native typed emitter accepts
/// `BypassRedactionMarker<T>` wherever `T: slog::Value`, keeping the emitted
/// type rather than flattening it to a string. It also accepts a type
/// implementing neither `Display` nor `Debug`.
///
/// For a `ToRedacted` boundary, use [`BypassDisplayRedaction`],
/// [`BypassDebugRedaction`] or [`BypassJsonRedaction`] instead.
pub struct BypassRedactionMarker<T>(pub T);

impl<T> BypassRedactionMarker<T> {
    /// Returns the inner value.
    #[must_use]
    pub fn inner(&self) -> &T {
        &self.0
    }
}

impl<T> Deref for BypassRedactionMarker<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for BypassRedactionMarker<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> Display for BypassRedactionMarker<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(&self.0, f)
    }
}

impl<T> Debug for BypassRedactionMarker<T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Debug::fmt(&self.0, f)
    }
}

// =============================================================================
// BypassDisplayRedaction - log the Display form as is
// =============================================================================

/// Logs a value's `Display` form without redacting it.
///
/// Constructing this wrapper declares that the complete formatted value is safe
/// to log. Construct it over a reference for a borrowed logging view
/// (`BypassDisplayRedaction(&value)`) or over the value itself when the wrapper
/// must own it. Consume an owned wrapper with [`Self::into_inner`].
///
/// # Raw serialization warning
///
/// `Serialize` and `Deserialize` transparently expose the complete inner value.
/// This supports ordinary transport and storage; it is not redaction and must
/// not be treated as sanitized log output. See [`BypassDebugRedaction`] for
/// `Debug`-selected output, [`BypassJsonRedaction`] for a borrowed JSON view,
/// and [`BypassRedactionMarker`] when no logging format should be selected.
///
/// ```
/// use redactable::{BypassDisplayRedaction, ToRedacted};
///
/// let count = BypassDisplayRedaction(42_u64);
/// assert_eq!(count.to_redacted().text(), "42");
/// assert_eq!(count.into_inner(), 42);
/// ```
///
/// The `Display` bound is checked where the value is produced, so a type
/// without `Display` cannot reach a logging boundary this way:
///
/// ```compile_fail
/// use redactable::{BypassDisplayRedaction, ToRedacted};
///
/// struct NoDisplay;
///
/// fn main() {
///     let value = BypassDisplayRedaction(NoDisplay);
///     let _ = value.to_redacted();
/// }
/// ```
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BypassDisplayRedaction<T>(pub T);

impl<T> BypassDisplayRedaction<T> {
    /// Returns the inner value.
    #[must_use]
    pub fn inner(&self) -> &T {
        &self.0
    }

    /// Consumes the wrapper and returns the owned inner value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> ToRedacted for BypassDisplayRedaction<T>
where
    T: Display,
{
    fn to_redacted(&self) -> RedactedValue {
        RedactedValue::from_text(self.0.to_string())
    }
}

impl<T> Display for BypassDisplayRedaction<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(&self.0, f)
    }
}

impl<T> Debug for BypassDisplayRedaction<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(&self.0, f)
    }
}

impl<T: Serialize> Serialize for BypassDisplayRedaction<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for BypassDisplayRedaction<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self)
    }
}

// =============================================================================
// BypassDebugRedaction - log the Debug form as is
// =============================================================================

/// Logs a value's `Debug` form without redacting it.
///
/// Constructing this wrapper declares that the complete debug representation is
/// safe to log. Construct it over a reference for a borrowed logging view
/// (`BypassDebugRedaction(&value)`) or over the value itself when the wrapper
/// must own it. Consume an owned wrapper with [`Self::into_inner`].
///
/// # Raw serialization warning
///
/// `Serialize` and `Deserialize` transparently expose the complete inner value.
/// This supports ordinary transport and storage; it is not redaction and must
/// not be treated as sanitized log output. See [`BypassDisplayRedaction`] for
/// `Display`-selected output, [`BypassJsonRedaction`] for a borrowed JSON view,
/// and [`BypassRedactionMarker`] when no logging format should be selected.
///
/// ```
/// use redactable::{BypassDebugRedaction, ToRedacted};
///
/// let id = BypassDebugRedaction(("public", 7_u64));
/// assert_eq!(id.to_redacted().text(), "(\"public\", 7)");
/// assert_eq!(id.into_inner(), ("public", 7));
/// ```
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BypassDebugRedaction<T>(pub T);

impl<T> BypassDebugRedaction<T> {
    /// Returns the inner value.
    #[must_use]
    pub fn inner(&self) -> &T {
        &self.0
    }

    /// Consumes the wrapper and returns the owned inner value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> ToRedacted for BypassDebugRedaction<T>
where
    T: Debug,
{
    fn to_redacted(&self) -> RedactedValue {
        RedactedValue::from_text(format!("{:?}", self.0))
    }
}

impl<T> Debug for BypassDebugRedaction<T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Debug::fmt(&self.0, f)
    }
}

impl<T: Serialize> Serialize for BypassDebugRedaction<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for BypassDebugRedaction<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self)
    }
}

// =============================================================================
// BypassJsonRedaction - log the Serialize form as is
// =============================================================================

/// Logs a value's `Serialize` form without redacting it.
///
/// Constructing this wrapper declares the borrowed value safe to log as JSON:
/// `BypassJsonRedaction(&value)`.
pub struct BypassJsonRedaction<'a, T: ?Sized>(pub &'a T);

impl<T: ?Sized> BypassJsonRedaction<'_, T> {
    /// Returns the inner value.
    #[must_use]
    pub fn inner(&self) -> &T {
        self.0
    }
}

impl<T> ToRedacted for BypassJsonRedaction<'_, T>
where
    T: Serialize + ?Sized,
{
    fn to_redacted(&self) -> RedactedValue {
        RedactedValue::from_json(serialize_redacted_json(self.0))
    }
}

impl<T> Debug for BypassJsonRedaction<'_, T>
where
    T: Serialize + ?Sized,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_tuple("BypassJsonRedaction")
            .field(&self.to_redacted())
            .finish()
    }
}

// =============================================================================
// BypassTextRedaction - log author-composed text
// =============================================================================

/// Logs author-composed summary text in place of a redacted value.
///
/// The caller chooses and reviews the text: `BypassTextRedaction(summary)`.
/// This wrapper performs no redaction and makes no promise that the summary
/// includes every field. Empty summaries are allowed; assert the intended
/// summary separately in logging tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BypassTextRedaction(pub String);

impl ToRedacted for BypassTextRedaction {
    fn to_redacted(&self) -> RedactedValue {
        RedactedValue::from_text(self.0.clone())
    }
}
