//! Escape hatches for explicitly non-sensitive values.
//!
//! This module provides wrappers and extension traits for marking values as
//! explicitly non-sensitive at logging boundaries:
//!
//! - [`NotSensitive`]: Wrapper with no formatting preference
//! - [`NotSensitiveDisplay`]: Wrapper using `Display` formatting
//! - [`NotSensitiveDebug`]: Wrapper using `Debug` formatting
//! - [`NotSensitiveJson`]: Wrapper using JSON serialization (requires `json` feature)
//!
//! `NotSensitiveDisplay` and `NotSensitiveDebug` can own their values when
//! constructed directly. Their Serde implementations, available through the
//! `json` feature, preserve the raw inner wire value and do not redact it.
//!
//! And their corresponding extension traits:
//! - [`NotSensitiveExt`]: Provides `.not_sensitive()`
//! - [`NotSensitiveDisplayExt`]: Provides `.not_sensitive_display()`
//! - [`NotSensitiveDebugExt`]: Provides `.not_sensitive_debug()`
//! - [`NotSensitiveJsonExt`]: Provides `.not_sensitive_json()`

use std::{
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    ops::{Deref, DerefMut},
};

#[cfg(feature = "json")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "json")]
use super::output::serialize_redacted_json;
use super::output::{RedactedOutput, ToRedactedOutput};

// =============================================================================
// NotSensitive - Generic wrapper with no formatting preference
// =============================================================================

/// Wrapper for explicitly non-sensitive values without formatting opinions.
///
/// Use `.not_sensitive()` to mark a value as safe to log. For `ToRedactedOutput`
/// boundaries, use `NotSensitiveDisplay` or `NotSensitiveDebug`.
pub struct NotSensitive<T>(pub T);

impl<T> NotSensitive<T> {
    /// Returns the inner value.
    #[must_use]
    pub fn inner(&self) -> &T {
        &self.0
    }
}

impl<T> Deref for NotSensitive<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for NotSensitive<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> Display for NotSensitive<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(&self.0, f)
    }
}

impl<T> Debug for NotSensitive<T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Debug::fmt(&self.0, f)
    }
}

// =============================================================================
// NotSensitiveDisplay - Wrapper using Display
// =============================================================================

/// Owns an explicitly non-sensitive value and emits its `Display` representation.
///
/// Constructing this wrapper declares that the complete formatted value is safe
/// to log. Use `.not_sensitive_display()` when a borrowed logging view is enough,
/// or construct `NotSensitiveDisplay(value)` when the wrapper must own the value.
/// Consume an owned wrapper with [`Self::into_inner`].
///
/// # Raw serialization warning
///
/// With the `json` feature, `Serialize` and `Deserialize` transparently expose
/// the complete inner value. This supports ordinary transport and storage; it
/// is not redaction and must not be treated as sanitized log output.
/// See [`NotSensitiveDebug`] for Debug-selected output, `NotSensitiveJson`
/// for a borrowed JSON logging view, and
/// [`crate::NotSensitiveValue`] when no logging format should be selected.
///
/// ```
/// use redactable::{NotSensitiveDisplay, RedactedOutputView, ToRedactedOutput};
///
/// let count = NotSensitiveDisplay(42_u64);
/// assert_eq!(
///     count.to_redacted_output().view(),
///     RedactedOutputView::Text("42")
/// );
/// assert_eq!(count.into_inner(), 42);
/// ```
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NotSensitiveDisplay<T>(pub T);

impl<T> NotSensitiveDisplay<T> {
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

impl<T> ToRedactedOutput for NotSensitiveDisplay<T>
where
    T: Display,
{
    fn to_redacted_output(&self) -> RedactedOutput {
        RedactedOutput::text(self.0.to_string())
    }
}

impl<T> Display for NotSensitiveDisplay<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(&self.0, f)
    }
}

impl<T> Debug for NotSensitiveDisplay<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(&self.0, f)
    }
}

#[cfg(feature = "json")]
impl<T: Serialize> Serialize for NotSensitiveDisplay<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

#[cfg(feature = "json")]
impl<'de, T: Deserialize<'de>> Deserialize<'de> for NotSensitiveDisplay<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self)
    }
}

// =============================================================================
// NotSensitiveDebug - Wrapper using Debug
// =============================================================================

/// Owns an explicitly non-sensitive value and emits its `Debug` representation.
///
/// Constructing this wrapper declares that the complete debug representation is
/// safe to log. Use `.not_sensitive_debug()` when a borrowed logging view is
/// enough, or construct `NotSensitiveDebug(value)` when the wrapper must own the
/// value. Consume an owned wrapper with [`Self::into_inner`].
///
/// # Raw serialization warning
///
/// With the `json` feature, `Serialize` and `Deserialize` transparently expose
/// the complete inner value. This supports ordinary transport and storage; it
/// is not redaction and must not be treated as sanitized log output.
/// See [`NotSensitiveDisplay`] for Display-selected output,
/// `NotSensitiveJson` for a borrowed JSON logging view, and
/// [`crate::NotSensitiveValue`] when no logging format should be selected.
///
/// ```
/// use redactable::{NotSensitiveDebug, RedactedOutputView, ToRedactedOutput};
///
/// let id = NotSensitiveDebug(("public", 7_u64));
/// assert_eq!(
///     id.to_redacted_output().view(),
///     RedactedOutputView::Text("(\"public\", 7)")
/// );
/// assert_eq!(id.into_inner(), ("public", 7));
/// ```
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NotSensitiveDebug<T>(pub T);

impl<T> NotSensitiveDebug<T> {
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

impl<T> ToRedactedOutput for NotSensitiveDebug<T>
where
    T: Debug,
{
    fn to_redacted_output(&self) -> RedactedOutput {
        RedactedOutput::text(format!("{:?}", self.0))
    }
}

impl<T> Debug for NotSensitiveDebug<T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Debug::fmt(&self.0, f)
    }
}

#[cfg(feature = "json")]
impl<T: Serialize> Serialize for NotSensitiveDebug<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

#[cfg(feature = "json")]
impl<'de, T: Deserialize<'de>> Deserialize<'de> for NotSensitiveDebug<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self)
    }
}

// =============================================================================
// NotSensitiveJson - Wrapper using JSON serialization
// =============================================================================

/// Wrapper for explicitly non-sensitive values using JSON serialization.
///
/// Use `.not_sensitive_json()` to declare a value safe to log as JSON.
#[cfg(feature = "json")]
pub struct NotSensitiveJson<'a, T: ?Sized>(&'a T);

#[cfg(feature = "json")]
impl<T: ?Sized> NotSensitiveJson<'_, T> {
    /// Returns the inner value.
    #[must_use]
    pub fn inner(&self) -> &T {
        self.0
    }
}

#[cfg(feature = "json")]
impl<T> ToRedactedOutput for NotSensitiveJson<'_, T>
where
    T: Serialize + ?Sized,
{
    fn to_redacted_output(&self) -> RedactedOutput {
        RedactedOutput::json(serialize_redacted_json(self.0))
    }
}

#[cfg(feature = "json")]
impl<T> Debug for NotSensitiveJson<'_, T>
where
    T: Serialize + ?Sized,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_tuple("NotSensitiveJson")
            .field(&self.to_redacted_output())
            .finish()
    }
}

// =============================================================================
// Extension traits
// =============================================================================

/// Extension trait to mark values as explicitly non-sensitive for logging.
pub trait NotSensitiveExt: Sized {
    /// Wraps a reference to the value as explicitly non-sensitive.
    fn not_sensitive(&self) -> NotSensitive<&Self> {
        NotSensitive(self)
    }
}

impl<T: Sized> NotSensitiveExt for T {}

/// Extension trait to mark values as explicitly non-sensitive using `Display`.
///
/// ```compile_fail
/// use redactable::NotSensitiveDisplayExt;
///
/// struct NoDisplay;
///
/// fn main() {
///     let value = NoDisplay;
///     let _ = value.not_sensitive_display();
/// }
/// ```
pub trait NotSensitiveDisplayExt: Sized + Display {
    /// Wraps a reference to the value as explicitly non-sensitive using `Display`.
    fn not_sensitive_display(&self) -> NotSensitiveDisplay<&Self> {
        NotSensitiveDisplay(self)
    }
}

impl<T> NotSensitiveDisplayExt for T where T: Display {}

/// Extension trait to mark values as explicitly non-sensitive using `Debug`.
pub trait NotSensitiveDebugExt: Sized + Debug {
    /// Wraps a reference to the value as explicitly non-sensitive using `Debug`.
    fn not_sensitive_debug(&self) -> NotSensitiveDebug<&Self> {
        NotSensitiveDebug(self)
    }
}

impl<T> NotSensitiveDebugExt for T where T: Debug {}

/// Extension trait to mark values as explicitly non-sensitive using JSON.
#[cfg(feature = "json")]
pub trait NotSensitiveJsonExt {
    /// Wraps the value as explicitly non-sensitive using JSON serialization.
    fn not_sensitive_json(&self) -> NotSensitiveJson<'_, Self>
    where
        Self: Sized;
}

#[cfg(feature = "json")]
impl<T> NotSensitiveJsonExt for T
where
    T: Serialize,
{
    fn not_sensitive_json(&self) -> NotSensitiveJson<'_, Self> {
        NotSensitiveJson(self)
    }
}

/// Deliberately selected summary text for a logging boundary.
///
/// The caller chooses and reviews the text. This wrapper performs no redaction
/// and makes no promise that the summary includes every field. Empty summaries
/// are allowed; assert the intended summary separately in logging tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UncheckedRedactedSummary(String);

impl UncheckedRedactedSummary {
    /// Declares the supplied text to be the intended logging summary.
    #[must_use]
    pub fn new(text: String) -> Self {
        Self(text)
    }
}

impl ToRedactedOutput for UncheckedRedactedSummary {
    fn to_redacted_output(&self) -> RedactedOutput {
        RedactedOutput::text(self.0.clone())
    }
}
