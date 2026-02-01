//! Wrapper types for sensitive and non-sensitive values.
//!
//! This module provides wrapper types for handling foreign types:
//!
//! - [`SensitiveValue<T, P>`]: Wraps a value and applies a redaction policy
//! - [`NotSensitiveValue<T>`]: Wraps a value that should pass through unchanged

use std::marker::PhantomData;

#[cfg(feature = "json")]
use serde::Serialize;

use super::{
    redact::RedactableMapper,
    traits::{RedactableContainer, RedactableWithPolicy},
};
use crate::policy::RedactionPolicy;

// =============================================================================
// SensitiveValue - Wrapper for leaf values with a policy
// =============================================================================

/// Wrapper for leaf values to apply a redaction policy.
///
/// This is useful when a field's type does not implement `RedactableLeaf`.
/// For external types, implement `RedactableWithPolicy<P>` in your crate and
/// wrap the value in `SensitiveValue<T, P>` to apply the policy.
///
/// **Serialization:** when the `json` feature is enabled, `serde::Serialize`
/// emits the raw inner value unchanged. This is intentional; call `.redact()`,
/// `.redacted()`, or `.to_redacted_output()` before serialization if you need
/// redacted output.
///
/// Leaf values are **atomic**: if `T` implements `RedactableLeaf` (even if `T`
/// is a struct), its fields are not traversed.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SensitiveValue<T, P>(T, PhantomData<P>);

impl<T, P> SensitiveValue<T, P>
where
    T: RedactableWithPolicy<P>,
    P: RedactionPolicy,
{
    /// Returns the redacted string representation using the policy `P`.
    #[must_use]
    pub fn redacted(&self) -> String {
        let policy = P::policy();
        self.0.redacted_string(&policy)
    }
}

impl<T, P> RedactableContainer for SensitiveValue<T, P>
where
    T: RedactableWithPolicy<P>,
    P: RedactionPolicy,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        let redacted = mapper.map_sensitive::<T, P>(self.0);
        Self(redacted, PhantomData)
    }
}

impl<T, P> From<T> for SensitiveValue<T, P> {
    fn from(value: T) -> Self {
        Self(value, PhantomData)
    }
}

impl<T, P> SensitiveValue<T, P> {
    /// Explicitly access the inner value.
    ///
    /// This method makes it clear in your code that you are intentionally
    /// accessing the raw sensitive value. Use with care.
    #[must_use]
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Explicitly access the inner value mutably.
    ///
    /// This method makes it clear in your code that you are intentionally
    /// accessing the raw sensitive value. Use with care.
    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.0
    }

    /// Consume the wrapper and return the inner value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T, P> std::fmt::Debug for SensitiveValue<T, P>
where
    T: RedactableWithPolicy<P>,
    P: RedactionPolicy,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SensitiveValue")
            .field(&self.redacted())
            .finish()
    }
}

#[cfg(feature = "json")]
impl<T, P> Serialize for SensitiveValue<T, P>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

// =============================================================================
// NotSensitiveValue - Wrapper for foreign types that should not be redacted
// =============================================================================

/// Wrapper for foreign types that should pass through unchanged.
///
/// Use this when a field's type comes from another crate and doesn't implement
/// `RedactableContainer`. The wrapper provides a passthrough implementation
/// that simply returns the value without any redaction.
///
/// **Serialization:** when the `json` feature is enabled, `serde::Serialize`
/// emits the raw inner value unchanged. This wrapper is intentionally a
/// passthrough for both redaction and serialization.
///
/// This is the mirror of [`SensitiveValue<T, P>`]: where `SensitiveValue` applies a policy,
/// `NotSensitiveValue` explicitly opts out of redaction.
///
/// Note: This type coexists with the `#[derive(NotSensitive)]` macro. The derive
/// macro is for types you own; this wrapper is for foreign types you don't own.
///
/// ```ignore
/// use redactable::{NotSensitiveValue, Sensitive};
///
/// #[derive(Clone, Sensitive)]
/// struct Config {
///     // ForeignConfig doesn't implement RedactableContainer
///     foreign: NotSensitiveValue<other_crate::ForeignConfig>,
/// }
/// ```
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NotSensitiveValue<T>(pub T);

impl<T> RedactableContainer for NotSensitiveValue<T> {
    fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
        self
    }
}

impl<T> From<T> for NotSensitiveValue<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> std::ops::Deref for NotSensitiveValue<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for NotSensitiveValue<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for NotSensitiveValue<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("NotSensitiveValue").field(&self.0).finish()
    }
}

#[cfg(feature = "json")]
impl<T: Serialize> Serialize for NotSensitiveValue<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}
