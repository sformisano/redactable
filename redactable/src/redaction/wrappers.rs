//! Wrapper types for sensitive and non-sensitive values.
//!
//! This module provides wrapper types for handling foreign types:
//!
//! - [`SensitiveValue<T, P>`]: Wraps a value and applies a redaction policy
//! - [`BypassRedaction<T>`]: Wraps a value that should pass through unchanged

use std::{
    fmt::{Debug, Formatter, Result as FmtResult},
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{
    redact::RedactableMapper,
    traits::{Redactable, RedactableWithMapper, SensitiveWithPolicy},
};
use crate::policy::RedactionPolicy;
use crate::{
    __private::{
        PolicyApplicableRefForFormatting, PolicyApplicableRefForGeneratedFormatting,
        PolicyFormattingOutput, PolicyMapper,
    },
    PolicyApplicableRef, RedactableWithFormatter,
    policy::RecursivePolicyKind,
};

// =============================================================================
// SensitiveValue - Wrapper for leaf values with a policy
// =============================================================================

/// Wrapper for leaf values to apply a redaction policy.
///
/// For external types, implement `SensitiveWithPolicy<P>` in your crate and
/// wrap the value in `SensitiveValue<T, P>` to apply the policy.
///
/// # Serialization warning
///
/// `serde::Serialize` emits the raw inner value unchanged. This is intentional
/// because application storage and wire formats usually need the real value.
/// Logging integrations redact before serializing the log value; direct `serde`
/// serialization does not. `.redacted()` returns the policy-selected text, and
/// `.to_redacted()` carries that same text as the sink value. These are
/// logging representations; direct transport serialization remains raw.
///
/// Leaf values are **atomic**: `SensitiveValue` treats `T` as an opaque unit
/// and does not traverse its fields.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SensitiveValue<T, P>(T, PhantomData<P>);

impl<T, P> SensitiveValue<T, P>
where
    T: SensitiveWithPolicy<P>,
    P: RedactionPolicy,
{
    /// Returns the redacted string representation using the policy `P`.
    #[must_use]
    pub fn redacted(&self) -> String {
        let policy = P::policy();
        self.0.redacted_string(&policy)
    }
}

impl<T, P> RedactableWithMapper for SensitiveValue<T, P>
where
    T: SensitiveWithPolicy<P>,
    P: RedactionPolicy,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        let redacted = mapper.map_sensitive::<T, P>(self.0);
        Self(redacted, PhantomData)
    }
}

impl<T, P> Redactable for SensitiveValue<T, P>
where
    T: SensitiveWithPolicy<P>,
    P: RedactionPolicy,
{
}

impl<T, P> RedactableWithFormatter for SensitiveValue<T, P>
where
    T: SensitiveWithPolicy<P>,
    P: RedactionPolicy,
{
    fn fmt_redacted(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str(&self.redacted())
    }
}

impl<T, P> PolicyApplicableRefForGeneratedFormatting for SensitiveValue<T, P>
where
    T: SensitiveWithPolicy<P>,
    P: RedactionPolicy,
{
    type FormattingOutput = String;

    fn apply_policy_ref_for_generated_formatting<Q, M>(
        &self,
        _mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        Q: RedactionPolicy,
        Q::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        PolicyFormattingOutput::Value(self.redacted())
    }
}

impl<T, P> PolicyApplicableRef for SensitiveValue<T, P>
where
    T: SensitiveWithPolicy<P>,
    P: RedactionPolicy,
{
    type Output = String;

    fn apply_policy_ref<Q, M>(&self, _mapper: &M) -> Self::Output
    where
        Q: RedactionPolicy,
        Q::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.redacted()
    }
}

impl<T, P> PolicyApplicableRefForFormatting for SensitiveValue<T, P>
where
    T: SensitiveWithPolicy<P>,
    P: RedactionPolicy,
{
    fn fmt_policy_display<Q>(&self, formatter: &mut Formatter<'_>) -> FmtResult
    where
        Q: RedactionPolicy,
        Q::Kind: RecursivePolicyKind,
        Self: PolicyApplicableRef,
        <Self as PolicyApplicableRef>::Output: RedactableWithFormatter,
    {
        self.apply_policy_ref_for_generated_formatting::<Q, _>(&PolicyMapper)
            .fmt_redacted(formatter)
    }

    fn fmt_policy_debug<Q>(&self, formatter: &mut Formatter<'_>) -> FmtResult
    where
        Q: RedactionPolicy,
        Q::Kind: RecursivePolicyKind,
        Self: PolicyApplicableRef,
        <Self as PolicyApplicableRef>::Output: Debug,
    {
        Debug::fmt(
            &self.apply_policy_ref_for_generated_formatting::<Q, _>(&PolicyMapper),
            formatter,
        )
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

impl<T, P> Debug for SensitiveValue<T, P>
where
    T: SensitiveWithPolicy<P>,
    P: RedactionPolicy,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_tuple("SensitiveValue")
            .field(&self.redacted())
            .finish()
    }
}

impl<T, P> Serialize for SensitiveValue<T, P>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, T, P> Deserialize<'de> for SensitiveValue<T, P>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self::from)
    }
}

// =============================================================================
// BypassRedaction - Wrapper for foreign types that should not be redacted
// =============================================================================

/// Satisfies a `Redactable` bound on a value you do not own.
///
/// Reach for this only at a boundary that demands `Redactable` on a foreign
/// value: the wrapper is a passthrough that returns the value without any
/// redaction, and wrapping is the declaration that doing so is intended.
///
/// **A foreign field inside a struct you own does not need this wrapper.**
/// Annotate the field `#[not_sensitive]` instead — the declaration then sits
/// on the field it describes, and the field keeps its own type.
///
/// **Serialization:** `serde::Serialize` emits the raw inner value unchanged.
/// This wrapper is intentionally a passthrough for both redaction and
/// serialization.
///
/// This is the mirror of [`SensitiveValue<T, P>`]: where `SensitiveValue` applies a policy,
/// `BypassRedaction` explicitly opts out of redaction. It deliberately does not
/// implement `ToRedacted`; a sink that needs a value takes
/// [`crate::BypassJsonRedaction`] or one of its siblings.
///
/// Note: This type coexists with the `#[derive(NotSensitive)]` macro. The derive
/// macro is for types you own; this wrapper is for foreign types you don't own.
///
/// ```ignore
/// use other_crate::ForeignConfig;
/// use redactable::{BypassRedaction, Redactable};
///
/// fn audit<T: Redactable>(value: T) -> T { value.redact() }
///
/// let checked = audit(BypassRedaction(ForeignConfig::default()));
/// ```
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BypassRedaction<T>(pub T);

impl<T> RedactableWithMapper for BypassRedaction<T> {
    fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
        self
    }
}

// The wrapper itself is the declaration: wrapping a value in
// `BypassRedaction` is an explicit opt-out, unlike a bare passthrough leaf.
impl<T> Redactable for BypassRedaction<T> {}

impl<T> From<T> for BypassRedaction<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> Deref for BypassRedaction<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for BypassRedaction<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Debug> Debug for BypassRedaction<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_tuple("BypassRedaction").field(&self.0).finish()
    }
}

impl<T: Serialize> Serialize for BypassRedaction<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for BypassRedaction<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self::from)
    }
}
