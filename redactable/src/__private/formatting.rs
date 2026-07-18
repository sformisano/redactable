//! Borrowed formatting projections and the probe-based dispatch that selects
//! between legacy and generated formatting routes.

use std::marker::PhantomData;

use crate::{RedactableWithFormatter, RedactionPolicy, redaction::PolicyMapper};

use super::{
    field::{
        PolicyApplicableRefForFormatting, PolicyApplicableRefForGeneratedFormatting, PolicyFieldRef,
    },
    kinds::{
        GeneratedPolicyKindDebugFormatting, GeneratedPolicyKindDisplayFormatting,
        PolicyKindDebugFormatting, PolicyKindDisplayFormatting,
    },
};

/// Method-dispatch bridge from generated placeholders to borrowed policy formatting.
///
/// Library-owned field shapes provide more specific receiver implementations
/// that format recursively without cloning. The double-reference implementation
/// below is the compatibility fallback for downstream manual policy types.
#[doc(hidden)]
pub trait PolicyFormattingDispatch {
    /// Borrowed formatting projection for policy `P`.
    type Output<P: RedactionPolicy>;

    /// Creates a formatting projection without cloning or consuming the field.
    fn redactable_policy_formatting<P: RedactionPolicy>(self) -> Self::Output<P>;
}

/// Compatibility formatting projection for downstream manual policy types.
#[doc(hidden)]
pub struct LegacyPolicyFormattingRef<'a, P, T: ?Sized> {
    value: &'a T,
    policy: PhantomData<P>,
}

/// Ordinary borrowed projection used only by the explicit legacy field option.
#[doc(hidden)]
pub struct ExplicitLegacyPolicyFormattingRef<'a, P, T: ?Sized> {
    value: &'a T,
    policy: PhantomData<P>,
}

/// Selects the ordinary borrowed policy projection for an explicitly opted-in field.
///
/// This route preserves the historical downstream extension contract. Unlike the
/// built-in generated route, it inherits `PolicyApplicableRef`'s container bounds
/// and borrow behavior.
#[doc(hidden)]
pub fn legacy_policy_formatting_ref<P, T: ?Sized>(
    value: &T,
) -> ExplicitLegacyPolicyFormattingRef<'_, P, T> {
    ExplicitLegacyPolicyFormattingRef {
        value,
        policy: PhantomData,
    }
}

impl<P, T> std::fmt::Display for ExplicitLegacyPolicyFormattingRef<'_, P, T>
where
    P: RedactionPolicy,
    T: PolicyFieldRef<P> + ?Sized,
    <T as PolicyFieldRef<P>>::Output: RedactableWithFormatter,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value
            .apply_field_ref(&PolicyMapper)
            .fmt_redacted(formatter)
    }
}

impl<P, T> std::fmt::Debug for ExplicitLegacyPolicyFormattingRef<'_, P, T>
where
    P: RedactionPolicy,
    T: PolicyFieldRef<P> + ?Sized,
    <T as PolicyFieldRef<P>>::Output: std::fmt::Debug,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.value.apply_field_ref(&PolicyMapper), formatter)
    }
}

impl<P, T> std::fmt::Display for LegacyPolicyFormattingRef<'_, P, T>
where
    P: RedactionPolicy,
    P::Kind: PolicyKindDisplayFormatting<P, T>,
    T: ?Sized,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <P::Kind as PolicyKindDisplayFormatting<P, T>>::fmt_display(self.value, formatter)
    }
}

impl<P, T> std::fmt::Debug for LegacyPolicyFormattingRef<'_, P, T>
where
    P: RedactionPolicy,
    P::Kind: PolicyKindDebugFormatting<P, T>,
    T: ?Sized,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <P::Kind as PolicyKindDebugFormatting<P, T>>::fmt_debug(self.value, formatter)
    }
}

/// Nominal dispatch probe used to prefer library-owned conflict-safe formatting.
#[doc(hidden)]
pub struct PolicyFormattingProbe<'a, T: ?Sized> {
    value: &'a T,
}

/// Creates a policy-formatting probe without inspecting or cloning the value.
#[doc(hidden)]
pub fn policy_formatting_probe<T: ?Sized>(value: &T) -> PolicyFormattingProbe<'_, T> {
    PolicyFormattingProbe { value }
}

impl<'a, T> PolicyFormattingDispatch for PolicyFormattingProbe<'a, T>
where
    T: PolicyApplicableRefForGeneratedFormatting + ?Sized,
{
    type Output<P: RedactionPolicy> = GeneratedPolicyFormattingRef<'a, P, T>;

    fn redactable_policy_formatting<P: RedactionPolicy>(self) -> Self::Output<P> {
        GeneratedPolicyFormattingRef {
            value: self.value,
            policy: PhantomData,
        }
    }
}

impl<'a, T> PolicyFormattingDispatch for &PolicyFormattingProbe<'a, T>
where
    T: PolicyApplicableRefForFormatting + ?Sized,
{
    type Output<P: RedactionPolicy> = LegacyPolicyFormattingRef<'a, P, T>;

    fn redactable_policy_formatting<P: RedactionPolicy>(self) -> Self::Output<P> {
        LegacyPolicyFormattingRef {
            value: self.value,
            policy: PhantomData,
        }
    }
}

/// Borrowed formatting projection whose capability is selected by rustc.
#[doc(hidden)]
pub struct PolicyFormattingRef<'a, P, T: ?Sized> {
    value: &'a T,
    policy: PhantomData<P>,
}

/// Creates a borrowed policy-formatting projection.
#[doc(hidden)]
pub fn policy_formatting_ref<P, T: ?Sized>(value: &T) -> PolicyFormattingRef<'_, P, T> {
    PolicyFormattingRef {
        value,
        policy: PhantomData,
    }
}

impl<P, T> std::fmt::Display for PolicyFormattingRef<'_, P, T>
where
    P: RedactionPolicy,
    P::Kind: PolicyKindDisplayFormatting<P, T>,
    T: ?Sized,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <P::Kind as PolicyKindDisplayFormatting<P, T>>::fmt_display(self.value, formatter)
    }
}

impl<P, T> std::fmt::Debug for PolicyFormattingRef<'_, P, T>
where
    P: RedactionPolicy,
    P::Kind: PolicyKindDebugFormatting<P, T>,
    T: ?Sized,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <P::Kind as PolicyKindDebugFormatting<P, T>>::fmt_debug(self.value, formatter)
    }
}

/// Borrowed formatter whose policy kind selects recursive or IP-safe traversal.
#[doc(hidden)]
pub struct GeneratedPolicyFormattingRef<'a, P, T: ?Sized> {
    value: &'a T,
    policy: PhantomData<P>,
}

impl<P, T> std::fmt::Display for GeneratedPolicyFormattingRef<'_, P, T>
where
    P: RedactionPolicy,
    P::Kind: GeneratedPolicyKindDisplayFormatting<P, T>,
    T: ?Sized,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <P::Kind as GeneratedPolicyKindDisplayFormatting<P, T>>::fmt_generated_display(
            self.value, formatter,
        )
    }
}

impl<P, T> std::fmt::Debug for GeneratedPolicyFormattingRef<'_, P, T>
where
    P: RedactionPolicy,
    P::Kind: GeneratedPolicyKindDebugFormatting<P, T>,
    T: ?Sized,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <P::Kind as GeneratedPolicyKindDebugFormatting<P, T>>::fmt_generated_debug(
            self.value, formatter,
        )
    }
}
