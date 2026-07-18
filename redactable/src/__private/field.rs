//! Field-level policy dispatch for owned and borrowed generated field shapes.

use crate::{
    IpAddressPolicyKind, RedactableMapper, RedactableWithFormatter, RedactionPolicy,
    ScalarRedaction, SecretPolicyKind, TextPolicyKind,
    policy::RecursivePolicyKind,
    redaction::{
        IpPolicyApplicable, IpPolicyApplicableRef, PolicyApplicable, PolicyApplicableRef,
        PolicyMapper,
    },
};

use super::output::PolicyFormattingOutput;

/// Consuming policy operation emitted for one annotated field.
pub trait PolicyField<P: RedactionPolicy>: Sized {
    /// Applies `P` to this direct field.
    #[must_use]
    fn apply_field<M: RedactableMapper>(self, mapper: &M) -> Self;
}

/// Reference policy operation emitted for one formatted annotated field.
pub trait PolicyFieldRef<P: RedactionPolicy> {
    /// Already-redacted output formatted by the generated template.
    type Output;

    /// Applies `P` without consuming the source field.
    fn apply_field_ref<M: RedactableMapper>(&self, mapper: &M) -> Self::Output;
}

/// Conflict-safe reference operation available for supported generated field shapes.
#[doc(hidden)]
pub trait PolicyFieldRefForFormatting<P: RedactionPolicy> {
    /// Conflict-safe output used only by generated formatting.
    type FormattingOutput;

    /// Applies `P` while propagating a nested borrow conflict.
    fn apply_field_ref_for_formatting<M: RedactableMapper>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>;
}

/// Conflict-safe companion capability for generated recursive policy formatting.
///
/// Custom [`PolicyApplicableRef`] leaves use an empty implementation to select
/// the legacy fallback. Library-owned recursive containers use the separate
/// internal companion below to propagate [`PolicyFormattingOutput::Borrowed`].
/// The explicit `#[redactable(legacy_formatting)]` field route calls
/// [`PolicyFieldRef`] directly and does not require this marker.
///
/// ```ignore
/// impl redactable::__private::PolicyApplicableRefForFormatting for MyLeaf {}
/// ```
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot use generated policy formatting",
    note = "custom `PolicyApplicableRef` types used by `SensitiveDisplay` must also implement `redactable::__private::PolicyApplicableRefForFormatting`"
)]
#[doc(hidden)]
pub trait PolicyApplicableRefForFormatting {
    /// Formats a recursively policy-redacted value through the legacy borrowed projection.
    ///
    /// Legacy compatibility implementations may override this method. Default
    /// generated wrappers use the separate generated-formatting capability.
    fn fmt_policy_display<P>(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        Self: PolicyApplicableRef,
        <Self as PolicyApplicableRef>::Output: RedactableWithFormatter,
    {
        self.apply_policy_ref::<P, _>(&PolicyMapper)
            .fmt_redacted(formatter)
    }

    /// Debug-formats a recursively policy-redacted value through the legacy projection.
    ///
    /// Default generated wrappers use the separate generated-formatting
    /// capability to preserve nested borrow conflicts without cloning.
    fn fmt_policy_debug<P>(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        Self: PolicyApplicableRef,
        <Self as PolicyApplicableRef>::Output: std::fmt::Debug,
    {
        std::fmt::Debug::fmt(&self.apply_policy_ref::<P, _>(&PolicyMapper), formatter)
    }
}

/// Library-owned conflict-safe companion used by generated formatting.
///
/// This internal capability is separate from [`PolicyApplicableRefForFormatting`]
/// so downstream empty marker implementations remain source-compatible.
#[doc(hidden)]
pub trait PolicyApplicableRefForGeneratedFormatting {
    /// Conflict-safe output used only by generated formatting.
    type FormattingOutput;

    /// Applies a recursive policy for generated formatting.
    ///
    /// Library-owned recursive implementations propagate a child's `Borrowed` state.
    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper;
}

/// Recursive consuming capability. Scalar and IP direct leaves intentionally omit it.
pub trait RecursivePolicyField<P: RedactionPolicy>: Sized {
    /// Applies `P` through the recursive compatibility route.
    #[must_use]
    fn apply_recursive<M: RedactableMapper>(self, mapper: &M) -> Self;
}

impl<P, T> RecursivePolicyField<P> for T
where
    P: RedactionPolicy,
    P::Kind: RecursivePolicyKind,
    T: PolicyApplicable,
{
    fn apply_recursive<M: RedactableMapper>(self, mapper: &M) -> Self {
        self.apply_policy::<P, M>(mapper)
    }
}

/// Kind-level consuming dispatch behind the single generated field trait impl.
#[doc(hidden)]
pub trait PolicyKindField<P: RedactionPolicy, T: Sized> {
    /// Applies the selected policy kind.
    fn apply_kind<M: RedactableMapper>(value: T, mapper: &M) -> T;
}

impl<P, T> PolicyKindField<P, T> for TextPolicyKind
where
    P: RedactionPolicy<Kind = TextPolicyKind>,
    T: RecursivePolicyField<P>,
{
    fn apply_kind<M: RedactableMapper>(value: T, mapper: &M) -> T {
        value.apply_recursive(mapper)
    }
}

impl<P, T> PolicyKindField<P, T> for SecretPolicyKind
where
    P: RedactionPolicy<Kind = SecretPolicyKind>,
    T: PolicyApplicable,
{
    fn apply_kind<M: RedactableMapper>(value: T, mapper: &M) -> T {
        value.apply_policy::<P, M>(mapper)
    }
}

impl<P, T> PolicyKindField<P, T> for IpAddressPolicyKind
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicable<P>,
{
    fn apply_kind<M: RedactableMapper>(value: T, mapper: &M) -> T {
        value.apply_ip_policy(mapper)
    }
}

impl<P, T> PolicyField<P> for T
where
    P: RedactionPolicy,
    P::Kind: PolicyKindField<P, T>,
{
    fn apply_field<M: RedactableMapper>(self, mapper: &M) -> Self {
        <P::Kind as PolicyKindField<P, T>>::apply_kind(self, mapper)
    }
}

/// Kind-level reference dispatch behind the single generated field trait impl.
#[doc(hidden)]
pub trait PolicyKindFieldRef<P: RedactionPolicy, T: ?Sized> {
    /// Already-redacted output for this kind and field.
    type Output;

    /// Applies the selected kind by reference.
    fn apply_kind_ref<M: RedactableMapper>(value: &T, mapper: &M) -> Self::Output;
}

/// Kind-level conflict-safe reference dispatch for supported generated shapes.
#[doc(hidden)]
pub trait PolicyKindFieldRefForFormatting<P: RedactionPolicy, T: ?Sized> {
    /// Conflict-safe output used only by generated formatting.
    type FormattingOutput;

    /// Applies the selected kind through the conflict-safe formatting route.
    fn apply_kind_ref_for_formatting<M: RedactableMapper>(
        value: &T,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>;
}

impl<P, T> PolicyKindFieldRef<P, T> for TextPolicyKind
where
    P: RedactionPolicy<Kind = TextPolicyKind>,
    T: PolicyApplicableRef,
{
    type Output = <T as PolicyApplicableRef>::Output;

    fn apply_kind_ref<M: RedactableMapper>(value: &T, mapper: &M) -> Self::Output {
        value.apply_policy_ref::<P, M>(mapper)
    }
}

impl<P, T> PolicyKindFieldRefForFormatting<P, T> for TextPolicyKind
where
    P: RedactionPolicy<Kind = TextPolicyKind>,
    T: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = T::FormattingOutput;

    fn apply_kind_ref_for_formatting<M: RedactableMapper>(
        value: &T,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput> {
        value.apply_policy_ref_for_generated_formatting::<P, M>(mapper)
    }
}

impl<P, T> PolicyKindFieldRef<P, T> for SecretPolicyKind
where
    P: RedactionPolicy<Kind = SecretPolicyKind>,
    T: PolicyApplicableRef,
{
    type Output = <T as PolicyApplicableRef>::Output;

    fn apply_kind_ref<M: RedactableMapper>(value: &T, mapper: &M) -> Self::Output {
        value.apply_policy_ref::<P, M>(mapper)
    }
}

impl<P, T> PolicyKindFieldRefForFormatting<P, T> for SecretPolicyKind
where
    P: RedactionPolicy<Kind = SecretPolicyKind>,
    T: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = T::FormattingOutput;

    fn apply_kind_ref_for_formatting<M: RedactableMapper>(
        value: &T,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput> {
        value.apply_policy_ref_for_generated_formatting::<P, M>(mapper)
    }
}

impl<P, T> PolicyKindFieldRef<P, T> for IpAddressPolicyKind
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicableRef<P>,
{
    type Output = T::Output;

    fn apply_kind_ref<M: RedactableMapper>(value: &T, mapper: &M) -> Self::Output {
        value.apply_ip_policy_ref(mapper)
    }
}

impl<P, T> PolicyKindFieldRefForFormatting<P, T> for IpAddressPolicyKind
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicableRef<P>,
{
    type FormattingOutput = T::Output;

    fn apply_kind_ref_for_formatting<M: RedactableMapper>(
        value: &T,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput> {
        value.apply_ip_policy_ref_for_formatting(mapper)
    }
}

impl<P, T: ?Sized> PolicyFieldRef<P> for T
where
    P: RedactionPolicy,
    P::Kind: PolicyKindFieldRef<P, T>,
{
    type Output = <P::Kind as PolicyKindFieldRef<P, T>>::Output;

    fn apply_field_ref<M: RedactableMapper>(&self, mapper: &M) -> Self::Output {
        <P::Kind as PolicyKindFieldRef<P, T>>::apply_kind_ref(self, mapper)
    }
}

impl<P, T: ?Sized> PolicyFieldRefForFormatting<P> for T
where
    P: RedactionPolicy,
    P::Kind: PolicyKindFieldRefForFormatting<P, T>,
{
    type FormattingOutput = <P::Kind as PolicyKindFieldRefForFormatting<P, T>>::FormattingOutput;

    fn apply_field_ref_for_formatting<M: RedactableMapper>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput> {
        <P::Kind as PolicyKindFieldRefForFormatting<P, T>>::apply_kind_ref_for_formatting(
            self, mapper,
        )
    }
}

macro_rules! impl_secret_scalar {
    ($($ty:ty),+ $(,)?) => {$ (
        impl<P> PolicyKindField<P, $ty> for SecretPolicyKind
        where
            P: RedactionPolicy<Kind = SecretPolicyKind>,
        {
            fn apply_kind<M: RedactableMapper>(value: $ty, _mapper: &M) -> $ty {
                ScalarRedaction::redact(value)
            }
        }

        impl<P> PolicyKindFieldRef<P, $ty> for SecretPolicyKind
        where
            P: RedactionPolicy<Kind = SecretPolicyKind>,
        {
            type Output = $ty;

            fn apply_kind_ref<M: RedactableMapper>(value: &$ty, _mapper: &M) -> Self::Output {
                ScalarRedaction::redact(*value)
            }
        }

        impl<P> PolicyKindFieldRefForFormatting<P, $ty> for SecretPolicyKind
        where
            P: RedactionPolicy<Kind = SecretPolicyKind>,
        {
            type FormattingOutput = $ty;

            fn apply_kind_ref_for_formatting<M: RedactableMapper>(
                value: &$ty,
                _mapper: &M,
            ) -> PolicyFormattingOutput<$ty> {
                PolicyFormattingOutput::Value(ScalarRedaction::redact(*value))
            }
        }
    )+ };
}

impl_secret_scalar!(
    i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize, f32, f64, bool, char,
);
