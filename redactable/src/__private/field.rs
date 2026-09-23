//! Field-level policy dispatch for owned and borrowed generated field shapes.

use crate::{
    IpAddressPolicyKind, RedactableMapper, RedactionPolicy, ScalarRedaction, SecretPolicyKind,
    TextPolicyKind,
    redaction::{IpPolicyApplicable, IpPolicyApplicableRef, PolicyApplicable, PolicyApplicableRef},
};

/// Consuming policy operation emitted for one annotated field.
pub trait PolicyField<P: RedactionPolicy>: Sized {
    /// Applies `P` to this direct field.
    #[must_use]
    fn apply_field<M: RedactableMapper>(self, mapper: &M) -> Self;
}

/// Reference policy operation behind the kind-aware `apply_policy_ref` function.
pub trait PolicyFieldRef<P: RedactionPolicy> {
    /// Already-redacted output of the same shape as the source field.
    type Output;

    /// Applies `P` without consuming the source field.
    fn apply_field_ref<M: RedactableMapper>(&self, mapper: &M) -> Self::Output;
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
    T: PolicyApplicable,
{
    fn apply_kind<M: RedactableMapper>(value: T, mapper: &M) -> T {
        value.apply_policy::<P, M>(mapper)
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
    )+ };
}

impl_secret_scalar!(
    i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize, f32, f64, bool, char,
);
