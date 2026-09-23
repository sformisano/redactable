//! Policy-kind formatting dispatch behind [`PolicyDisplay`](crate::PolicyDisplay)
//! and [`PolicyDebug`](crate::PolicyDebug).
//!
//! Text and secret kinds format through [`PolicyFormat`],
//! which propagates nested `RefCell` borrow conflicts as `<borrowed>`. Secret
//! scalars and bare typed IP values are direct leaves with their own
//! implementations, and the IP kind formats through its fail-closed traversal.

#[cfg(feature = "ip-address")]
use crate::{IpAddress, RedactableMapper, SensitiveWithPolicy};
use crate::{
    IpAddressPolicyKind, PolicyFormat, RedactableWithFormatter, RedactionPolicy, ScalarRedaction,
    SecretPolicyKind, TextPolicyKind,
    redaction::{IpPolicyApplicableRef, PolicyFormattingMapper, PolicyMapper},
};
use std::fmt::{Debug, Formatter, Result as FmtResult};
#[cfg(feature = "ip-address")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[cfg(feature = "ip-address")]
use super::field::{PolicyKindField, PolicyKindFieldRef};

/// Kind-level display formatter for a policy field.
#[doc(hidden)]
pub trait PolicyKindDisplayFormatting<P: RedactionPolicy, T: ?Sized> {
    /// Formats the policy result for a display placeholder.
    fn fmt_display(value: &T, formatter: &mut Formatter<'_>) -> FmtResult;
}

/// Kind-level debug formatter for a policy field.
#[doc(hidden)]
pub trait PolicyKindDebugFormatting<P: RedactionPolicy, T: ?Sized> {
    /// Debug-formats the policy result for a debug placeholder.
    fn fmt_debug(value: &T, formatter: &mut Formatter<'_>) -> FmtResult;
}

macro_rules! impl_recursive_kind_formatting {
    ($kind:ty) => {
        impl<P, T> PolicyKindDisplayFormatting<P, T> for $kind
        where
            P: RedactionPolicy<Kind = $kind>,
            T: PolicyFormat + ?Sized,
            T::Output: RedactableWithFormatter,
        {
            fn fmt_display(value: &T, formatter: &mut Formatter<'_>) -> FmtResult {
                value
                    .apply_policy_for_formatting::<P, _>(&PolicyFormattingMapper::new(
                        formatter.alternate(),
                    ))
                    .fmt_redacted(formatter)
            }
        }

        impl<P, T> PolicyKindDebugFormatting<P, T> for $kind
        where
            P: RedactionPolicy<Kind = $kind>,
            T: PolicyFormat + ?Sized,
            T::Output: Debug,
        {
            fn fmt_debug(value: &T, formatter: &mut Formatter<'_>) -> FmtResult {
                Debug::fmt(
                    &value.apply_policy_for_formatting::<P, _>(&PolicyFormattingMapper::new(
                        formatter.alternate(),
                    )),
                    formatter,
                )
            }
        }
    };
}

impl_recursive_kind_formatting!(TextPolicyKind);
impl_recursive_kind_formatting!(SecretPolicyKind);

impl<P, T> PolicyKindDisplayFormatting<P, T> for IpAddressPolicyKind
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicableRef<P> + ?Sized,
    T::Output: RedactableWithFormatter,
{
    fn fmt_display(value: &T, formatter: &mut Formatter<'_>) -> FmtResult {
        value
            .apply_ip_policy_ref_for_formatting(&PolicyMapper)
            .fmt_redacted(formatter)
    }
}

impl<P, T> PolicyKindDebugFormatting<P, T> for IpAddressPolicyKind
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicableRef<P> + ?Sized,
    T::Output: Debug,
{
    fn fmt_debug(value: &T, formatter: &mut Formatter<'_>) -> FmtResult {
        Debug::fmt(
            &value.apply_ip_policy_ref_for_formatting(&PolicyMapper),
            formatter,
        )
    }
}

macro_rules! impl_secret_scalar_formatting {
    ($($ty:ty),+ $(,)?) => {$ (
        impl<P> PolicyKindDisplayFormatting<P, $ty> for SecretPolicyKind
        where
            P: RedactionPolicy<Kind = SecretPolicyKind>,
        {
            fn fmt_display(value: &$ty, formatter: &mut Formatter<'_>) -> FmtResult {
                ScalarRedaction::redact(*value).fmt_redacted(formatter)
            }
        }

        impl<P> PolicyKindDebugFormatting<P, $ty> for SecretPolicyKind
        where
            P: RedactionPolicy<Kind = SecretPolicyKind>,
        {
            fn fmt_debug(value: &$ty, formatter: &mut Formatter<'_>) -> FmtResult {
                Debug::fmt(&ScalarRedaction::redact(*value), formatter)
            }
        }
    )+ };
}

impl_secret_scalar_formatting!(
    i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize, f32, f64, bool, char,
);

#[cfg(feature = "ip-address")]
macro_rules! impl_root_ip_field {
    ($($ty:ty),+ $(,)?) => {$ (
        impl PolicyKindField<IpAddress, $ty> for IpAddressPolicyKind {
            fn apply_kind<M: RedactableMapper>(value: $ty, _mapper: &M) -> $ty {
                value.redact_with_policy(&IpAddress::policy())
            }
        }

        impl PolicyKindFieldRef<IpAddress, $ty> for IpAddressPolicyKind {
            type Output = String;

            fn apply_kind_ref<M: RedactableMapper>(value: &$ty, _mapper: &M) -> Self::Output {
                value.redacted_string(&IpAddress::policy())
            }
        }

        impl PolicyKindDisplayFormatting<IpAddress, $ty> for IpAddressPolicyKind {
            fn fmt_display(value: &$ty, formatter: &mut Formatter<'_>) -> FmtResult {
                value
                    .redacted_string(&IpAddress::policy())
                    .fmt_redacted(formatter)
            }
        }

        impl PolicyKindDebugFormatting<IpAddress, $ty> for IpAddressPolicyKind {
            fn fmt_debug(value: &$ty, formatter: &mut Formatter<'_>) -> FmtResult {
                Debug::fmt(&value.redacted_string(&IpAddress::policy()), formatter)
            }
        }
    )+ };
}

#[cfg(feature = "ip-address")]
impl_root_ip_field!(Ipv4Addr, Ipv6Addr, IpAddr, SocketAddr,);
