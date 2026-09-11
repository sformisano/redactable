//! Policy-kind formatting routing for generated and legacy borrowed projections.

#[cfg(feature = "ip-address")]
use crate::{IpAddress, RedactableMapper, SensitiveWithPolicy};
use crate::{
    IpAddressPolicyKind, RedactableWithFormatter, RedactionPolicy, SecretPolicyKind,
    TextPolicyKind,
    redaction::{IpPolicyApplicableRef, PolicyApplicableRef, PolicyFormattingMapper, PolicyMapper},
};
use std::fmt::{Debug, Formatter, Result as FmtResult};
#[cfg(feature = "ip-address")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    rc::Rc,
    sync::Arc,
};

use super::field::{
    PolicyApplicableRefForFormatting, PolicyApplicableRefForGeneratedFormatting, PolicyFieldRef,
};
#[cfg(feature = "ip-address")]
use super::{
    field::{PolicyKindField, PolicyKindFieldRef, PolicyKindFieldRefForFormatting},
    output::PolicyFormattingOutput,
};

/// Kind-level display formatter for a library-owned field shape.
#[doc(hidden)]
pub trait PolicyKindDisplayFormatting<P: RedactionPolicy, T: ?Sized> {
    /// Formats the policy result for a display placeholder.
    fn fmt_display(value: &T, formatter: &mut Formatter<'_>) -> FmtResult;
}

/// Kind-level debug formatter for a library-owned field shape.
#[doc(hidden)]
pub trait PolicyKindDebugFormatting<P: RedactionPolicy, T: ?Sized> {
    /// Formats the policy result for a debug placeholder.
    fn fmt_debug(value: &T, formatter: &mut Formatter<'_>) -> FmtResult;
}

/// Display formatting selected only for generated borrowed projections.
#[doc(hidden)]
pub trait GeneratedPolicyKindDisplayFormatting<P: RedactionPolicy, T: ?Sized> {
    /// Formats the generated borrowed policy result.
    fn fmt_generated_display(value: &T, formatter: &mut Formatter<'_>) -> FmtResult;
}

/// Debug formatting selected only for generated borrowed projections.
#[doc(hidden)]
pub trait GeneratedPolicyKindDebugFormatting<P: RedactionPolicy, T: ?Sized> {
    /// Debug-formats the generated borrowed policy result.
    fn fmt_generated_debug(value: &T, formatter: &mut Formatter<'_>) -> FmtResult;
}

macro_rules! impl_recursive_generated_kind_formatting {
    ($kind:ty) => {
        impl<P, T> GeneratedPolicyKindDisplayFormatting<P, T> for $kind
        where
            P: RedactionPolicy<Kind = $kind>,
            T: PolicyApplicableRefForGeneratedFormatting + ?Sized,
            T::FormattingOutput: RedactableWithFormatter,
        {
            fn fmt_generated_display(value: &T, formatter: &mut Formatter<'_>) -> FmtResult {
                value
                    .apply_policy_ref_for_generated_formatting::<P, _>(
                        &PolicyFormattingMapper::new(formatter.alternate()),
                    )
                    .fmt_redacted(formatter)
            }
        }

        impl<P, T> GeneratedPolicyKindDebugFormatting<P, T> for $kind
        where
            P: RedactionPolicy<Kind = $kind>,
            T: PolicyApplicableRefForGeneratedFormatting + ?Sized,
            T::FormattingOutput: Debug,
        {
            fn fmt_generated_debug(value: &T, formatter: &mut Formatter<'_>) -> FmtResult {
                Debug::fmt(
                    &value.apply_policy_ref_for_generated_formatting::<P, _>(
                        &PolicyFormattingMapper::new(formatter.alternate()),
                    ),
                    formatter,
                )
            }
        }
    };
}

impl_recursive_generated_kind_formatting!(TextPolicyKind);
impl_recursive_generated_kind_formatting!(SecretPolicyKind);

impl<P, T> GeneratedPolicyKindDisplayFormatting<P, T> for IpAddressPolicyKind
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicableRef<P> + ?Sized,
    T::Output: RedactableWithFormatter,
{
    fn fmt_generated_display(value: &T, formatter: &mut Formatter<'_>) -> FmtResult {
        value
            .apply_ip_policy_ref_for_formatting(&PolicyMapper)
            .fmt_redacted(formatter)
    }
}

impl<P, T> GeneratedPolicyKindDebugFormatting<P, T> for IpAddressPolicyKind
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicableRef<P> + ?Sized,
    T::Output: Debug,
{
    fn fmt_generated_debug(value: &T, formatter: &mut Formatter<'_>) -> FmtResult {
        Debug::fmt(
            &value.apply_ip_policy_ref_for_formatting(&PolicyMapper),
            formatter,
        )
    }
}

impl<P, T> PolicyKindDisplayFormatting<P, T> for TextPolicyKind
where
    P: RedactionPolicy<Kind = TextPolicyKind>,
    T: PolicyApplicableRefForFormatting + PolicyApplicableRef + ?Sized,
    T::Output: RedactableWithFormatter,
{
    fn fmt_display(value: &T, formatter: &mut Formatter<'_>) -> FmtResult {
        value.fmt_policy_display::<P>(formatter)
    }
}

impl<P, T> PolicyKindDebugFormatting<P, T> for TextPolicyKind
where
    P: RedactionPolicy<Kind = TextPolicyKind>,
    T: PolicyApplicableRefForFormatting + PolicyApplicableRef + ?Sized,
    T::Output: Debug,
{
    fn fmt_debug(value: &T, formatter: &mut Formatter<'_>) -> FmtResult {
        value.fmt_policy_debug::<P>(formatter)
    }
}

impl<P, T> PolicyKindDisplayFormatting<P, T> for SecretPolicyKind
where
    P: RedactionPolicy<Kind = SecretPolicyKind>,
    T: PolicyApplicableRefForFormatting + PolicyApplicableRef + ?Sized,
    T::Output: RedactableWithFormatter,
{
    fn fmt_display(value: &T, formatter: &mut Formatter<'_>) -> FmtResult {
        value.fmt_policy_display::<P>(formatter)
    }
}

impl<P, T> PolicyKindDebugFormatting<P, T> for SecretPolicyKind
where
    P: RedactionPolicy<Kind = SecretPolicyKind>,
    T: PolicyApplicableRefForFormatting + PolicyApplicableRef + ?Sized,
    T::Output: Debug,
{
    fn fmt_debug(value: &T, formatter: &mut Formatter<'_>) -> FmtResult {
        value.fmt_policy_debug::<P>(formatter)
    }
}

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

macro_rules! impl_generated_kind_formatting {
    ($( [$($generics:tt)*] $ty:ty );+ $(;)?) => {$ (
        impl<P, $($generics)*> PolicyKindDisplayFormatting<P, $ty> for TextPolicyKind
        where
            P: RedactionPolicy<Kind = TextPolicyKind>,
            $ty: PolicyApplicableRefForGeneratedFormatting,
            <$ty as PolicyApplicableRefForGeneratedFormatting>::FormattingOutput:
                RedactableWithFormatter,
        {
            fn fmt_display(value: &$ty, formatter: &mut Formatter<'_>) -> FmtResult {
                value
                    .apply_policy_ref_for_generated_formatting::<P, _>(
                        &PolicyFormattingMapper::new(formatter.alternate()),
                    )
                    .fmt_redacted(formatter)
            }
        }

        impl<P, $($generics)*> PolicyKindDebugFormatting<P, $ty> for TextPolicyKind
        where
            P: RedactionPolicy<Kind = TextPolicyKind>,
            $ty: PolicyApplicableRefForGeneratedFormatting,
            <$ty as PolicyApplicableRefForGeneratedFormatting>::FormattingOutput: Debug,
        {
            fn fmt_debug(value: &$ty, formatter: &mut Formatter<'_>) -> FmtResult {
                Debug::fmt(
                    &value.apply_policy_ref_for_generated_formatting::<P, _>(
                        &PolicyFormattingMapper::new(formatter.alternate()),
                    ),
                    formatter,
                )
            }
        }

        impl<P, $($generics)*> PolicyKindDisplayFormatting<P, $ty> for SecretPolicyKind
        where
            P: RedactionPolicy<Kind = SecretPolicyKind>,
            $ty: PolicyApplicableRefForGeneratedFormatting,
            <$ty as PolicyApplicableRefForGeneratedFormatting>::FormattingOutput:
                RedactableWithFormatter,
        {
            fn fmt_display(value: &$ty, formatter: &mut Formatter<'_>) -> FmtResult {
                value
                    .apply_policy_ref_for_generated_formatting::<P, _>(
                        &PolicyFormattingMapper::new(formatter.alternate()),
                    )
                    .fmt_redacted(formatter)
            }
        }

        impl<P, $($generics)*> PolicyKindDebugFormatting<P, $ty> for SecretPolicyKind
        where
            P: RedactionPolicy<Kind = SecretPolicyKind>,
            $ty: PolicyApplicableRefForGeneratedFormatting,
            <$ty as PolicyApplicableRefForGeneratedFormatting>::FormattingOutput: Debug,
        {
            fn fmt_debug(value: &$ty, formatter: &mut Formatter<'_>) -> FmtResult {
                Debug::fmt(
                    &value.apply_policy_ref_for_generated_formatting::<P, _>(
                        &PolicyFormattingMapper::new(formatter.alternate()),
                    ),
                    formatter,
                )
            }
        }
    )+ };
}

impl_generated_kind_formatting!(
    [T] Option<T>;
    [T] Vec<T>;
    [T] VecDeque<T>;
    [T, const N: usize] [T; N];
    [T] Arc<T>;
    [T] Rc<T>;
    [T] RefCell<T>;
    [T] Cell<T>;
    [T, E] Result<T, E>;
    [K, V, S] HashMap<K, V, S>;
    [K, V] BTreeMap<K, V>;
    [T, S] HashSet<T, S>;
    [T] BTreeSet<T>;
);

macro_rules! impl_secret_scalar_formatting {
    ($($ty:ty),+ $(,)?) => {$ (
        impl<P: RedactionPolicy<Kind = SecretPolicyKind>> GeneratedPolicyKindDisplayFormatting<P, $ty> for SecretPolicyKind {
            fn fmt_generated_display(value: &$ty, formatter: &mut Formatter<'_>) -> FmtResult {
                <Self as PolicyKindDisplayFormatting<P, $ty>>::fmt_display(value, formatter)
            }
        }
        impl<P: RedactionPolicy<Kind = SecretPolicyKind>> GeneratedPolicyKindDebugFormatting<P, $ty> for SecretPolicyKind {
            fn fmt_generated_debug(value: &$ty, formatter: &mut Formatter<'_>) -> FmtResult {
                <Self as PolicyKindDebugFormatting<P, $ty>>::fmt_debug(value, formatter)
            }
        }

        impl PolicyApplicableRefForFormatting for $ty {}

        impl<P> PolicyKindDisplayFormatting<P, $ty> for SecretPolicyKind
        where
            P: RedactionPolicy<Kind = SecretPolicyKind>,
        {
            fn fmt_display(value: &$ty, formatter: &mut Formatter<'_>) -> FmtResult {
                <$ty as PolicyFieldRef<P>>::apply_field_ref(value, &PolicyMapper)
                    .fmt_redacted(formatter)
            }
        }

        impl<P> PolicyKindDebugFormatting<P, $ty> for SecretPolicyKind
        where
            P: RedactionPolicy<Kind = SecretPolicyKind>,
        {
            fn fmt_debug(value: &$ty, formatter: &mut Formatter<'_>) -> FmtResult {
                Debug::fmt(
                    &<$ty as PolicyFieldRef<P>>::apply_field_ref(value, &PolicyMapper),
                    formatter,
                )
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
        impl GeneratedPolicyKindDisplayFormatting<IpAddress, $ty> for IpAddressPolicyKind {
            fn fmt_generated_display(value: &$ty, formatter: &mut Formatter<'_>) -> FmtResult {
                <Self as PolicyKindDisplayFormatting<IpAddress, $ty>>::fmt_display(value, formatter)
            }
        }
        impl GeneratedPolicyKindDebugFormatting<IpAddress, $ty> for IpAddressPolicyKind {
            fn fmt_generated_debug(value: &$ty, formatter: &mut Formatter<'_>) -> FmtResult {
                <Self as PolicyKindDebugFormatting<IpAddress, $ty>>::fmt_debug(value, formatter)
            }
        }

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

        impl PolicyKindFieldRefForFormatting<IpAddress, $ty> for IpAddressPolicyKind {
            type FormattingOutput = String;

            fn apply_kind_ref_for_formatting<M: RedactableMapper>(
                value: &$ty,
                _mapper: &M,
            ) -> PolicyFormattingOutput<String> {
                PolicyFormattingOutput::Value(value.redacted_string(&IpAddress::policy()))
            }
        }

        impl PolicyApplicableRefForFormatting for $ty {}

        impl PolicyKindDisplayFormatting<IpAddress, $ty> for IpAddressPolicyKind {
            fn fmt_display(
                value: &$ty,
                formatter: &mut Formatter<'_>,
            ) -> FmtResult {
                value
                    .redacted_string(&IpAddress::policy())
                    .fmt_redacted(formatter)
            }
        }

        impl PolicyKindDebugFormatting<IpAddress, $ty> for IpAddressPolicyKind {
            fn fmt_debug(
                value: &$ty,
                formatter: &mut Formatter<'_>,
            ) -> FmtResult {
                Debug::fmt(
                    &value.redacted_string(&IpAddress::policy()),
                    formatter,
                )
            }
        }
    )+ };
}

#[cfg(feature = "ip-address")]
impl_root_ip_field!(Ipv4Addr, Ipv6Addr, IpAddr, SocketAddr,);
