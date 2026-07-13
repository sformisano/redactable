//! Private compile-time support used by derive-generated policy operations.
//!
//! Direct field eligibility is distinct from recursive policy traversal. Built-in
//! scalar and IP leaves are direct-only, while existing `PolicyApplicable` traits
//! remain the recursive compatibility route for text, custom, and generic fields.

use std::{cell::RefCell, marker::PhantomData};

use crate::{
    IpAddress, RedactableMapper, RedactableWithFormatter, RedactionPolicy, ScalarRedaction, Secret,
    redaction::{PolicyApplicable, PolicyApplicableRef},
};

#[cfg(feature = "ip-address")]
use crate::SensitiveWithPolicy;

/// Fail-closed JSON serialization used by redacted logging adapters.
#[cfg(feature = "json")]
pub use crate::redaction::serialize_redacted_json;
/// Serialization support used by derive-generated slog implementations.
#[cfg(feature = "json")]
pub use serde;
/// Logging support used by derive-generated slog implementations.
#[cfg(feature = "slog")]
pub use slog;

/// Default mapper used by generated private field operations.
pub use crate::redaction::PolicyMapper;

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

/// Recursive consuming capability. Scalar and IP direct leaves intentionally omit it.
pub trait RecursivePolicyField<P: RedactionPolicy>: Sized {
    /// Applies `P` through the recursive compatibility route.
    #[must_use]
    fn apply_recursive<M: RedactableMapper>(self, mapper: &M) -> Self;
}

/// Recursive reference capability. Scalar and IP direct leaves intentionally omit it.
pub trait RecursivePolicyFieldRef<P: RedactionPolicy> {
    /// Recursive already-redacted output.
    type Output;

    /// Applies `P` through the recursive reference route.
    fn apply_recursive_ref<M: RedactableMapper>(&self, mapper: &M) -> Self::Output;
}

impl<P, T> RecursivePolicyField<P> for T
where
    P: RedactionPolicy,
    T: PolicyApplicable,
{
    fn apply_recursive<M: RedactableMapper>(self, mapper: &M) -> Self {
        self.apply_policy::<P, M>(mapper)
    }
}

impl<P, T> PolicyField<P> for T
where
    P: RedactionPolicy,
    T: RecursivePolicyField<P>,
{
    fn apply_field<M: RedactableMapper>(self, mapper: &M) -> Self {
        self.apply_recursive(mapper)
    }
}

impl<P, T> RecursivePolicyFieldRef<P> for T
where
    P: RedactionPolicy,
    T: PolicyApplicableRef,
{
    type Output = T::Output;

    fn apply_recursive_ref<M: RedactableMapper>(&self, mapper: &M) -> Self::Output {
        self.apply_policy_ref::<P, M>(mapper)
    }
}

impl<P, T> PolicyFieldRef<P> for T
where
    P: RedactionPolicy,
    T: RecursivePolicyFieldRef<P>,
{
    type Output = T::Output;

    fn apply_field_ref<M: RedactableMapper>(&self, mapper: &M) -> Self::Output {
        self.apply_recursive_ref(mapper)
    }
}

macro_rules! impl_secret_scalar {
    ($($ty:ty),+ $(,)?) => {$ (
        impl PolicyField<Secret> for $ty {
            fn apply_field<M: RedactableMapper>(self, _mapper: &M) -> Self {
                ScalarRedaction::redact(self)
            }
        }

        impl PolicyFieldRef<Secret> for $ty {
            type Output = $ty;

            fn apply_field_ref<M: RedactableMapper>(&self, _mapper: &M) -> Self::Output {
                ScalarRedaction::redact(*self)
            }
        }
    )+ };
}

impl_secret_scalar!(
    i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize, f32, f64, bool, char,
);

#[cfg(feature = "ip-address")]
macro_rules! impl_ip_leaf {
    ($($ty:ty),+ $(,)?) => {$ (
        impl PolicyField<IpAddress> for $ty {
            fn apply_field<M: RedactableMapper>(self, _mapper: &M) -> Self {
                <Self as SensitiveWithPolicy<IpAddress>>::redact_with_policy(
                    self,
                    &<IpAddress as RedactionPolicy>::policy(),
                )
            }
        }

        impl PolicyFieldRef<IpAddress> for $ty {
            type Output = String;

            fn apply_field_ref<M: RedactableMapper>(&self, _mapper: &M) -> Self::Output {
                <Self as SensitiveWithPolicy<IpAddress>>::redacted_string(
                    self,
                    &<IpAddress as RedactionPolicy>::policy(),
                )
            }
        }
    )+ };
}

#[cfg(feature = "ip-address")]
impl_ip_leaf!(
    std::net::Ipv4Addr,
    std::net::Ipv6Addr,
    std::net::IpAddr,
    std::net::SocketAddr,
);

/// Borrow-safe result of applying a reference policy through `RefCell`.
pub enum PolicyRefCellOutput<T> {
    /// The source was borrowable and contains the original output shape.
    Value(RefCell<T>),
    /// The source was mutably borrowed; no value or error is retained.
    Borrowed,
}

impl<T: RedactableWithFormatter> RedactableWithFormatter for PolicyRefCellOutput<T> {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Value(value) => value.fmt_redacted(f),
            Self::Borrowed => f.write_str("<borrowed>"),
        }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for PolicyRefCellOutput<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Value(value) => std::fmt::Debug::fmt(value, f),
            Self::Borrowed => f.write_str("<borrowed>"),
        }
    }
}

/// Zero-sized policy identity probe used by generated validation guards.
pub struct PolicyProbe<P, F>(PhantomData<fn() -> (P, F)>);

impl<P, F> PolicyProbe<P, F> {
    /// Creates a probe without constructing either type.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<P, F> Default for PolicyProbe<P, F> {
    fn default() -> Self {
        Self::new()
    }
}

/// Marker returned for concrete built-in `IpAddress` policy identity.
#[derive(Clone, Copy)]
pub struct BuiltinIpAddress;

/// Marker returned for custom or generic policy identity.
#[derive(Clone, Copy)]
pub struct OtherPolicy;

/// Stable autoref selector used by generated policy guards.
pub trait ClassifyPolicy {
    /// Selected marker type.
    type Kind;

    /// Selects concrete built-in identity on the value receiver and the generic route by autoref.
    fn classify(self) -> Self::Kind;
}

macro_rules! impl_builtin_ip_probe {
    ($($ty:ty),+ $(,)?) => {$ (
        impl ClassifyPolicy for PolicyProbe<IpAddress, $ty> {
            type Kind = BuiltinIpAddress;

            fn classify(self) -> Self::Kind {
                BuiltinIpAddress
            }
        }
    )+ };
}

impl_builtin_ip_probe!(
    std::net::Ipv4Addr,
    std::net::Ipv6Addr,
    std::net::IpAddr,
    std::net::SocketAddr,
);

impl<P, F> ClassifyPolicy for &PolicyProbe<P, F> {
    type Kind = OtherPolicy;

    fn classify(self) -> Self::Kind {
        OtherPolicy
    }
}

/// Obligation implemented only by non-built-in policy markers.
pub trait RequireNonBuiltinIp {}

impl RequireNonBuiltinIp for OtherPolicy {}

/// Rejects an unwrapped-IP field when the selected policy is the built-in `IpAddress`.
pub fn require_non_builtin_ip<T: RequireNonBuiltinIp>(_marker: T) {}
