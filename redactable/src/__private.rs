//! Private compile-time support used by derive-generated policy operations.
//!
//! Field behavior is selected by `RedactionPolicy::Kind`. Text and secret kinds
//! retain recursive compatibility traversal, while IP kinds use a positive,
//! fail-closed structural traversal with safe map-key bounds.

use std::{cell::RefCell, marker::PhantomData};

#[cfg(feature = "ip-address")]
use crate::{IpAddress, SensitiveWithPolicy};
use crate::{
    IpAddressPolicyKind, RedactableMapper, RedactableWithFormatter, RedactionPolicy,
    ScalarRedaction, SecretPolicyKind, TextPolicyKind,
    policy::RecursivePolicyKind,
    redaction::{PolicyApplicable, PolicyApplicableRef},
};

#[doc(hidden)]
pub use crate::redaction::{IpPolicyApplicable, IpPolicyApplicableRef};

/// Fail-closed JSON serialization used by redacted logging adapters.
#[cfg(feature = "json")]
pub use crate::redaction::serialize_redacted_json;
/// Serialization support used by derive-generated slog implementations.
#[cfg(feature = "json")]
pub use serde;
/// JSON support used by derive-generated slog implementations.
#[cfg(feature = "slog")]
pub use serde_json;
/// Logging support used by derive-generated slog implementations.
#[cfg(feature = "slog")]
pub use slog;

/// Default mapper used by generated private field operations.
pub use crate::redaction::{PolicyFormattingMapper, PolicyMapper};

/// Constructs generated borrowed slog output without exposing internal constructors.
#[cfg(feature = "slog")]
#[doc(hidden)]
pub fn generated_redacted_json(value: serde_json::Value) -> crate::RedactedJson {
    crate::RedactedJson::new(value)
}

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

/// Borrowed formatter whose policy kind selects recursive or IP-safe traversal.
#[doc(hidden)]
pub struct GeneratedPolicyFormattingRef<'a, P, T: ?Sized> {
    value: &'a T,
    policy: PhantomData<P>,
}

/// Kind-level display formatter for a library-owned field shape.
#[doc(hidden)]
pub trait PolicyKindDisplayFormatting<P: RedactionPolicy, T: ?Sized> {
    /// Formats the policy result for a display placeholder.
    fn fmt_display(value: &T, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
}

/// Kind-level debug formatter for a library-owned field shape.
#[doc(hidden)]
pub trait PolicyKindDebugFormatting<P: RedactionPolicy, T: ?Sized> {
    /// Formats the policy result for a debug placeholder.
    fn fmt_debug(value: &T, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
}

/// Display formatting selected only for generated borrowed projections.
#[doc(hidden)]
pub trait GeneratedPolicyKindDisplayFormatting<P: RedactionPolicy, T: ?Sized> {
    /// Formats the generated borrowed policy result.
    fn fmt_generated_display(
        value: &T,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result;
}

/// Debug formatting selected only for generated borrowed projections.
#[doc(hidden)]
pub trait GeneratedPolicyKindDebugFormatting<P: RedactionPolicy, T: ?Sized> {
    /// Debug-formats the generated borrowed policy result.
    fn fmt_generated_debug(value: &T, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
}

macro_rules! impl_recursive_generated_kind_formatting {
    ($kind:ty) => {
        impl<P, T> GeneratedPolicyKindDisplayFormatting<P, T> for $kind
        where
            P: RedactionPolicy<Kind = $kind>,
            T: PolicyApplicableRefForGeneratedFormatting + ?Sized,
            T::FormattingOutput: RedactableWithFormatter,
        {
            fn fmt_generated_display(
                value: &T,
                formatter: &mut std::fmt::Formatter<'_>,
            ) -> std::fmt::Result {
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
            T::FormattingOutput: std::fmt::Debug,
        {
            fn fmt_generated_debug(
                value: &T,
                formatter: &mut std::fmt::Formatter<'_>,
            ) -> std::fmt::Result {
                std::fmt::Debug::fmt(
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
    fn fmt_generated_display(
        value: &T,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        value
            .apply_ip_policy_ref_for_formatting(&PolicyMapper)
            .fmt_redacted(formatter)
    }
}

impl<P, T> GeneratedPolicyKindDebugFormatting<P, T> for IpAddressPolicyKind
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicableRef<P> + ?Sized,
    T::Output: std::fmt::Debug,
{
    fn fmt_generated_debug(value: &T, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(
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
    fn fmt_display(value: &T, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        value.fmt_policy_display::<P>(formatter)
    }
}

impl<P, T> PolicyKindDebugFormatting<P, T> for TextPolicyKind
where
    P: RedactionPolicy<Kind = TextPolicyKind>,
    T: PolicyApplicableRefForFormatting + PolicyApplicableRef + ?Sized,
    T::Output: std::fmt::Debug,
{
    fn fmt_debug(value: &T, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        value.fmt_policy_debug::<P>(formatter)
    }
}

impl<P, T> PolicyKindDisplayFormatting<P, T> for SecretPolicyKind
where
    P: RedactionPolicy<Kind = SecretPolicyKind>,
    T: PolicyApplicableRefForFormatting + PolicyApplicableRef + ?Sized,
    T::Output: RedactableWithFormatter,
{
    fn fmt_display(value: &T, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        value.fmt_policy_display::<P>(formatter)
    }
}

impl<P, T> PolicyKindDebugFormatting<P, T> for SecretPolicyKind
where
    P: RedactionPolicy<Kind = SecretPolicyKind>,
    T: PolicyApplicableRefForFormatting + PolicyApplicableRef + ?Sized,
    T::Output: std::fmt::Debug,
{
    fn fmt_debug(value: &T, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        value.fmt_policy_debug::<P>(formatter)
    }
}

impl<P, T> PolicyKindDisplayFormatting<P, T> for IpAddressPolicyKind
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicableRef<P> + ?Sized,
    T::Output: RedactableWithFormatter,
{
    fn fmt_display(value: &T, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        value
            .apply_ip_policy_ref_for_formatting(&PolicyMapper)
            .fmt_redacted(formatter)
    }
}

impl<P, T> PolicyKindDebugFormatting<P, T> for IpAddressPolicyKind
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicableRef<P> + ?Sized,
    T::Output: std::fmt::Debug,
{
    fn fmt_debug(value: &T, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(
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
            fn fmt_display(value: &$ty, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
            <$ty as PolicyApplicableRefForGeneratedFormatting>::FormattingOutput: std::fmt::Debug,
        {
            fn fmt_debug(value: &$ty, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Debug::fmt(
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
            fn fmt_display(value: &$ty, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
            <$ty as PolicyApplicableRefForGeneratedFormatting>::FormattingOutput: std::fmt::Debug,
        {
            fn fmt_debug(value: &$ty, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Debug::fmt(
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
    [T] std::collections::VecDeque<T>;
    [T, const N: usize] [T; N];
    [T] std::sync::Arc<T>;
    [T] std::rc::Rc<T>;
    [T] std::cell::RefCell<T>;
    [T] std::cell::Cell<T>;
    [T, E] Result<T, E>;
    [K, V, S] std::collections::HashMap<K, V, S>;
    [K, V] std::collections::BTreeMap<K, V>;
    [T, S] std::collections::HashSet<T, S>;
    [T] std::collections::BTreeSet<T>;
);

macro_rules! impl_secret_scalar_formatting {
    ($($ty:ty),+ $(,)?) => {$ (
        impl PolicyApplicableRefForFormatting for $ty {}

        impl<P> PolicyKindDisplayFormatting<P, $ty> for SecretPolicyKind
        where
            P: RedactionPolicy<Kind = SecretPolicyKind>,
        {
            fn fmt_display(value: &$ty, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                <$ty as PolicyFieldRef<P>>::apply_field_ref(value, &PolicyMapper)
                    .fmt_redacted(formatter)
            }
        }

        impl<P> PolicyKindDebugFormatting<P, $ty> for SecretPolicyKind
        where
            P: RedactionPolicy<Kind = SecretPolicyKind>,
        {
            fn fmt_debug(value: &$ty, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Debug::fmt(
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
                formatter: &mut std::fmt::Formatter<'_>,
            ) -> std::fmt::Result {
                value
                    .redacted_string(&IpAddress::policy())
                    .fmt_redacted(formatter)
            }
        }

        impl PolicyKindDebugFormatting<IpAddress, $ty> for IpAddressPolicyKind {
            fn fmt_debug(
                value: &$ty,
                formatter: &mut std::fmt::Formatter<'_>,
            ) -> std::fmt::Result {
                std::fmt::Debug::fmt(
                    &value.redacted_string(&IpAddress::policy()),
                    formatter,
                )
            }
        }
    )+ };
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

#[cfg(feature = "ip-address")]
impl_root_ip_field!(
    std::net::Ipv4Addr,
    std::net::Ipv6Addr,
    std::net::IpAddr,
    std::net::SocketAddr,
);

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

/// Legacy borrow-safe `RefCell` policy output retained for API compatibility.
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

/// Formatting-only result of applying a reference policy.
///
/// This keeps borrow-conflict handling out of [`PolicyApplicableRef::Output`],
/// preserving that public associated-type contract for downstream callers.
pub enum PolicyFormattingOutput<T> {
    /// The policy was applied and produced the normal output shape.
    Value(T),
    /// The source was mutably borrowed; no value or error is retained.
    Borrowed,
}

impl<T> PolicyFormattingOutput<T> {
    /// Transforms a successful formatting value while preserving a borrow conflict.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> PolicyFormattingOutput<U> {
        match self {
            Self::Value(value) => PolicyFormattingOutput::Value(f(value)),
            Self::Borrowed => PolicyFormattingOutput::Borrowed,
        }
    }
}

impl<T: RedactableWithFormatter> RedactableWithFormatter for PolicyFormattingOutput<T> {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Value(value) => value.fmt_redacted(f),
            Self::Borrowed => f.write_str("<borrowed>"),
        }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for PolicyFormattingOutput<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Value(value) => std::fmt::Debug::fmt(value, f),
            Self::Borrowed => f.write_str("<borrowed>"),
        }
    }
}
