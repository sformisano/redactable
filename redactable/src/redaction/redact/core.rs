//! Core redaction traits, mappers, and entry points.
//!
//! This module defines the traversal contract the rest of the redaction
//! machinery is built on: [`RedactableMapper`] (the visitor threaded through
//! traversal) with its concrete [`PolicyMapper`] and [`PolicyFormattingMapper`]
//! implementations, [`PolicyApplicable`] / [`PolicyApplicableRef`] (owned and
//! borrowed recursive policy application), [`ScalarRedaction`] (default-value
//! redaction for scalars), and the public entry points [`redact`],
//! [`apply_policy`], and [`apply_policy_ref`]. It also holds the shared
//! formatting helpers used by the borrowed container implementations.
//!
//! Invariant: there are deliberately no blanket implementations here or in
//! the sibling modules — every type family opts in explicitly so that
//! unsupported shapes fail closed at compile time.

use crate::{
    __private::{
        PolicyApplicableRefForGeneratedFormatting, PolicyField, PolicyFieldRef,
        PolicyFormattingOutput,
    },
    policy::{RecursivePolicyKind, RedactionPolicy},
    redaction::traits::{RedactableWithMapper, SensitiveWithPolicy},
};

pub(super) fn collect_policy_formatting<T, C>(
    values: impl IntoIterator<Item = PolicyFormattingOutput<T>>,
) -> PolicyFormattingOutput<C>
where
    C: FromIterator<T>,
{
    let collected = values
        .into_iter()
        .map(|value| match value {
            PolicyFormattingOutput::Value(value) => Some(value),
            PolicyFormattingOutput::Borrowed => None,
        })
        .collect::<Option<C>>();

    collected.map_or_else(
        || PolicyFormattingOutput::Borrowed,
        PolicyFormattingOutput::Value,
    )
}

// =============================================================================
// RedactableMapper - Internal mapping trait
// =============================================================================

/// Maps sensitive and non-sensitive values during traversal.
///
/// This is the internal machinery that applies redaction policies.
/// Implementations must return the same value type for `map_sensitive`.
#[doc(hidden)]
pub trait RedactableMapper {
    /// Maps a sensitive, string-like value.
    fn map_sensitive<V, P>(&self, value: V) -> V
    where
        V: SensitiveWithPolicy<P>,
        P: RedactionPolicy;

    /// Maps a sensitive scalar value to its default.
    ///
    /// Scalars are marked with bare `#[sensitive]` and can only use `#[sensitive(Secret)]`.
    fn map_scalar<S>(&self, value: S) -> S
    where
        S: Default + ScalarRedaction;

    /// Reports the requested Debug mode for generated map-key formatting.
    ///
    /// Ordinary redaction mappers keep compact formatting. The generated
    /// formatting mapper overrides this during a caller's formatting request.
    #[doc(hidden)]
    fn debug_alternate(&self) -> bool {
        false
    }
}

/// The default mapper that applies redaction policies.
#[derive(Clone, Copy, Debug)]
#[doc(hidden)]
pub struct PolicyMapper;

impl RedactableMapper for PolicyMapper {
    fn map_sensitive<V, P>(&self, value: V) -> V
    where
        V: SensitiveWithPolicy<P>,
        P: RedactionPolicy,
    {
        value.redact_with_policy(&P::policy())
    }

    fn map_scalar<S>(&self, value: S) -> S
    where
        S: Default + ScalarRedaction,
    {
        // Special case: char defaults to '\0' which isn't useful, so use '*' instead
        // We use a helper trait to handle this cleanly
        ScalarRedaction::redact(value)
    }
}

/// Mapper used while a generated formatter projects policy-redacted values.
///
/// It carries the active alternate-Debug flag through nested containers so map
/// keys are formatted once, in the mode requested by the outer formatter.
#[derive(Clone, Copy, Debug)]
#[doc(hidden)]
pub struct PolicyFormattingMapper {
    debug_alternate: bool,
}

impl PolicyFormattingMapper {
    /// Captures the map-key Debug mode selected by the active formatter.
    #[must_use]
    pub fn new(debug_alternate: bool) -> Self {
        Self { debug_alternate }
    }
}

impl RedactableMapper for PolicyFormattingMapper {
    fn map_sensitive<V, P>(&self, value: V) -> V
    where
        V: SensitiveWithPolicy<P>,
        P: RedactionPolicy,
    {
        PolicyMapper.map_sensitive::<V, P>(value)
    }

    fn map_scalar<S>(&self, value: S) -> S
    where
        S: Default + ScalarRedaction,
    {
        PolicyMapper.map_scalar(value)
    }

    fn debug_alternate(&self) -> bool {
        self.debug_alternate
    }
}

// =============================================================================
// ScalarRedaction - Helper for scalar defaults
// =============================================================================

/// Helper trait to handle scalar redaction, with special cases.
#[doc(hidden)]
pub trait ScalarRedaction: Default {
    #[must_use]
    fn redact(self) -> Self {
        Self::default()
    }
}

impl ScalarRedaction for i8 {}
impl ScalarRedaction for i16 {}
impl ScalarRedaction for i32 {}
impl ScalarRedaction for i64 {}
impl ScalarRedaction for i128 {}
impl ScalarRedaction for isize {}
impl ScalarRedaction for u8 {}
impl ScalarRedaction for u16 {}
impl ScalarRedaction for u32 {}
impl ScalarRedaction for u64 {}
impl ScalarRedaction for u128 {}
impl ScalarRedaction for usize {}
impl ScalarRedaction for f32 {}
impl ScalarRedaction for f64 {}
impl ScalarRedaction for bool {}

impl ScalarRedaction for char {
    fn redact(self) -> Self {
        '*'
    }
}

// =============================================================================
// redact() - Entry point function
// =============================================================================

/// Redacts a value using policy-bound redaction.
///
/// The traversal is defined by [`crate::RedactableWithMapper`] implementations, typically
/// generated by the derive macro.
///
/// This function is total: policy application does not propagate errors. Any
/// failure handling is performed by the selected policy implementation.
pub fn redact<W>(value: W) -> W
where
    W: RedactableWithMapper,
{
    let mapper = PolicyMapper;
    value.redact_with(&mapper)
}

/// Applies a redaction policy using its kind-aware field dispatch.
///
/// Typed IP values therefore follow the same bare-field and fail-closed
/// container rules as derive-generated policy fields.
pub fn apply_policy<P, V>(value: V) -> V
where
    P: RedactionPolicy,
    V: PolicyField<P>,
{
    let mapper = PolicyMapper;
    value.apply_field(&mapper)
}

/// Applies a redaction policy by reference using kind-aware field dispatch.
///
/// This standalone helper avoids cloning and returns the policy field's normal
/// reference output. It does not use the formatting-only borrow-conflict channel.
/// Generated `SensitiveDisplay` implementations instead call the
/// [`PolicyFieldRefForFormatting`](crate::__private::PolicyFieldRefForFormatting)
/// facade, backed by
/// [`PolicyApplicableRefForFormatting`](crate::__private::PolicyApplicableRefForFormatting)
/// for recursive text and secret policies.
///
/// # Panics
///
/// Panics if a traversed [`RefCell`](std::cell::RefCell) is already mutably borrowed.
pub fn apply_policy_ref<P, V>(value: &V) -> <V as PolicyFieldRef<P>>::Output
where
    P: RedactionPolicy,
    V: PolicyFieldRef<P> + ?Sized,
{
    let mapper = PolicyMapper;
    value.apply_field_ref(&mapper)
}

// =============================================================================
// PolicyApplicable - Recursive policy application
// =============================================================================

/// A type that can have a redaction policy applied recursively to its inner values.
///
/// This trait enables `#[sensitive(Policy)]` to work on nested wrapper types
/// like `Option<Vec<String>>` by recursively delegating through each wrapper layer
/// until reaching a leaf type that implements [`SensitiveWithPolicy`].
///
/// ## Implementors
///
/// - **Wrapper types** (`Option`, `Vec`, `VecDeque`, arrays, `Box`, maps, sets):
///   Recursively apply to contents
/// - **Leaf types** (`String`, `Cow<str>`): Apply the redaction policy directly
///
/// ## Example
///
/// ```ignore
/// #[derive(Clone, Sensitive)]
/// struct User {
///     #[sensitive(Email)]
///     emails: Option<Vec<String>>,  // Works! Recursively applies Email to each String
/// }
/// ```
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot have a policy applied",
    label = "this type doesn't support redaction policies",
    note = "policies work on String, Cow<str>, and containers of these types",
    note = "for custom values, implement `SensitiveWithPolicy<YourPolicy>` and wrap them in `SensitiveValue<T, YourPolicy>`"
)]
#[doc(hidden)]
pub trait PolicyApplicable {
    /// Applies a redaction policy through the type structure.
    ///
    /// For wrapper types, this recursively applies to inner values.
    /// For leaf types, this applies the policy directly.
    #[must_use]
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper;
}

/// A type that can have a redaction policy applied recursively by reference.
///
/// This mirrors [`PolicyApplicable`] but avoids cloning the input. It is used
/// primarily for redacted display formatting.
#[doc(hidden)]
pub trait PolicyApplicableRef {
    /// The redacted output type.
    type Output;

    /// Applies a redaction policy through the type structure by reference.
    #[must_use]
    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper;
}

pub(super) fn apply_child_policy_ref_for_formatting<P, T, M>(
    value: &T,
    mapper: &M,
) -> PolicyFormattingOutput<T::FormattingOutput>
where
    P: RedactionPolicy,
    P::Kind: RecursivePolicyKind,
    T: PolicyApplicableRefForGeneratedFormatting,
    M: RedactableMapper,
{
    value.apply_policy_ref_for_generated_formatting::<P, M>(mapper)
}
