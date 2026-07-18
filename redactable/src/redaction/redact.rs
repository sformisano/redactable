//! Application layer: Redaction machinery.
//!
//! This module provides the infrastructure for applying redaction:
//!
//! - [`RedactableMapper`]: Internal trait for mapping values during traversal
//! - [`PolicyApplicable`]: Types that can have policies applied recursively
//! - [`redact`]: The entry point function for redacting a value
//! - [`ScalarRedaction`]: Helper trait for scalar default values
//!
//! ## How `PolicyApplicable` Works
//!
//! For a field like:
//! ```ignore
//! #[sensitive(Token)]
//! api_keys: Option<Vec<String>>
//! ```
//!
//! The generated code calls:
//! ```ignore
//! PolicyApplicable::apply_policy::<Token, _>(api_keys, mapper)
//! ```
//!
//! At runtime, this recursively descends:
//! 1. `Option<Vec<String>>` → calls `.map(|v| v.apply_policy::<Token, _>(mapper))`
//! 2. `Vec<String>` → calls `.into_iter().map(|v| v.apply_policy::<Token, _>(mapper)).collect()`
//! 3. `String` → calls `mapper.map_sensitive::<_, Token>(self)`
//!
//! The recursion handles any nesting depth automatically!

use std::{
    borrow::Cow,
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    hash::{BuildHasher, Hash},
    rc::Rc,
    sync::Arc,
};

use super::traits::{RedactableWithMapper, SensitiveWithPolicy};
use crate::{
    __private::{
        PolicyApplicableRefForFormatting, PolicyApplicableRefForGeneratedFormatting, PolicyField,
        PolicyFieldRef, PolicyFormattingOutput,
    },
    policy::{RecursivePolicyKind, RedactionPolicy},
};

fn collect_policy_formatting<T, C>(
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

/// Owned reference-policy output for maps.
///
/// Keys are rendered from the source map by reference, so formatting never
/// clones a borrow-sensitive key. Values remain structurally redacted.
#[doc(hidden)]
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyMapOutput<V> {
    entries: Vec<(PolicyMapKey, V)>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
struct PolicyMapKey {
    rendered: String,
}

impl std::fmt::Debug for PolicyMapKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.rendered)
    }
}

impl<V: std::fmt::Debug> std::fmt::Debug for PolicyMapOutput<V> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut map = formatter.debug_map();
        for (key, value) in &self.entries {
            map.entry(key, value);
        }
        map.finish()
    }
}

impl<V: crate::RedactableWithFormatter> crate::RedactableWithFormatter for PolicyMapOutput<V> {
    fn fmt_redacted(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut map = formatter.debug_map();
        for (key, value) in &self.entries {
            map.entry(key, &value.redacted_display());
        }
        map.finish()
    }
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

fn apply_child_policy_ref_for_formatting<P, T, M>(
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

// =============================================================================
// PolicyApplicable: Base case implementations (leaf types)
// =============================================================================

impl PolicyApplicable for String {
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        mapper.map_sensitive::<_, P>(self)
    }
}

impl PolicyApplicable for Cow<'_, str> {
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        mapper.map_sensitive::<_, P>(self)
    }
}

// =============================================================================
// PolicyApplicableRef: Base case implementations (leaf types)
// =============================================================================

impl PolicyApplicableRef for String {
    type Output = String;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let policy = P::policy();
        policy.apply_to(self.as_str())
    }
}

impl PolicyApplicableRef for Cow<'_, str> {
    /// Redacted `Cow` output is always owned so it never borrows from the raw input.
    type Output = Cow<'static, str>;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let policy = P::policy();
        Cow::Owned(policy.apply_to(self.as_ref()))
    }
}

impl PolicyApplicableRef for &str {
    type Output = String;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let policy = P::policy();
        policy.apply_to(self)
    }
}

macro_rules! impl_policy_ref_formatting_leaf {
    ($($ty:ty),+ $(,)?) => {$ (
        impl PolicyApplicableRefForGeneratedFormatting for $ty {
            type FormattingOutput = <Self as PolicyApplicableRef>::Output;

            fn apply_policy_ref_for_generated_formatting<P, M>(
                &self,
                mapper: &M,
            ) -> PolicyFormattingOutput<Self::FormattingOutput>
            where
                P: RedactionPolicy,
                P::Kind: RecursivePolicyKind,
                M: RedactableMapper,
            {
                PolicyFormattingOutput::Value(self.apply_policy_ref::<P, M>(mapper))
            }
        }
    )+ };
}

impl_policy_ref_formatting_leaf!(String, Cow<'_, str>, &str);

impl PolicyApplicableRefForFormatting for String {}
impl PolicyApplicableRefForFormatting for Cow<'_, str> {}
impl PolicyApplicableRefForFormatting for &str {}

#[cfg(feature = "json")]
impl_policy_ref_formatting_leaf!(serde_json::Value);

#[cfg(feature = "json")]
impl PolicyApplicableRefForFormatting for serde_json::Value {}

// =============================================================================
// PolicyApplicable: Recursive implementations (wrapper types)
// =============================================================================

impl<T: PolicyApplicable> PolicyApplicable for Option<T> {
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.map(|v| v.apply_policy::<P, M>(mapper))
    }
}

// =============================================================================
// PolicyApplicableRef: Recursive implementations (wrapper types)
// =============================================================================

impl<T> PolicyApplicableRef for Option<T>
where
    T: PolicyApplicableRef,
{
    type Output = Option<T::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.as_ref().map(|v| v.apply_policy_ref::<P, M>(mapper))
    }
}

impl<T> PolicyApplicableRefForGeneratedFormatting for Option<T>
where
    T: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = Option<T::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.as_ref().map_or_else(
            || PolicyFormattingOutput::Value(None),
            |value| apply_child_policy_ref_for_formatting::<P, _, M>(value, mapper).map(Some),
        )
    }
}

impl<T> PolicyApplicableRef for Vec<T>
where
    T: PolicyApplicableRef,
{
    type Output = Vec<T::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.iter()
            .map(|v| v.apply_policy_ref::<P, M>(mapper))
            .collect()
    }
}

impl<T> PolicyApplicableRefForGeneratedFormatting for Vec<T>
where
    T: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = Vec<T::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        collect_policy_formatting(
            self.iter()
                .map(|value| apply_child_policy_ref_for_formatting::<P, _, M>(value, mapper)),
        )
    }
}

impl<T> PolicyApplicableRef for VecDeque<T>
where
    T: PolicyApplicableRef,
{
    type Output = VecDeque<T::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.iter()
            .map(|v| v.apply_policy_ref::<P, M>(mapper))
            .collect()
    }
}

impl<T> PolicyApplicableRefForGeneratedFormatting for VecDeque<T>
where
    T: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = VecDeque<T::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        collect_policy_formatting(
            self.iter()
                .map(|value| apply_child_policy_ref_for_formatting::<P, _, M>(value, mapper)),
        )
    }
}

impl<T, const N: usize> PolicyApplicableRef for [T; N]
where
    T: PolicyApplicableRef,
{
    type Output = [T::Output; N];

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.each_ref().map(|v| v.apply_policy_ref::<P, M>(mapper))
    }
}

impl<T, const N: usize> PolicyApplicableRefForGeneratedFormatting for [T; N]
where
    T: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = [T::FormattingOutput; N];

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let values = self
            .each_ref()
            .map(|value| apply_child_policy_ref_for_formatting::<P, _, M>(value, mapper));
        if values
            .iter()
            .any(|value| matches!(value, PolicyFormattingOutput::Borrowed))
        {
            return PolicyFormattingOutput::Borrowed;
        }
        PolicyFormattingOutput::Value(values.map(|value| match value {
            PolicyFormattingOutput::Value(value) => value,
            PolicyFormattingOutput::Borrowed => unreachable!("borrow conflicts returned above"),
        }))
    }
}

impl<T> PolicyApplicableRef for Box<T>
where
    T: PolicyApplicableRef,
{
    type Output = Box<T::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        Box::new((**self).apply_policy_ref::<P, M>(mapper))
    }
}

impl<T> PolicyApplicableRefForGeneratedFormatting for Box<T>
where
    T: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = Box<T::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        apply_child_policy_ref_for_formatting::<P, _, M>(&**self, mapper).map(Box::new)
    }
}

impl<T> PolicyApplicableRef for Arc<T>
where
    T: PolicyApplicableRef,
{
    type Output = Arc<T::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        Arc::new((**self).apply_policy_ref::<P, M>(mapper))
    }
}

impl<T> PolicyApplicableRefForGeneratedFormatting for Arc<T>
where
    T: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = Arc<T::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        apply_child_policy_ref_for_formatting::<P, _, M>(&**self, mapper).map(Arc::new)
    }
}

impl<T> PolicyApplicableRef for Rc<T>
where
    T: PolicyApplicableRef,
{
    type Output = Rc<T::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        Rc::new((**self).apply_policy_ref::<P, M>(mapper))
    }
}

impl<T> PolicyApplicableRefForGeneratedFormatting for Rc<T>
where
    T: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = Rc<T::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        apply_child_policy_ref_for_formatting::<P, _, M>(&**self, mapper).map(Rc::new)
    }
}

impl<T> PolicyApplicableRef for RefCell<T>
where
    T: PolicyApplicableRef,
{
    type Output = RefCell<T::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        RefCell::new(self.borrow().apply_policy_ref::<P, M>(mapper))
    }
}

impl<T> PolicyApplicableRefForGeneratedFormatting for RefCell<T>
where
    T: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = RefCell<T::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.try_borrow().map_or_else(
            |_| PolicyFormattingOutput::Borrowed,
            |value| {
                apply_child_policy_ref_for_formatting::<P, _, M>(&*value, mapper).map(RefCell::new)
            },
        )
    }
}

impl<T> PolicyApplicableRef for Cell<T>
where
    T: PolicyApplicableRef + Copy,
    T::Output: Copy,
{
    type Output = Cell<T::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let value = self.get();
        Cell::new(value.apply_policy_ref::<P, M>(mapper))
    }
}

impl<T> PolicyApplicableRefForGeneratedFormatting for Cell<T>
where
    T: PolicyApplicableRefForGeneratedFormatting + Copy,
    T::FormattingOutput: Copy,
{
    type FormattingOutput = Cell<T::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        apply_child_policy_ref_for_formatting::<P, _, M>(&self.get(), mapper).map(Cell::new)
    }
}

impl<T, E> PolicyApplicableRef for Result<T, E>
where
    T: PolicyApplicableRef,
    E: PolicyApplicableRef,
{
    type Output = Result<T::Output, E::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        match self {
            Ok(v) => Ok(v.apply_policy_ref::<P, M>(mapper)),
            Err(e) => Err(e.apply_policy_ref::<P, M>(mapper)),
        }
    }
}

impl<T, E> PolicyApplicableRefForGeneratedFormatting for Result<T, E>
where
    T: PolicyApplicableRefForGeneratedFormatting,
    E: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = Result<T::FormattingOutput, E::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        match self {
            Ok(value) => apply_child_policy_ref_for_formatting::<P, _, M>(value, mapper).map(Ok),
            Err(error) => apply_child_policy_ref_for_formatting::<P, _, M>(error, mapper).map(Err),
        }
    }
}

impl<T: PolicyApplicable> PolicyApplicable for Vec<T> {
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.into_iter()
            .map(|v| v.apply_policy::<P, M>(mapper))
            .collect()
    }
}

impl<T: PolicyApplicable> PolicyApplicable for VecDeque<T> {
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.into_iter()
            .map(|v| v.apply_policy::<P, M>(mapper))
            .collect()
    }
}

impl<T: PolicyApplicable, const N: usize> PolicyApplicable for [T; N] {
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.map(|v| v.apply_policy::<P, M>(mapper))
    }
}

impl<T: PolicyApplicable> PolicyApplicable for Box<T> {
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        Box::new((*self).apply_policy::<P, M>(mapper))
    }
}

impl<T> PolicyApplicable for Arc<T>
where
    T: PolicyApplicable + Clone,
{
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        Arc::new((*self).clone().apply_policy::<P, M>(mapper))
    }
}

impl<T> PolicyApplicable for Rc<T>
where
    T: PolicyApplicable + Clone,
{
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        Rc::new((*self).clone().apply_policy::<P, M>(mapper))
    }
}

impl<T> PolicyApplicable for RefCell<T>
where
    T: PolicyApplicable,
{
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        RefCell::new(self.into_inner().apply_policy::<P, M>(mapper))
    }
}

impl<T> PolicyApplicable for Cell<T>
where
    T: PolicyApplicable + Copy,
{
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        Cell::new(self.get().apply_policy::<P, M>(mapper))
    }
}

impl<T, E> PolicyApplicable for Result<T, E>
where
    T: PolicyApplicable,
    E: PolicyApplicable,
{
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        match self {
            Ok(v) => Ok(v.apply_policy::<P, M>(mapper)),
            Err(e) => Err(e.apply_policy::<P, M>(mapper)),
        }
    }
}

// Maps: apply policy to values only (keys unchanged)
impl<K, V, S> PolicyApplicable for HashMap<K, V, S>
where
    K: Hash + Eq,
    V: PolicyApplicable,
    S: BuildHasher + Clone,
{
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let hasher = self.hasher().clone();
        let mut result = HashMap::with_capacity_and_hasher(self.len(), hasher);
        result.extend(
            self.into_iter()
                .map(|(k, v)| (k, v.apply_policy::<P, M>(mapper))),
        );
        result
    }
}

impl<K, V> PolicyApplicable for BTreeMap<K, V>
where
    K: Ord,
    V: PolicyApplicable,
{
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.into_iter()
            .map(|(k, v)| (k, v.apply_policy::<P, M>(mapper)))
            .collect()
    }
}

impl<K, V, S> PolicyApplicableRef for HashMap<K, V, S>
where
    K: Clone + Hash + Eq,
    V: PolicyApplicableRef,
    S: BuildHasher + Clone,
{
    type Output = HashMap<K, V::Output, S>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let mut result = HashMap::with_capacity_and_hasher(self.len(), self.hasher().clone());
        result.extend(
            self.iter()
                .map(|(key, value)| (key.clone(), value.apply_policy_ref::<P, M>(mapper))),
        );
        result
    }
}

impl<K, V, S> PolicyApplicableRefForGeneratedFormatting for HashMap<K, V, S>
where
    K: Hash + Eq + std::fmt::Debug,
    V: PolicyApplicableRefForGeneratedFormatting,
    S: BuildHasher,
{
    type FormattingOutput = PolicyMapOutput<V::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let mut entries = Vec::with_capacity(self.len());
        for (key, value) in self {
            match apply_child_policy_ref_for_formatting::<P, _, M>(value, mapper) {
                PolicyFormattingOutput::Value(value) => {
                    let rendered = if mapper.debug_alternate() {
                        format!("{key:#?}")
                    } else {
                        format!("{key:?}")
                    };
                    entries.push((PolicyMapKey { rendered }, value));
                }
                PolicyFormattingOutput::Borrowed => return PolicyFormattingOutput::Borrowed,
            }
        }
        PolicyFormattingOutput::Value(PolicyMapOutput { entries })
    }
}

impl<K, V> PolicyApplicableRef for BTreeMap<K, V>
where
    K: Clone + Ord,
    V: PolicyApplicableRef,
{
    type Output = BTreeMap<K, V::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.iter()
            .map(|(key, value)| (key.clone(), value.apply_policy_ref::<P, M>(mapper)))
            .collect()
    }
}

impl<K, V> PolicyApplicableRefForGeneratedFormatting for BTreeMap<K, V>
where
    K: Ord + std::fmt::Debug,
    V: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = PolicyMapOutput<V::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        collect_policy_formatting(self.iter().map(|(key, value)| {
            apply_child_policy_ref_for_formatting::<P, _, M>(value, mapper).map(|value| {
                let rendered = if mapper.debug_alternate() {
                    format!("{key:#?}")
                } else {
                    format!("{key:?}")
                };
                (PolicyMapKey { rendered }, value)
            })
        }))
        .map(|entries| PolicyMapOutput { entries })
    }
}

// Sets: apply policy to elements.
//
// **Warning**: Sets may shrink after redaction. If multiple distinct values redact
// to the same string (e.g., all to `"[REDACTED]"`), the resulting set will have
// fewer elements. If cardinality matters, use `Vec` instead.
impl<T, S> PolicyApplicable for HashSet<T, S>
where
    T: PolicyApplicable + Hash + Eq,
    S: BuildHasher + Clone,
{
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let hasher = self.hasher().clone();
        let mut result = HashSet::with_capacity_and_hasher(self.len(), hasher);
        result.extend(self.into_iter().map(|v| v.apply_policy::<P, M>(mapper)));
        result
    }
}

impl<T> PolicyApplicable for BTreeSet<T>
where
    T: PolicyApplicable + Ord,
{
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.into_iter()
            .map(|v| v.apply_policy::<P, M>(mapper))
            .collect()
    }
}

impl<T, S> PolicyApplicableRef for HashSet<T, S>
where
    T: PolicyApplicableRef,
    T::Output: Hash + Eq,
    S: BuildHasher + Clone,
{
    type Output = HashSet<T::Output, S>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let hasher = self.hasher().clone();
        let mut result = HashSet::with_capacity_and_hasher(self.len(), hasher);
        result.extend(self.iter().map(|v| v.apply_policy_ref::<P, M>(mapper)));
        result
    }
}

impl<T, S> PolicyApplicableRefForGeneratedFormatting for HashSet<T, S>
where
    T: PolicyApplicableRefForGeneratedFormatting,
    T::FormattingOutput: Hash + Eq,
    S: BuildHasher,
{
    type FormattingOutput = HashSet<T::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let mut result = HashSet::with_capacity(self.len());
        for value in self {
            match apply_child_policy_ref_for_formatting::<P, _, M>(value, mapper) {
                PolicyFormattingOutput::Value(value) => {
                    result.insert(value);
                }
                PolicyFormattingOutput::Borrowed => return PolicyFormattingOutput::Borrowed,
            }
        }
        PolicyFormattingOutput::Value(result)
    }
}

impl<T> PolicyApplicableRef for BTreeSet<T>
where
    T: PolicyApplicableRef,
    T::Output: Ord,
{
    type Output = BTreeSet<T::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.iter()
            .map(|v| v.apply_policy_ref::<P, M>(mapper))
            .collect()
    }
}

impl<T> PolicyApplicableRefForGeneratedFormatting for BTreeSet<T>
where
    T: PolicyApplicableRefForGeneratedFormatting,
    T::FormattingOutput: Ord,
{
    type FormattingOutput = BTreeSet<T::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        collect_policy_formatting(
            self.iter()
                .map(|value| apply_child_policy_ref_for_formatting::<P, _, M>(value, mapper)),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
        rc::Rc,
        sync::Arc,
    };

    use super::{PolicyApplicableRef, RecursivePolicyKind, apply_policy, apply_policy_ref, redact};
    use crate::{
        __private::{
            PolicyApplicableRefForGeneratedFormatting, PolicyFormattingOutput, PolicyMapper,
        },
        RedactableMapper, RedactionPolicy, Secret, Sensitive,
    };

    #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
    struct SimulatedBorrowConflict {
        _non_zst: u8,
    }

    const SIMULATED_BORROW_CONFLICT: SimulatedBorrowConflict =
        SimulatedBorrowConflict { _non_zst: 0 };

    impl PolicyApplicableRef for SimulatedBorrowConflict {
        type Output = &'static str;

        fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
        where
            P: RedactionPolicy,
            P::Kind: RecursivePolicyKind,
            M: RedactableMapper,
        {
            "[REDACTED]"
        }
    }

    impl PolicyApplicableRefForGeneratedFormatting for SimulatedBorrowConflict {
        type FormattingOutput = &'static str;

        fn apply_policy_ref_for_generated_formatting<P, M>(
            &self,
            _mapper: &M,
        ) -> PolicyFormattingOutput<Self::FormattingOutput>
        where
            P: RedactionPolicy,
            P::Kind: RecursivePolicyKind,
            M: RedactableMapper,
        {
            PolicyFormattingOutput::Borrowed
        }
    }

    fn assert_formatting_conflict_propagates<T>(value: &T)
    where
        T: PolicyApplicableRefForGeneratedFormatting,
    {
        assert!(matches!(
            value.apply_policy_ref_for_generated_formatting::<Secret, _>(&PolicyMapper),
            PolicyFormattingOutput::Borrowed
        ));
    }

    #[test]
    fn all_builtin_recursive_routes_propagate_formatting_conflicts() {
        assert_formatting_conflict_propagates(&Some(SIMULATED_BORROW_CONFLICT));
        assert_formatting_conflict_propagates(&vec![SIMULATED_BORROW_CONFLICT]);
        assert_formatting_conflict_propagates(&VecDeque::from([SIMULATED_BORROW_CONFLICT]));
        assert_formatting_conflict_propagates(&[SIMULATED_BORROW_CONFLICT]);
        assert_formatting_conflict_propagates(&Box::new(SIMULATED_BORROW_CONFLICT));
        assert_formatting_conflict_propagates(&Arc::new(SIMULATED_BORROW_CONFLICT));
        assert_formatting_conflict_propagates(&Rc::new(SIMULATED_BORROW_CONFLICT));
        assert_formatting_conflict_propagates(&RefCell::new(SIMULATED_BORROW_CONFLICT));
        assert_formatting_conflict_propagates(&Cell::new(SIMULATED_BORROW_CONFLICT));
        assert_formatting_conflict_propagates(&Result::<_, SimulatedBorrowConflict>::Ok(
            SIMULATED_BORROW_CONFLICT,
        ));
        assert_formatting_conflict_propagates(&Result::<SimulatedBorrowConflict, _>::Err(
            SIMULATED_BORROW_CONFLICT,
        ));
        assert_formatting_conflict_propagates(&HashMap::from([("key", SIMULATED_BORROW_CONFLICT)]));
        assert_formatting_conflict_propagates(&BTreeMap::from([(
            "key",
            SIMULATED_BORROW_CONFLICT,
        )]));
        assert_formatting_conflict_propagates(&HashSet::from([SIMULATED_BORROW_CONFLICT]));
        assert_formatting_conflict_propagates(&BTreeSet::from([SIMULATED_BORROW_CONFLICT]));
    }

    #[test]
    fn redact_applies_policy() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct DefaultValue {
            #[sensitive(Secret)]
            value: String,
        }

        let value = DefaultValue {
            value: "top_secret".to_string(),
        };
        let redacted = redact(value);
        assert_eq!(redacted.value, "[REDACTED]");
    }

    #[test]
    fn apply_policy_to_string() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Simple {
            #[sensitive(Secret)]
            value: String,
        }

        let s = Simple {
            value: "secret".into(),
        };
        let redacted = redact(s);
        assert_eq!(redacted.value, "[REDACTED]");
    }

    #[test]
    fn apply_policy_to_option_string() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct WithOption {
            #[sensitive(Secret)]
            value: Option<String>,
        }

        let s = WithOption {
            value: Some("secret".into()),
        };
        let redacted = redact(s);
        assert_eq!(redacted.value, Some("[REDACTED]".into()));
    }

    #[test]
    fn apply_policy_to_vec_string() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct WithVec {
            #[sensitive(Secret)]
            values: Vec<String>,
        }

        let s = WithVec {
            values: vec!["secret1".into(), "secret2".into()],
        };
        let redacted = redact(s);
        assert_eq!(redacted.values, vec!["[REDACTED]", "[REDACTED]"]);
    }

    #[test]
    fn apply_policy_to_arc_string() {
        let value = Arc::new("secret".to_string());
        let redacted = apply_policy::<Secret, _>(value);
        assert_eq!(&*redacted, "[REDACTED]");
    }

    #[test]
    fn apply_policy_to_nested_option_vec() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Nested {
            #[sensitive(Secret)]
            values: Option<Vec<String>>,
        }

        let s = Nested {
            values: Some(vec!["secret1".into(), "secret2".into()]),
        };
        let redacted = redact(s);
        assert_eq!(
            redacted.values,
            Some(vec!["[REDACTED]".into(), "[REDACTED]".into()])
        );
    }

    #[test]
    fn apply_policy_to_nested_vec_option() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct Nested {
            #[sensitive(Secret)]
            values: Vec<Option<String>>,
        }

        let s = Nested {
            values: vec![Some("secret1".into()), None, Some("secret2".into())],
        };
        let redacted = redact(s);
        assert_eq!(
            redacted.values,
            vec![Some("[REDACTED]".into()), None, Some("[REDACTED]".into())]
        );
    }

    #[test]
    fn apply_policy_to_deeply_nested() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct DeepNest {
            #[sensitive(Secret)]
            values: Option<Vec<Option<String>>>,
        }

        let s = DeepNest {
            values: Some(vec![Some("secret".into()), None]),
        };
        let redacted = redact(s);
        assert_eq!(redacted.values, Some(vec![Some("[REDACTED]".into()), None]));
    }

    #[test]
    fn apply_policy_to_hashmap_values() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct WithMap {
            #[sensitive(Secret)]
            data: HashMap<String, String>,
        }

        let mut data = HashMap::new();
        data.insert("key1".into(), "secret1".into());
        data.insert("key2".into(), "secret2".into());

        let s = WithMap { data };
        let redacted = redact(s);

        // Keys preserved, values redacted
        assert!(redacted.data.contains_key("key1"));
        assert!(redacted.data.contains_key("key2"));
        assert_eq!(redacted.data.get("key1"), Some(&"[REDACTED]".to_string()));
        assert_eq!(redacted.data.get("key2"), Some(&"[REDACTED]".to_string()));
    }

    #[test]
    fn apply_policy_to_nested_map_vec() {
        #[derive(Clone, Sensitive)]
        #[cfg_attr(feature = "slog", derive(serde::Serialize))]
        struct ComplexNest {
            #[sensitive(Secret)]
            data: HashMap<String, Vec<String>>,
        }

        let mut data = HashMap::new();
        data.insert("secrets".into(), vec!["secret1".into(), "secret2".into()]);

        let s = ComplexNest { data };
        let redacted = redact(s);

        assert_eq!(
            redacted.data.get("secrets"),
            Some(&vec!["[REDACTED]".to_string(), "[REDACTED]".to_string()])
        );
    }

    #[test]
    fn apply_policy_ref_to_str() {
        let value = "secret";
        let redacted = apply_policy_ref::<Secret, _>(&value);
        assert_eq!(redacted, "[REDACTED]");
    }

    #[test]
    fn apply_policy_ref_to_option_str() {
        let value: Option<&str> = Some("secret");
        let redacted = apply_policy_ref::<Secret, _>(&value);
        assert_eq!(redacted, Some("[REDACTED]".to_string()));
    }
}
