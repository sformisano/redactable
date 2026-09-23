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

use std::fmt::{Debug, Formatter, Result as FmtResult};

use crate::{
    __private::{PolicyField, PolicyFieldRef},
    RedactableWithFormatter,
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
// RedactableMapper - Mapping trait
// =============================================================================

/// Maps sensitive and non-sensitive values during traversal.
///
/// Custom [`PolicyFormat`] implementations receive a mapper through
/// [`PolicyFormat::apply_policy_for_formatting`]. Use its mapping methods when
/// projecting supported sensitive values or scalars. Implementations must
/// return the same value type for `map_sensitive`.
pub trait RedactableMapper {
    /// Maps a sensitive, string-like value.
    fn map_sensitive<V, P>(&self, value: V) -> V
    where
        V: SensitiveWithPolicy<P>,
        P: RedactionPolicy;

    /// Maps a sensitive scalar value to its default.
    ///
    /// Scalar policy fields use `#[sensitive(Secret)]`; bare `#[sensitive]` is rejected.
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

/// Defines the default redacted value for a supported scalar.
///
/// This is the scalar bound exposed by [`RedactableMapper::map_scalar`]. The
/// crate implements it for its supported primitive scalar types; custom policy
/// formatting code can use the bound without implementing new scalar behavior.
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
/// This low-level function requires only mapper support. Bare strings and
/// scalars can pass through unchanged; use [`crate::Redactable`] declarations
/// and the selected-output traits for a logging boundary. Traversal and custom
/// policies can panic, including clone failures behind shared ownership.
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
/// This helper borrows its input and returns the policy field's normal reference
/// output. Individual projections can clone, including map keys and hashers.
/// It does not use the formatting-only borrow-conflict channel that generated
/// `SensitiveDisplay` implementations take through
/// [`PolicyFormat`] for recursive text and secret policies.
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
/// This mirrors [`PolicyApplicable`] through a borrowed input. Individual
/// implementations can clone parts of that input, including map keys and hashers.
/// The [`apply_policy_ref`] function uses this projection. For template
/// formatting, implement [`PolicyFormat`] instead.
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

// =============================================================================
// PolicyFormat - Borrowed policy application for templates
// =============================================================================

/// Result of applying a policy by reference for template formatting.
///
/// Generated templates render a mutably borrowed [`RefCell`](std::cell::RefCell)
/// as `<borrowed>`. Containers propagate [`Borrowed`](Self::Borrowed) so a nested
/// conflict reaches the template. This enum carries formatting conflicts
/// separately from [`PolicyApplicableRef::Output`], which keeps its ordinary
/// redacted output type.
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
    fn fmt_redacted(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Value(value) => value.fmt_redacted(f),
            Self::Borrowed => f.write_str("<borrowed>"),
        }
    }
}

impl<T: Debug> Debug for PolicyFormattingOutput<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Value(value) => Debug::fmt(value, f),
            Self::Borrowed => f.write_str("<borrowed>"),
        }
    }
}

/// A type that can have a redaction policy applied by reference for template formatting.
///
/// Implement this trait for a custom leaf used as a `#[sensitive(Policy)]`
/// field in a `SensitiveDisplay` or `SensitiveDual` template.
///
/// `String`,
/// `Cow<str>`, `&str`, `serde_json::Value`, [`SensitiveValue`](crate::SensitiveValue)
/// and the supported standard containers implement it. Containers forward to
/// their contents and propagate a nested `RefCell` borrow conflict as
/// [`PolicyFormattingOutput::Borrowed`].
///
/// # Implementor obligations
///
/// Apply the selected policy before returning [`PolicyFormattingOutput::Value`].
/// The output must contain already-redacted data for every supported formatting
/// mode: [`RedactableWithFormatter`] handles `{}` and [`Debug`] handles `{:?}`,
/// including alternate Debug. Formatting must never fall back to the raw source.
///
/// Custom containers must propagate a child's [`PolicyFormattingOutput::Borrowed`]
/// instead of unwrapping it or substituting raw data. [`PolicyFormattingOutput::map`]
/// preserves that state while wrapping a successful projection. If a custom
/// implementation reads a `RefCell`, use a fallible borrow and return `Borrowed`
/// on conflict. Both placeholder modes then render `<borrowed>`.
///
/// Custom implementations and policies remain responsible for their own redaction
/// correctness and panic behavior. This trait does not catch their panics or
/// validate their output.
///
/// # Migrating custom formatting
///
/// Move previous `fmt_policy_display` and `fmt_policy_debug` overrides into an
/// owned output newtype implementing [`RedactableWithFormatter`] and [`Debug`].
/// Apply `P` before constructing it, and store only the redacted projection.
/// This example preserves distinct display and Debug forms:
///
/// ```
/// # #![allow(hidden_glob_reexports)]
/// # pub use redactable::*;
/// use std::fmt::{Debug, Formatter, Result as FmtResult};
///
/// use redactable::{
///     PolicyFormat, PolicyFormattingOutput, RedactableMapper,
///     RedactableWithFormatter, RedactionPolicy, Secret, SensitiveDisplay,
///     policy::RecursivePolicyKind,
/// };
///
/// struct AccountNumber(String);
/// struct RedactedAccount(String);
///
/// impl RedactableWithFormatter for RedactedAccount {
///     fn fmt_redacted(&self, f: &mut Formatter<'_>) -> FmtResult {
///         write!(f, "account({})", self.0)
///     }
/// }
///
/// impl Debug for RedactedAccount {
///     fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
///         f.debug_tuple("RedactedAccount").field(&self.0).finish()
///     }
/// }
///
/// impl PolicyFormat for AccountNumber {
///     type Output = RedactedAccount;
///
///     fn apply_policy_for_formatting<P, M>(
///         &self,
///         _mapper: &M,
///     ) -> PolicyFormattingOutput<RedactedAccount>
///     where
///         P: RedactionPolicy,
///         P::Kind: RecursivePolicyKind,
///         M: RedactableMapper,
///     {
///         PolicyFormattingOutput::Value(RedactedAccount(P::policy().apply_to(&self.0)))
///     }
/// }
///
/// #[derive(SensitiveDisplay)]
/// #[error("{number} | {number:?}")]
/// struct Transfer {
///     #[sensitive(Secret)]
///     number: Option<AccountNumber>,
/// }
///
/// # fn main() {
/// let transfer = Transfer { number: Some(AccountNumber("12345678".into())) };
/// let rendered = transfer.redacted_display().to_string();
/// assert_eq!(rendered, "Some(account([REDACTED])) | Some(RedactedAccount(\"[REDACTED]\"))");
/// assert!(!rendered.contains("12345678"));
/// # }
/// ```
///
/// Implement [`PolicyApplicableRef`] as well only when the leaf must also support the
/// [`apply_policy_ref`] function.
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be formatted by reference under a redaction policy",
    label = "this policy field has no borrowed formatting support",
    note = "text policies format `String`, `Cow<str>`, `&str`, `serde_json::Value`, `SensitiveValue<T, P>`, and supported containers of these",
    note = "for a generic field, declare `T: PolicyDisplay<P>` for `{{}}` or `T: PolicyDebug<P>` for `{{:?}}`",
    note = "for a custom leaf type, implement `redactable::PolicyFormat`"
)]
pub trait PolicyFormat {
    /// Already-redacted output rendered by the template placeholder.
    type Output;

    /// Applies a redaction policy through the type structure by reference.
    ///
    /// Return already-redacted data and propagate a child's `Borrowed` state.
    fn apply_policy_for_formatting<P, M>(&self, mapper: &M) -> PolicyFormattingOutput<Self::Output>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper;
}

pub(super) fn apply_child_policy_ref_for_formatting<P, T, M>(
    value: &T,
    mapper: &M,
) -> PolicyFormattingOutput<<T as PolicyFormat>::Output>
where
    P: RedactionPolicy,
    P::Kind: RecursivePolicyKind,
    T: PolicyFormat,
    M: RedactableMapper,
{
    value.apply_policy_for_formatting::<P, M>(mapper)
}
