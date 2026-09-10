//! Core traits for identifying and redacting sensitive data.
//!
//! This module defines the fundamental traits:
//!
//! - [`SensitiveWithPolicy`]: Policy-aware leaf redaction
//! - [`RedactableWithMapper`]: Types that participate in redaction traversal
//! - [`Redactable`]: User-facing `.redact()` method

use std::{
    borrow::Cow,
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    hash::{BuildHasher, Hash},
    marker::PhantomData,
    rc::Rc,
    sync::{Arc, Mutex, RwLock},
};

use super::redact::RedactableMapper;
use crate::policy::{RedactionPolicy, TextRedactionPolicy};

// =============================================================================
// SensitiveWithPolicy - Policy-aware leaf redaction
// =============================================================================

/// A type that can be redacted using a specific policy.
///
/// Implement this for your types when you need them to work with
/// [`crate::SensitiveValue<T, P>`]. This trait alone does not make a bare
/// `#[sensitive(P)]` field work; direct annotated fields use the separate
/// policy-application traits. The orphan rule is satisfied when the policy
/// `P` is local to your crate.
///
/// `String` and `Cow<str>` have built-in implementations for all policies.
/// For your own types, implement this trait for the specific policy you need:
///
/// ```ignore
/// impl SensitiveWithPolicy<MyPolicy> for MyType {
///     fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self { ... }
///     fn redacted_string(&self, policy: &TextRedactionPolicy) -> String { ... }
/// }
///
/// let protected = SensitiveValue::<MyType, MyPolicy>::from(MyType::new());
/// ```
pub trait SensitiveWithPolicy<P>: Sized {
    /// Returns a redacted version of `self` using the provided policy.
    #[must_use]
    fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self;

    /// Returns a redacted string representation using the provided policy.
    #[must_use]
    fn redacted_string(&self, policy: &TextRedactionPolicy) -> String;
}

impl<P: RedactionPolicy> SensitiveWithPolicy<P> for String {
    fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self {
        policy.apply_to(self.as_str())
    }

    fn redacted_string(&self, policy: &TextRedactionPolicy) -> String {
        policy.apply_to(self.as_str())
    }
}

impl<P: RedactionPolicy> SensitiveWithPolicy<P> for Cow<'_, str> {
    fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self {
        Cow::Owned(policy.apply_to(self.as_ref()))
    }

    fn redacted_string(&self, policy: &TextRedactionPolicy) -> String {
        policy.apply_to(self.as_ref())
    }
}

// =============================================================================
// RedactableWithMapper - Types that CONTAIN sensitive data (containers)
// =============================================================================

/// A type that participates in redaction traversal.
///
/// This trait is implemented by types that derive `Sensitive`, `SensitiveDual`, or a non-sensitive derive,
/// as well as by standard library types (scalars, strings, collections) via
/// built-in implementations. It walks the type's fields and applies redaction
/// to fields marked with `#[sensitive(Policy)]`. The mapper alone is not a
/// declaration that a raw leaf is safe at a logging boundary.
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not implement `RedactableWithMapper`",
    label = "this type cannot be walked for sensitive data",
    note = "use `#[derive(Sensitive)]` on the type definition",
    note = "or use `#[sensitive(Policy)]` if this is a leaf value like String"
)]
#[doc(hidden)]
pub trait RedactableWithMapper: Sized {
    /// Applies redaction to this value using the provided mapper.
    #[must_use]
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self;
}

// =============================================================================
// Redactable - User-facing .redact() method
// =============================================================================

/// Public entrypoint for redaction on types with declared redaction behavior.
///
/// `Redactable` is implemented by the `Sensitive`, `SensitiveDual`, `NotSensitive`, and
/// `NotSensitiveDisplay` derives, by `SensitiveValue` / `BypassRedaction`,
/// by `serde_json::Value`, and by std containers of such types. It provides the
/// `redact()` method and is the structural half every generated `ToRedacted`
/// producer builds on.
///
/// Passthrough leaves like `String` and scalars deliberately do **not**
/// implement it: they provide low-level mapper behavior, but default fields
/// inside sensitive-derived containers also need this declaration. Nobody
/// declared what redacting bare leaves means,
/// so calling `redact()` on them - or certifying them as redacted output -
/// must not compile.
///
/// Containers preserve that boundary: forwarding applies only when their
/// contents are also certified.
///
/// ```compile_fail
/// use redactable::Redactable;
///
/// fn require_redactable<T: Redactable>(_: T) {}
///
/// require_redactable(std::collections::VecDeque::from([String::from("raw")]));
/// require_redactable([String::from("raw")]);
/// require_redactable((String::from("raw"),));
/// require_redactable(std::sync::Mutex::new(String::from("raw")));
/// require_redactable(std::sync::RwLock::new(String::from("raw")));
/// ```
///
/// `redact` is implemented in terms of the default mapping behavior provided by
/// [`super::redact::redact`], which applies policies associated with policy
/// marker types.
#[diagnostic::on_unimplemented(
    message = "`{Self}` has no declared redaction behavior",
    label = "this value needs a redaction declaration",
    note = "for a local container, derive `Sensitive` and select field policies or explicit `#[not_sensitive]` declarations",
    note = "for a raw value, use `SensitiveValue<T, P>` or deliberately declare it public with `BypassRedaction<T>`"
)]
pub trait Redactable: RedactableWithMapper {
    /// Redacts the value using policy-bound redaction.
    ///
    /// This consumes `self` and returns a redacted copy.
    #[must_use]
    fn redact(self) -> Self {
        super::redact::redact(self)
    }
}

// Containers forward the certification exactly like redaction traversal walks
// them. Map keys are exempt, mirroring values-only map redaction. The bounds
// mirror the matching `RedactableWithMapper` container impls so the supertrait
// is always satisfied.

impl<T: Redactable> Redactable for Option<T> {}

// PhantomData carries no value to inspect or transform.
impl<T> Redactable for PhantomData<T> {}

impl<T: Redactable, E: Redactable> Redactable for Result<T, E> {}

impl<T: Redactable> Redactable for Vec<T> {}

impl<T: Redactable> Redactable for VecDeque<T> {}

impl<T: Redactable, const N: usize> Redactable for [T; N] {}

impl<T: Redactable> Redactable for Box<T> {}

impl<T: Redactable + Clone> Redactable for Arc<T> {}

impl<T: Redactable + Clone> Redactable for Rc<T> {}

impl<T: Redactable> Redactable for RefCell<T> {}

impl<T: Redactable + Copy> Redactable for Cell<T> {}

impl<T: Redactable> Redactable for Mutex<T> {}

impl<T: Redactable> Redactable for RwLock<T> {}

impl<K, V, S> Redactable for HashMap<K, V, S>
where
    K: Hash + Eq,
    V: Redactable,
    S: BuildHasher + Clone,
{
}

impl<K: Ord, V: Redactable> Redactable for BTreeMap<K, V> {}

impl<T, S> Redactable for HashSet<T, S>
where
    T: Redactable + Hash + Eq,
    S: BuildHasher + Clone,
{
}

impl<T: Redactable + Ord> Redactable for BTreeSet<T> {}

macro_rules! impl_tuple_redactable {
    ($($name:ident),+ $(,)?) => {
        impl<$($name),+> Redactable for ($($name,)+)
        where
            $($name: Redactable,)+
        {
        }
    };
}

impl_tuple_redactable!(T0);
impl_tuple_redactable!(T0, T1);
impl_tuple_redactable!(T0, T1, T2);
impl_tuple_redactable!(T0, T1, T2, T3);

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::SensitiveWithPolicy;
    use crate::policy::{Secret, TextRedactionPolicy};

    #[test]
    fn string_redact_with_policy() {
        let original = String::from("my_secret");
        let policy = TextRedactionPolicy::default_full();
        let redacted: String =
            <String as SensitiveWithPolicy<Secret>>::redact_with_policy(original, &policy);
        assert_eq!(redacted, "[REDACTED]");
    }

    #[test]
    fn string_redacted_string() {
        let original = String::from("my_secret");
        let policy = TextRedactionPolicy::default_full();
        let result = <String as SensitiveWithPolicy<Secret>>::redacted_string(&original, &policy);
        assert_eq!(result, "[REDACTED]");
    }

    #[test]
    fn cow_redact_with_policy() {
        let original: Cow<'static, str> = Cow::Borrowed("my_secret");
        let policy = TextRedactionPolicy::default_full();
        let redacted =
            <Cow<'_, str> as SensitiveWithPolicy<Secret>>::redact_with_policy(original, &policy);
        match redacted {
            Cow::Owned(value) => assert_eq!(value, "[REDACTED]"),
            Cow::Borrowed(_) => panic!("redacted Cow should be owned"),
        }
    }

    #[test]
    fn cow_redacted_string() {
        let original: Cow<'static, str> = Cow::Borrowed("my_secret");
        let policy = TextRedactionPolicy::default_full();
        let result =
            <Cow<'_, str> as SensitiveWithPolicy<Secret>>::redacted_string(&original, &policy);
        assert_eq!(result, "[REDACTED]");
    }
}
