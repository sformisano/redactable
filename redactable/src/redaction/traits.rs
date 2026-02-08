//! Core traits for identifying and redacting sensitive data.
//!
//! This module defines the fundamental traits:
//!
//! - [`SensitiveWithPolicy`]: Policy-aware leaf redaction
//! - [`RedactableWithMapper`]: Types that participate in redaction traversal
//! - [`Redactable`]: User-facing `.redact()` method

use std::borrow::Cow;

use super::redact::RedactableMapper;
use crate::policy::{RedactionPolicy, TextRedactionPolicy};

// =============================================================================
// SensitiveWithPolicy - Policy-aware leaf redaction
// =============================================================================

/// A type that can be redacted using a specific policy.
///
/// Implement this for your types when you need them to work with
/// `SensitiveValue<T, P>` or `#[sensitive(Policy)]`. The orphan rule is
/// satisfied because the policy `P` is local to your crate.
///
/// `String` and `Cow<str>` have built-in implementations for all policies.
/// For your own types, implement this trait for the specific policy you need:
///
/// ```ignore
/// impl SensitiveWithPolicy<MyPolicy> for MyType {
///     fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self { ... }
///     fn redacted_string(&self, policy: &TextRedactionPolicy) -> String { ... }
/// }
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
/// This trait is implemented by types that derive `Sensitive` or `NotSensitive`,
/// as well as by standard library types (scalars, strings, collections) via
/// blanket implementations. It walks the type's fields and applies redaction
/// to any fields marked with `#[sensitive]` or `#[sensitive(Policy)]`.
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

/// Public entrypoint for redaction on traversable types.
///
/// This trait is blanket-implemented for all [`RedactableWithMapper`] types and
/// provides a convenience `redact()` method.
///
/// `redact` is implemented in terms of the default mapping behavior provided by
/// [`super::redact::redact`], which applies policies associated with policy markers
/// types.
pub trait Redactable: RedactableWithMapper {
    /// Redacts the value using policy-bound redaction.
    ///
    /// This consumes `self` and returns a redacted copy.
    #[must_use]
    fn redact(self) -> Self {
        super::redact::redact(self)
    }
}

impl<T> Redactable for T where T: RedactableWithMapper {}

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
