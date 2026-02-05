//! Core traits for identifying and redacting sensitive data.
//!
//! This module defines the fundamental traits:
//!
//! - [`RedactableLeaf`]: Types that *are* sensitive data (String, Cow<str>)
//! - [`RedactableWithPolicy`]: Policy-aware leaf redaction
//! - [`RedactableContainer`]: Types that *contain* sensitive data (structs, enums)
//! - [`Redactable`]: User-facing `.redact()` method

use std::borrow::Cow;

use super::redact::RedactableMapper;
use crate::policy::{RedactionPolicy, TextRedactionPolicy};

// =============================================================================
// RedactableLeaf - Types that ARE sensitive data (leaf values)
// =============================================================================

/// String-like payloads that can be redacted via policies.
///
/// The redaction engine treats these values as strings for the purpose of policy
/// application. Scalar values (numbers, booleans, chars) are not `RedactableLeaf`
/// and instead redact to their defaults via `#[sensitive]` and `map_scalar`.
///
/// ## Relationship with `RedactableContainer`
///
/// - `RedactableLeaf`: A type that *is* sensitive data (String, custom newtypes)
/// - `RedactableContainer`: A type that *contains* sensitive data (structs, enums)
///
/// Use `#[sensitive(Policy)]` on fields of `RedactableLeaf` types.
/// Nested `RedactableContainer` fields are walked by default.
///
/// ## Foreign string-like types
///
/// If the sensitive field type comes from another crate, you cannot implement
/// `RedactableLeaf` for it directly (Rust's orphan rules). The recommended
/// pattern is to define a local newtype in your project and implement
/// `RedactableLeaf` for that wrapper.
///
/// `from_redacted` is not required to preserve the original representation; it
/// only needs to construct a value that corresponds to the redacted string
/// returned by the applied policy.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a `RedactableLeaf`",
    label = "this type cannot have a policy applied directly",
    note = "policies like `#[sensitive(Secret)]` are for leaf values (String, etc.)",
    note = "if `{Self}` is a struct that derives `Sensitive`, remove the policy and let traversal walk into it"
)]
pub trait RedactableLeaf: Sized {
    /// Returns a read-only view of the sensitive value.
    fn as_str(&self) -> &str;
    /// Reconstructs the value from a redacted string.
    #[must_use]
    fn from_redacted(redacted: String) -> Self;
}

impl RedactableLeaf for String {
    fn as_str(&self) -> &str {
        self.as_str()
    }

    fn from_redacted(redacted: String) -> Self {
        redacted
    }
}

impl RedactableLeaf for Cow<'_, str> {
    fn as_str(&self) -> &str {
        self.as_ref()
    }

    fn from_redacted(redacted: String) -> Self {
        Cow::Owned(redacted)
    }
}

// =============================================================================
// RedactableWithPolicy - Policy-aware leaf redaction
// =============================================================================

/// A policy-aware leaf that can be redacted without requiring a local newtype.
///
/// This is the external-type escape hatch: you can implement it for a foreign type
/// using a local policy `P`, even when you cannot implement `RedactableLeaf` due to
/// orphan rules.
pub trait RedactableWithPolicy<P>: Sized {
    /// Returns a redacted version of `self` using the provided policy.
    #[must_use]
    fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self;

    /// Returns a redacted string representation using the provided policy.
    #[must_use]
    fn redacted_string(&self, policy: &TextRedactionPolicy) -> String;
}

impl<T, P> RedactableWithPolicy<P> for T
where
    T: RedactableLeaf,
    P: RedactionPolicy,
{
    fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self {
        let redacted = policy.apply_to(self.as_str());
        T::from_redacted(redacted)
    }

    fn redacted_string(&self, policy: &TextRedactionPolicy) -> String {
        policy.apply_to(self.as_str())
    }
}

// =============================================================================
// RedactableContainer - Types that CONTAIN sensitive data (containers)
// =============================================================================

/// A type that contains sensitive data and can be traversed for redaction.
///
/// This trait is implemented by types that derive `Sensitive`. It walks the
/// type's fields and applies scalar redaction to any fields marked with `#[sensitive]`.
///
/// ## When to use
///
/// - Structs/enums containing sensitive fields should derive `Sensitive`
/// - Use `#[sensitive]` on scalar fields to redact to defaults
/// - Use `#[sensitive(Policy)]` on leaf values (strings, etc.)
///
/// ## Relationship with `RedactableLeaf`
///
/// - `RedactableContainer`: A type that *contains* sensitive data (structs, enums)
/// - `RedactableLeaf`: A type that *is* sensitive data (String, custom newtypes)
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not implement `RedactableContainer`",
    label = "this type cannot be walked for sensitive data",
    note = "use `#[derive(Sensitive)]` on the type definition",
    note = "or use `#[sensitive(Policy)]` if this is a leaf value like String"
)]
#[doc(hidden)]
pub trait RedactableContainer: Sized {
    /// Applies redaction to this value using the provided mapper.
    #[must_use]
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self;
}

// =============================================================================
// Redactable - User-facing .redact() method
// =============================================================================

/// Public entrypoint for redaction on traversable types.
///
/// This trait is blanket-implemented for all [`RedactableContainer`] types and
/// provides a convenience `redact()` method.
///
/// `redact` is implemented in terms of the default mapping behavior provided by
/// [`super::redact::redact`], which applies policies associated with policy markers
/// types.
pub trait Redactable: RedactableContainer {
    /// Redacts the value using policy-bound redaction.
    ///
    /// This consumes `self` and returns a redacted copy.
    #[must_use]
    fn redact(self) -> Self {
        super::redact::redact(self)
    }
}

impl<T> Redactable for T where T: RedactableContainer {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::RedactableLeaf;

    #[test]
    fn string_sensitive_value_round_trip() {
        let original = "secret".to_string();
        assert_eq!(original.as_str(), "secret");
        let redacted = String::from_redacted("[REDACTED]".to_string());
        assert_eq!(redacted, "[REDACTED]");
    }

    #[test]
    fn cow_sensitive_value_round_trip() {
        let original: Cow<'static, str> = Cow::Borrowed("secret");
        assert_eq!(original.as_str(), "secret");
        let redacted = Cow::from_redacted("[REDACTED]".to_string());
        match redacted {
            Cow::Owned(value) => assert_eq!(value, "[REDACTED]"),
            Cow::Borrowed(_) => panic!("redacted Cow should be owned"),
        }
    }
}
