//! Standard redaction policies: marker types and their implementations.
//!
//! This module provides:
//!
//! - **Marker types**: Zero-sized types like `Pii`, `Token`, `Email` that identify
//!   what kind of sensitive data a field contains.
//!
//! - **The trait**: [`RedactionPolicy`] associates marker types with their concrete
//!   redaction strategies.
//!
//! - **Built-in implementations**: Each marker type has a default `RedactionPolicy`
//!   implementation that defines how values should be redacted.
//!
//! # Custom Policies
//!
//! You can define your own policy markers:
//!
//! ```rust
//! use redactable::{RedactionPolicy, TextPolicyKind, TextRedactionPolicy};
//!
//! #[derive(Clone, Copy)]
//! struct MyCustomPolicy;
//!
//! impl RedactionPolicy for MyCustomPolicy {
//!     type Kind = TextPolicyKind;
//!
//!     fn policy() -> TextRedactionPolicy {
//!         TextRedactionPolicy::keep_last(2)
//!     }
//! }
//! ```

use super::text::TextRedactionPolicy;

// =============================================================================
// RedactionPolicy trait
// =============================================================================

mod kind_sealed {
    pub trait Sealed {}
}

mod recursive_kind_sealed {
    pub trait Sealed {}
}

/// Structural behavior selected by a [`RedactionPolicy`] implementation.
///
/// This trait is sealed. Policy authors choose one of the exported kind marker
/// types instead of defining new structural traversal behavior.
pub trait PolicyKind: kind_sealed::Sealed {}

/// Standard text-policy behavior.
///
/// This kind applies the policy recursively to supported string leaves and is
/// the correct choice for custom text policies.
#[derive(Clone, Copy, Debug)]
pub struct TextPolicyKind;

impl kind_sealed::Sealed for TextPolicyKind {}
impl PolicyKind for TextPolicyKind {}
impl recursive_kind_sealed::Sealed for TextPolicyKind {}

/// Full-secret behavior, including bare scalar redaction.
#[derive(Clone, Copy, Debug)]
pub struct SecretPolicyKind;

impl kind_sealed::Sealed for SecretPolicyKind {}
impl PolicyKind for SecretPolicyKind {}
impl recursive_kind_sealed::Sealed for SecretPolicyKind {}

/// Policy kinds permitted to use the legacy recursive traversal traits.
///
/// This internal capability is sealed and intentionally excludes
/// [`IpAddressPolicyKind`], whose fail-closed traversal is structurally distinct.
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot use the legacy recursive policy traversal",
    note = "use `apply_policy` or `apply_policy_ref` for kind-aware dispatch; inside IP containers wrap typed values in `SensitiveValue<T, IpAddress>`"
)]
#[doc(hidden)]
pub trait RecursivePolicyKind: PolicyKind + recursive_kind_sealed::Sealed {}

impl RecursivePolicyKind for TextPolicyKind {}
impl RecursivePolicyKind for SecretPolicyKind {}

/// IP-aware structural behavior.
///
/// The built-in policy accepts typed IP values only as bare annotated fields.
/// Recursive containers support text leaves and `SensitiveValue` wrappers;
/// raw typed IP leaves inside containers fail closed.
#[derive(Clone, Copy, Debug)]
pub struct IpAddressPolicyKind;

impl kind_sealed::Sealed for IpAddressPolicyKind {}
impl PolicyKind for IpAddressPolicyKind {}

/// Associates a policy marker type with a concrete string redaction policy.
///
/// The policy is defined per marker type and is independent of runtime context.
pub trait RedactionPolicy {
    /// Selects the structural field behavior for this policy.
    ///
    /// Custom string policies should use [`TextPolicyKind`].
    type Kind: PolicyKind;

    /// Returns the policy for this marker type.
    fn policy() -> TextRedactionPolicy;
}

// =============================================================================
// Marker types and their policy implementations
// =============================================================================

/// Generic secret policy: complete redaction for strings, default value for scalars.
///
/// Use this for sensitive data that doesn't fit a specific category (Token, Email, etc.).
///
/// - Strings redact to `"[REDACTED]"`
/// - Integers and floats redact to `0`
/// - Booleans redact to `false`
/// - Characters redact to `'*'`
#[derive(Clone, Copy)]
pub struct Secret;

impl RedactionPolicy for Secret {
    type Kind = SecretPolicyKind;

    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::default_full()
    }
}

/// Policy marker for blockchain addresses (e.g., Ethereum, Bitcoin).
///
/// Keeps exactly the last 6 characters visible.
///
/// ```
/// use redactable::{BlockchainAddress, RedactionPolicy};
///
/// let policy = BlockchainAddress::policy();
/// assert_eq!(policy.apply_to("0x1234567890abcdef"), "************abcdef");
/// ```
#[derive(Clone, Copy)]
pub struct BlockchainAddress;

impl RedactionPolicy for BlockchainAddress {
    type Kind = TextPolicyKind;

    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(6)
    }
}

/// Policy marker for credit card numbers or PANs.
///
/// Keeps the last 4 digits visible (e.g., `"4111111111111111"` → `"************1111"`).
#[derive(Clone, Copy)]
pub struct CreditCard;

impl RedactionPolicy for CreditCard {
    type Kind = TextPolicyKind;

    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(4)
    }
}

/// Policy marker for email addresses.
///
/// Keeps the first 2 characters of the local part and the full domain
/// (e.g., `"alice@example.com"` → `"al***@example.com"`).
#[derive(Clone, Copy)]
pub struct Email;

impl RedactionPolicy for Email {
    type Kind = TextPolicyKind;

    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::email_local(2)
    }
}

/// Policy marker for IP addresses.
///
/// Typed IPv4 values keep the last octet (e.g., `"192.168.1.100"` →
/// `"0.0.0.100"`); typed IPv6 values keep the last 16-bit segment. Text fields
/// use the policy's separate keep-last-4 masking behavior.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IpAddress;

impl RedactionPolicy for IpAddress {
    type Kind = IpAddressPolicyKind;

    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(4)
    }
}

/// Policy marker for phone numbers.
///
/// Keeps the last 4 digits visible (e.g., `"+1-555-123-4567"` → `"***********4567"`).
#[derive(Clone, Copy)]
pub struct PhoneNumber;

impl RedactionPolicy for PhoneNumber {
    type Kind = TextPolicyKind;

    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(4)
    }
}

/// Policy marker for personally identifiable information.
///
/// Keeps the last 2 characters visible (e.g., `"John Doe"` → `"******oe"`).
/// Values of 2 characters or fewer are fully masked: keep policies fail
/// closed rather than revealing values shorter than the keep window.
#[derive(Clone, Copy)]
pub struct Pii;

impl RedactionPolicy for Pii {
    type Kind = TextPolicyKind;

    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(2)
    }
}

/// Policy marker for authentication tokens and API keys.
///
/// Keeps the last 4 characters visible (e.g., `"sk_live_abc123def456"` → `"****************f456"`).
#[derive(Clone, Copy)]
pub struct Token;

impl RedactionPolicy for Token {
    type Kind = TextPolicyKind;

    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(4)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_policies_use_expected_defaults() {
        let policy = Token::policy();
        // Token keeps last 4
        assert_eq!(policy.apply_to("sk_live_abc123"), "**********c123");

        let policy = BlockchainAddress::policy();
        assert_eq!(policy.apply_to("0x1234567890abcdef"), "************abcdef");

        let policy = CreditCard::policy();
        assert_eq!(policy.apply_to("4111111111111111"), "************1111");
        assert_eq!(policy.apply_to("1234"), "****");

        let policy = Email::policy();
        assert_eq!(policy.apply_to("alice@example.com"), "al***@example.com");

        let policy = PhoneNumber::policy();
        // PhoneNumber keeps last 4
        assert_eq!(policy.apply_to("+1-555-123-4567"), "***********4567");

        let policy = Pii::policy();
        // Pii keeps last 2
        assert_eq!(policy.apply_to("John Doe"), "******oe");
    }
}
