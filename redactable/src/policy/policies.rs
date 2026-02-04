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
//! use redactable::{RedactionPolicy, TextRedactionPolicy};
//!
//! #[derive(Clone, Copy)]
//! struct MyCustomPolicy;
//!
//! impl RedactionPolicy for MyCustomPolicy {
//!     fn policy() -> TextRedactionPolicy {
//!         TextRedactionPolicy::keep_last(2)
//!     }
//! }
//! ```

use super::text::TextRedactionPolicy;

// =============================================================================
// RedactionPolicy trait
// =============================================================================

/// Associates a policy marker type with a concrete string redaction policy.
///
/// The policy is defined per marker type and is independent of runtime context.
pub trait RedactionPolicy {
    /// Returns the policy for this marker type.
    fn policy() -> TextRedactionPolicy;
}

// =============================================================================
// Marker types and their policy implementations
// =============================================================================

/// Default policy: full redaction for strings, default value for scalars.
///
/// - Strings redact to `"[REDACTED]"`
/// - Integers and floats redact to `0`
/// - Booleans redact to `false`
/// - Characters redact to `'*'`
#[derive(Clone, Copy)]
pub struct Default;

impl RedactionPolicy for Default {
    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::default_full()
    }
}

/// Policy marker for blockchain addresses (e.g., Ethereum, Bitcoin).
///
/// Keeps the last 6 characters visible (e.g., `"0x1234...abcd"` → `"******...abcd"`).
#[derive(Clone, Copy)]
pub struct BlockchainAddress;

impl RedactionPolicy for BlockchainAddress {
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
    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::email_local(2)
    }
}

/// Policy marker for IP addresses.
///
/// Keeps the last 4 characters visible (e.g., `"192.168.1.100"` → `"*********1.100"`).
#[derive(Clone, Copy)]
pub struct IpAddress;

impl RedactionPolicy for IpAddress {
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
    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(4)
    }
}

/// Policy marker for personally identifiable information.
///
/// Keeps the last 2 characters visible to protect short names
/// (e.g., `"John Doe"` → `"******oe"`).
#[derive(Clone, Copy)]
pub struct Pii;

impl RedactionPolicy for Pii {
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
