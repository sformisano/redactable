//! Redaction policies: marker types and text transformations.
//!
//! This module provides:
//!
//! - **Policies** (`policies`): Zero-sized marker types like `Pii`, `Token`, `Email`
//!   that identify what kind of sensitive data a field contains, along with the
//!   [`RedactionPolicy`] trait and built-in implementations.
//!
//! - **Text policies** (`text`): The [`TextRedactionPolicy`] enum and its configuration
//!   types (`KeepConfig`, `MaskConfig`, `EmailConfig`) for transforming strings.
//!
//! # Example
//!
//! ```rust
//! use redactable::{RedactionPolicy, TextRedactionPolicy, Token};
//!
//! // Built-in policies have default implementations
//! let policy = Token::policy();
//! assert_eq!(policy.apply_to("sk_live_abc123def456"), "****************f456");
//!
//! // Or create custom policies directly
//! let custom = TextRedactionPolicy::keep_last(4).with_mask_char('#');
//! assert_eq!(custom.apply_to("sensitive-data"), "##########data");
//! ```

pub mod policies;
pub mod text;

// Re-export everything at the module level for convenience
pub use policies::{
    BlockchainAddress, CreditCard, Email, IpAddress, PhoneNumber, Pii, RedactionPolicy, Secret,
    Token,
};
pub use text::{
    EmailConfig, KeepConfig, MASK_CHAR, MaskConfig, REDACTED_PLACEHOLDER, TextRedactionPolicy,
};
