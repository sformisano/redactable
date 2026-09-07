//! Type-directed redaction for structured data.
//!
//! This crate separates:
//! - **Policy markers**: what kind of sensitive data this is (e.g., `Pii`, `Token`, `Email`).
//! - **Redaction policies**: how that data should be redacted.
//!
//! `Redactable::redact()` transforms a declared structural input. The free
//! `redact()` function uses lower-level mapper support and can leave raw leaves
//! unchanged. Use `ToRedactedOutput` for a selected logging boundary.
//!
//! What this crate does:
//! - defines policy marker types (e.g., `Pii`, `Token`, `Email`)
//! - defines redaction policies and structural traversal operations
//! - provides integrations behind feature flags (e.g. `slog`)
//!
//! What it does not do:
//! - perform I/O or logging
//! - validate your policy choices
//!
//! Explicitly non-sensitive output remains an exceptional opt-in. Use
//! `NotSensitiveDebug` or `NotSensitiveDisplay` only when the complete formatted
//! value is safe to log. With the `json` feature, those wrappers serialize the
//! raw inner value for transport or storage; Serde output is not redaction.
//! Use `SensitiveValue` for a leaf policy. Structured output can use `Sensitive`
//! or `SensitiveDual` with `#[redactable(output = json)]`, or `.redacted_json()`.
//! Both JSON routes require `json`, `Clone`, and `Serialize`. Custom
//! `ToRedactedOutput` implementations can select a different projection or summary.
//! The output APIs require `redaction`; JSON bridges additionally require `json`.
//!
//! The `Sensitive` derive macro lives in `redactable-derive` and is re-exported
//! from this crate.

// <https://doc.rust-lang.org/rustc/lints/listing/allowed-by-default.html>
#![warn(
    anonymous_parameters,
    bare_trait_objects,
    elided_lifetimes_in_paths,
    missing_copy_implementations,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unreachable_pub,
    unsafe_code,
    unused_extern_crates,
    unused_import_braces
)]
// <https://rust-lang.github.io/rust-clippy/stable>
#![warn(
    clippy::all,
    clippy::cargo,
    clippy::dbg_macro,
    clippy::float_cmp_const,
    clippy::get_unwrap,
    clippy::mem_forget,
    clippy::nursery,
    clippy::pedantic,
    clippy::todo,
    clippy::unwrap_used,
    clippy::uninlined_format_args
)]
// Allow some clippy lints
#![allow(
    clippy::cargo_common_metadata,
    clippy::missing_const_for_fn,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::use_self
)]
// Allow some lints while testing
#![cfg_attr(test, allow(clippy::non_ascii_literal, clippy::unwrap_used))]

pub use redactable_derive::{
    NotSensitive, NotSensitiveDisplay, Sensitive, SensitiveDisplay, SensitiveDual,
};

#[allow(unused_extern_crates)]
extern crate self as redactable;

// Module declarations
#[doc(hidden)]
#[cfg(feature = "redaction")]
pub mod __private;
#[cfg(feature = "policy")]
pub mod policy;
#[cfg(feature = "redaction")]
mod redaction;
#[cfg(feature = "slog")]
pub mod slog;
#[cfg(all(feature = "testing", feature = "json"))]
pub mod testing;
#[cfg(feature = "tracing")]
pub mod tracing;

// Re-exports from policy module
#[cfg(feature = "policy")]
pub use policy::{
    BlockchainAddress, CreditCard, Email, EmailConfig, IpAddress, IpAddressPolicyKind, KeepConfig,
    MASK_CHAR, MaskConfig, PhoneNumber, Pii, PolicyKind, REDACTED_PLACEHOLDER, RedactionPolicy,
    Secret, SecretPolicyKind, TextPolicyKind, TextRedactionPolicy, Token,
};
// Re-exports from redaction module: public API
#[cfg(feature = "json")]
pub use redaction::{
    IntoRedactedJsonExt, NotSensitiveJson, NotSensitiveJsonExt, RedactedJson, RedactedJsonExt,
    RedactedJsonRef, RedactedList,
};
#[cfg(feature = "redaction")]
pub use redaction::{
    IntoRedactedOutputExt, NotSensitive, NotSensitiveDebug, NotSensitiveDebugExt,
    NotSensitiveDisplay, NotSensitiveDisplayExt, NotSensitiveExt, NotSensitiveValue, Redactable,
    RedactableWithFormatter, RedactedFormatterRef, RedactedOutput, RedactedOutputExt,
    RedactedOutputRef, RedactedOutputView, SensitiveValue, SensitiveWithPolicy, ToRedactedOutput,
    UncheckedRedactedSummary,
};
// Re-exports from redaction module: internal machinery (used by derive-generated code)
#[doc(hidden)]
#[cfg(feature = "redaction")]
pub use redaction::PolicyRedactedFormatterRef;
#[doc(hidden)]
#[cfg(feature = "redaction")]
pub use redaction::{
    PolicyApplicable, PolicyApplicableRef, RedactableMapper, RedactableWithMapper, ScalarRedaction,
    apply_policy, apply_policy_ref, redact,
};
#[cfg(feature = "slog")]
pub use slog::{RedactedDisplayValue, SlogRedactedDisplayExt, SlogRedactedExt};
