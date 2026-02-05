//! Type-directed redaction for structured data.
//!
//! This crate separates:
//! - **Policy markers**: what kind of sensitive data this is (e.g., `Pii`, `Token`, `Email`).
//! - **Redaction policies**: how that data should be redacted.
//!
//! The derive macro walks your data and applies the policy at the boundary when
//! you call `redact()` or `Redactable::redact()`.
//!
//! What this crate does:
//! - defines policy marker types (e.g., `Pii`, `Token`, `Email`)
//! - defines redaction policies and the `redact` entrypoint
//! - provides integrations behind feature flags (e.g. `slog`)
//!
//! What it does not do:
//! - perform I/O or logging
//! - validate your policy choices
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
    clippy::default_trait_access,
    clippy::doc_markdown,
    clippy::if_not_else,
    clippy::module_name_repetitions,
    clippy::multiple_crate_versions,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::needless_ifs,
    clippy::use_self,
    clippy::cargo_common_metadata,
    clippy::missing_errors_doc,
    clippy::enum_glob_use,
    clippy::struct_excessive_bools,
    clippy::missing_const_for_fn,
    clippy::redundant_pub_crate,
    clippy::result_large_err,
    clippy::future_not_send,
    clippy::option_if_let_else,
    clippy::from_over_into,
    clippy::manual_inspect
)]
// Allow some lints while testing
#![cfg_attr(test, allow(clippy::non_ascii_literal, clippy::unwrap_used))]

pub use redactable_derive::{NotSensitive, NotSensitiveDisplay, Sensitive, SensitiveDisplay};

#[allow(unused_extern_crates)]
extern crate self as redactable;

// Module declarations
#[cfg(feature = "policy")]
pub mod policy;
#[cfg(feature = "redaction")]
mod redaction;
#[cfg(feature = "slog")]
pub mod slog;
#[cfg(feature = "tracing")]
pub mod tracing;

// Re-exports from policy module
#[cfg(feature = "policy")]
pub use policy::{
    BlockchainAddress, CreditCard, Email, EmailConfig, IpAddress, KeepConfig, MASK_CHAR,
    MaskConfig, PhoneNumber, Pii, REDACTED_PLACEHOLDER, RedactionPolicy, Secret,
    TextRedactionPolicy, Token,
};
// Re-exports from redaction module
#[doc(hidden)]
#[cfg(feature = "redaction")]
pub use redaction::PolicyApplicable;
#[cfg(feature = "redaction")]
pub use redaction::{
    NotSensitive, NotSensitiveDebug, NotSensitiveDebugExt, NotSensitiveDisplay,
    NotSensitiveDisplayExt, NotSensitiveExt, NotSensitiveValue, PolicyApplicableRef, Redactable,
    RedactableContainer, RedactableDisplay, RedactableLeaf, RedactableMapper, RedactableWithPolicy,
    RedactedDisplayRef, RedactedOutput, RedactedOutputExt, RedactedOutputRef, ScalarRedaction,
    SensitiveValue, ToRedactedOutput, apply_policy, apply_policy_ref, redact,
};
#[cfg(feature = "json")]
pub use redaction::{
    NotSensitiveJson, NotSensitiveJsonExt, RedactedJson, RedactedJsonExt, RedactedJsonRef,
};
#[cfg(feature = "slog")]
pub use slog::{RedactedDisplayValue, SlogRedactedExt};
