//! Redaction for structured values and formatted text.
//!
//! Mark sensitive data with a policy marker such as `Pii`, `Token`, or `Email`.
//! Each marker selects a redaction policy that defines how to transform the data.
//!
//! Use `Redactable::redact()` to transform a value whose type declares redaction
//! behavior. Use `ToRedacted` to produce owned text or JSON for logging.
//!
//! Choose a derive for the `ToRedacted` output you need:
//!
//! - `Sensitive` produces redacted JSON and requires `Clone + Serialize`.
//! - `SensitiveDisplay` produces redacted template text.
//! - `SensitiveDual` produces both and requires `Clone + Serialize` and a template.
//! - `NotSensitive` produces the raw JSON you declare public and requires `Serialize`.
//! - `NotSensitiveDisplay` produces the raw `Display` text you declare public.
//!
//! Use `SensitiveValue` to apply a policy to an individual value.
//!
//! Use a bypass wrapper only when its complete output is public.
//! `BypassDisplayRedaction`, `BypassDebugRedaction`, and `BypassJsonRedaction`
//! select an output format. `BypassRedactionMarker` declares a value public
//! without choosing a format. `BypassRedaction` satisfies a `Redactable` bound.
//!
//! Serde on `BypassDisplayRedaction`, `BypassDebugRedaction`, and
//! `BypassRedaction` exposes the raw inner value for transport or storage.
//! It does not redact that value. `BypassJsonRedaction` and
//! `BypassRedactionMarker` do not implement Serde traits themselves.
//! A handwritten `ToRedacted` implementation can select different fields or
//! compose summary text. These APIs require `redaction`, which enables `serde`
//! and `serde_json`.
//!
//! The free `redact()` function uses the lower-level mapper and can leave raw
//! leaves unchanged. It is not a logging boundary. Logging integrations such
//! as `slog` have their own feature flags. This crate performs no I/O or logging
//! and does not validate your policy choices.
//!
//! The five derive macros live in `redactable-derive` and are re-exported here.

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
#[cfg(all(feature = "testing", feature = "redaction"))]
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
#[cfg(feature = "redaction")]
pub use __private::DeclaredFormatting;
#[cfg(feature = "redaction")]
#[allow(deprecated)]
pub use redaction::BypassTextRedaction;
#[cfg(feature = "redaction")]
pub use redaction::{
    BypassDebugRedaction, BypassDisplayRedaction, BypassJsonRedaction, BypassRedaction,
    BypassRedactionMarker, PolicyDebug, PolicyDisplay, PolicyFormat, PolicyFormattingOutput,
    Redactable, RedactableMapper, RedactableWithFormatter, RedactedFormatterRef, RedactedList,
    RedactedValue, ScalarRedaction, SensitiveValue, SensitiveWithPolicy, ToRedacted,
};
// Re-exports from redaction module: internal machinery (used by derive-generated code)
#[doc(hidden)]
#[cfg(feature = "redaction")]
pub use redaction::{
    PolicyApplicable, PolicyApplicableRef, RedactableWithMapper, apply_policy, apply_policy_ref,
    redact,
};
#[cfg(feature = "slog")]
pub use slog::{RedactedDisplayValue, SlogRedactedExt};
