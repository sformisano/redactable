//! Redaction for structured values and formatted text.
//!
//! Preserve useful context for the output's audience and choose protection field
//! by field. Credentials use `Secret`; partial policies such as `Token` and
//! `Email` retain fragments that need their own diagnostic purpose.
//! Public fields use `#[not_sensitive]`; nested types retain their own policies.
//! For a `serde_json::Value` field in `Sensitive` or `SensitiveDual`, choose
//! `#[sensitive(Secret)]` to mask the payload or `#[not_sensitive]` to keep it.
//! This also applies to type aliases and JSON values inside traversed containers.
//! Structurally traversed maps require public keys. String and integer keys
//! qualify directly. Derive `NotSensitive` on a public custom key to keep the
//! key and apply the field's redaction policy to map values.
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
//! leaves unchanged.
//!
//! The five derive macros live in `redactable-derive` and are re-exported here.
//!
//! # Checked logging
//!
//! Enable the `log` feature to use your application's installed logger.
//! Write `redactable::info!(user; "signed in")` for a structured field or
//! `redactable::info!("signed in as {}", user)` for a message. Both require
//! `user` to implement `ToRedacted`. Import `BypassRedactionExt` to publish
//! a value's full Display text with `channel.bypass_display()` or its JSON with
//! `roles.bypass_json()`. Applications using slog or tracing can choose their
//! destination once with `logging::set_sink`.
//!
//! A logger with Serde support for structured fields can serialize a saved
//! `&RedactedValue` directly. See the
//! [logging examples](https://github.com/sformisano/redactable/blob/main/README.md#integrations)
//! for backend setup and output.

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
#[cfg(feature = "log")]
pub mod log;
#[cfg(any(feature = "log", feature = "slog", feature = "tracing"))]
pub mod logging;
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
    BypassRedactionExt, BypassRedactionMarker, PolicyDebug, PolicyDisplay, PolicyFormat,
    PolicyFormattingOutput, PublicMapKey, Redactable, RedactableMapper, RedactableWithFormatter,
    RedactedFormatterRef, RedactedList, RedactedValue, ScalarRedaction, SensitiveValue,
    SensitiveWithPolicy, ToRedacted,
};
// Re-exports from redaction module: internal machinery (used by derive-generated code)
#[doc(hidden)]
#[cfg(feature = "redaction")]
pub use redaction::{
    PolicyApplicable, PolicyApplicableRef, RedactableWithMapper, apply_policy, apply_policy_ref,
    redact,
};

#[cfg(feature = "log")]
pub use log::LogRedactedExt;
#[cfg(feature = "slog")]
pub use slog::{RedactedDisplayValue, SlogRedactedExt};
