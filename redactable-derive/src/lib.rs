//! Derive macros for `redactable`.
//!
//! This crate generates traversal code behind `#[derive(Sensitive)]`,
//! `#[derive(SensitiveDisplay)]`, `#[derive(SensitiveDual)]`, `#[derive(NotSensitive)]`, and
//! `#[derive(NotSensitiveDisplay)]`. It:
//! - reads `#[sensitive(...)]` and `#[not_sensitive]` attributes
//! - emits trait implementations for redaction and logging integration
//!
//! It does **not** define policy markers or text policies. Those live in the main
//! `redactable` crate and are applied at runtime.

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

#[allow(unused_extern_crates)]
extern crate proc_macro;

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

mod container;
mod crate_paths;
mod declaration;
mod derive_enum;
mod derive_struct;
mod fresh_ident;
mod generics;
mod not_sensitive;
mod output;
mod redacted_display;
mod sensitive;
mod strategy;
mod transform;

pub(crate) use crate_paths::{crate_path, crate_root};
use not_sensitive::{expand_not_sensitive, expand_not_sensitive_display};
pub(crate) use sensitive::DeriveOutput;
use sensitive::{Expansion, expand};

/// Derives `redactable::RedactableWithMapper` (and related impls) for structs and enums.
///
/// `Sensitive` and `SensitiveDisplay` are standalone derives. Use `SensitiveDual` when a type
/// needs both structural and display redaction.
///
/// # Recursive Fields
///
/// Use `#[redactable(recursive)]` on a field whose crate-qualified, aliased, or
/// mutually recursive type would otherwise create a self-referential inferred
/// bound. Unannotated fields retain their exact complete-type bounds.
///
/// # Field Attributes
///
/// - **No annotation**: The field requires declared `Redactable` behavior and is traversed
///   with the supplied mapper. Raw leaves need a policy or an explicit public declaration.
///
/// - `#[sensitive(Secret)]`: For scalar types (i32, bool, char, etc.), redacts to default values
///   (0, false, '*'). For string-like types, applies full redaction to `"[REDACTED]"`.
///
/// - `#[sensitive(Policy)]`: Applies the policy's redaction rules to string-like
///   values. Works for `String`, `Option<String>`, `Vec<String>`, `Box<String>`. Scalars can only
///   use `#[sensitive(Secret)]`.
///
/// - `#[not_sensitive]`: Explicit passthrough - the field is not transformed at all. Use this
///   for foreign types that don't implement `RedactableWithMapper`. This is the right
///   declaration for a foreign field in a struct you own; `BypassRedaction<T>` is only
///   for satisfying a `Redactable` bound on a value you cannot annotate.
///
/// Field operations are checked against the original declaration bounds, even
/// when no generated method is called. For an unannotated generic field `T`,
/// declare `T: Redactable`; complete container bounds may be declared instead.
/// Policy fields require the corresponding complete-type `PolicyField<P>` bound.
/// The recursion override omits inferred recursive predicates, but still checks
/// the actual field operations.
///
/// Unions are rejected at compile time.
///
/// # Generated Impls
///
/// - `ToRedacted`: always generated. It clones, redacts and serializes, producing a
///   `RedactedValue` that carries redacted JSON. This is why `Sensitive` requires
///   `Clone` and `serde::Serialize` on the type; a missing bound is reported on the
///   generated impl.
/// - `RedactableWithMapper`: always generated.
/// - `Redactable`: always generated. Provides `.redact()` and allows the type
///   inside `Sensitive` containers.
/// - `Debug`: uses the production redacted representation in every build mode.
/// - `slog::Value` + `SlogRedacted` (requires `slog` feature): borrowed generated output is a
///   fixed fail-closed placeholder and never clones or serializes the raw reference. Owned values
///   can use `SlogRedactedExt::slog_redacted_json` for redact-then-serialize structured output.
/// - `TracingRedacted` (requires `tracing` feature): marker trait.
#[proc_macro_derive(Sensitive, attributes(sensitive, not_sensitive, redactable))]
pub fn derive_sensitive_container(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(input, Expansion::Sensitive) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.into_compile_error().into(),
    }
}

/// Derives structural redaction and redacted template text for the same type.
///
/// Use this instead of combining `Sensitive` and `SensitiveDisplay` with the
/// legacy `#[sensitive(dual)]` coordination attribute. Every structural field is checked,
/// including fields omitted from the template. Its single `ToRedacted` impl carries
/// both representations: the template text and the redacted JSON. It therefore
/// requires `Clone` and `serde::Serialize` as well as a template.
#[proc_macro_derive(SensitiveDual, attributes(sensitive, not_sensitive, redactable, error))]
pub fn derive_sensitive_dual(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(input, Expansion::Dual) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.into_compile_error().into(),
    }
}

/// Derives a no-op `redactable::RedactableWithMapper` implementation, along with
/// `slog::Value` / `SlogRedacted` and `TracingRedacted`.
///
/// This is useful for types that are known to be non-sensitive but still need to
/// satisfy `RedactableWithMapper` / `Redactable` bounds. Because the type has no
/// sensitive data, logging integration works without wrappers.
///
/// # Generated Impls
///
/// - `RedactableWithMapper`: no-op passthrough (the type has no sensitive data)
/// - `Redactable`: declares the type public and allows it inside `Sensitive` containers.
/// - `ToRedacted`: always generated; emits the raw `Serialize` output the author
///   declared public. This is why `NotSensitive` requires `serde::Serialize`; `Clone`
///   is not required, because nothing is redacted.
/// - `slog::Value` and `SlogRedacted` (behind `cfg(feature = "slog")`): serializes the explicitly
///   non-sensitive value directly as structured JSON. Requires `Serialize` on the type.
///   Serialization borrows the value without cloning it. Serde reports an active
///   mutable `RefCell` borrow as an error, which becomes `"[REDACTED]"`.
/// - `TracingRedacted` (behind `cfg(feature = "tracing")`): marker trait
///
/// `NotSensitive` does **not** generate a `Debug` impl - there's nothing to redact.
/// Use `#[derive(Debug)]` when needed.
///
/// # Rejected Attributes
///
/// `#[sensitive]` and `#[not_sensitive]` attributes are rejected on both the container
/// and its fields - the former is wrong (the type is explicitly non-sensitive), the
/// latter is redundant (the entire type is already non-sensitive).
///
/// Unions are rejected at compile time.
#[proc_macro_derive(NotSensitive, attributes(sensitive, not_sensitive, redactable))]
pub fn derive_not_sensitive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand_not_sensitive(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.into_compile_error().into(),
    }
}

/// Derives `redactable::RedactableWithFormatter` for types with no sensitive data.
///
/// This is the display counterpart to `NotSensitive`. Use it when you have a type
/// with no sensitive data that needs logging integration (e.g., for use with slog).
///
/// Unlike `SensitiveDisplay`, this derive does **not** require a display template.
/// Instead, it delegates directly to the type's existing `Display` implementation.
///
/// # Required Bounds
///
/// The type must implement `Display`. This is required because `RedactableWithFormatter` delegates
/// to `Display::fmt`.
///
/// # Generated Impls
///
/// - `RedactableWithMapper`: no-op passthrough (allows use inside `Sensitive` containers)
/// - `Redactable`: declares the type public and allows it inside `Sensitive` containers.
/// - `RedactableWithFormatter`: delegates to `Display::fmt`
/// - `ToRedacted`: emits the `Display` text for `slog_redacted()` and `tracing_redacted()`
/// - `slog::Value` and `SlogRedacted` (behind `cfg(feature = "slog")`): uses `RedactableWithFormatter` output
/// - `TracingRedacted` (behind `cfg(feature = "tracing")`): marker trait
///
/// # Debug
///
/// `NotSensitiveDisplay` does **not** generate a `Debug` impl - there's nothing to redact.
/// Use `#[derive(Debug)]` alongside `NotSensitiveDisplay` when needed.
///
/// # Rejected Attributes
///
/// `#[sensitive]` and `#[not_sensitive]` attributes are rejected on both the container
/// and its fields - the former is wrong (the type is explicitly non-sensitive), the
/// latter is redundant (the entire type is already non-sensitive).
///
/// # Example
///
/// ```ignore
/// use redactable::NotSensitiveDisplay;
/// use std::fmt::{Display, Formatter, Result as FmtResult};
///
/// #[derive(NotSensitiveDisplay)]
/// enum RetryDecision {
///     Retry,
///     Abort,
/// }
///
/// impl Display for RetryDecision {
///     fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
///         formatter.write_str(match self {
///             Self::Retry => "Retry",
///             Self::Abort => "Abort",
///         })
///     }
/// }
///
/// assert_eq!(RetryDecision::Retry.to_string(), "Retry");
/// ```
#[proc_macro_derive(NotSensitiveDisplay, attributes(sensitive, not_sensitive, redactable))]
pub fn derive_not_sensitive_display(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand_not_sensitive_display(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.into_compile_error().into(),
    }
}

/// Derives `redactable::RedactableWithFormatter` using a display template.
///
/// This generates a redacted string representation by borrowing the source.
/// The text/secret route needs no `Clone`; IP-map formatting clones keys and the HashMap hasher.
/// Referenced unannotated fields require declared formatting, such as a nested
/// `SensitiveDisplay` type. Unreferenced fields and constant templates remain supported.
///
/// # Field Annotations
///
/// - *(none)*: Uses `RedactableWithFormatter` and the public
///   `redactable::DeclaredFormatting` declaration
/// - `#[sensitive(Policy)]`: Apply the policy's redaction rules
/// - `#[not_sensitive]`: Render raw via `Display` (use for types without `RedactableWithFormatter`)
///
/// The display template is taken from `#[error("...")]` (thiserror-style) or from
/// doc comments (displaydoc-style). If neither is present, the derive fails.
///
/// # Policy Formatting
///
/// A custom leaf supports policy formatting by implementing
/// `redactable::PolicyFormat`. Supported containers forward
/// to their contents. A nested `RefCell` borrow conflict renders as `<borrowed>`.
///
/// Generic policy fields declare `PolicyDisplay<P>` for `{value}`,
/// `PolicyDebug<P>` for `{value:?}`, or both when both modes are used.
/// The same requirements apply to concrete policy fields.
/// These policy-specific bounds permit supported scalars and typed IP addresses
/// without requiring structural `Redactable` or `Clone`. Missing capabilities
/// reject the declaration even when no formatting method is called.
///
/// Use `SensitiveDual` instead when the same type also needs structural redaction.
/// Its declarations must satisfy both structural and template capabilities.
///
/// # Generated Impls
///
/// - `RedactableWithFormatter`: always generated.
/// - `ToRedacted`: always generated; emits the redacted display text for
///   `slog_redacted()` and `tracing_redacted()`.
/// - `Debug`: uses the production redacted representation in every build mode.
/// - `slog::Value` + `SlogRedacted`: emits the redacted display string (requires `slog` feature).
/// - `TracingRedacted`: marker trait (requires `tracing` feature).
#[proc_macro_derive(
    SensitiveDisplay,
    attributes(sensitive, not_sensitive, redactable, error)
)]
pub fn derive_sensitive_display(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(input, Expansion::SensitiveDisplay) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.into_compile_error().into(),
    }
}

#[cfg(all(test, feature = "slog"))]
mod generated_dependency_tests;

#[cfg(all(test, feature = "slog"))]
#[test]
fn structural_generated_dependency_roots() {
    generated_dependency_tests::run_structural_generated_dependency_roots();
}
