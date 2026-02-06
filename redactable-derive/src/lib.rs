//! Derive macros for `redactable`.
//!
//! This crate generates traversal code behind `#[derive(Sensitive)]`,
//! `#[derive(SensitiveDisplay)]`, `#[derive(NotSensitive)]`, and
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

use proc_macro_crate::{FoundCrate, crate_name};
#[cfg(feature = "slog")]
use proc_macro2::Span;
use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};
#[cfg(feature = "slog")]
use syn::parse_quote;
use syn::{
    Data, DataEnum, DataStruct, DeriveInput, Fields, Result, parse_macro_input, spanned::Spanned,
};

mod container;
mod derive_enum;
mod derive_struct;
mod generics;
mod redacted_display;
mod strategy;
mod transform;
mod types;
use container::{ContainerOptions, parse_container_options};
use derive_enum::derive_enum;
use derive_struct::derive_struct;
use generics::{
    add_container_bounds, add_debug_bounds, add_display_bounds, add_policy_applicable_bounds,
    add_policy_applicable_ref_bounds, add_redacted_display_bounds, collect_generics_from_type,
};
use redacted_display::derive_redacted_display;

/// Derives `redactable::RedactableContainer` (and related impls) for structs and enums.
///
/// # Container Attributes
///
/// These attributes are placed on the struct/enum itself:
///
/// - `#[sensitive(skip_debug)]` - Opt out of `Debug` impl generation. Use this when you need a
///   custom `Debug` implementation or the type already derives `Debug` elsewhere.
///
/// # Field Attributes
///
/// - **No annotation**: The field is traversed by default. Scalars pass through unchanged; nested
///   structs/enums are walked using `RedactableContainer` (so external types must implement it).
///
/// - `#[sensitive(Secret)]`: For scalar types (i32, bool, char, etc.), redacts to default values
///   (0, false, '*'). For string-like types, applies full redaction to `"[REDACTED]"`.
///
/// - `#[sensitive(Policy)]`: Applies the policy's redaction rules to string-like
///   values. Works for `String`, `Option<String>`, `Vec<String>`, `Box<String>`. Scalars can only
///   use `#[sensitive(Secret)]`.
///
/// - `#[not_sensitive]`: Explicit passthrough - the field is not transformed at all. Use this
///   for foreign types that don't implement `RedactableContainer`. This is equivalent to wrapping
///   the field type in `NotSensitiveValue<T>`, but without changing the type signature.
///
/// Unions are rejected at compile time.
///
/// # Additional Generated Impls
///
/// - `Debug`: when *not* building with `cfg(any(test, feature = "testing"))`, sensitive fields are
///   formatted as the string `"[REDACTED]"` rather than their values. Use `#[sensitive(skip_debug)]`
///   on the container to opt out.
/// - `slog::Value` (behind `cfg(feature = "slog")`): implemented by cloning the value and routing
///   it through `redactable::slog::SlogRedactedExt`. **Note:** this impl requires `Clone` and
///   `serde::Serialize` because it emits structured JSON. The derive first looks for a top-level
///   `slog` crate; if not found, it checks the `REDACTABLE_SLOG_CRATE` env var for an alternate path
///   (e.g., `my_log::slog`). If neither is available, compilation fails with a clear error.
#[proc_macro_derive(Sensitive, attributes(sensitive, not_sensitive))]
pub fn derive_sensitive_container(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(input, SlogMode::RedactedJson) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.into_compile_error().into(),
    }
}

/// Derives a no-op `redactable::RedactableContainer` implementation, along with
/// `slog::Value` / `SlogRedacted` and `TracingRedacted`.
///
/// This is useful for types that are known to be non-sensitive but still need to
/// satisfy `RedactableContainer` / `Redactable` bounds. Because the type has no
/// sensitive data, logging integration works without wrappers.
///
/// # Generated Impls
///
/// - `RedactableContainer`: no-op passthrough (the type has no sensitive data)
/// - `slog::Value` and `SlogRedacted` (behind `cfg(feature = "slog")`): serializes the value
///   directly as structured JSON without redaction (same format as `Sensitive`, but skips
///   the redaction step). Requires `Serialize` on the type.
/// - `TracingRedacted` (behind `cfg(feature = "tracing")`): marker trait
///
/// `NotSensitive` does **not** generate a `Debug` impl — there's nothing to redact.
/// Use `#[derive(Debug)]` when needed.
///
/// # Rejected Attributes
///
/// `#[sensitive]` and `#[not_sensitive]` attributes are rejected on both the container
/// and its fields — the former is wrong (the type is explicitly non-sensitive), the
/// latter is redundant (the entire type is already non-sensitive).
///
/// Unions are rejected at compile time.
#[proc_macro_derive(NotSensitive, attributes(not_sensitive))]
pub fn derive_not_sensitive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand_not_sensitive(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.into_compile_error().into(),
    }
}

#[allow(clippy::too_many_lines)]
fn expand_not_sensitive(input: DeriveInput) -> Result<TokenStream> {
    let DeriveInput {
        ident,
        generics,
        data,
        attrs,
        ..
    } = input;

    // Reject unions
    if let Data::Union(u) = &data {
        return Err(syn::Error::new(
            u.union_token.span(),
            "`NotSensitive` cannot be derived for unions",
        ));
    }

    // Reject #[sensitive] and #[not_sensitive] attributes on container or fields.
    // #[sensitive] is wrong because the type is explicitly not-sensitive.
    // #[not_sensitive] is redundant/nonsensical — the entire type is already not-sensitive.
    for attr in &attrs {
        if attr.path().is_ident("sensitive") {
            return Err(syn::Error::new(
                attr.span(),
                "`#[sensitive]` attributes are not allowed on `NotSensitive` types",
            ));
        }
        if attr.path().is_ident("not_sensitive") {
            return Err(syn::Error::new(
                attr.span(),
                "`#[not_sensitive]` attributes are not needed on `NotSensitive` types (the entire type is already non-sensitive)",
            ));
        }
    }

    match &data {
        Data::Struct(data) => {
            for field in &data.fields {
                for attr in &field.attrs {
                    if attr.path().is_ident("sensitive") {
                        return Err(syn::Error::new(
                            attr.span(),
                            "`#[sensitive]` attributes are not allowed on `NotSensitive` types",
                        ));
                    }
                    if attr.path().is_ident("not_sensitive") {
                        return Err(syn::Error::new(
                            attr.span(),
                            "`#[not_sensitive]` attributes are not needed on `NotSensitive` types (the entire type is already non-sensitive)",
                        ));
                    }
                }
            }
        }
        Data::Enum(data) => {
            for variant in &data.variants {
                for field in &variant.fields {
                    for attr in &field.attrs {
                        if attr.path().is_ident("sensitive") {
                            return Err(syn::Error::new(
                                attr.span(),
                                "`#[sensitive]` attributes are not allowed on `NotSensitive` types",
                            ));
                        }
                        if attr.path().is_ident("not_sensitive") {
                            return Err(syn::Error::new(
                                attr.span(),
                                "`#[not_sensitive]` attributes are not needed on `NotSensitive` types (the entire type is already non-sensitive)",
                            ));
                        }
                    }
                }
            }
        }
        Data::Union(_) => unreachable!("unions rejected above"),
    }

    let crate_root = crate_root();

    // RedactableContainer impl (no-op passthrough)
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let container_impl = quote! {
        impl #impl_generics #crate_root::RedactableContainer for #ident #ty_generics #where_clause {
            fn redact_with<M: #crate_root::RedactableMapper>(self, _mapper: &M) -> Self {
                self
            }
        }
    };

    // slog impl - serialize directly as structured JSON (no redaction needed)
    #[cfg(feature = "slog")]
    let slog_impl = {
        let slog_crate = slog_crate()?;
        let mut slog_generics = generics.clone();
        let (_, ty_generics, _) = slog_generics.split_for_impl();
        let self_ty: syn::Type = parse_quote!(#ident #ty_generics);
        slog_generics
            .make_where_clause()
            .predicates
            .push(parse_quote!(#self_ty: ::serde::Serialize));
        let (slog_impl_generics, slog_ty_generics, slog_where_clause) =
            slog_generics.split_for_impl();
        quote! {
            impl #slog_impl_generics #slog_crate::Value for #ident #slog_ty_generics #slog_where_clause {
                fn serialize(
                    &self,
                    _record: &#slog_crate::Record<'_>,
                    key: #slog_crate::Key,
                    serializer: &mut dyn #slog_crate::Serializer,
                ) -> #slog_crate::Result {
                    #crate_root::slog::__slog_serialize_not_sensitive(self, _record, key, serializer)
                }
            }

            impl #slog_impl_generics #crate_root::slog::SlogRedacted for #ident #slog_ty_generics #slog_where_clause {}
        }
    };

    #[cfg(not(feature = "slog"))]
    let slog_impl = quote! {};

    // tracing impl
    #[cfg(feature = "tracing")]
    let tracing_impl = {
        let (tracing_impl_generics, tracing_ty_generics, tracing_where_clause) =
            generics.split_for_impl();
        quote! {
            impl #tracing_impl_generics #crate_root::tracing::TracingRedacted for #ident #tracing_ty_generics #tracing_where_clause {}
        }
    };

    #[cfg(not(feature = "tracing"))]
    let tracing_impl = quote! {};

    Ok(quote! {
        #container_impl
        #slog_impl
        #tracing_impl
    })
}

/// Derives `redactable::RedactableDisplay` for types with no sensitive data.
///
/// This is the display counterpart to `NotSensitive`. Use it when you have a type
/// with no sensitive data that needs logging integration (e.g., for use with slog).
///
/// Unlike `SensitiveDisplay`, this derive does **not** require a display template.
/// Instead, it delegates directly to the type's existing `Display` implementation.
///
/// # Required Bounds
///
/// The type must implement `Display`. This is required because `RedactableDisplay` delegates
/// to `Display::fmt`.
///
/// # Generated Impls
///
/// - `RedactableContainer`: no-op passthrough (allows use inside `Sensitive` containers)
/// - `RedactableDisplay`: delegates to `Display::fmt`
/// - `slog::Value` and `SlogRedacted` (behind `cfg(feature = "slog")`): uses `RedactableDisplay` output
/// - `TracingRedacted` (behind `cfg(feature = "tracing")`): marker trait
///
/// # Debug
///
/// `NotSensitiveDisplay` does **not** generate a `Debug` impl — there's nothing to redact.
/// Use `#[derive(Debug)]` alongside `NotSensitiveDisplay` when needed:
///
/// # Rejected Attributes
///
/// `#[sensitive]` and `#[not_sensitive]` attributes are rejected on both the container
/// and its fields — the former is wrong (the type is explicitly non-sensitive), the
/// latter is redundant (the entire type is already non-sensitive).
///
/// # Example
///
/// ```ignore
/// use redactable::NotSensitiveDisplay;
///
/// #[derive(Clone, NotSensitiveDisplay)]
/// #[display(fmt = "RetryDecision")]  // Or use displaydoc/thiserror for Display impl
/// enum RetryDecision {
///     Retry,
///     Abort,
/// }
/// ```
#[proc_macro_derive(NotSensitiveDisplay)]
pub fn derive_not_sensitive_display(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand_not_sensitive_display(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.into_compile_error().into(),
    }
}

#[allow(clippy::too_many_lines)]
fn expand_not_sensitive_display(input: DeriveInput) -> Result<TokenStream> {
    let DeriveInput {
        ident,
        generics,
        data,
        attrs,
        ..
    } = input;

    // Reject unions
    if let Data::Union(u) = &data {
        return Err(syn::Error::new(
            u.union_token.span(),
            "`NotSensitiveDisplay` cannot be derived for unions",
        ));
    }

    // Check for #[sensitive] attributes which shouldn't be on NotSensitiveDisplay types
    let mut sensitive_attr_spans = Vec::new();
    if let Some(attr) = attrs.iter().find(|attr| attr.path().is_ident("sensitive")) {
        sensitive_attr_spans.push(attr.span());
    }

    match &data {
        Data::Struct(data) => {
            for field in &data.fields {
                if field
                    .attrs
                    .iter()
                    .any(|attr| attr.path().is_ident("sensitive"))
                {
                    sensitive_attr_spans.push(field.span());
                }
            }
        }
        Data::Enum(data) => {
            for variant in &data.variants {
                for field in &variant.fields {
                    if field
                        .attrs
                        .iter()
                        .any(|attr| attr.path().is_ident("sensitive"))
                    {
                        sensitive_attr_spans.push(field.span());
                    }
                }
            }
        }
        Data::Union(_) => unreachable!("unions rejected above"),
    }

    if let Some(span) = sensitive_attr_spans.first() {
        return Err(syn::Error::new(
            *span,
            "`#[sensitive]` attributes are not allowed on `NotSensitiveDisplay` types",
        ));
    }

    // Check for #[not_sensitive] attributes which are redundant on NotSensitiveDisplay types
    let mut not_sensitive_attr_spans = Vec::new();
    match &data {
        Data::Struct(data) => {
            for field in &data.fields {
                if field
                    .attrs
                    .iter()
                    .any(|attr| attr.path().is_ident("not_sensitive"))
                {
                    not_sensitive_attr_spans.push(field.span());
                }
            }
        }
        Data::Enum(data) => {
            for variant in &data.variants {
                for field in &variant.fields {
                    if field
                        .attrs
                        .iter()
                        .any(|attr| attr.path().is_ident("not_sensitive"))
                    {
                        not_sensitive_attr_spans.push(field.span());
                    }
                }
            }
        }
        Data::Union(_) => unreachable!("unions rejected above"),
    }

    if let Some(span) = not_sensitive_attr_spans.first() {
        return Err(syn::Error::new(
            *span,
            "`#[not_sensitive]` attributes are not needed on `NotSensitiveDisplay` types (the entire type is already non-sensitive)",
        ));
    }

    let crate_root = crate_root();

    // Generate the RedactableContainer no-op passthrough impl
    // This is always generated, allowing NotSensitiveDisplay to be used inside Sensitive containers
    let (container_impl_generics, container_ty_generics, container_where_clause) =
        generics.split_for_impl();
    let container_impl = quote! {
        impl #container_impl_generics #crate_root::RedactableContainer for #ident #container_ty_generics #container_where_clause {
            fn redact_with<M: #crate_root::RedactableMapper>(self, _mapper: &M) -> Self {
                self
            }
        }
    };

    // Always delegate to Display::fmt (no template parsing for NotSensitiveDisplay)
    // Add Display bound to generics for RedactableDisplay impl
    let mut display_generics = generics.clone();
    let display_where_clause = display_generics.make_where_clause();
    // Collect type parameters that need Display bound
    for param in generics.type_params() {
        let ident = &param.ident;
        display_where_clause
            .predicates
            .push(syn::parse_quote!(#ident: ::core::fmt::Display));
    }

    let (display_impl_generics, display_ty_generics, display_where_clause) =
        display_generics.split_for_impl();

    // RedactableDisplay impl - delegates to Display
    let redacted_display_impl = quote! {
        impl #display_impl_generics #crate_root::RedactableDisplay for #ident #display_ty_generics #display_where_clause {
            fn fmt_redacted(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Display::fmt(self, f)
            }
        }
    };

    // slog impl
    #[cfg(feature = "slog")]
    let slog_impl = {
        let slog_crate = slog_crate()?;
        let mut slog_generics = generics;
        let (_, ty_generics, _) = slog_generics.split_for_impl();
        let self_ty: syn::Type = syn::parse_quote!(#ident #ty_generics);
        slog_generics
            .make_where_clause()
            .predicates
            .push(syn::parse_quote!(#self_ty: #crate_root::RedactableDisplay));
        let (slog_impl_generics, slog_ty_generics, slog_where_clause) =
            slog_generics.split_for_impl();
        quote! {
            impl #slog_impl_generics #slog_crate::Value for #ident #slog_ty_generics #slog_where_clause {
                fn serialize(
                    &self,
                    _record: &#slog_crate::Record<'_>,
                    key: #slog_crate::Key,
                    serializer: &mut dyn #slog_crate::Serializer,
                ) -> #slog_crate::Result {
                    let redacted = #crate_root::RedactableDisplay::redacted_display(self);
                    serializer.emit_arguments(key, &format_args!("{}", redacted))
                }
            }

            impl #slog_impl_generics #crate_root::slog::SlogRedacted for #ident #slog_ty_generics #slog_where_clause {}
        }
    };

    #[cfg(not(feature = "slog"))]
    let slog_impl = quote! {};

    // tracing impl
    #[cfg(feature = "tracing")]
    let tracing_impl = {
        let (tracing_impl_generics, tracing_ty_generics, tracing_where_clause) =
            display_generics.split_for_impl();
        quote! {
            impl #tracing_impl_generics #crate_root::tracing::TracingRedacted for #ident #tracing_ty_generics #tracing_where_clause {}
        }
    };

    #[cfg(not(feature = "tracing"))]
    let tracing_impl = quote! {};

    Ok(quote! {
        #container_impl
        #redacted_display_impl
        #slog_impl
        #tracing_impl
    })
}

/// Derives `redactable::RedactableDisplay` using a display template.
///
/// This generates a redacted string representation without requiring `Clone`.
/// Unannotated fields use `RedactableDisplay` by default (passthrough for scalars,
/// redacted display for nested `SensitiveDisplay` types).
///
/// # Container Attributes
///
/// - `#[sensitive(skip_debug)]` - Opt out of `Debug` impl generation. Use this when you need a
///   custom `Debug` implementation or the type already derives `Debug` elsewhere.
///
/// # Field Annotations
///
/// - *(none)*: Uses `RedactableDisplay` (requires the field type to implement it)
/// - `#[sensitive(Policy)]`: Apply the policy's redaction rules
/// - `#[not_sensitive]`: Render raw via `Display` (use for types without `RedactableDisplay`)
///
/// The display template is taken from `#[error("...")]` (thiserror-style) or from
/// doc comments (displaydoc-style). If neither is present, the derive fails.
///
/// Fields are redacted by reference, so field types do not need `Clone`.
///
/// # Additional Generated Impls
///
/// - `Debug`: when *not* building with `cfg(any(test, feature = "testing"))`, `Debug` formats via
///   `RedactableDisplay::fmt_redacted`. In test/testing builds, it shows actual values for
///   debugging.
#[proc_macro_derive(SensitiveDisplay, attributes(sensitive, not_sensitive, error))]
pub fn derive_sensitive_display(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(input, SlogMode::RedactedDisplay) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.into_compile_error().into(),
    }
}

/// Returns the token stream to reference the redactable crate root.
///
/// Handles crate renaming (e.g., `my_redact = { package = "redactable", ... }`)
/// and internal usage (when derive is used inside the redactable crate itself).
fn crate_root() -> proc_macro2::TokenStream {
    match crate_name("redactable") {
        Ok(FoundCrate::Itself) => quote! { crate },
        Ok(FoundCrate::Name(name)) => {
            let ident = format_ident!("{}", name);
            quote! { ::#ident }
        }
        Err(_) => quote! { ::redactable },
    }
}

/// Returns the token stream to reference the slog crate root.
///
/// Handles crate renaming (e.g., `my_slog = { package = "slog", ... }`).
/// If the top-level `slog` crate is not available, falls back to the
/// `REDACTABLE_SLOG_CRATE` env var, which should be a path like `my_log::slog`.
#[cfg(feature = "slog")]
fn slog_crate() -> Result<proc_macro2::TokenStream> {
    match crate_name("slog") {
        Ok(FoundCrate::Itself) => Ok(quote! { crate }),
        Ok(FoundCrate::Name(name)) => {
            let ident = format_ident!("{}", name);
            Ok(quote! { ::#ident })
        }
        Err(_) => {
            let env_value = std::env::var("REDACTABLE_SLOG_CRATE").map_err(|_| {
                syn::Error::new(
                    Span::call_site(),
                    "slog support is enabled, but no top-level `slog` crate was found. \
Set the REDACTABLE_SLOG_CRATE env var to a path (e.g., `my_log::slog`) or add \
`slog` as a direct dependency.",
                )
            })?;
            let path = syn::parse_str::<syn::Path>(&env_value).map_err(|_| {
                syn::Error::new(
                    Span::call_site(),
                    format!("REDACTABLE_SLOG_CRATE must be a valid Rust path (got `{env_value}`)"),
                )
            })?;
            Ok(quote! { #path })
        }
    }
}

fn crate_path(item: &str) -> proc_macro2::TokenStream {
    let root = crate_root();
    let item_ident = syn::parse_str::<syn::Path>(item).expect("redactable crate path should parse");
    quote! { #root::#item_ident }
}

struct DeriveOutput {
    redaction_body: TokenStream,
    used_generics: Vec<Ident>,
    policy_applicable_generics: Vec<Ident>,
    debug_redacted_body: TokenStream,
    debug_redacted_generics: Vec<Ident>,
    debug_unredacted_body: TokenStream,
    debug_unredacted_generics: Vec<Ident>,
    redacted_display_body: Option<TokenStream>,
    redacted_display_generics: Vec<Ident>,
    redacted_display_debug_generics: Vec<Ident>,
    redacted_display_policy_ref_generics: Vec<Ident>,
    redacted_display_nested_generics: Vec<Ident>,
}

struct DebugOutput {
    body: TokenStream,
    generics: Vec<Ident>,
}

enum SlogMode {
    RedactedJson,
    RedactedDisplay,
}

#[allow(clippy::too_many_lines, clippy::redundant_clone)]
fn expand(input: DeriveInput, slog_mode: SlogMode) -> Result<TokenStream> {
    let DeriveInput {
        ident,
        generics,
        data,
        attrs,
        ..
    } = input;

    let ContainerOptions { skip_debug } = parse_container_options(&attrs)?;

    let crate_root = crate_root();

    if matches!(slog_mode, SlogMode::RedactedDisplay) {
        let redacted_display_output = derive_redacted_display(&ident, &data, &attrs, &generics)?;
        let redacted_display_generics =
            add_display_bounds(generics.clone(), &redacted_display_output.display_generics);
        let redacted_display_generics = add_debug_bounds(
            redacted_display_generics,
            &redacted_display_output.debug_generics,
        );
        let redacted_display_generics = add_policy_applicable_ref_bounds(
            redacted_display_generics,
            &redacted_display_output.policy_ref_generics,
        );
        let redacted_display_generics = add_redacted_display_bounds(
            redacted_display_generics,
            &redacted_display_output.nested_generics,
        );
        let (display_impl_generics, display_ty_generics, display_where_clause) =
            redacted_display_generics.split_for_impl();
        let redacted_display_body = redacted_display_output.body;
        let redacted_display_impl = quote! {
            impl #display_impl_generics #crate_root::RedactableDisplay for #ident #display_ty_generics #display_where_clause {
                fn fmt_redacted(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    #redacted_display_body
                }
            }
        };
        let debug_impl = if skip_debug {
            quote! {}
        } else {
            let debug_output = derive_unredacted_debug(&ident, &data, &generics)?;
            let debug_unredacted_generics =
                add_debug_bounds(generics.clone(), &debug_output.generics);
            let (
                debug_unredacted_impl_generics,
                debug_unredacted_ty_generics,
                debug_unredacted_where_clause,
            ) = debug_unredacted_generics.split_for_impl();
            let (
                debug_redacted_impl_generics,
                debug_redacted_ty_generics,
                debug_redacted_where_clause,
            ) = redacted_display_generics.split_for_impl();
            let debug_unredacted_body = debug_output.body;
            quote! {
                #[cfg(any(test, feature = "testing"))]
                impl #debug_unredacted_impl_generics ::core::fmt::Debug for #ident #debug_unredacted_ty_generics #debug_unredacted_where_clause {
                    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                        #debug_unredacted_body
                    }
                }

                #[cfg(not(any(test, feature = "testing")))]
                impl #debug_redacted_impl_generics ::core::fmt::Debug for #ident #debug_redacted_ty_generics #debug_redacted_where_clause {
                    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                        #crate_root::RedactableDisplay::fmt_redacted(self, f)
                    }
                }
            }
        };

        // Only generate slog impl when the slog feature is enabled on redactable-derive.
        // If slog is not available, emit a clear error with instructions.
        #[cfg(feature = "slog")]
        let slog_impl = {
            let slog_crate = slog_crate()?;
            let mut slog_generics = generics;
            // Get ty_generics first (immutable borrow) before make_where_clause (mutable borrow)
            let (_, ty_generics, _) = slog_generics.split_for_impl();
            let self_ty: syn::Type = parse_quote!(#ident #ty_generics);
            slog_generics
                .make_where_clause()
                .predicates
                .push(parse_quote!(#self_ty: #crate_root::RedactableDisplay));
            let (slog_impl_generics, slog_ty_generics, slog_where_clause) =
                slog_generics.split_for_impl();
            quote! {
                impl #slog_impl_generics #slog_crate::Value for #ident #slog_ty_generics #slog_where_clause {
                    fn serialize(
                        &self,
                        _record: &#slog_crate::Record<'_>,
                        key: #slog_crate::Key,
                        serializer: &mut dyn #slog_crate::Serializer,
                    ) -> #slog_crate::Result {
                        let redacted = #crate_root::RedactableDisplay::redacted_display(self);
                        serializer.emit_arguments(key, &format_args!("{}", redacted))
                    }
                }

                impl #slog_impl_generics #crate_root::slog::SlogRedacted for #ident #slog_ty_generics #slog_where_clause {}
            }
        };

        #[cfg(not(feature = "slog"))]
        let slog_impl = quote! {};

        #[cfg(feature = "tracing")]
        let tracing_impl = {
            let (tracing_impl_generics, tracing_ty_generics, tracing_where_clause) =
                redacted_display_generics.split_for_impl();
            quote! {
                impl #tracing_impl_generics #crate_root::tracing::TracingRedacted for #ident #tracing_ty_generics #tracing_where_clause {}
            }
        };

        #[cfg(not(feature = "tracing"))]
        let tracing_impl = quote! {};

        return Ok(quote! {
            #redacted_display_impl
            #debug_impl
            #slog_impl
            #tracing_impl
        });
    }

    // Only SlogMode::RedactedJson reaches this point (RedactedDisplay returns early above).
    // RedactableDisplay is not generated for the Sensitive derive.

    let derive_output = match &data {
        Data::Struct(data) => {
            let output = derive_struct(&ident, data.clone(), &generics)?;
            DeriveOutput {
                redaction_body: output.redaction_body,
                used_generics: output.used_generics,
                policy_applicable_generics: output.policy_applicable_generics,
                debug_redacted_body: output.debug_redacted_body,
                debug_redacted_generics: output.debug_redacted_generics,
                debug_unredacted_body: output.debug_unredacted_body,
                debug_unredacted_generics: output.debug_unredacted_generics,
                redacted_display_body: None,
                redacted_display_generics: Vec::new(),
                redacted_display_debug_generics: Vec::new(),
                redacted_display_policy_ref_generics: Vec::new(),
                redacted_display_nested_generics: Vec::new(),
            }
        }
        Data::Enum(data) => {
            let output = derive_enum(&ident, data.clone(), &generics)?;
            DeriveOutput {
                redaction_body: output.redaction_body,
                used_generics: output.used_generics,
                policy_applicable_generics: output.policy_applicable_generics,
                debug_redacted_body: output.debug_redacted_body,
                debug_redacted_generics: output.debug_redacted_generics,
                debug_unredacted_body: output.debug_unredacted_body,
                debug_unredacted_generics: output.debug_unredacted_generics,
                redacted_display_body: None,
                redacted_display_generics: Vec::new(),
                redacted_display_debug_generics: Vec::new(),
                redacted_display_policy_ref_generics: Vec::new(),
                redacted_display_nested_generics: Vec::new(),
            }
        }
        Data::Union(u) => {
            return Err(syn::Error::new(
                u.union_token.span(),
                "`Sensitive` cannot be derived for unions",
            ));
        }
    };

    let policy_generics = add_container_bounds(generics.clone(), &derive_output.used_generics);
    let policy_generics =
        add_policy_applicable_bounds(policy_generics, &derive_output.policy_applicable_generics);
    let (impl_generics, ty_generics, where_clause) = policy_generics.split_for_impl();
    let debug_redacted_generics =
        add_debug_bounds(generics.clone(), &derive_output.debug_redacted_generics);
    let (debug_redacted_impl_generics, debug_redacted_ty_generics, debug_redacted_where_clause) =
        debug_redacted_generics.split_for_impl();
    let debug_unredacted_generics =
        add_debug_bounds(generics.clone(), &derive_output.debug_unredacted_generics);
    let (
        debug_unredacted_impl_generics,
        debug_unredacted_ty_generics,
        debug_unredacted_where_clause,
    ) = debug_unredacted_generics.split_for_impl();
    let redaction_body = &derive_output.redaction_body;
    let debug_redacted_body = &derive_output.debug_redacted_body;
    let debug_unredacted_body = &derive_output.debug_unredacted_body;
    let debug_impl = if skip_debug {
        quote! {}
    } else {
        quote! {
            #[cfg(any(test, feature = "testing"))]
            impl #debug_unredacted_impl_generics ::core::fmt::Debug for #ident #debug_unredacted_ty_generics #debug_unredacted_where_clause {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    #debug_unredacted_body
                }
            }

            #[cfg(not(any(test, feature = "testing")))]
            #[allow(unused_variables)]
            impl #debug_redacted_impl_generics ::core::fmt::Debug for #ident #debug_redacted_ty_generics #debug_redacted_where_clause {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    #debug_redacted_body
                }
            }
        }
    };

    let redacted_display_body = derive_output.redacted_display_body.as_ref();
    let redacted_display_impl = if matches!(slog_mode, SlogMode::RedactedDisplay) {
        let redacted_display_generics =
            add_display_bounds(generics.clone(), &derive_output.redacted_display_generics);
        let redacted_display_generics = add_debug_bounds(
            redacted_display_generics,
            &derive_output.redacted_display_debug_generics,
        );
        let redacted_display_generics = add_policy_applicable_ref_bounds(
            redacted_display_generics,
            &derive_output.redacted_display_policy_ref_generics,
        );
        let redacted_display_generics = add_redacted_display_bounds(
            redacted_display_generics,
            &derive_output.redacted_display_nested_generics,
        );
        let (display_impl_generics, display_ty_generics, display_where_clause) =
            redacted_display_generics.split_for_impl();
        let redacted_display_body = redacted_display_body
            .cloned()
            .unwrap_or_else(TokenStream::new);
        quote! {
            impl #display_impl_generics #crate_root::RedactableDisplay for #ident #display_ty_generics #display_where_clause {
                fn fmt_redacted(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    #redacted_display_body
                }
            }
        }
    } else {
        quote! {}
    };

    // Only generate slog impl when the slog feature is enabled on redactable-derive.
    // If slog is not available, emit a clear error with instructions.
    #[cfg(feature = "slog")]
    let slog_impl = {
        let slog_crate = slog_crate()?;
        let mut slog_generics = generics;
        let slog_where_clause = slog_generics.make_where_clause();
        let self_ty: syn::Type = parse_quote!(#ident #ty_generics);
        match slog_mode {
            SlogMode::RedactedJson => {
                slog_where_clause
                    .predicates
                    .push(parse_quote!(#self_ty: ::core::clone::Clone));
                // SlogRedactedExt requires Self: Serialize, so we add this bound to enable
                // generic types to work with slog when their type parameters implement Serialize.
                slog_where_clause
                    .predicates
                    .push(parse_quote!(#self_ty: ::serde::Serialize));
                slog_where_clause
                    .predicates
                    .push(parse_quote!(#self_ty: #crate_root::slog::SlogRedactedExt));
                let (slog_impl_generics, slog_ty_generics, slog_where_clause) =
                    slog_generics.split_for_impl();
                quote! {
                    impl #slog_impl_generics #slog_crate::Value for #ident #slog_ty_generics #slog_where_clause {
                        fn serialize(
                            &self,
                            _record: &#slog_crate::Record<'_>,
                            key: #slog_crate::Key,
                            serializer: &mut dyn #slog_crate::Serializer,
                        ) -> #slog_crate::Result {
                            let redacted = #crate_root::slog::SlogRedactedExt::slog_redacted_json(self.clone());
                            #slog_crate::Value::serialize(&redacted, _record, key, serializer)
                        }
                    }

                    impl #slog_impl_generics #crate_root::slog::SlogRedacted for #ident #slog_ty_generics #slog_where_clause {}
                }
            }
            SlogMode::RedactedDisplay => {
                slog_where_clause
                    .predicates
                    .push(parse_quote!(#self_ty: #crate_root::RedactableDisplay));
                let (slog_impl_generics, slog_ty_generics, slog_where_clause) =
                    slog_generics.split_for_impl();
                quote! {
                    impl #slog_impl_generics #slog_crate::Value for #ident #slog_ty_generics #slog_where_clause {
                        fn serialize(
                            &self,
                            _record: &#slog_crate::Record<'_>,
                            key: #slog_crate::Key,
                            serializer: &mut dyn #slog_crate::Serializer,
                        ) -> #slog_crate::Result {
                            let redacted = #crate_root::RedactableDisplay::redacted_display(self);
                            serializer.emit_arguments(key, &format_args!("{}", redacted))
                        }
                    }

                    impl #slog_impl_generics #crate_root::slog::SlogRedacted for #ident #slog_ty_generics #slog_where_clause {}
                }
            }
        }
    };

    #[cfg(not(feature = "slog"))]
    let slog_impl = quote! {};

    #[cfg(feature = "tracing")]
    let tracing_impl = quote! {
        impl #impl_generics #crate_root::tracing::TracingRedacted for #ident #ty_generics #where_clause {}
    };

    #[cfg(not(feature = "tracing"))]
    let tracing_impl = quote! {};

    let trait_impl = quote! {
        impl #impl_generics #crate_root::RedactableContainer for #ident #ty_generics #where_clause {
            fn redact_with<M: #crate_root::RedactableMapper>(self, mapper: &M) -> Self {
                use #crate_root::RedactableContainer as _;
                #redaction_body
            }
        }

        #debug_impl

        #redacted_display_impl

        #slog_impl

        #tracing_impl

        // `slog` already provides `impl<V: Value> Value for &V`, so a reference
        // impl here would conflict with the blanket impl.
    };
    Ok(trait_impl)
}

fn derive_unredacted_debug(
    name: &Ident,
    data: &Data,
    generics: &syn::Generics,
) -> Result<DebugOutput> {
    match data {
        Data::Struct(data) => Ok(derive_unredacted_debug_struct(name, data, generics)),
        Data::Enum(data) => Ok(derive_unredacted_debug_enum(name, data, generics)),
        Data::Union(u) => Err(syn::Error::new(
            u.union_token.span(),
            "`SensitiveDisplay` cannot be derived for unions",
        )),
    }
}

fn derive_unredacted_debug_struct(
    name: &Ident,
    data: &DataStruct,
    generics: &syn::Generics,
) -> DebugOutput {
    let mut debug_generics = Vec::new();
    match &data.fields {
        Fields::Named(fields) => {
            let mut bindings = Vec::new();
            let mut debug_fields = Vec::new();
            for field in &fields.named {
                let ident = field
                    .ident
                    .clone()
                    .expect("named field should have identifier");
                bindings.push(ident.clone());
                collect_generics_from_type(&field.ty, generics, &mut debug_generics);
                debug_fields.push(quote! {
                    debug.field(stringify!(#ident), #ident);
                });
            }
            DebugOutput {
                body: quote! {
                    match self {
                        Self { #(#bindings),* } => {
                            let mut debug = f.debug_struct(stringify!(#name));
                            #(#debug_fields)*
                            debug.finish()
                        }
                    }
                },
                generics: debug_generics,
            }
        }
        Fields::Unnamed(fields) => {
            let mut bindings = Vec::new();
            let mut debug_fields = Vec::new();
            for (index, field) in fields.unnamed.iter().enumerate() {
                let ident = format_ident!("field_{index}");
                bindings.push(ident.clone());
                collect_generics_from_type(&field.ty, generics, &mut debug_generics);
                debug_fields.push(quote! {
                    debug.field(#ident);
                });
            }
            DebugOutput {
                body: quote! {
                    match self {
                        Self ( #(#bindings),* ) => {
                            let mut debug = f.debug_tuple(stringify!(#name));
                            #(#debug_fields)*
                            debug.finish()
                        }
                    }
                },
                generics: debug_generics,
            }
        }
        Fields::Unit => DebugOutput {
            body: quote! {
                f.write_str(stringify!(#name))
            },
            generics: debug_generics,
        },
    }
}

fn derive_unredacted_debug_enum(
    name: &Ident,
    data: &DataEnum,
    generics: &syn::Generics,
) -> DebugOutput {
    let mut debug_generics = Vec::new();
    let mut debug_arms = Vec::new();
    for variant in &data.variants {
        let variant_ident = &variant.ident;
        match &variant.fields {
            Fields::Unit => {
                debug_arms.push(quote! {
                    #name::#variant_ident => f.write_str(stringify!(#name::#variant_ident))
                });
            }
            Fields::Named(fields) => {
                let mut bindings = Vec::new();
                let mut debug_fields = Vec::new();
                for field in &fields.named {
                    let ident = field
                        .ident
                        .clone()
                        .expect("named field should have identifier");
                    bindings.push(ident.clone());
                    collect_generics_from_type(&field.ty, generics, &mut debug_generics);
                    debug_fields.push(quote! {
                        debug.field(stringify!(#ident), #ident);
                    });
                }
                debug_arms.push(quote! {
                    #name::#variant_ident { #(#bindings),* } => {
                        let mut debug = f.debug_struct(stringify!(#name::#variant_ident));
                        #(#debug_fields)*
                        debug.finish()
                    }
                });
            }
            Fields::Unnamed(fields) => {
                let mut bindings = Vec::new();
                let mut debug_fields = Vec::new();
                for (index, field) in fields.unnamed.iter().enumerate() {
                    let ident = format_ident!("field_{index}");
                    bindings.push(ident.clone());
                    collect_generics_from_type(&field.ty, generics, &mut debug_generics);
                    debug_fields.push(quote! {
                        debug.field(#ident);
                    });
                }
                debug_arms.push(quote! {
                    #name::#variant_ident ( #(#bindings),* ) => {
                        let mut debug = f.debug_tuple(stringify!(#name::#variant_ident));
                        #(#debug_fields)*
                        debug.finish()
                    }
                });
            }
        }
    }
    DebugOutput {
        body: quote! {
            match self {
                #(#debug_arms),*
            }
        },
        generics: debug_generics,
    }
}
