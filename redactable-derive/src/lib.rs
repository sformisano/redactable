//! Derive macros for `redactable`.
//!
//! This crate generates traversal code behind `#[derive(Sensitive)]` and
//! `#[derive(SensitiveError)]`. It:
//! - reads `#[sensitive(...)]` field attributes
//! - emits a `RedactableContainer` implementation that calls into a mapper
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
use syn::{Data, DeriveInput, Result, parse_macro_input, spanned::Spanned};

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
    add_clone_bounds, add_container_bounds, add_debug_bounds, add_display_bounds,
    add_policy_applicable_bounds, add_redacted_display_bounds,
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
/// - `#[sensitive(Default)]`: For scalar types (i32, bool, char, etc.), redacts to default values
///   (0, false, '*'). For string-like types, applies full redaction to `"[REDACTED]"`.
///
/// - `#[sensitive(Policy)]`: Applies the policy's redaction rules to string-like
///   values. Works for `String`, `Option<String>`, `Vec<String>`, `Box<String>`. Scalars can only
///   use `#[sensitive(Default)]`.
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
#[proc_macro_derive(Sensitive, attributes(sensitive))]
pub fn derive_sensitive_container(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(input, SlogMode::RedactedJson) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.into_compile_error().into(),
    }
}

#[proc_macro_derive(SensitiveData, attributes(sensitive))]
pub fn derive_sensitive_data(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    derive_sensitive_container(input)
}

/// Derives a no-op `redactable::RedactableContainer` implementation.
///
/// This is useful for types that are known to be non-sensitive but still need to
/// satisfy `RedactableContainer` / `Redactable` bounds.
#[proc_macro_derive(NotSensitive)]
pub fn derive_not_sensitive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let ident = input.ident;
    let generics = input.generics;
    let attrs = input.attrs;
    let data = input.data;

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
        Data::Union(data) => {
            return syn::Error::new(
                data.union_token.span(),
                "`NotSensitive` cannot be derived for unions",
            )
            .into_compile_error()
            .into();
        }
    }

    if let Some(span) = sensitive_attr_spans.first() {
        return syn::Error::new(
            *span,
            "`#[sensitive]` attributes are not allowed on `NotSensitive` types",
        )
        .into_compile_error()
        .into();
    }
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let crate_root = crate_root();

    let tokens = quote! {
        impl #impl_generics #crate_root::RedactableContainer for #ident #ty_generics #where_clause {
            fn redact_with<M: #crate_root::RedactableMapper>(self, _mapper: &M) -> Self {
                self
            }
        }
    };
    tokens.into()
}

/// Derives `redactable::RedactableContainer` for types that should log without `Serialize`.
///
/// This emits the same traversal and redacted `Debug` impls as `Sensitive`, but uses
/// a `slog::Value` implementation that logs a redacted string derived from a
/// display template.
///
/// The display template is taken from `#[error("...")]` (thiserror-style) or from
/// doc comments (displaydoc-style). If neither is present, the derive fails with a
/// compile error to avoid accidental exposure of sensitive fields.
///
/// Classified fields referenced in the template are redacted by applying the
/// policy to an owned copy of the field value, so those field types must
/// implement `Clone`.
#[proc_macro_derive(SensitiveError, attributes(sensitive, error))]
pub fn derive_sensitive_error(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(input, SlogMode::RedactableErrorString) {
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
    redacted_display_clone_generics: Vec<Ident>,
    redacted_display_nested_generics: Vec<Ident>,
}

enum SlogMode {
    RedactedJson,
    RedactableErrorString,
}

#[allow(clippy::too_many_lines)]
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

    let redacted_display_output = if matches!(slog_mode, SlogMode::RedactableErrorString) {
        Some(derive_redacted_display(&ident, &data, &attrs, &generics)?)
    } else {
        None
    };

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
                redacted_display_body: redacted_display_output
                    .as_ref()
                    .map(|output| output.body.clone()),
                redacted_display_generics: redacted_display_output
                    .as_ref()
                    .map(|output| output.display_generics.clone())
                    .unwrap_or_default(),
                redacted_display_debug_generics: redacted_display_output
                    .as_ref()
                    .map(|output| output.debug_generics.clone())
                    .unwrap_or_default(),
                redacted_display_clone_generics: redacted_display_output
                    .as_ref()
                    .map(|output| output.clone_generics.clone())
                    .unwrap_or_default(),
                redacted_display_nested_generics: redacted_display_output
                    .as_ref()
                    .map(|output| output.nested_generics.clone())
                    .unwrap_or_default(),
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
                redacted_display_body: redacted_display_output
                    .as_ref()
                    .map(|output| output.body.clone()),
                redacted_display_generics: redacted_display_output
                    .as_ref()
                    .map(|output| output.display_generics.clone())
                    .unwrap_or_default(),
                redacted_display_debug_generics: redacted_display_output
                    .as_ref()
                    .map(|output| output.debug_generics.clone())
                    .unwrap_or_default(),
                redacted_display_clone_generics: redacted_display_output
                    .as_ref()
                    .map(|output| output.clone_generics.clone())
                    .unwrap_or_default(),
                redacted_display_nested_generics: redacted_display_output
                    .as_ref()
                    .map(|output| output.nested_generics.clone())
                    .unwrap_or_default(),
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
    let redacted_display_impl = if matches!(slog_mode, SlogMode::RedactableErrorString) {
        let redacted_display_generics =
            add_display_bounds(generics.clone(), &derive_output.redacted_display_generics);
        let redacted_display_generics = add_debug_bounds(
            redacted_display_generics,
            &derive_output.redacted_display_debug_generics,
        );
        let redacted_display_generics = add_clone_bounds(
            redacted_display_generics,
            &derive_output.redacted_display_clone_generics,
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
            impl #display_impl_generics #crate_root::RedactableError for #ident #display_ty_generics #display_where_clause {
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
                }
            }
            SlogMode::RedactableErrorString => {
                slog_where_clause
                    .predicates
                    .push(parse_quote!(#self_ty: #crate_root::RedactableError));
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
                            let redacted = #crate_root::RedactableError::redacted_error(self);
                            serializer.emit_arguments(key, &format_args!("{}", redacted))
                        }
                    }
                }
            }
        }
    };

    #[cfg(not(feature = "slog"))]
    let slog_impl = quote! {};

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

        // `slog` already provides `impl<V: Value> Value for &V`, so a reference
        // impl here would conflict with the blanket impl.
    };
    Ok(trait_impl)
}
