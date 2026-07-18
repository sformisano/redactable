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
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use syn::{
    Data, DataEnum, DataStruct, DeriveInput, Fields, Result, parse_macro_input, parse_quote,
    spanned::Spanned,
};

mod container;
mod derive_enum;
mod derive_struct;
mod fresh_ident;
mod generics;
mod redacted_display;
mod strategy;
mod transform;
use container::{ContainerOptions, parse_container_options, reject_field_only_container_attrs};
use derive_enum::derive_enum;
use derive_struct::derive_struct;
use fresh_ident::FreshIdentAllocator;
use generics::{add_predicates, push_debug_predicate};
use redacted_display::derive_redacted_display;
use strategy::parse_redactable_field_options;

/// Derives `redactable::RedactableWithMapper` (and related impls) for structs and enums.
///
/// # Container Attributes
///
/// These attributes are placed on the struct/enum itself:
///
/// `Sensitive` and `SensitiveDisplay` are standalone derives. Use `SensitiveDual` when a type
/// needs both structural and display redaction.
///
/// Use `#[redactable(recursive)]` on a field whose crate-qualified, aliased, or
/// mutually recursive type would otherwise create a self-referential inferred
/// bound. Unannotated fields retain their exact complete-type bounds.
/// `#[redactable(legacy_formatting)]` and `#[redactable(generated_formatting)]`
/// are display-only formatting options; standalone `Sensitive` rejects **both**.
/// Apply them on `SensitiveDisplay` or `SensitiveDual` (which is what to use when
/// a type needs structural and display redaction together); those derives
/// document what each option selects.
///
/// # Field Attributes
///
/// - **No annotation**: The field is traversed by default. Scalars pass through unchanged; nested
///   structs/enums are walked using `RedactableWithMapper` (so external types must implement it).
///
/// - `#[sensitive(Secret)]`: For scalar types (i32, bool, char, etc.), redacts to default values
///   (0, false, '*'). For string-like types, applies full redaction to `"[REDACTED]"`.
///
/// - `#[sensitive(Policy)]`: Applies the policy's redaction rules to string-like
///   values. Works for `String`, `Option<String>`, `Vec<String>`, `Box<String>`. Scalars can only
///   use `#[sensitive(Secret)]`.
///
/// - `#[not_sensitive]`: Explicit passthrough - the field is not transformed at all. Use this
///   for foreign types that don't implement `RedactableWithMapper`. This is equivalent to wrapping
///   the field type in `NotSensitiveValue<T>`, but without changing the type signature.
///
/// Unions are rejected at compile time.
///
/// # Generated Impls
///
/// - `RedactableWithMapper`: always generated.
/// - `Redactable`: always generated. Provides `.redact()` and certifies the type for the
///   redacted-output extension traits (`RedactedOutputExt`, `RedactedJsonExt`, `SlogRedactedExt`).
/// - `Debug`: redacted by default; actual values in the consumer's `cfg(test)` builds or when
///   `redactable`'s `testing` feature is enabled.
/// - `slog::Value` + `SlogRedacted` (requires `slog` feature): borrowed generated output is a
///   fixed fail-closed placeholder and never clones or serializes the raw reference. Owned values
///   can use `SlogRedactedExt::slog_redacted_json` for redact-then-serialize structured output.
/// - `TracingRedacted` (requires `tracing` feature): marker trait.
#[proc_macro_derive(Sensitive, attributes(sensitive, not_sensitive, redactable))]
pub fn derive_sensitive_container(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(input, DeriveKind::Sensitive) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.into_compile_error().into(),
    }
}

/// Derives structural and display redaction as one authenticated expansion.
///
/// Use this instead of combining `Sensitive` and `SensitiveDisplay` with the
/// legacy `#[sensitive(dual)]` coordination attribute.
#[proc_macro_derive(SensitiveDual, attributes(sensitive, not_sensitive, redactable, error))]
pub fn derive_sensitive_dual(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let sensitive = expand_with_mode(input.clone(), DeriveKind::Sensitive, true);
    let display = expand_with_mode(input, DeriveKind::SensitiveDisplay, true);
    match (sensitive, display) {
        (Ok(sensitive), Ok(display)) => quote!(#sensitive #display).into(),
        (Err(mut first), Err(second)) => {
            first.combine(second);
            first.into_compile_error().into()
        }
        (Err(err), _) | (_, Err(err)) => err.into_compile_error().into(),
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
/// - `Redactable`: deriving `NotSensitive` is an explicit declaration, so the type is
///   certified for consuming and borrowed adapters. Generated slog serialization borrows rather
///   than clones; serde's `RefCell` implementation
///   reports an active mutable borrow as an error, which is converted to `"[REDACTED]"`.
/// - `slog::Value` and `SlogRedacted` (behind `cfg(feature = "slog")`): serializes the explicitly
///   non-sensitive value directly as structured JSON. Requires `Serialize` on the type.
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
#[proc_macro_derive(NotSensitive, attributes(sensitive, not_sensitive))]
pub fn derive_not_sensitive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand_not_sensitive(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.into_compile_error().into(),
    }
}

/// Rejects `#[sensitive]` and `#[not_sensitive]` attributes on a non-sensitive type.
///
/// Checks container-level, variant-level, and field-level attributes. `#[sensitive]`
/// is wrong because the type is explicitly non-sensitive; `#[not_sensitive]` is
/// redundant because the entire type is already non-sensitive.
fn reject_sensitivity_attrs(attrs: &[syn::Attribute], data: &Data, macro_name: &str) -> Result<()> {
    let check_attr = |attr: &syn::Attribute| -> Result<()> {
        if attr.path().is_ident("sensitive") {
            return Err(syn::Error::new(
                attr.span(),
                format!("`#[sensitive]` attributes are not allowed on `{macro_name}` types"),
            ));
        }
        if attr.path().is_ident("not_sensitive") {
            return Err(syn::Error::new(
                attr.span(),
                format!(
                    "`#[not_sensitive]` attributes are not needed on `{macro_name}` types (the entire type is already non-sensitive)"
                ),
            ));
        }
        Ok(())
    };

    for attr in attrs {
        check_attr(attr)?;
    }

    match data {
        Data::Struct(data) => {
            for field in &data.fields {
                for attr in &field.attrs {
                    check_attr(attr)?;
                }
            }
        }
        Data::Enum(data) => {
            for variant in &data.variants {
                for attr in &variant.attrs {
                    check_attr(attr)?;
                }
                for field in &variant.fields {
                    for attr in &field.attrs {
                        check_attr(attr)?;
                    }
                }
            }
        }
        Data::Union(_) => {}
    }

    Ok(())
}

fn expand_not_sensitive(input: DeriveInput) -> Result<TokenStream> {
    let mut fresh = FreshIdentAllocator::new(&input);
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

    reject_sensitivity_attrs(&attrs, &data, "NotSensitive")?;

    let crate_root = crate_root();
    let mapper_type = fresh.fresh("__RedactableMapper");
    let mapper = fresh.fresh("__redactable_mapper");

    // RedactableWithMapper impl (no-op passthrough). Deriving NotSensitive is
    // an explicit declaration, so the type also gets Redactable.
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let container_impl = quote! {
        impl #impl_generics #crate_root::RedactableWithMapper for #ident #ty_generics #where_clause {
            fn redact_with<#mapper_type: #crate_root::RedactableMapper>(self, #mapper: &#mapper_type) -> Self {
                self
            }
        }

        impl #impl_generics #crate_root::Redactable for #ident #ty_generics #where_clause {}
    };

    // slog impl - serialize directly as structured JSON (no redaction needed)
    #[cfg(feature = "slog")]
    let slog_impl = {
        let record = fresh.fresh("__redactable_record");
        let key = fresh.fresh("key");
        let serializer = fresh.fresh("serializer");
        let slog_crate = quote! { #crate_root::__private::slog };
        let mut slog_generics = generics.clone();
        let (_, ty_generics, _) = slog_generics.split_for_impl();
        let self_ty: syn::Type = parse_quote!(#ident #ty_generics);
        slog_generics
            .make_where_clause()
            .predicates
            .push(parse_quote!(#self_ty: #crate_root::__private::serde::Serialize));
        let (slog_impl_generics, slog_ty_generics, slog_where_clause) =
            slog_generics.split_for_impl();
        quote! {
            impl #slog_impl_generics #slog_crate::Value for #ident #slog_ty_generics #slog_where_clause {
                fn serialize(
                    &self,
                    #record: &#slog_crate::Record<'_>,
                    #key: #slog_crate::Key,
                    #serializer: &mut dyn #slog_crate::Serializer,
                ) -> #slog_crate::Result {
                    #crate_root::slog::__slog_serialize_not_sensitive(self, #record, #key, #serializer)
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

    let generated = quote! {
        #container_impl
        #slog_impl
        #tracing_impl
    };
    Ok(isolate_generated_items(generated, &fresh))
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
/// - `Redactable`: deriving `NotSensitiveDisplay` is an explicit declaration, so the type is
///   certified for consuming and borrowed adapters.
/// - `RedactableWithFormatter`: delegates to `Display::fmt`
/// - `ToRedactedOutput`: emits the `Display` text; certifies the type for
///   `slog_redacted_display()` and `tracing_redacted()`
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
/// use std::fmt;
///
/// #[derive(NotSensitiveDisplay)]
/// enum RetryDecision {
///     Retry,
///     Abort,
/// }
///
/// impl fmt::Display for RetryDecision {
///     fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
///         formatter.write_str(match self {
///             Self::Retry => "Retry",
///             Self::Abort => "Abort",
///         })
///     }
/// }
///
/// assert_eq!(RetryDecision::Retry.to_string(), "Retry");
/// ```
#[proc_macro_derive(NotSensitiveDisplay, attributes(sensitive, not_sensitive))]
pub fn derive_not_sensitive_display(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand_not_sensitive_display(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.into_compile_error().into(),
    }
}

fn expand_not_sensitive_display(input: DeriveInput) -> Result<TokenStream> {
    let mut fresh = FreshIdentAllocator::new(&input);
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

    reject_sensitivity_attrs(&attrs, &data, "NotSensitiveDisplay")?;

    let crate_root = crate_root();
    let mapper_type = fresh.fresh("__RedactableMapper");
    let mapper = fresh.fresh("__redactable_mapper");
    let formatter = fresh.fresh("__redactable_f");

    let (container_impl, redacted_display_impl) = not_sensitive_display_core_impls(
        &ident,
        &generics,
        &crate_root,
        &mapper_type,
        &mapper,
        &formatter,
    );

    // tracing impl - uses the original generics (no extra Display bounds needed for marker trait)
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

    // slog impl
    #[cfg(feature = "slog")]
    let slog_impl = {
        let record = fresh.fresh("__redactable_record");
        let key = fresh.fresh("key");
        let serializer = fresh.fresh("serializer");
        let redacted = fresh.fresh("__redactable_value");
        let slog_crate = quote! { #crate_root::__private::slog };
        let mut slog_generics = generics;
        let (_, ty_generics, _) = slog_generics.split_for_impl();
        let self_ty: syn::Type = syn::parse_quote!(#ident #ty_generics);
        slog_generics
            .make_where_clause()
            .predicates
            .push(syn::parse_quote!(#self_ty: #crate_root::RedactableWithFormatter));
        let (slog_impl_generics, slog_ty_generics, slog_where_clause) =
            slog_generics.split_for_impl();
        quote! {
            impl #slog_impl_generics #slog_crate::Value for #ident #slog_ty_generics #slog_where_clause {
                fn serialize(
                    &self,
                    #record: &#slog_crate::Record<'_>,
                    #key: #slog_crate::Key,
                    #serializer: &mut dyn #slog_crate::Serializer,
                ) -> #slog_crate::Result {
                    let #redacted = #crate_root::RedactableWithFormatter::redacted_display(self);
                    #serializer.emit_arguments(#key, &format_args!("{}", #redacted))
                }
            }

            impl #slog_impl_generics #crate_root::slog::SlogRedacted for #ident #slog_ty_generics #slog_where_clause {}
        }
    };

    #[cfg(not(feature = "slog"))]
    let slog_impl = quote! {};

    let generated = quote! {
        #container_impl
        #redacted_display_impl
        #slog_impl
        #tracing_impl
    };
    Ok(isolate_generated_items(generated, &fresh))
}

fn not_sensitive_display_core_impls(
    ident: &Ident,
    generics: &syn::Generics,
    crate_root: &TokenStream,
    mapper_type: &Ident,
    mapper: &Ident,
    formatter: &Ident,
) -> (TokenStream, TokenStream) {
    let (container_impl_generics, container_ty_generics, container_where_clause) =
        generics.split_for_impl();
    let container_impl = quote! {
        impl #container_impl_generics #crate_root::RedactableWithMapper for #ident #container_ty_generics #container_where_clause {
            fn redact_with<#mapper_type: #crate_root::RedactableMapper>(self, #mapper: &#mapper_type) -> Self {
                self
            }
        }

        impl #container_impl_generics #crate_root::Redactable for #ident #container_ty_generics #container_where_clause {}
    };

    let mut display_generics = generics.clone();
    let (_, display_ty, _) = generics.split_for_impl();
    let display_self_ty: syn::Type = parse_quote!(#ident #display_ty);
    display_generics
        .make_where_clause()
        .predicates
        .push(parse_quote!(#display_self_ty: ::core::fmt::Display));
    let (display_impl_generics, display_ty_generics, display_where_clause) =
        display_generics.split_for_impl();
    let redacted_display_impl = quote! {
        impl #display_impl_generics #crate_root::RedactableWithFormatter for #ident #display_ty_generics #display_where_clause {
            fn fmt_redacted(&self, #formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Display::fmt(self, #formatter)
            }
        }

        impl #display_impl_generics #crate_root::ToRedactedOutput for #ident #display_ty_generics #display_where_clause {
            fn to_redacted_output(&self) -> #crate_root::RedactedOutput {
                #crate_root::RedactedOutput::Text(
                    ::std::string::ToString::to_string(
                        &#crate_root::RedactableWithFormatter::redacted_display(self),
                    ),
                )
            }
        }
    };

    (container_impl, redacted_display_impl)
}

/// Derives `redactable::RedactableWithFormatter` using a display template.
///
/// This generates a redacted string representation without requiring `Clone`.
/// Unannotated fields use `RedactableWithFormatter` by default (passthrough for scalars,
/// redacted display for nested `SensitiveDisplay` types).
///
/// # Field Annotations
///
/// - *(none)*: Uses `RedactableWithFormatter` (requires the field type to implement it)
/// - `#[sensitive(Policy)]`: Apply the policy's redaction rules
/// - `#[not_sensitive]`: Render raw via `Display` (use for types without `RedactableWithFormatter`)
///
/// The display template is taken from `#[error("...")]` (thiserror-style) or from
/// doc comments (displaydoc-style). If neither is present, the derive fails.
///
/// Fields are redacted by reference, so field types do not need `Clone`.
/// A custom `PolicyApplicableRef` leaf nested inside a container can explicitly
/// select its ordinary borrowed projection with
/// `#[redactable(legacy_formatting)]`. The explicit route does not require the
/// direct-leaf formatting marker; it requires `PolicyApplicableRef` on the whole
/// field and the selected format capability on its output. It inherits the
/// projection's `Clone` requirements and borrow behavior; library-owned fields
/// should stay on the default conflict-safe route. It composes with
/// `#[redactable(recursive)]`, retaining the projection/output bounds while
/// suppressing the cyclic inferred field bound.
///
/// `#[redactable(generated_formatting)]` instead selects the library-owned
/// recursive formatter for an alias-hidden or otherwise ambiguous container
/// field. `legacy_formatting` and `generated_formatting` are mutually exclusive,
/// and standalone `Sensitive` rejects both (they only affect display output).
///
/// Use `SensitiveDual` instead when the same type also needs structural redaction.
///
/// # Generated Impls
///
/// - `RedactableWithFormatter`: always generated.
/// - `ToRedactedOutput`: always generated; emits the redacted display text and certifies the
///   type for `slog_redacted_display()` and `tracing_redacted()`.
/// - `Debug`: redacted by default; actual values in the consumer's `cfg(test)` builds or when
///   `redactable`'s `testing` feature is enabled.
/// - `slog::Value` + `SlogRedacted`: emits the redacted display string (requires `slog` feature).
/// - `TracingRedacted`: marker trait (requires `tracing` feature).
#[proc_macro_derive(
    SensitiveDisplay,
    attributes(sensitive, not_sensitive, redactable, error)
)]
pub fn derive_sensitive_display(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(input, DeriveKind::SensitiveDisplay) {
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
            let ident = dependency_crate_ident(&name);
            quote! { ::#ident }
        }
        Err(_) => quote! { ::redactable },
    }
}

/// Converts a Cargo dependency key into a Rust path identifier without panicking.
///
/// Cargo permits aliases that are Rust keywords. Those aliases must be emitted as
/// raw identifiers (`r#type`) in generated paths.
fn dependency_crate_ident(name: &str) -> Ident {
    syn::parse_str::<Ident>(name)
        .or_else(|_| syn::parse_str::<Ident>(&format!("r#{name}")))
        .unwrap_or_else(|_| Ident::new("__redactable_invalid_dependency_alias", Span::call_site()))
}

fn crate_path(item: &str) -> proc_macro2::TokenStream {
    let root = crate_root();
    let item_ident = syn::parse_str::<syn::Path>(item).expect("redactable crate path should parse");
    quote! { #root::#item_ident }
}

/// Isolates generated binders from unrelated caller-scope constants.
///
/// Rust treats a same-named constant as a const pattern instead of a new function
/// parameter binding. Local function items occupy the value namespace without being
/// const patterns, so generated bindings can safely shadow them. The anonymous const
/// gives every derive expansion its own item scope and still supports local types.
fn isolate_generated_items(generated: TokenStream, fresh: &FreshIdentAllocator) -> TokenStream {
    let value_shadows = fresh.allocated();
    quote! {
        const _: () = {
            #(#[allow(dead_code, non_snake_case)] fn #value_shadows() {})*
            #generated
        };
    }
}

/// Output produced by struct/enum derive logic for `Sensitive`.
///
/// Shared by `derive_struct`, `derive_enum`, and the top-level `expand()`.
pub(crate) struct DeriveOutput {
    pub(crate) redaction_body: TokenStream,
    pub(crate) used_generics: Vec<syn::WherePredicate>,
    pub(crate) policy_applicable_generics: Vec<syn::WherePredicate>,
    pub(crate) debug_redacted_body: TokenStream,
    pub(crate) debug_unredacted_body: TokenStream,
    pub(crate) debug_unredacted_generics: Vec<syn::WherePredicate>,
}

struct DebugOutput {
    body: TokenStream,
    generics: Vec<syn::WherePredicate>,
}

/// Which derive macro invoked `expand()`.
///
/// Controls what impls are generated: `Sensitive` emits `RedactableWithMapper` (structural
/// traversal), while `SensitiveDisplay` emits `RedactableWithFormatter` (display formatting).
enum DeriveKind {
    /// `#[derive(Sensitive)]` — structural redaction via `RedactableWithMapper`.
    Sensitive,
    /// `#[derive(SensitiveDisplay)]` — display formatting via `RedactableWithFormatter`.
    SensitiveDisplay,
}

#[allow(clippy::too_many_lines)]
fn expand(input: DeriveInput, kind: DeriveKind) -> Result<TokenStream> {
    expand_with_mode(input, kind, false)
}

#[allow(clippy::too_many_lines)]
fn expand_with_mode(
    input: DeriveInput,
    kind: DeriveKind,
    authenticated_dual: bool,
) -> Result<TokenStream> {
    let mut fresh = FreshIdentAllocator::new(&input);
    let DeriveInput {
        ident,
        generics,
        data,
        attrs,
        ..
    } = input;

    reject_field_only_container_attrs(&attrs)?;
    let ContainerOptions {
        dual: requested_dual,
    } = parse_container_options(&attrs)?;
    if requested_dual && !authenticated_dual {
        return Err(syn::Error::new(
            ident.span(),
            "`#[sensitive(dual)]` is no longer accepted on `Sensitive` or `SensitiveDisplay`; use `#[derive(SensitiveDual)]` instead",
        ));
    }
    if matches!(&kind, DeriveKind::Sensitive) && !authenticated_dual {
        reject_display_only_field_options(&data)?;
    }
    let dual = authenticated_dual;
    let crate_root = crate_root();
    let formatter = fresh.fresh("__redactable_f");
    let mapper = fresh.fresh("__redactable_mapper");
    let mapper_type = fresh.fresh("__RedactableMapper");

    if matches!(kind, DeriveKind::SensitiveDisplay) {
        let redacted_display_output =
            derive_redacted_display(&ident, &data, &attrs, &generics, &formatter, &mut fresh)?;
        let redacted_display_generics = add_predicates(
            generics.clone(),
            &redacted_display_output.display_generics,
            &ident,
        );
        let redacted_display_generics = add_predicates(
            redacted_display_generics,
            &redacted_display_output.debug_generics,
            &ident,
        );
        let redacted_display_generics = add_predicates(
            redacted_display_generics,
            &redacted_display_output.policy_ref_generics,
            &ident,
        );
        let redacted_display_generics = add_predicates(
            redacted_display_generics,
            &redacted_display_output.nested_generics,
            &ident,
        );
        let (display_impl_generics, display_ty_generics, display_where_clause) =
            redacted_display_generics.split_for_impl();
        let redacted_display_body = redacted_display_output.body;
        let redacted_display_impl = quote! {
            impl #display_impl_generics #crate_root::RedactableWithFormatter for #ident #display_ty_generics #display_where_clause {
                fn fmt_redacted(&self, #formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    #redacted_display_body
                }
            }
        };
        let to_redacted_output_impl = quote! {
            impl #display_impl_generics #crate_root::ToRedactedOutput for #ident #display_ty_generics #display_where_clause {
                fn to_redacted_output(&self) -> #crate_root::RedactedOutput {
                    #crate_root::RedactedOutput::Text(
                        ::std::string::ToString::to_string(
                            &#crate_root::RedactableWithFormatter::redacted_display(self),
                        ),
                    )
                }
            }
        };

        let debug_output =
            derive_unredacted_debug(&ident, &data, &generics, &formatter, &mut fresh)?;
        // A single impl branches at runtime on `cfg!(test) || redactable::__TESTING`
        // rather than emitting two `#[cfg]`-gated impls. The `feature = "testing"`
        // check must resolve against `redactable`'s own feature, not the consumer's,
        // so it is routed through the `__TESTING` constant. The where-clause is the
        // union of the formatter bounds (redacted body) and the Debug bounds
        // (unredacted body) because both bodies live in the same impl.
        let debug_generics = add_predicates(
            redacted_display_generics.clone(),
            &debug_output.generics,
            &ident,
        );
        let (debug_impl_generics, debug_ty_generics, debug_where_clause) =
            debug_generics.split_for_impl();
        let debug_unredacted_body = debug_output.body;
        let debug_impl = quote! {
            impl #debug_impl_generics ::core::fmt::Debug for #ident #debug_ty_generics #debug_where_clause {
                fn fmt(&self, #formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    if ::core::cfg!(test) || #crate_root::__TESTING {
                        #debug_unredacted_body
                    } else {
                        #crate_root::RedactableWithFormatter::fmt_redacted(self, #formatter)
                    }
                }
            }
        };

        // In dual mode, Sensitive provides slog and tracing impls — skip them here.
        let slog_impl = if dual {
            quote! {}
        } else {
            #[cfg(feature = "slog")]
            {
                let record = fresh.fresh("__redactable_record");
                let key = fresh.fresh("key");
                let serializer = fresh.fresh("serializer");
                let redacted = fresh.fresh("__redactable_value");
                let slog_crate = quote! { #crate_root::__private::slog };
                let mut slog_generics = generics;
                let (_, ty_generics, _) = slog_generics.split_for_impl();
                let self_ty: syn::Type = parse_quote!(#ident #ty_generics);
                slog_generics
                    .make_where_clause()
                    .predicates
                    .push(parse_quote!(#self_ty: #crate_root::RedactableWithFormatter));
                let (slog_impl_generics, slog_ty_generics, slog_where_clause) =
                    slog_generics.split_for_impl();
                quote! {
                    impl #slog_impl_generics #slog_crate::Value for #ident #slog_ty_generics #slog_where_clause {
                        fn serialize(
                            &self,
                            #record: &#slog_crate::Record<'_>,
                            #key: #slog_crate::Key,
                            #serializer: &mut dyn #slog_crate::Serializer,
                        ) -> #slog_crate::Result {
                            let #redacted = #crate_root::RedactableWithFormatter::redacted_display(self);
                            #serializer.emit_arguments(#key, &format_args!("{}", #redacted))
                        }
                    }

                    impl #slog_impl_generics #crate_root::slog::SlogRedacted for #ident #slog_ty_generics #slog_where_clause {}
                }
            }

            #[cfg(not(feature = "slog"))]
            {
                quote! {}
            }
        };

        let tracing_impl = if dual {
            quote! {}
        } else {
            #[cfg(feature = "tracing")]
            {
                let (tracing_impl_generics, tracing_ty_generics, tracing_where_clause) =
                    redacted_display_generics.split_for_impl();
                quote! {
                    impl #tracing_impl_generics #crate_root::tracing::TracingRedacted for #ident #tracing_ty_generics #tracing_where_clause {}
                }
            }

            #[cfg(not(feature = "tracing"))]
            {
                quote! {}
            }
        };

        let generated = quote! {
            #redacted_display_impl
            #to_redacted_output_impl
            #debug_impl
            #slog_impl
            #tracing_impl
        };
        return Ok(isolate_generated_items(generated, &fresh));
    }

    // Only DeriveKind::Sensitive reaches this point (SensitiveDisplay returns early above).

    let derive_output = match data {
        Data::Struct(data) => {
            derive_struct(&ident, data, &generics, &formatter, &mapper, &mut fresh)?
        }
        Data::Enum(data) => derive_enum(&ident, data, &generics, &formatter, &mapper, &mut fresh)?,
        Data::Union(u) => {
            return Err(syn::Error::new(
                u.union_token.span(),
                "`Sensitive` cannot be derived for unions",
            ));
        }
    };

    let policy_generics = add_predicates(generics.clone(), &derive_output.used_generics, &ident);
    let policy_generics = add_predicates(
        policy_generics,
        &derive_output.policy_applicable_generics,
        &ident,
    );
    let (impl_generics, ty_generics, where_clause) = policy_generics.split_for_impl();
    #[cfg(feature = "slog")]
    let slog_base_generics = generics.clone();
    // The merged Debug impl uses the unredacted bounds (a superset of the
    // redacted bounds) because both bodies share one impl.
    let debug_unredacted_generics =
        add_predicates(generics, &derive_output.debug_unredacted_generics, &ident);
    let (
        debug_unredacted_impl_generics,
        debug_unredacted_ty_generics,
        debug_unredacted_where_clause,
    ) = debug_unredacted_generics.split_for_impl();
    let redaction_body = &derive_output.redaction_body;
    let debug_redacted_body = &derive_output.debug_redacted_body;
    let debug_unredacted_body = &derive_output.debug_unredacted_body;
    // In dual mode, SensitiveDisplay provides Debug — skip it here.
    //
    // A single impl branches at runtime on `cfg!(test) || redactable::__TESTING`
    // rather than emitting two `#[cfg]`-gated impls. The `feature = "testing"`
    // check must resolve against `redactable`'s own feature, not the consumer's,
    // so it is routed through the `__TESTING` constant. The where-clause uses the
    // unredacted bounds (a superset of the redacted bounds) because both bodies
    // live in the same impl.
    let debug_impl = if dual {
        quote! {}
    } else {
        quote! {
            impl #debug_unredacted_impl_generics ::core::fmt::Debug for #ident #debug_unredacted_ty_generics #debug_unredacted_where_clause {
                fn fmt(&self, #formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    if ::core::cfg!(test) || #crate_root::__TESTING {
                        #debug_unredacted_body
                    } else {
                        #debug_redacted_body
                    }
                }
            }
        }
    };

    #[cfg(feature = "slog")]
    let slog_impl = {
        let record = fresh.fresh("__redactable_record");
        let key = fresh.fresh("key");
        let serializer = fresh.fresh("serializer");
        let redacted = fresh.fresh("__redactable_value");
        let slog_crate = quote! { #crate_root::__private::slog };
        let slog_generics = slog_base_generics;
        let (slog_impl_generics, slog_ty_generics, slog_where_clause) =
            slog_generics.split_for_impl();
        quote! {
            impl #slog_impl_generics #slog_crate::Value for #ident #slog_ty_generics #slog_where_clause {
                fn serialize(
                    &self,
                    #record: &#slog_crate::Record<'_>,
                    #key: #slog_crate::Key,
                    #serializer: &mut dyn #slog_crate::Serializer,
                ) -> #slog_crate::Result {
                    // `slog::Value` receives only `&self`. Stable Rust cannot prove
                    // that cloning or serializing that reference is observation-free
                    // for arbitrary fields, so generated borrowed logging fails closed.
                    // Callers that own the value can opt into structured output with
                    // `SlogRedactedExt::slog_redacted_json`.
                    let #redacted = #crate_root::__private::generated_redacted_json(
                        #crate_root::__private::serde_json::Value::String(
                            <::std::string::String as ::core::convert::From<&str>>::from(
                                #crate_root::REDACTED_PLACEHOLDER,
                            ),
                        ),
                    );
                    #slog_crate::Value::serialize(&#redacted, #record, #key, #serializer)
                }
            }

            impl #slog_impl_generics #crate_root::slog::SlogRedacted for #ident #slog_ty_generics #slog_where_clause {}
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
        impl #impl_generics #crate_root::RedactableWithMapper for #ident #ty_generics #where_clause {
            fn redact_with<#mapper_type: #crate_root::RedactableMapper>(self, #mapper: &#mapper_type) -> Self {
                use #crate_root::RedactableWithMapper as _;
                #redaction_body
            }
        }

        impl #impl_generics #crate_root::Redactable for #ident #ty_generics #where_clause {}

        #debug_impl

        #slog_impl

        #tracing_impl

    };
    Ok(isolate_generated_items(trait_impl, &fresh))
}

/// Rejects formatting-only field options when no display derive consumes them.
fn reject_display_only_field_options(data: &Data) -> Result<()> {
    fn check_field(field: &syn::Field) -> Result<()> {
        let options = parse_redactable_field_options(&field.attrs)?;
        if options.legacy_formatting || options.generated_formatting {
            let span = field
                .attrs
                .iter()
                .find(|attr| attr.path().is_ident("redactable"))
                .map_or_else(|| field.span(), Spanned::span);
            return Err(syn::Error::new(
                span,
                "formatting route overrides are only used by `SensitiveDisplay`; use `SensitiveDual` when structural and display redaction are both needed",
            ));
        }
        Ok(())
    }

    fn check_fields(fields: &Fields) -> Result<()> {
        for field in fields {
            check_field(field)?;
        }
        Ok(())
    }

    match data {
        Data::Struct(data) => check_fields(&data.fields),
        Data::Enum(data) => {
            for variant in &data.variants {
                check_fields(&variant.fields)?;
            }
            Ok(())
        }
        Data::Union(data) => {
            for field in &data.fields.named {
                check_field(field)?;
            }
            Ok(())
        }
    }
}

fn derive_unredacted_debug(
    name: &Ident,
    data: &Data,
    _generics: &syn::Generics,
    formatter: &Ident,
    fresh: &mut FreshIdentAllocator,
) -> Result<DebugOutput> {
    match data {
        Data::Struct(data) => derive_unredacted_debug_struct(name, data, formatter, fresh),
        Data::Enum(data) => derive_unredacted_debug_enum(name, data, formatter, fresh),
        Data::Union(u) => Err(syn::Error::new(
            u.union_token.span(),
            "`SensitiveDisplay` cannot be derived for unions",
        )),
    }
}

fn derive_unredacted_debug_struct(
    name: &Ident,
    data: &DataStruct,
    formatter: &Ident,
    fresh: &mut FreshIdentAllocator,
) -> Result<DebugOutput> {
    let debug = fresh.fresh("__redactable_debug");
    let mut debug_generics = Vec::new();
    match &data.fields {
        Fields::Named(fields) => {
            let mut patterns = Vec::new();
            let mut debug_fields = Vec::new();
            for field in &fields.named {
                let ident = field
                    .ident
                    .clone()
                    .expect("named field should have identifier");
                let binding = fresh.fresh_with_ident("__redactable_field_", &ident);
                patterns.push(quote! { #ident: #binding });
                let options = parse_redactable_field_options(&field.attrs)?;
                if !options.recursive || options.legacy_formatting || options.generated_formatting {
                    push_debug_predicate(&mut debug_generics, &field.ty);
                }
                debug_fields.push(quote! {
                    #debug.field(stringify!(#ident), #binding);
                });
            }
            Ok(DebugOutput {
                body: quote! {
                    match self {
                        Self { #(#patterns),* } => {
                            let mut #debug = #formatter.debug_struct(stringify!(#name));
                            #(#debug_fields)*
                            #debug.finish()
                        }
                    }
                },
                generics: debug_generics,
            })
        }
        Fields::Unnamed(fields) => {
            let mut bindings = Vec::new();
            let mut debug_fields = Vec::new();
            for (index, field) in fields.unnamed.iter().enumerate() {
                let ident = fresh.fresh(&format!("field_{index}"));
                bindings.push(ident.clone());
                let options = parse_redactable_field_options(&field.attrs)?;
                if !options.recursive || options.legacy_formatting || options.generated_formatting {
                    push_debug_predicate(&mut debug_generics, &field.ty);
                }
                debug_fields.push(quote! {
                    #debug.field(#ident);
                });
            }
            Ok(DebugOutput {
                body: quote! {
                    match self {
                        Self ( #(#bindings),* ) => {
                            let mut #debug = #formatter.debug_tuple(stringify!(#name));
                            #(#debug_fields)*
                            #debug.finish()
                        }
                    }
                },
                generics: debug_generics,
            })
        }
        Fields::Unit => Ok(DebugOutput {
            body: quote! {
                #formatter.write_str(stringify!(#name))
            },
            generics: debug_generics,
        }),
    }
}

fn derive_unredacted_debug_enum(
    name: &Ident,
    data: &DataEnum,
    formatter: &Ident,
    fresh: &mut FreshIdentAllocator,
) -> Result<DebugOutput> {
    let debug = fresh.fresh("__redactable_debug");
    let mut debug_generics = Vec::new();
    let mut debug_arms = Vec::new();
    for variant in &data.variants {
        let variant_ident = &variant.ident;
        let debug_name = quote! { concat!(stringify!(#name), "::", stringify!(#variant_ident)) };
        match &variant.fields {
            Fields::Unit => {
                debug_arms.push(quote! {
                    #name::#variant_ident => #formatter.write_str(#debug_name)
                });
            }
            Fields::Named(fields) => {
                let mut patterns = Vec::new();
                let mut debug_fields = Vec::new();
                for field in &fields.named {
                    let ident = field
                        .ident
                        .clone()
                        .expect("named field should have identifier");
                    let binding = fresh.fresh_with_ident("__redactable_field_", &ident);
                    patterns.push(quote! { #ident: #binding });
                    let options = parse_redactable_field_options(&field.attrs)?;
                    if !options.recursive
                        || options.legacy_formatting
                        || options.generated_formatting
                    {
                        push_debug_predicate(&mut debug_generics, &field.ty);
                    }
                    debug_fields.push(quote! {
                        #debug.field(stringify!(#ident), #binding);
                    });
                }
                debug_arms.push(quote! {
                    #name::#variant_ident { #(#patterns),* } => {
                        let mut #debug = #formatter.debug_struct(#debug_name);
                        #(#debug_fields)*
                        #debug.finish()
                    }
                });
            }
            Fields::Unnamed(fields) => {
                let mut bindings = Vec::new();
                let mut debug_fields = Vec::new();
                for (index, field) in fields.unnamed.iter().enumerate() {
                    let ident = fresh.fresh(&format!("field_{index}"));
                    bindings.push(ident.clone());
                    let options = parse_redactable_field_options(&field.attrs)?;
                    if !options.recursive
                        || options.legacy_formatting
                        || options.generated_formatting
                    {
                        push_debug_predicate(&mut debug_generics, &field.ty);
                    }
                    debug_fields.push(quote! {
                        #debug.field(#ident);
                    });
                }
                debug_arms.push(quote! {
                    #name::#variant_ident ( #(#bindings),* ) => {
                        let mut #debug = #formatter.debug_tuple(#debug_name);
                        #(#debug_fields)*
                        #debug.finish()
                    }
                });
            }
        }
    }
    let body = if debug_arms.is_empty() {
        quote! { match *self {} }
    } else {
        quote! {
            match self {
                #(#debug_arms),*
            }
        }
    };
    Ok(DebugOutput {
        body,
        generics: debug_generics,
    })
}

#[cfg(all(test, feature = "slog"))]
mod generated_dependency_tests;

#[cfg(all(test, feature = "slog"))]
#[test]
fn structural_generated_dependency_roots() {
    generated_dependency_tests::run_structural_generated_dependency_roots();
}

#[cfg(test)]
mod crate_alias_tests {
    use super::dependency_crate_ident;

    #[test]
    fn keyword_dependency_alias_becomes_raw_identifier() {
        assert_eq!(dependency_crate_ident("type").to_string(), "r#type");
        assert_eq!(dependency_crate_ident("renamed").to_string(), "renamed");
    }
}
