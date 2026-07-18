//! `NotSensitive` and `NotSensitiveDisplay` expansion.
//!
//! This module emits the no-op redaction impls and logging integration for types
//! that are explicitly declared free of sensitive data.

use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::{Data, DeriveInput, Result, parse_quote, spanned::Spanned};

use crate::{
    crate_paths::{crate_root, isolate_generated_items},
    fresh_ident::FreshIdentAllocator,
};

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

pub(crate) fn expand_not_sensitive(input: DeriveInput) -> Result<TokenStream> {
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

pub(crate) fn expand_not_sensitive_display(input: DeriveInput) -> Result<TokenStream> {
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
