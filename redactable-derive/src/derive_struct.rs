//! Struct-specific `RedactableWithMapper` derivation.
//!
//! This module generates traversal logic for struct fields and collects generic
//! parameters that require trait bounds.

use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote, quote_spanned};
use syn::{DataStruct, Fields, Result, spanned::Spanned};

use crate::{
    DeriveOutput, crate_path,
    strategy::{Strategy, parse_field_strategy},
    transform::{DeriveContext, generate_field_transform},
};

pub(crate) fn derive_struct(
    name: &Ident,
    data: DataStruct,
    _generics: &syn::Generics,
) -> Result<DeriveOutput> {
    let container_path = crate_path("RedactableWithMapper");
    let formatter = crate::internal_ident("__redactable_f");
    match data.fields {
        Fields::Named(fields) => derive_named_struct(name, fields, &container_path),
        Fields::Unnamed(fields) => derive_unnamed_struct(name, fields, &container_path),
        Fields::Unit => Ok(DeriveOutput {
            redaction_body: quote! { self },
            used_generics: Vec::new(),
            policy_applicable_generics: Vec::new(),
            debug_redacted_body: quote! {
                #formatter.write_str(stringify!(#name))
            },
            debug_unredacted_body: quote! {
                #formatter.write_str(stringify!(#name))
            },
            debug_unredacted_generics: Vec::new(),
        }),
    }
}

fn derive_named_struct(
    name: &Ident,
    fields: syn::FieldsNamed,
    container_path: &TokenStream,
) -> Result<DeriveOutput> {
    let formatter = crate::internal_ident("__redactable_f");
    let debug = crate::internal_ident("__redactable_debug");
    let mut bindings = Vec::new();
    let mut transforms = Vec::new();
    let mut used_generics = Vec::new();
    let mut policy_applicable_generics = Vec::new();
    let mut debug_redacted_fields = Vec::new();
    let mut debug_redacted_patterns = Vec::new();
    let mut debug_unredacted_fields = Vec::new();
    let mut debug_unredacted_generics = Vec::new();

    let mut ctx = DeriveContext {
        container_path,
        container_predicates: &mut used_generics,
        policy_predicates: &mut policy_applicable_generics,
        debug_unredacted_predicates: &mut debug_unredacted_generics,
    };

    for field in fields.named {
        let span = field.span();
        let strategy = parse_field_strategy(&field.attrs)?;
        let ident = field.ident.expect("named field should have an identifier");
        let binding = ident.clone();
        let ty = &field.ty;
        bindings.push(ident);

        let is_sensitive = matches!(&strategy, Strategy::Policy(_));
        let transform = generate_field_transform(&mut ctx, ty, &binding, span, &strategy)?;

        let debug_redacted_field = if is_sensitive {
            // Sensitive: use wildcard pattern to avoid unused binding
            debug_redacted_patterns.push(quote_spanned! { span => #binding: _ });
            quote_spanned! { span =>
                #debug.field(stringify!(#binding), &"[REDACTED]");
            }
        } else {
            // Non-sensitive: normal binding, referenced in the field output
            debug_redacted_patterns.push(quote_spanned! { span => #binding });
            quote_spanned! { span =>
                #debug.field(stringify!(#binding), #binding);
            }
        };
        let debug_unredacted_field = quote_spanned! { span =>
            #debug.field(stringify!(#binding), #binding);
        };

        transforms.push(transform);
        debug_redacted_fields.push(debug_redacted_field);
        debug_unredacted_fields.push(debug_unredacted_field);
    }

    Ok(DeriveOutput {
        redaction_body: quote! {
            let Self { #(#bindings),* } = self;
            #(#transforms)*
            Self { #(#bindings),* }
        },
        used_generics,
        policy_applicable_generics,
        debug_redacted_body: quote! {
            match self {
                Self { #(#debug_redacted_patterns),* } => {
                    let mut #debug = #formatter.debug_struct(stringify!(#name));
                    #(#debug_redacted_fields)*
                    #debug.finish()
                }
            }
        },
        debug_unredacted_body: quote! {
            match self {
                Self { #(#bindings),* } => {
                    let mut #debug = #formatter.debug_struct(stringify!(#name));
                    #(#debug_unredacted_fields)*
                    #debug.finish()
                }
            }
        },
        debug_unredacted_generics,
    })
}

fn derive_unnamed_struct(
    name: &Ident,
    fields: syn::FieldsUnnamed,
    container_path: &TokenStream,
) -> Result<DeriveOutput> {
    let formatter = crate::internal_ident("__redactable_f");
    let debug = crate::internal_ident("__redactable_debug");
    let mut bindings = Vec::new();
    let mut transforms = Vec::new();
    let mut used_generics = Vec::new();
    let mut policy_applicable_generics = Vec::new();
    let mut debug_redacted_fields = Vec::new();
    let mut debug_redacted_patterns = Vec::new();
    let mut debug_unredacted_fields = Vec::new();
    let mut debug_unredacted_generics = Vec::new();

    let mut ctx = DeriveContext {
        container_path,
        container_predicates: &mut used_generics,
        policy_predicates: &mut policy_applicable_generics,
        debug_unredacted_predicates: &mut debug_unredacted_generics,
    };

    for (index, field) in fields.unnamed.into_iter().enumerate() {
        let ident = format_ident!("field_{index}", span = proc_macro2::Span::mixed_site());
        let binding = ident.clone();
        let span = field.span();
        let ty = &field.ty;
        let strategy = parse_field_strategy(&field.attrs)?;
        bindings.push(ident);

        let is_sensitive = matches!(&strategy, Strategy::Policy(_));
        let transform = generate_field_transform(&mut ctx, ty, &binding, span, &strategy)?;

        let debug_redacted_field = if is_sensitive {
            // Sensitive: use wildcard pattern to avoid unused binding
            debug_redacted_patterns.push(quote_spanned! { span => _ });
            quote_spanned! { span =>
                #debug.field(&"[REDACTED]");
            }
        } else {
            // Non-sensitive: normal binding, referenced in the field output
            debug_redacted_patterns.push(quote_spanned! { span => #binding });
            quote_spanned! { span =>
                #debug.field(#binding);
            }
        };
        let debug_unredacted_field = quote_spanned! { span =>
            #debug.field(#binding);
        };

        transforms.push(transform);
        debug_redacted_fields.push(debug_redacted_field);
        debug_unredacted_fields.push(debug_unredacted_field);
    }

    Ok(DeriveOutput {
        redaction_body: quote! {
            let Self ( #(#bindings),* ) = self;
            #(#transforms)*
            Self ( #(#bindings),* )
        },
        used_generics,
        policy_applicable_generics,
        debug_redacted_body: quote! {
            match self {
                Self ( #(#debug_redacted_patterns),* ) => {
                    let mut #debug = #formatter.debug_tuple(stringify!(#name));
                    #(#debug_redacted_fields)*
                    #debug.finish()
                }
            }
        },
        debug_unredacted_body: quote! {
            match self {
                Self ( #(#bindings),* ) => {
                    let mut #debug = #formatter.debug_tuple(stringify!(#name));
                    #(#debug_unredacted_fields)*
                    #debug.finish()
                }
            }
        },
        debug_unredacted_generics,
    })
}
