//! Enum-specific `RedactableWithMapper` derivation.
//!
//! This module generates match arms for each variant and collects generic
//! parameters that require trait bounds.

use proc_macro2::{Ident, TokenStream};
use quote::{quote, quote_spanned};
use syn::{DataEnum, Fields, Result, spanned::Spanned};

use crate::{
    DeriveOutput, crate_path,
    fresh_ident::FreshIdentAllocator,
    strategy::{
        Strategy, parse_field_strategy, parse_redactable_field_options,
        reject_variant_sensitivity_attrs,
    },
    transform::{DeriveContext, generate_field_transform},
};

/// Context for deriving a single enum variant.
struct VariantContext<'a> {
    name: &'a Ident,
    variant_ident: &'a Ident,
    arms: &'a mut Vec<TokenStream>,
    debug_redacted_arms: &'a mut Vec<TokenStream>,
    debug_unredacted_arms: &'a mut Vec<TokenStream>,
    formatter: &'a Ident,
    fresh: &'a mut FreshIdentAllocator,
}

pub(crate) fn derive_enum(
    name: &Ident,
    data: DataEnum,
    _generics: &syn::Generics,
    formatter: &Ident,
    mapper: &Ident,
    fresh: &mut FreshIdentAllocator,
) -> Result<DeriveOutput> {
    let container_path = crate_path("RedactableWithMapper");
    let mut arms = Vec::new();
    let mut used_generics = Vec::new();
    let mut policy_applicable_generics = Vec::new();
    let mut debug_redacted_arms = Vec::new();
    let mut debug_unredacted_arms = Vec::new();
    let mut debug_unredacted_generics = Vec::new();

    for variant in data.variants {
        reject_variant_sensitivity_attrs(&variant.attrs)?;
        let variant_ident = &variant.ident;
        let mut variant_ctx = VariantContext {
            name,
            variant_ident,
            arms: &mut arms,
            debug_redacted_arms: &mut debug_redacted_arms,
            debug_unredacted_arms: &mut debug_unredacted_arms,
            formatter,
            fresh,
        };
        let mut derive_ctx = DeriveContext {
            container_path: &container_path,
            container_predicates: &mut used_generics,
            policy_predicates: &mut policy_applicable_generics,
            debug_unredacted_predicates: &mut debug_unredacted_generics,
            mapper,
        };

        match variant.fields {
            Fields::Unit => {
                derive_unit_variant(&mut variant_ctx);
            }
            Fields::Named(fields) => {
                derive_named_variant(&mut variant_ctx, &mut derive_ctx, fields)?;
            }
            Fields::Unnamed(fields) => {
                derive_unnamed_variant(&mut variant_ctx, &mut derive_ctx, fields)?;
            }
        }
    }

    let body = quote! {
        match self {
            #(#arms),*
        }
    };
    let debug_redacted_body = if debug_redacted_arms.is_empty() {
        quote! { match *self {} }
    } else {
        quote! {
            match self {
                #(#debug_redacted_arms),*
            }
        }
    };

    let debug_unredacted_body = if debug_unredacted_arms.is_empty() {
        quote! { match *self {} }
    } else {
        quote! {
            match self {
                #(#debug_unredacted_arms),*
            }
        }
    };

    Ok(DeriveOutput {
        redaction_body: body,
        used_generics,
        policy_applicable_generics,
        debug_redacted_body,
        debug_unredacted_body,
        debug_unredacted_generics,
    })
}

fn derive_unit_variant(ctx: &mut VariantContext<'_>) {
    let formatter = ctx.formatter;
    let name = ctx.name;
    let variant_ident = ctx.variant_ident;
    let debug_name = quote! { concat!(stringify!(#name), "::", stringify!(#variant_ident)) };

    ctx.arms
        .push(quote! { #name::#variant_ident => #name::#variant_ident });
    ctx.debug_redacted_arms.push(quote! {
        #name::#variant_ident => #formatter.write_str(#debug_name)
    });
    ctx.debug_unredacted_arms.push(quote! {
        #name::#variant_ident => #formatter.write_str(#debug_name)
    });
}

fn derive_named_variant(
    variant_ctx: &mut VariantContext<'_>,
    derive_ctx: &mut DeriveContext<'_>,
    fields: syn::FieldsNamed,
) -> Result<()> {
    let formatter = variant_ctx.formatter;
    let debug = variant_ctx.fresh.fresh("__redactable_debug");
    let name = variant_ctx.name;
    let variant_ident = variant_ctx.variant_ident;
    let debug_name = quote! { concat!(stringify!(#name), "::", stringify!(#variant_ident)) };

    let mut patterns = Vec::new();
    let mut reconstructions = Vec::new();
    let mut transforms = Vec::new();
    let mut debug_redacted_fields = Vec::new();
    let mut debug_redacted_patterns = Vec::new();
    let mut debug_unredacted_fields = Vec::new();

    for field in fields.named {
        let span = field.span();
        let strategy = parse_field_strategy(&field.attrs)?;
        let recursive_bound_override = parse_redactable_field_options(&field.attrs)?.recursive;
        let ident = field.ident.expect("named field should have an identifier");
        let binding = variant_ctx
            .fresh
            .fresh_with_ident("__redactable_field_", &ident);
        let ty = &field.ty;
        patterns.push(quote_spanned! { span => #ident: #binding });
        reconstructions.push(quote_spanned! { span => #ident: #binding });

        let is_sensitive = matches!(&strategy, Strategy::Policy(_));
        let transform = generate_field_transform(
            derive_ctx,
            ty,
            &binding,
            span,
            &strategy,
            recursive_bound_override,
        );
        let debug_redacted_field = if is_sensitive {
            // Sensitive: use wildcard pattern to avoid unused binding
            debug_redacted_patterns.push(quote_spanned! { span => #ident: _ });
            quote_spanned! { span =>
                #debug.field(stringify!(#ident), &"[REDACTED]");
            }
        } else {
            // Non-sensitive: normal binding, referenced in the field output
            debug_redacted_patterns.push(quote_spanned! { span => #ident: #binding });
            quote_spanned! { span =>
                #debug.field(stringify!(#ident), #binding);
            }
        };
        let debug_unredacted_field = quote_spanned! { span =>
            #debug.field(stringify!(#ident), #binding);
        };

        transforms.push(transform);
        debug_redacted_fields.push(debug_redacted_field);
        debug_unredacted_fields.push(debug_unredacted_field);
    }

    let pattern = quote! { { #(#patterns),* } };
    let reconstruction = quote! { { #(#reconstructions),* } };
    let debug_redacted_pattern = quote! { { #(#debug_redacted_patterns),* } };
    variant_ctx.arms.push(quote! {
        #name::#variant_ident #pattern => {
            #(#transforms)*
            #name::#variant_ident #reconstruction
        }
    });
    variant_ctx.debug_redacted_arms.push(quote! {
        #name::#variant_ident #debug_redacted_pattern => {
            let mut #debug = #formatter.debug_struct(#debug_name);
            #(#debug_redacted_fields)*
            #debug.finish()
        }
    });
    variant_ctx.debug_unredacted_arms.push(quote! {
        #name::#variant_ident #pattern => {
            let mut #debug = #formatter.debug_struct(#debug_name);
            #(#debug_unredacted_fields)*
            #debug.finish()
        }
    });
    Ok(())
}

fn derive_unnamed_variant(
    variant_ctx: &mut VariantContext<'_>,
    derive_ctx: &mut DeriveContext<'_>,
    fields: syn::FieldsUnnamed,
) -> Result<()> {
    let formatter = variant_ctx.formatter;
    let debug = variant_ctx.fresh.fresh("__redactable_debug");
    let name = variant_ctx.name;
    let variant_ident = variant_ctx.variant_ident;
    let debug_name = quote! { concat!(stringify!(#name), "::", stringify!(#variant_ident)) };

    let mut bindings = Vec::new();
    let mut transforms = Vec::new();
    let mut debug_redacted_fields = Vec::new();
    let mut debug_redacted_patterns = Vec::new();
    let mut debug_unredacted_fields = Vec::new();

    for (index, field) in fields.unnamed.into_iter().enumerate() {
        let ident = variant_ctx.fresh.fresh(&format!("field_{index}"));
        let binding = ident.clone();
        let span = field.span();
        let ty = &field.ty;
        let strategy = parse_field_strategy(&field.attrs)?;
        let recursive_bound_override = parse_redactable_field_options(&field.attrs)?.recursive;
        bindings.push(ident);

        let is_sensitive = matches!(&strategy, Strategy::Policy(_));
        let transform = generate_field_transform(
            derive_ctx,
            ty,
            &binding,
            span,
            &strategy,
            recursive_bound_override,
        );
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

    variant_ctx.arms.push(quote! {
        #name::#variant_ident ( #(#bindings),* ) => {
            #(#transforms)*
            #name::#variant_ident ( #(#bindings),* )
        }
    });
    variant_ctx.debug_redacted_arms.push(quote! {
        #name::#variant_ident ( #(#debug_redacted_patterns),* ) => {
            let mut #debug = #formatter.debug_tuple(#debug_name);
            #(#debug_redacted_fields)*
            #debug.finish()
        }
    });
    variant_ctx.debug_unredacted_arms.push(quote! {
        #name::#variant_ident ( #(#bindings),* ) => {
            let mut #debug = #formatter.debug_tuple(#debug_name);
            #(#debug_unredacted_fields)*
            #debug.finish()
        }
    });
    Ok(())
}
