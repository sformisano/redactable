//! Enum-specific `RedactableWithMapper` derivation.
//!
//! This module generates match arms for each variant and collects generic
//! parameters that require trait bounds.

use proc_macro2::Ident;
use quote::quote;
use syn::{DataEnum, Result};

use crate::{
    DeriveOutput, crate_path,
    fresh_ident::FreshIdentAllocator,
    strategy::reject_variant_sensitivity_attrs,
    transform::{DeriveContext, FieldsOutput, derive_fields},
};

pub(crate) fn derive_enum(
    name: &Ident,
    data: DataEnum,
    formatter: &Ident,
    mapper: &Ident,
    fresh: &mut FreshIdentAllocator,
) -> Result<DeriveOutput> {
    let container_path = crate_path("RedactableWithMapper");
    let mut arms = Vec::new();
    let mut debug_redacted_arms = Vec::new();
    let mut predicates = Vec::new();
    let mut debug_predicates = Vec::new();

    for variant in data.variants {
        reject_variant_sensitivity_attrs(&variant.attrs)?;
        let variant_ident = &variant.ident;
        let debug_name = quote! { concat!(stringify!(#name), "::", stringify!(#variant_ident)) };
        let mut ctx = DeriveContext {
            container_path: &container_path,
            predicates: &mut predicates,
            debug_predicates: &mut debug_predicates,
            mapper,
        };

        match derive_fields(&mut ctx, variant.fields, formatter, &debug_name, fresh)? {
            None => {
                arms.push(quote! { #name::#variant_ident => #name::#variant_ident });
                debug_redacted_arms.push(quote! {
                    #name::#variant_ident => #formatter.write_str(#debug_name)
                });
            }
            Some(FieldsOutput {
                pattern,
                reconstruction,
                transforms,
                debug_pattern,
                debug_body,
            }) => {
                arms.push(quote! {
                    #name::#variant_ident #pattern => {
                        #(#transforms)*
                        #name::#variant_ident #reconstruction
                    }
                });
                debug_redacted_arms.push(quote! {
                    #name::#variant_ident #debug_pattern => #debug_body
                });
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

    Ok(DeriveOutput {
        redaction_body: body,
        predicates,
        debug_redacted_body,
        debug_predicates,
    })
}
