//! Struct-specific `RedactableWithMapper` derivation.

use proc_macro2::Ident;
use quote::quote;
use syn::{DataStruct, Result};

use crate::{
    DeriveOutput, crate_path,
    fresh_ident::FreshIdentAllocator,
    transform::{DeriveContext, FieldsOutput, derive_fields},
};

pub(crate) fn derive_struct(
    name: &Ident,
    data: DataStruct,
    formatter: &Ident,
    mapper: &Ident,
    fresh: &mut FreshIdentAllocator,
) -> Result<DeriveOutput> {
    let container_path = crate_path("RedactableWithMapper");
    let mut predicates = Vec::new();
    let mut debug_predicates = Vec::new();
    let mut ctx = DeriveContext {
        container_path: &container_path,
        predicates: &mut predicates,
        debug_predicates: &mut debug_predicates,
        mapper,
    };
    let debug_name = quote! { stringify!(#name) };
    let Some(fields) = derive_fields(&mut ctx, data.fields, formatter, &debug_name, fresh)? else {
        return Ok(DeriveOutput {
            redaction_body: quote! { self },
            predicates,
            debug_redacted_body: quote! {
                #formatter.write_str(stringify!(#name))
            },
            debug_predicates,
        });
    };
    let FieldsOutput {
        pattern,
        reconstruction,
        transforms,
        debug_pattern,
        debug_body,
    } = fields;

    Ok(DeriveOutput {
        redaction_body: quote! {
            let Self #pattern = self;
            #(#transforms)*
            Self #reconstruction
        },
        predicates,
        debug_redacted_body: quote! {
            match self {
                Self #debug_pattern => #debug_body
            }
        },
        debug_predicates,
    })
}
