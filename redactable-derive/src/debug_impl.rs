//! Generated `Debug` implementation support.
//!
//! This module builds the unredacted `Debug` bodies that generated impls use in
//! the consumer's `cfg(test)` builds or when `redactable`'s `testing` feature is
//! enabled.

use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::{Data, DataEnum, DataStruct, Fields, Result, spanned::Spanned};

use crate::{
    fresh_ident::FreshIdentAllocator, generics::push_debug_predicate,
    strategy::parse_redactable_field_options,
};

pub(crate) struct DebugOutput {
    pub(crate) body: TokenStream,
    pub(crate) generics: Vec<syn::WherePredicate>,
}

pub(crate) fn derive_unredacted_debug(
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
