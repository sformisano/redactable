//! Generates collision-free definition-time guards for semantic policy identity.
//!
//! Guards live in anonymous const scopes and implement a mixed-site local trait
//! for the derived type, preserving generic and `Self`-bearing where clauses.

use proc_macro2::{Ident, Span, TokenStream};
use quote::{quote, quote_spanned};
use syn::{Data, Fields, Result, spanned::Spanned};

use crate::{
    crate_root,
    strategy::{Strategy, parse_field_strategy},
    types::{contains_unwrapped_ip_address_type, is_ip_address_type},
};

pub(crate) fn generate_policy_guards(
    name: &Ident,
    data: &Data,
    generics: &syn::Generics,
) -> Result<TokenStream> {
    let mut checks = Vec::new();
    for fields in data_fields(data) {
        for field in fields {
            let Strategy::Policy(policy) = parse_field_strategy(&field.attrs)? else {
                continue;
            };
            if contains_unwrapped_ip_address_type(&field.ty) && !is_ip_address_type(&field.ty) {
                let span = field.span();
                let root = crate_root();
                for candidate in ip_candidates(&field.ty) {
                    checks.push(quote_spanned! { span =>
                        #root::__private::require_non_builtin_ip(
                            #root::__private::PolicyProbe::<#policy, #candidate>::new().classify()
                        );
                    });
                }
            }
        }
    }

    if checks.is_empty() {
        return Ok(TokenStream::new());
    }

    let guard_trait = Ident::new("__RedactablePolicyGuard", Span::mixed_site());
    let guard_method = Ident::new("__redactable_check", Span::mixed_site());
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let root = crate_root();

    Ok(quote! {
        const _: () = {
            trait #guard_trait {
                fn #guard_method();
            }

            impl #impl_generics #guard_trait for #name #ty_generics #where_clause {
                fn #guard_method() {
                    use #root::__private::ClassifyPolicy as _;
                    #(#checks)*
                }
            }
        };
    })
}

fn ip_candidates(ty: &syn::Type) -> Vec<&syn::Type> {
    if is_ip_address_type(ty) {
        return vec![ty];
    }
    match ty {
        syn::Type::Array(array) => ip_candidates(&array.elem),
        syn::Type::Group(group) => ip_candidates(&group.elem),
        syn::Type::Paren(paren) => ip_candidates(&paren.elem),
        syn::Type::Reference(reference) => ip_candidates(&reference.elem),
        syn::Type::Slice(slice) => ip_candidates(&slice.elem),
        syn::Type::Tuple(tuple) => tuple.elems.iter().flat_map(ip_candidates).collect(),
        syn::Type::Path(path) => {
            if path
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "SensitiveValue")
            {
                return Vec::new();
            }
            path.path
                .segments
                .iter()
                .flat_map(|segment| match &segment.arguments {
                    syn::PathArguments::AngleBracketed(arguments) => arguments
                        .args
                        .iter()
                        .flat_map(|argument| match argument {
                            syn::GenericArgument::Type(ty) => ip_candidates(ty),
                            _ => Vec::new(),
                        })
                        .collect(),
                    syn::PathArguments::Parenthesized(arguments) => {
                        let mut found: Vec<_> =
                            arguments.inputs.iter().flat_map(ip_candidates).collect();
                        if let syn::ReturnType::Type(_, output) = &arguments.output {
                            found.extend(ip_candidates(output));
                        }
                        found
                    }
                    syn::PathArguments::None => Vec::new(),
                })
                .collect()
        }
        _ => Vec::new(),
    }
}

fn data_fields(data: &Data) -> Vec<&Fields> {
    match data {
        Data::Struct(data) => vec![&data.fields],
        Data::Enum(data) => data
            .variants
            .iter()
            .map(|variant| &variant.fields)
            .collect(),
        Data::Union(_) => Vec::new(),
    }
}
