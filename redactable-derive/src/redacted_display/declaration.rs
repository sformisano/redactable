//! Checks formatting under declared bounds while keeping impls conditional.

use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::Generics;

use crate::fresh_ident::FreshIdentAllocator;

/// Returns an inherent helper and its call, or the body when no helper is needed.
pub(crate) fn checked_display_body(
    owner: &Ident,
    declared: &Generics,
    bounded: &Generics,
    formatter: &Ident,
    body: TokenStream,
    fresh: &mut FreshIdentAllocator,
) -> (TokenStream, TokenStream) {
    if predicate_count(bounded) == predicate_count(declared) {
        return (TokenStream::new(), body);
    }
    let method = fresh.fresh("__redactable_fmt_declared");
    let (impl_generics, ty_generics, where_clause) = declared.split_for_impl();
    let helper = quote! {
        impl #impl_generics #owner #ty_generics #where_clause {
            fn #method(&self, #formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                #body
            }
        }
    };
    (helper, quote! { Self::#method(self, #formatter) })
}

fn predicate_count(generics: &Generics) -> usize {
    generics
        .where_clause
        .as_ref()
        .map_or(0, |clause| clause.predicates.len())
}
