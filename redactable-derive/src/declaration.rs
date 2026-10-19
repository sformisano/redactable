//! Checks actual derive operations under the owner's declared bounds.

use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::Generics;

/// Wraps a check method without adding inferred field predicates.
///
/// `bounded` is `declared` with the trait impls' inferred predicates appended.
/// When it appends none, the trait impl bodies already run under the declared
/// bounds, so a separate check would only report each error a second time.
pub(crate) fn declaration_check(
    owner: &Ident,
    declared: &Generics,
    bounded: &Generics,
    method: TokenStream,
) -> TokenStream {
    if predicate_count(bounded) == predicate_count(declared) {
        return TokenStream::new();
    }
    let (impl_generics, ty_generics, where_clause) = declared.split_for_impl();
    quote! {
        impl #impl_generics #owner #ty_generics #where_clause {
            #[allow(dead_code)]
            #method
        }
    }
}

fn predicate_count(generics: &Generics) -> usize {
    generics
        .where_clause
        .as_ref()
        .map_or(0, |clause| clause.predicates.len())
}
