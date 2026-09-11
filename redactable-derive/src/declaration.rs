//! Checks actual derive operations under the owner's declared bounds.

use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::Generics;

/// Wraps a check method without adding inferred field predicates.
pub(crate) fn declaration_check(
    owner: &Ident,
    generics: &Generics,
    method: TokenStream,
) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    quote! {
        impl #impl_generics #owner #ty_generics #where_clause {
            #[allow(dead_code)]
            #method
        }
    }
}
