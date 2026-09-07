//! Selected output implementations shared by sensitive derives.

use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::{Generics, Type, parse_quote};

/// Delegates structural output to the existing JSON bridge. Runtime feature
/// selection controls expansion, including when derive features are unified.
pub(crate) fn json_output_impl(
    ident: &Ident,
    generics: &Generics,
    crate_root: &TokenStream,
) -> TokenStream {
    let mut output_generics = generics.clone();
    let (_, ty_generics, _) = generics.split_for_impl();
    let self_ty: Type = parse_quote!(#ident #ty_generics);
    output_generics.make_where_clause().predicates.push(parse_quote!(
        #self_ty: #crate_root::Redactable + ::core::clone::Clone + #crate_root::__private::serde::Serialize
    ));
    let (impl_generics, ty_generics, where_clause) = output_generics.split_for_impl();
    quote! {
        #crate_root::__private::generated_json_output! {
            impl #impl_generics #crate_root::ToRedactedOutput for #ident #ty_generics #where_clause {
                fn to_redacted_output(&self) -> #crate_root::RedactedOutput {
                    #crate_root::ToRedactedOutput::to_redacted_output(
                        &#crate_root::RedactedJsonExt::redacted_json(self),
                    )
                }
            }
        }
    }
}
