//! Crate-path resolution and generated-item support.
//!
//! This module resolves the path to the `redactable` crate from a consumer
//! (including renamed dependencies) and isolates generated items from the
//! consumer's scope.

use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;

use crate::fresh_ident::FreshIdentAllocator;

/// Returns the token stream to reference the redactable crate root.
///
/// Handles crate renaming (e.g., `my_redact = { package = "redactable", ... }`)
/// and internal usage (when derive is used inside the redactable crate itself).
pub(crate) fn crate_root() -> proc_macro2::TokenStream {
    match crate_name("redactable") {
        Ok(FoundCrate::Itself) => quote! { crate },
        Ok(FoundCrate::Name(name)) => {
            let ident = dependency_crate_ident(&name);
            quote! { ::#ident }
        }
        Err(_) => quote! { ::redactable },
    }
}

/// Converts a Cargo dependency key into a Rust path identifier without panicking.
///
/// Cargo permits aliases that are Rust keywords. Those aliases must be emitted as
/// raw identifiers (`r#type`) in generated paths.
pub(crate) fn dependency_crate_ident(name: &str) -> Ident {
    syn::parse_str::<Ident>(name)
        .or_else(|_| syn::parse_str::<Ident>(&format!("r#{name}")))
        .unwrap_or_else(|_| Ident::new("__redactable_invalid_dependency_alias", Span::call_site()))
}

pub(crate) fn crate_path(item: &str) -> proc_macro2::TokenStream {
    let root = crate_root();
    let item_ident = syn::parse_str::<syn::Path>(item).expect("redactable crate path should parse");
    quote! { #root::#item_ident }
}

/// Isolates generated binders from unrelated caller-scope constants.
///
/// Rust treats a same-named constant as a const pattern instead of a new function
/// parameter binding. Local function items occupy the value namespace without being
/// const patterns, so generated bindings can safely shadow them. The anonymous const
/// gives every derive expansion its own item scope and still supports local types.
pub(crate) fn isolate_generated_items(
    generated: TokenStream,
    fresh: &FreshIdentAllocator,
) -> TokenStream {
    let value_shadows = fresh.allocated();
    quote! {
        const _: () = {
            #(#[allow(dead_code, non_snake_case)] fn #value_shadows() {})*
            #generated
        };
    }
}

#[cfg(test)]
mod crate_alias_tests {
    use super::dependency_crate_ident;

    #[test]
    fn keyword_dependency_alias_becomes_raw_identifier() {
        assert_eq!(dependency_crate_ident("type").to_string(), "r#type");
        assert_eq!(dependency_crate_ident("renamed").to_string(), "renamed");
    }
}
