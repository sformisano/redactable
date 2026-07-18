//! Redacted display formatting for `SensitiveDisplay`.
//!
//! This module derives a redacted formatting implementation from thiserror-style
//! `#[error("...")]` strings or displaydoc-style doc comments.
//!
//! Unannotated fields referenced in a template use `RedactableWithFormatter` by default.
//! Use `#[not_sensitive]` for raw output or `#[sensitive(Policy)]` for policy redaction.

mod bounds;
mod codegen;
mod model;
mod template;

use proc_macro2::{Ident, TokenStream};
use syn::{Attribute, Data, Result, spanned::Spanned};

use crate::fresh_ident::FreshIdentAllocator;

use self::codegen::{derive_enum_display, derive_struct_display};

pub(crate) struct RedactedDisplayOutput {
    pub(crate) body: TokenStream,
    pub(crate) display_generics: Vec<syn::WherePredicate>,
    pub(crate) debug_generics: Vec<syn::WherePredicate>,
    pub(crate) policy_ref_generics: Vec<syn::WherePredicate>,
    pub(crate) nested_generics: Vec<syn::WherePredicate>,
}

pub(crate) fn derive_redacted_display(
    name: &Ident,
    data: &Data,
    attrs: &[Attribute],
    generics: &syn::Generics,
    formatter: &Ident,
    fresh: &mut FreshIdentAllocator,
) -> Result<RedactedDisplayOutput> {
    match data {
        Data::Struct(data) => derive_struct_display(name, data, attrs, generics, formatter, fresh),
        Data::Enum(data) => derive_enum_display(name, data, generics, formatter, fresh),
        Data::Union(u) => Err(syn::Error::new(
            u.union_token.span(),
            "`SensitiveDisplay` cannot be derived for unions",
        )),
    }
}
