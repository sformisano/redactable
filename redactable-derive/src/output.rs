//! The `ToRedacted` implementations the sensitive derives always emit.
//!
//! Each derive decides the shape of the value its type produces, so these
//! builders are unconditional: there is no attribute to select a format and no
//! opt-out. The mandatory `Clone + Serialize` bound rides on the generated
//! `where` predicate, which is where a missing bound is reported.
//!
//! Every body hands the borrowed value to the matching `__private` helper,
//! which redacts or serializes it. Generated code never builds a payload and
//! passes it to the runtime, so the hidden channel stays closed to types that
//! carry a declaration.

use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::{Generics, Type, WherePredicate, parse_quote};

/// Adds the structural producer's mandatory bounds to a copy of `generics`.
fn with_structural_bounds(
    ident: &Ident,
    generics: &Generics,
    crate_root: &TokenStream,
) -> Generics {
    let mut bounded = generics.clone();
    let (_, ty_generics, _) = generics.split_for_impl();
    let self_ty: Type = parse_quote!(#ident #ty_generics);
    let predicate: WherePredicate = parse_quote!(
        #self_ty: #crate_root::Redactable + ::core::clone::Clone + #crate_root::__private::serde::Serialize
    );
    bounded.make_where_clause().predicates.push(predicate);
    bounded
}

/// Emits the JSON-only producer for a standalone `Sensitive` type.
///
/// The helper clones, redacts and serializes; the body only names the value.
pub(crate) fn structural_to_redacted_impl(
    ident: &Ident,
    generics: &Generics,
    crate_root: &TokenStream,
) -> TokenStream {
    let bounded = with_structural_bounds(ident, generics, crate_root);
    let (impl_generics, ty_generics, where_clause) = bounded.split_for_impl();
    quote! {
        impl #impl_generics #crate_root::ToRedacted for #ident #ty_generics #where_clause {
            fn to_redacted(&self) -> #crate_root::RedactedValue {
                #crate_root::__private::generated_redacted_json(self)
            }
        }
    }
}

/// Emits the text-only producer for a standalone `SensitiveDisplay` type.
///
/// The helper renders through the declared redacted formatting this expansion
/// generates beside it.
pub(crate) fn display_to_redacted_impl(
    ident: &Ident,
    generics: &Generics,
    crate_root: &TokenStream,
) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    quote! {
        impl #impl_generics #crate_root::ToRedacted for #ident #ty_generics #where_clause {
            fn to_redacted(&self) -> #crate_root::RedactedValue {
                #crate_root::__private::generated_redacted_display(self)
            }
        }
    }
}

/// Emits the dual producer, which carries the template text and the JSON.
///
/// `SensitiveDual` runs both expansions, so exactly one of them may emit a
/// `ToRedacted` impl. The display half owns it, because it is the half that
/// knows the template; the structural half emits none when `dual` is set.
pub(crate) fn dual_to_redacted_impl(
    ident: &Ident,
    display_generics: &Generics,
    crate_root: &TokenStream,
) -> TokenStream {
    let bounded = with_structural_bounds(ident, display_generics, crate_root);
    let (impl_generics, ty_generics, where_clause) = bounded.split_for_impl();
    quote! {
        impl #impl_generics #crate_root::ToRedacted for #ident #ty_generics #where_clause {
            fn to_redacted(&self) -> #crate_root::RedactedValue {
                #crate_root::__private::generated_redacted_dual(self)
            }
        }
    }
}

/// Emits the raw-JSON producer for a `NotSensitive` type.
///
/// The value is declared public by its author, so nothing is redacted here:
/// the type's own `Serialize` output is the value. `Clone` is not required.
/// The helper is bounded on the `DeclaredNotSensitive` companion this derive
/// emits beside the producer, so no undeclared type can reach it.
pub(crate) fn not_sensitive_to_redacted_impl(
    ident: &Ident,
    generics: &Generics,
    crate_root: &TokenStream,
) -> TokenStream {
    let mut bounded = generics.clone();
    let (_, ty_generics, _) = generics.split_for_impl();
    let self_ty: Type = parse_quote!(#ident #ty_generics);
    let predicate: WherePredicate =
        parse_quote!(#self_ty: #crate_root::__private::serde::Serialize);
    bounded.make_where_clause().predicates.push(predicate);
    let (impl_generics, ty_generics, where_clause) = bounded.split_for_impl();
    quote! {
        impl #impl_generics #crate_root::ToRedacted for #ident #ty_generics #where_clause {
            fn to_redacted(&self) -> #crate_root::RedactedValue {
                #crate_root::__private::generated_declared_json(self)
            }
        }
    }
}
