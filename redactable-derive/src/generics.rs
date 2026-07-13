//! Complete-type trait predicate management for generated implementations.
//!
//! Bounds describe the exact type used by each emitted operation. Container
//! implementations remain authoritative for their inner `Clone`, `Copy`, key,
//! hasher, ordering, and traversal requirements.

use quote::ToTokens;
use syn::{Generics, Type, WherePredicate, parse_quote};

use crate::{crate_path, crate_root};

/// Adds deduplicated where predicates to a generic declaration.
pub(crate) fn add_predicates(mut generics: Generics, predicates: &[WherePredicate]) -> Generics {
    let where_clause = generics.make_where_clause();
    for predicate in predicates {
        if !where_clause.predicates.iter().any(|existing| {
            existing.to_token_stream().to_string() == predicate.to_token_stream().to_string()
        }) {
            where_clause.predicates.push(predicate.clone());
        }
    }
    generics
}

fn push_unique(predicates: &mut Vec<WherePredicate>, predicate: WherePredicate) {
    if !predicates.iter().any(|existing| {
        existing.to_token_stream().to_string() == predicate.to_token_stream().to_string()
    }) {
        predicates.push(predicate);
    }
}

pub(crate) fn push_container_predicate(predicates: &mut Vec<WherePredicate>, ty: &Type) {
    let trait_path = crate_path("RedactableWithMapper");
    push_unique(predicates, parse_quote!(#ty: #trait_path));
}

pub(crate) fn push_policy_predicate(
    predicates: &mut Vec<WherePredicate>,
    ty: &Type,
    policy: &syn::Path,
) {
    let crate_root = crate_root();
    push_unique(
        predicates,
        parse_quote!(#ty: #crate_root::__private::PolicyField<#policy>),
    );
}

pub(crate) fn push_policy_ref_predicate(
    predicates: &mut Vec<WherePredicate>,
    ty: &Type,
    policy: &syn::Path,
) {
    let crate_root = crate_root();
    push_unique(
        predicates,
        parse_quote!(#ty: #crate_root::__private::PolicyFieldRef<#policy>),
    );
}

pub(crate) fn push_policy_output_display_predicate(
    predicates: &mut Vec<WherePredicate>,
    ty: &Type,
    policy: &syn::Path,
) {
    let crate_root = crate_root();
    let formatter_path = crate_path("RedactableWithFormatter");
    push_unique(
        predicates,
        parse_quote!(<#ty as #crate_root::__private::PolicyFieldRef<#policy>>::Output: #formatter_path),
    );
}

pub(crate) fn push_policy_output_debug_predicate(
    predicates: &mut Vec<WherePredicate>,
    ty: &Type,
    policy: &syn::Path,
) {
    let crate_root = crate_root();
    push_unique(
        predicates,
        parse_quote!(<#ty as #crate_root::__private::PolicyFieldRef<#policy>>::Output: ::core::fmt::Debug),
    );
}

pub(crate) fn push_debug_predicate(predicates: &mut Vec<WherePredicate>, ty: &Type) {
    push_unique(predicates, parse_quote!(#ty: ::core::fmt::Debug));
}

pub(crate) fn push_display_predicate(predicates: &mut Vec<WherePredicate>, ty: &Type) {
    push_unique(predicates, parse_quote!(#ty: ::core::fmt::Display));
}

pub(crate) fn push_redacted_display_predicate(predicates: &mut Vec<WherePredicate>, ty: &Type) {
    let trait_path = crate_path("RedactableWithFormatter");
    push_unique(predicates, parse_quote!(#ty: #trait_path));
}
