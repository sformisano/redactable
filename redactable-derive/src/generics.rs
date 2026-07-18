//! Complete-type trait predicate management for generated implementations.
//!
//! Bounds describe the exact type used by each emitted operation. Container
//! implementations remain authoritative for their inner `Clone`, `Copy`, key,
//! hasher, ordering, and traversal requirements.

use std::collections::BTreeSet;

use quote::ToTokens;
use syn::{Generics, Ident, Type, TypeParamBound, WherePredicate, parse_quote, visit::Visit};

use crate::{crate_path, crate_root};

/// Describes how a field type refers to one of its owner's type parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerTypeParameterUsage {
    /// The field type does not mention an owner type parameter.
    None,
    /// The field type is exactly one owner type parameter, such as `T`.
    Bare,
    /// The field type contains an owner type parameter, such as `Option<T>`.
    Composite,
}

/// Classifies whether `ty` is or contains one of `generics`' type parameters.
pub(crate) fn owner_type_parameter_usage(
    generics: &Generics,
    ty: &Type,
) -> OwnerTypeParameterUsage {
    if let Type::Path(path) = ty
        && path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == 1
    {
        let segment = &path.path.segments[0];
        if segment.arguments.is_empty() && is_owner_type_parameter(generics, &segment.ident) {
            return OwnerTypeParameterUsage::Bare;
        }
    }

    let mut visitor = OwnerTypeParameterVisitor {
        generics,
        found: false,
    };
    visitor.visit_type(ty);
    if visitor.found {
        OwnerTypeParameterUsage::Composite
    } else {
        OwnerTypeParameterUsage::None
    }
}

/// Returns whether `ty` references an owner type parameter explicitly bounded by
/// `PolicyApplicableRef` on the owner declaration.
pub(crate) fn references_explicit_policy_applicable_ref(generics: &Generics, ty: &Type) -> bool {
    let mut visitor = ReferencedOwnerTypeParameters {
        generics,
        referenced: BTreeSet::new(),
    };
    visitor.visit_type(ty);
    visitor.referenced.into_iter().any(|ident| {
        generics.type_params().any(|parameter| {
            parameter.ident == ident && bounds_include_policy_applicable_ref(&parameter.bounds)
        }) || generics.where_clause.as_ref().is_some_and(|where_clause| {
            where_clause.predicates.iter().any(|predicate| {
                let WherePredicate::Type(predicate) = predicate else {
                    return false;
                };
                bare_type_ident(&predicate.bounded_ty).is_some_and(|bounded| *bounded == ident)
                    && bounds_include_policy_applicable_ref(&predicate.bounds)
            })
        })
    })
}

fn bounds_include_policy_applicable_ref(
    bounds: &syn::punctuated::Punctuated<TypeParamBound, syn::token::Plus>,
) -> bool {
    bounds.iter().any(|bound| {
        matches!(bound, TypeParamBound::Trait(bound) if bound.path.segments.last().is_some_and(|segment| segment.ident == "PolicyApplicableRef"))
    })
}

fn bare_type_ident(ty: &Type) -> Option<&Ident> {
    let Type::Path(path) = ty else {
        return None;
    };
    (path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == 1
        && path.path.segments[0].arguments.is_empty())
    .then_some(&path.path.segments[0].ident)
}

struct ReferencedOwnerTypeParameters<'a> {
    generics: &'a Generics,
    referenced: BTreeSet<Ident>,
}

impl<'ast> Visit<'ast> for ReferencedOwnerTypeParameters<'_> {
    fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
        if node.qself.is_none() && node.path.leading_colon.is_none() {
            for segment in &node.path.segments {
                if is_owner_type_parameter(self.generics, &segment.ident) {
                    self.referenced.insert(segment.ident.clone());
                }
            }
        }
        syn::visit::visit_type_path(self, node);
    }
}

fn is_owner_type_parameter(generics: &Generics, ident: &Ident) -> bool {
    generics
        .type_params()
        .any(|parameter| parameter.ident == *ident)
}

pub(crate) fn policy_is_owner_type_parameter(generics: &Generics, policy: &syn::Path) -> bool {
    policy.leading_colon.is_none()
        && policy.segments.len() == 1
        && policy.segments[0].arguments.is_empty()
        && is_owner_type_parameter(generics, &policy.segments[0].ident)
}

struct OwnerTypeParameterVisitor<'a> {
    generics: &'a Generics,
    found: bool,
}

impl<'ast> Visit<'ast> for OwnerTypeParameterVisitor<'_> {
    fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
        if node.qself.is_none()
            && node.path.leading_colon.is_none()
            && node
                .path
                .segments
                .first()
                .is_some_and(|segment| is_owner_type_parameter(self.generics, &segment.ident))
        {
            self.found = true;
            return;
        }
        syn::visit::visit_type_path(self, node);
    }
}

/// Adds deduplicated where predicates to a generic declaration.
pub(crate) fn add_predicates(
    mut generics: Generics,
    predicates: &[WherePredicate],
    owner: &Ident,
) -> Generics {
    if generics.params.is_empty() {
        return generics;
    }
    let where_clause = generics.make_where_clause();
    for predicate in predicates {
        if predicate_has_recursive_self_type(predicate, owner) {
            continue;
        }
        if !where_clause.predicates.iter().any(|existing| {
            existing.to_token_stream().to_string() == predicate.to_token_stream().to_string()
        }) {
            where_clause.predicates.push(predicate.clone());
        }
    }
    generics
}

fn predicate_has_recursive_self_type(predicate: &WherePredicate, owner: &Ident) -> bool {
    let mut visitor = RecursiveSelfTypeVisitor {
        owner,
        found: false,
    };
    visitor.visit_where_predicate(predicate);
    visitor.found
}

struct RecursiveSelfTypeVisitor<'a> {
    owner: &'a Ident,
    found: bool,
}

impl<'ast> Visit<'ast> for RecursiveSelfTypeVisitor<'_> {
    fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
        if node.qself.is_none() && node.path.leading_colon.is_none() {
            let segments = &node.path.segments;
            let direct_owner = segments.len() == 1 && segments[0].ident == *self.owner;
            let qualified_owner = segments.len() > 1
                && segments
                    .first()
                    .is_some_and(|segment| segment.ident == "self")
                && segments
                    .last()
                    .is_some_and(|segment| segment.ident == *self.owner);
            if direct_owner || qualified_owner {
                self.found = true;
                return;
            }
        }
        syn::visit::visit_type_path(self, node);
    }
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

pub(crate) fn push_generated_policy_display_formatting_predicate(
    predicates: &mut Vec<WherePredicate>,
    ty: &Type,
    policy: &syn::Path,
) {
    let crate_root = crate_root();
    push_unique(
        predicates,
        parse_quote!(#ty: #crate_root::__private::PolicyApplicableRefForGeneratedFormatting),
    );
    push_unique(
        predicates,
        parse_quote!(<#policy as #crate_root::RedactionPolicy>::Kind: #crate_root::__private::GeneratedPolicyKindDisplayFormatting<#policy, #ty>),
    );
}

pub(crate) fn push_policy_display_formatting_predicate(
    predicates: &mut Vec<WherePredicate>,
    ty: &Type,
    policy: &syn::Path,
) {
    let crate_root = crate_root();
    push_unique(
        predicates,
        parse_quote!(<#policy as #crate_root::RedactionPolicy>::Kind: #crate_root::__private::PolicyKindDisplayFormatting<#policy, #ty>),
    );
}

pub(crate) fn push_policy_debug_formatting_predicate(
    predicates: &mut Vec<WherePredicate>,
    ty: &Type,
    policy: &syn::Path,
) {
    let crate_root = crate_root();
    push_unique(
        predicates,
        parse_quote!(<#policy as #crate_root::RedactionPolicy>::Kind: #crate_root::__private::PolicyKindDebugFormatting<#policy, #ty>),
    );
}

pub(crate) fn push_generated_policy_debug_formatting_predicate(
    predicates: &mut Vec<WherePredicate>,
    ty: &Type,
    policy: &syn::Path,
) {
    let crate_root = crate_root();
    push_unique(
        predicates,
        parse_quote!(#ty: #crate_root::__private::PolicyApplicableRefForGeneratedFormatting),
    );
    push_unique(
        predicates,
        parse_quote!(<#policy as #crate_root::RedactionPolicy>::Kind: #crate_root::__private::GeneratedPolicyKindDebugFormatting<#policy, #ty>),
    );
}

pub(crate) fn push_direct_marker_display_formatting_predicates(
    predicates: &mut Vec<WherePredicate>,
    ty: &Type,
) {
    let crate_root = crate_root();
    push_unique(
        predicates,
        parse_quote!(#ty: #crate_root::__private::PolicyApplicableRefForFormatting),
    );
    push_unique(
        predicates,
        parse_quote!(#ty: #crate_root::PolicyApplicableRef),
    );
    push_unique(
        predicates,
        parse_quote!(<#ty as #crate_root::PolicyApplicableRef>::Output: #crate_root::RedactableWithFormatter),
    );
}

pub(crate) fn push_direct_marker_debug_formatting_predicates(
    predicates: &mut Vec<WherePredicate>,
    ty: &Type,
) {
    let crate_root = crate_root();
    push_unique(
        predicates,
        parse_quote!(#ty: #crate_root::__private::PolicyApplicableRefForFormatting),
    );
    push_unique(
        predicates,
        parse_quote!(#ty: #crate_root::PolicyApplicableRef),
    );
    push_unique(
        predicates,
        parse_quote!(<#ty as #crate_root::PolicyApplicableRef>::Output: ::core::fmt::Debug),
    );
}

pub(crate) fn push_legacy_policy_display_formatting_predicates(
    predicates: &mut Vec<WherePredicate>,
    ty: &Type,
    policy: &syn::Path,
) {
    let crate_root = crate_root();
    push_unique(
        predicates,
        parse_quote!(#ty: #crate_root::__private::PolicyFieldRef<#policy>),
    );
    push_unique(
        predicates,
        parse_quote!(<#ty as #crate_root::__private::PolicyFieldRef<#policy>>::Output: #crate_root::RedactableWithFormatter),
    );
}

pub(crate) fn push_legacy_policy_debug_formatting_predicates(
    predicates: &mut Vec<WherePredicate>,
    ty: &Type,
    policy: &syn::Path,
) {
    let crate_root = crate_root();
    push_unique(
        predicates,
        parse_quote!(#ty: #crate_root::__private::PolicyFieldRef<#policy>),
    );
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
