//! Complete-type `Debug` predicates for the generated structural `Debug` impl.
//!
//! The traversal and formatting impls carry exactly the type's declared bounds.
//! A `Debug` bound names the exact field type the impl prints. Container
//! implementations remain authoritative for their inner requirements.

use quote::ToTokens;
use syn::{Generics, Ident, Type, TypePath, WherePredicate, parse_quote, visit::Visit};

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
    fn visit_type_path(&mut self, node: &'ast TypePath) {
        if node.qself.is_none() && node.path.leading_colon.is_none() {
            let segments = &node.path.segments;
            let direct_owner = segments.len() == 1 && segments[0].ident == *self.owner;
            let qualified_owner = segments.len() == 2
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

pub(crate) fn push_debug_predicate(predicates: &mut Vec<WherePredicate>, ty: &Type) {
    push_unique(predicates, parse_quote!(#ty: ::core::fmt::Debug));
}
