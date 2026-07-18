//! Shared field transformation logic for struct and enum derivation.
//!
//! This module extracts the common code for generating field transformations,
//! which was previously duplicated between `derive_struct` and `derive_enum`.

use proc_macro2::{Ident, Span, TokenStream};
use quote::quote_spanned;

use crate::{
    crate_root,
    generics::{push_container_predicate, push_debug_predicate, push_policy_predicate},
    strategy::Strategy,
};

/// Accumulated state during field processing.
///
/// This struct groups the mutable vectors that collect generics and output tokens
/// during traversal of struct fields or enum variants.
pub(crate) struct DeriveContext<'a> {
    pub(crate) container_path: &'a TokenStream,
    pub(crate) container_predicates: &'a mut Vec<syn::WherePredicate>,
    pub(crate) policy_predicates: &'a mut Vec<syn::WherePredicate>,
    pub(crate) debug_unredacted_predicates: &'a mut Vec<syn::WherePredicate>,
    pub(crate) mapper: &'a Ident,
}

/// Generates the transform token stream for a single field.
///
/// ## Field Transformation Rules
///
/// | Annotation              | Behavior                                             |
/// |-------------------------|------------------------------------------------------|
/// | None                    | Walk containers, scalars pass through                |
/// | `#[sensitive(Secret)]`  | Scalars redact to default; strings to "[REDACTED]"   |
/// | `#[sensitive(Policy)]`  | Apply policy recursively through wrappers            |
/// | `#[not_sensitive]`      | Explicit passthrough (no transformation)             |
pub(crate) fn generate_field_transform(
    ctx: &mut DeriveContext<'_>,
    ty: &syn::Type,
    binding: &Ident,
    span: Span,
    strategy: &Strategy,
    recursive_bound_override: bool,
) -> TokenStream {
    let container_path = ctx.container_path;
    let mapper = ctx.mapper;

    match strategy {
        Strategy::WalkDefault => {
            if !recursive_bound_override {
                push_container_predicate(ctx.container_predicates, ty);
                push_debug_predicate(ctx.debug_unredacted_predicates, ty);
            }
            quote_spanned! { span =>
                let #binding = #container_path::redact_with(#binding, #mapper);
            }
        }
        Strategy::NotSensitive => {
            // Explicit opt-out: no transformation, passthrough unchanged.
            // This is useful for foreign types that don't implement RedactableWithMapper.
            // Still collect debug generics: the field is printed in generated Debug impls
            // even though it's not transformed, so its type needs a Debug bound.
            if !recursive_bound_override {
                push_debug_predicate(ctx.debug_unredacted_predicates, ty);
            }
            TokenStream::new()
        }
        Strategy::Policy(policy_path) => {
            if !recursive_bound_override {
                push_policy_predicate(ctx.policy_predicates, ty, policy_path);
                push_debug_predicate(ctx.debug_unredacted_predicates, ty);
            }
            let policy = policy_path.clone();
            let crate_root = crate_root();
            quote_spanned! { span =>
                let #binding = <#ty as #crate_root::__private::PolicyField<#policy>>::apply_field(
                    #binding,
                    #mapper,
                );
            }
        }
    }
}
