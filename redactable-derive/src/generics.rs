//! Generic type parameter handling and trait bound management.
//!
//! This module adds bounds only for generics that are used by walked or
//! classified fields.
//!
//! ## PhantomData Handling
//!
//! `PhantomData<T>` fields are explicitly skipped when collecting generics.
//! This is essential for external type support:
//!
//! ```ignore
//! struct TypedId<T> {
//!     id: String,
//!     _marker: PhantomData<T>,  // T should NOT require RedactableContainer
//! }
//! ```
//!
//! Without this, `TypedId<DateTime<Utc>>` would fail because `DateTime<Utc>`
//! doesn't implement `RedactableContainer`, even though `_marker` passes through
//! unchanged (no `#[sensitive]` annotation).

use syn::{Ident, parse_quote};

use crate::crate_path;

fn push_if_generic(ident: &Ident, generics: &syn::Generics, result: &mut Vec<Ident>) {
    if generics.type_params().any(|param| param.ident == *ident)
        && !result.iter().any(|g| g == ident)
    {
        result.push(ident.clone());
    }
}

fn visit_type_param_bound(
    bound: &syn::TypeParamBound,
    generics: &syn::Generics,
    result: &mut Vec<Ident>,
) {
    if let syn::TypeParamBound::Trait(trait_bound) = bound {
        visit_path(&trait_bound.path, generics, result);
    }
}

fn visit_path_arguments(
    args: &syn::PathArguments,
    generics: &syn::Generics,
    result: &mut Vec<Ident>,
) {
    match args {
        syn::PathArguments::AngleBracketed(args) => {
            for arg in &args.args {
                match arg {
                    syn::GenericArgument::Type(inner_ty) => {
                        visit_type(inner_ty, generics, result);
                    }
                    syn::GenericArgument::AssocType(assoc) => {
                        visit_type(&assoc.ty, generics, result);
                    }
                    syn::GenericArgument::Constraint(constraint) => {
                        for bound in &constraint.bounds {
                            visit_type_param_bound(bound, generics, result);
                        }
                    }
                    _ => {}
                }
            }
        }
        syn::PathArguments::Parenthesized(args) => {
            for input in &args.inputs {
                visit_type(input, generics, result);
            }
            if let syn::ReturnType::Type(_, output) = &args.output {
                visit_type(output, generics, result);
            }
        }
        syn::PathArguments::None => {}
    }
}

fn visit_path(path: &syn::Path, generics: &syn::Generics, result: &mut Vec<Ident>) {
    if let Some(last_segment) = path.segments.last() {
        // Skip PhantomData - it's a zero-sized marker that doesn't need bounds.
        // This is critical: PhantomData<T> fields pass through unchanged,
        // so we shouldn't require T: RedactableContainer. This enables
        // patterns like `struct TypedId<T> { id: String, _marker: PhantomData<T> }`
        // to work even when T is an external type like DateTime<Utc>.
        if last_segment.ident == "PhantomData" {
            return;
        }
    }

    for segment in &path.segments {
        push_if_generic(&segment.ident, generics, result);
        visit_path_arguments(&segment.arguments, generics, result);
    }
}

fn visit_type(ty: &syn::Type, generics: &syn::Generics, result: &mut Vec<Ident>) {
    match ty {
        syn::Type::Path(type_path) => {
            if let Some(qself) = &type_path.qself {
                visit_type(&qself.ty, generics, result);
            }
            visit_path(&type_path.path, generics, result);
        }
        syn::Type::Reference(reference) => visit_type(&reference.elem, generics, result),
        syn::Type::Ptr(pointer) => visit_type(&pointer.elem, generics, result),
        syn::Type::Slice(slice) => visit_type(&slice.elem, generics, result),
        syn::Type::Array(array) => visit_type(&array.elem, generics, result),
        syn::Type::Tuple(tuple) => {
            for elem in &tuple.elems {
                visit_type(elem, generics, result);
            }
        }
        syn::Type::Paren(paren) => visit_type(&paren.elem, generics, result),
        syn::Type::Group(group) => visit_type(&group.elem, generics, result),
        syn::Type::TraitObject(obj) => {
            for bound in &obj.bounds {
                visit_type_param_bound(bound, generics, result);
            }
        }
        syn::Type::ImplTrait(impl_trait) => {
            for bound in &impl_trait.bounds {
                visit_type_param_bound(bound, generics, result);
            }
        }
        syn::Type::BareFn(bare_fn) => {
            for input in &bare_fn.inputs {
                visit_type(&input.ty, generics, result);
            }
            if let syn::ReturnType::Type(_, output) = &bare_fn.output {
                visit_type(output, generics, result);
            }
        }
        _ => {}
    }
}

pub(crate) fn collect_generics_from_type(
    ty: &syn::Type,
    generics: &syn::Generics,
    result: &mut Vec<Ident>,
) {
    visit_type(ty, generics, result);
}

/// Adds `RedactableContainer` bounds to generic parameters used in walked fields.
pub(crate) fn add_container_bounds(
    mut generics: syn::Generics,
    used_generics: &[Ident],
) -> syn::Generics {
    for param in generics.type_params_mut() {
        if used_generics.iter().any(|g| g == &param.ident) {
            let container_path = crate_path("RedactableContainer");
            param.bounds.push(parse_quote!(#container_path));
        }
    }
    generics
}

/// Adds `PolicyApplicable` bounds to generic parameters used in policy-annotated fields.
///
/// This enables `#[sensitive(Policy)]` to work on generic types like `T`
/// where `T` could be `String`, `Option<String>`, `Vec<String>`, etc.
pub(crate) fn add_policy_applicable_bounds(
    mut generics: syn::Generics,
    used_generics: &[Ident],
) -> syn::Generics {
    for param in generics.type_params_mut() {
        if used_generics.iter().any(|g| g == &param.ident) {
            let policy_applicable_path = crate_path("PolicyApplicable");
            param.bounds.push(parse_quote!(#policy_applicable_path));
        }
    }
    generics
}

/// Adds `PolicyApplicableRef` bounds to generic parameters used in policy-annotated fields.
pub(crate) fn add_policy_applicable_ref_bounds(
    mut generics: syn::Generics,
    used_generics: &[Ident],
) -> syn::Generics {
    for param in generics.type_params_mut() {
        if used_generics.iter().any(|g| g == &param.ident) {
            let policy_applicable_path = crate_path("PolicyApplicableRef");
            param.bounds.push(parse_quote!(#policy_applicable_path));
        }
    }
    generics
}

pub(crate) fn add_debug_bounds(
    mut generics: syn::Generics,
    used_generics: &[Ident],
) -> syn::Generics {
    for param in generics.type_params_mut() {
        if used_generics.iter().any(|g| g == &param.ident) {
            param.bounds.push(parse_quote!(::core::fmt::Debug));
        }
    }
    generics
}

pub(crate) fn add_display_bounds(
    mut generics: syn::Generics,
    used_generics: &[Ident],
) -> syn::Generics {
    for param in generics.type_params_mut() {
        if used_generics.iter().any(|g| g == &param.ident) {
            param.bounds.push(parse_quote!(::core::fmt::Display));
        }
    }
    generics
}

pub(crate) fn add_redacted_display_bounds(
    mut generics: syn::Generics,
    used_generics: &[Ident],
) -> syn::Generics {
    for param in generics.type_params_mut() {
        if used_generics.iter().any(|g| g == &param.ident) {
            let redacted_display_path = crate_path("RedactableDisplay");
            param.bounds.push(parse_quote!(#redacted_display_path));
        }
    }
    generics
}
