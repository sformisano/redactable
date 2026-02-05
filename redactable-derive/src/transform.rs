//! Shared field transformation logic for struct and enum derivation.
//!
//! This module extracts the common code for generating field transformations,
//! which was previously duplicated between `derive_struct` and `derive_enum`.

use proc_macro2::{Ident, Span, TokenStream};
use quote::quote_spanned;
use syn::Result;

use crate::{
    crate_path, generics::collect_generics_from_type, strategy::Strategy, types::is_scalar_type,
};

/// Accumulated state during field processing.
///
/// This struct groups the mutable vectors that collect generics and output tokens
/// during traversal of struct fields or enum variants.
pub(crate) struct DeriveContext<'a> {
    pub(crate) generics: &'a syn::Generics,
    pub(crate) container_path: &'a TokenStream,
    pub(crate) used_generics: &'a mut Vec<Ident>,
    pub(crate) policy_applicable_generics: &'a mut Vec<Ident>,
    pub(crate) debug_redacted_generics: &'a mut Vec<Ident>,
    pub(crate) debug_unredacted_generics: &'a mut Vec<Ident>,
}

/// Checks if a policy path refers to the `Default` policy.
fn is_default_policy(path: &syn::Path) -> bool {
    path.is_ident("Default")
}

/// Generates the transform token stream for a single field.
///
/// ## Field Transformation Rules
///
/// | Annotation              | Behavior                                             |
/// |-------------------------|------------------------------------------------------|
/// | None                    | Walk containers, scalars pass through                |
/// | `#[sensitive(Default)]` | Scalars redact to default; strings to "[REDACTED]"   |
/// | `#[sensitive(Policy)]`  | Apply policy recursively through wrappers            |
/// | `#[not_sensitive]`      | Explicit passthrough (no transformation)             |
pub(crate) fn generate_field_transform(
    ctx: &mut DeriveContext<'_>,
    ty: &syn::Type,
    binding: &Ident,
    span: Span,
    strategy: &Strategy,
) -> Result<TokenStream> {
    let container_path = ctx.container_path;

    match strategy {
        Strategy::WalkDefault => {
            if is_scalar_type(ty) {
                Ok(TokenStream::new())
            } else {
                collect_generics_from_type(ty, ctx.generics, ctx.used_generics);
                collect_generics_from_type(ty, ctx.generics, ctx.debug_redacted_generics);
                collect_generics_from_type(ty, ctx.generics, ctx.debug_unredacted_generics);
                Ok(quote_spanned! { span =>
                    let #binding = #container_path::redact_with(#binding, mapper);
                })
            }
        }
        Strategy::NotSensitive => {
            // Explicit opt-out: no transformation, passthrough unchanged.
            // This is useful for foreign types that don't implement RedactableContainer.
            Ok(TokenStream::new())
        }
        Strategy::Policy(policy_path) => {
            if is_scalar_type(ty) {
                if is_default_policy(policy_path) {
                    Ok(quote_spanned! { span =>
                        let #binding = mapper.map_scalar(#binding);
                    })
                } else {
                    Err(syn::Error::new(
                        span,
                        "scalar fields can only use #[sensitive(Default)]; \
                         other policies are for string-like types",
                    ))
                }
            } else {
                collect_generics_from_type(ty, ctx.generics, ctx.policy_applicable_generics);
                collect_generics_from_type(ty, ctx.generics, ctx.debug_unredacted_generics);
                let policy = policy_path.clone();
                let policy_applicable_path = crate_path("PolicyApplicable");
                Ok(quote_spanned! { span =>
                    let #binding = #policy_applicable_path::apply_policy::<#policy, _>(#binding, mapper);
                })
            }
        }
    }
}
