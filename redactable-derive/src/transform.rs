//! Shared field handling for struct and enum derivation.
//!
//! One loop produces the destructuring pattern, the per-field transforms and
//! the redacted `Debug` body for a named or unnamed field list. Structs and
//! enum variants only differ in the path that precedes the pattern.

use proc_macro2::{Ident, Span, TokenStream};
use quote::{quote, quote_spanned};
use syn::{Fields, Result, Type, WherePredicate, spanned::Spanned};

use crate::{
    crate_root,
    fresh_ident::FreshIdentAllocator,
    generics::{push_container_predicate, push_debug_predicate, push_policy_predicate},
    strategy::{Strategy, parse_field_strategy, parse_redactable_field_options},
};

/// Accumulated state during field processing.
///
/// This struct groups the mutable vectors that collect generics and output tokens
/// during traversal of struct fields or enum variants.
pub(crate) struct DeriveContext<'a> {
    pub(crate) container_path: &'a TokenStream,
    /// Traversal and policy bounds shared by every structural impl.
    pub(crate) predicates: &'a mut Vec<WherePredicate>,
    /// Extra bounds only the generated `Debug` impl needs.
    pub(crate) debug_predicates: &'a mut Vec<WherePredicate>,
    pub(crate) mapper: &'a Ident,
}

/// Tokens derived from one named or unnamed field list.
pub(crate) struct FieldsOutput {
    /// `{ a: binding, .. }` or `( binding, .. )`, following the owner's path.
    pub(crate) pattern: TokenStream,
    /// The same shape rebuilt from the transformed bindings.
    pub(crate) reconstruction: TokenStream,
    /// One `let` rebinding per field, in declaration order.
    pub(crate) transforms: Vec<TokenStream>,
    /// The redacted `Debug` pattern, with sensitive fields left unbound.
    pub(crate) debug_pattern: TokenStream,
    /// The redacted `Debug` builder block.
    pub(crate) debug_body: TokenStream,
}

/// Derives the redaction and `Debug` tokens for a field list.
///
/// Returns `None` for a unit shape, which has no fields to destructure.
pub(crate) fn derive_fields(
    ctx: &mut DeriveContext<'_>,
    fields: Fields,
    formatter: &Ident,
    debug_name: &TokenStream,
    fresh: &mut FreshIdentAllocator,
) -> Result<Option<FieldsOutput>> {
    let (named, fields) = match fields {
        Fields::Unit => return Ok(None),
        Fields::Named(fields) => (true, fields.named),
        Fields::Unnamed(fields) => (false, fields.unnamed),
    };
    let debug = fresh.fresh("__redactable_debug");
    let mut patterns = Vec::new();
    let mut reconstructions = Vec::new();
    let mut transforms = Vec::new();
    let mut debug_patterns = Vec::new();
    let mut debug_fields = Vec::new();

    for (index, field) in fields.into_iter().enumerate() {
        let span = field.span();
        let strategy = parse_field_strategy(&field.attrs)?;
        let recursive_bound_override = parse_redactable_field_options(&field.attrs)?.recursive;
        let ty = &field.ty;
        let is_sensitive = matches!(&strategy, Strategy::Policy(_));

        if named {
            let ident = field.ident.expect("named field should have an identifier");
            let binding = fresh.fresh_with_ident("__redactable_field_", &ident);
            patterns.push(quote_spanned! { span => #ident: #binding });
            reconstructions.push(quote_spanned! { span => #ident: #binding });
            transforms.push(generate_field_transform(
                ctx,
                ty,
                &binding,
                span,
                &strategy,
                recursive_bound_override,
            ));
            // Sensitive fields print a placeholder and are left unbound so the
            // redacted `Debug` impl never touches them.
            if is_sensitive {
                debug_patterns.push(quote_spanned! { span => #ident: _ });
                debug_fields.push(quote_spanned! { span =>
                    #debug.field(stringify!(#ident), &"[REDACTED]");
                });
            } else {
                debug_patterns.push(quote_spanned! { span => #ident: #binding });
                debug_fields.push(quote_spanned! { span =>
                    #debug.field(stringify!(#ident), #binding);
                });
            }
        } else {
            let binding = fresh.fresh(&format!("field_{index}"));
            patterns.push(quote! { #binding });
            reconstructions.push(quote! { #binding });
            transforms.push(generate_field_transform(
                ctx,
                ty,
                &binding,
                span,
                &strategy,
                recursive_bound_override,
            ));
            if is_sensitive {
                debug_patterns.push(quote_spanned! { span => _ });
                debug_fields.push(quote_spanned! { span =>
                    #debug.field(&"[REDACTED]");
                });
            } else {
                debug_patterns.push(quote_spanned! { span => #binding });
                debug_fields.push(quote_spanned! { span =>
                    #debug.field(#binding);
                });
            }
        }
    }

    let (pattern, reconstruction, debug_pattern, builder) = if named {
        (
            quote! { { #(#patterns),* } },
            quote! { { #(#reconstructions),* } },
            quote! { { #(#debug_patterns),* } },
            quote! { debug_struct },
        )
    } else {
        (
            quote! { ( #(#patterns),* ) },
            quote! { ( #(#reconstructions),* ) },
            quote! { ( #(#debug_patterns),* ) },
            quote! { debug_tuple },
        )
    };
    let debug_body = quote! {
        {
            let mut #debug = #formatter.#builder(#debug_name);
            #(#debug_fields)*
            #debug.finish()
        }
    };
    Ok(Some(FieldsOutput {
        pattern,
        reconstruction,
        transforms,
        debug_pattern,
        debug_body,
    }))
}

/// Generates the transform token stream for a single field.
///
/// ## Field Transformation Rules
///
/// | Annotation              | Behavior                                             |
/// |-------------------------|------------------------------------------------------|
/// | None                    | Traverse types with declared redaction behavior      |
/// | `#[sensitive(Secret)]`  | Scalars redact to default; strings to "[REDACTED]"   |
/// | `#[sensitive(Policy)]`  | Apply policy recursively through wrappers            |
/// | `#[not_sensitive]`      | Explicit passthrough (no transformation)             |
fn generate_field_transform(
    ctx: &mut DeriveContext<'_>,
    ty: &Type,
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
                push_container_predicate(ctx.predicates, ty);
                push_debug_predicate(ctx.debug_predicates, ty);
            }
            let crate_root = crate_root();
            quote_spanned! { span =>
                #crate_root::__private::require_declared_redaction::<#ty>(&#binding);
                let #binding = #container_path::redact_with(#binding, #mapper);
            }
        }
        Strategy::NotSensitive => {
            // Explicit opt-out: no transformation, passthrough unchanged.
            // This is useful for foreign types that don't implement RedactableWithMapper.
            // Still collect debug generics: the field is printed in generated Debug impls
            // even though it's not transformed, so its type needs a Debug bound.
            if !recursive_bound_override {
                push_debug_predicate(ctx.debug_predicates, ty);
            }
            TokenStream::new()
        }
        Strategy::Policy(policy_path) => {
            if !recursive_bound_override {
                push_policy_predicate(ctx.predicates, ty, policy_path);
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
