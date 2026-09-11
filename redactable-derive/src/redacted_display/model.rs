//! Internal placeholder and field model for redacted `Display`.
//!
//! Defines the shared vocabulary of the redacted-display pipeline:
//! [`FormatMode`] (whether a placeholder renders via `Display`, `Debug`, or
//! both), [`Placeholder`] / [`PlaceholderKey`] (parsed template holes),
//! [`FieldInfo`] (a syn field paired with its strategy and parsed options),
//! and [`FormatArgsOutput`] (the assembled format arguments). It also builds
//! that field model from the syn input (`build_fields_from_syn`), which is
//! where per-field strategy and option parsing is attached to each field.

use proc_macro2::{Ident, Span, TokenStream};
use syn::{Error, Fields, Generics, Result, Type, WherePredicate, spanned::Spanned};

use crate::{
    fresh_ident::FreshIdentAllocator,
    generics::{
        OwnerTypeParameterUsage, owner_type_parameter_usage, policy_is_owner_type_parameter,
        references_explicit_policy_applicable_ref,
    },
    strategy::{Strategy, parse_field_strategy, parse_redactable_field_options},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FormatMode {
    Display,
    Debug,
    Both,
}

#[derive(Clone, Debug)]
pub(super) enum PlaceholderKey {
    Named(Ident),
    Index(usize),
}

#[derive(Clone, Debug)]
pub(super) struct Placeholder {
    pub(super) key: PlaceholderKey,
    pub(super) mode: FormatMode,
    pub(super) span: Span,
}

pub(super) struct FieldInfo<'a> {
    pub(super) ident: Ident,
    pub(super) binding: Ident,
    pub(super) ty: &'a Type,
    pub(super) strategy: Strategy,
    pub(super) recursive_bound_override: bool,
    pub(super) formatting_route: FormattingRoute,
    pub(super) span: Span,
}

pub(super) struct FormatArgsOutput {
    pub(super) prelude: TokenStream,
    pub(super) display_generics: Vec<WherePredicate>,
    pub(super) debug_generics: Vec<WherePredicate>,
    pub(super) policy_ref_generics: Vec<WherePredicate>,
    pub(super) nested_generics: Vec<WherePredicate>,
}

pub(super) fn build_fields_from_syn<'a>(
    fields: &'a Fields,
    generics: &Generics,
    fresh: &mut FreshIdentAllocator,
) -> Result<Vec<FieldInfo<'a>>> {
    match fields {
        Fields::Named(fields) => fields
            .named
            .iter()
            .map(|field| {
                let strategy = parse_field_strategy(&field.attrs)?;
                let redactable_options = parse_redactable_field_options(&field.attrs)?;
                if redactable_options.legacy_formatting
                    && !matches!(strategy, Strategy::Policy(_))
                {
                    return Err(Error::new(
                        field.span(),
                        "`#[redactable(legacy_formatting)]` requires `#[sensitive(Policy)]` on the same field",
                    ));
                }
                if redactable_options.generated_formatting
                    && !matches!(strategy, Strategy::Policy(_))
                {
                    return Err(Error::new(
                        field.span(),
                        "`#[redactable(generated_formatting)]` requires `#[sensitive(Policy)]` on the same field",
                    ));
                }
                if redactable_options.legacy_formatting && redactable_options.generated_formatting {
                    return Err(Error::new(
                        field.span(),
                        "`legacy_formatting` and `generated_formatting` are mutually exclusive",
                    ));
                }
                let ident = field
                    .ident
                    .clone()
                    .expect("named field should have identifier");
                let binding = fresh.fresh_with_ident("__redactable_field_", &ident);
                Ok(FieldInfo {
                    ident,
                    binding,
                    ty: &field.ty,
                    formatting_route: formatting_route(generics, &field.ty, &strategy, redactable_options.legacy_formatting, redactable_options.generated_formatting),
                    strategy,
                    recursive_bound_override: redactable_options.recursive,
                    span: field.span(),
                })
            })
            .collect(),
        Fields::Unnamed(fields) => {
            let mut output = Vec::with_capacity(fields.unnamed.len());
            for (index, field) in fields.unnamed.iter().enumerate() {
                let strategy = parse_field_strategy(&field.attrs)?;
                let redactable_options = parse_redactable_field_options(&field.attrs)?;
                if redactable_options.legacy_formatting
                    && !matches!(strategy, Strategy::Policy(_))
                {
                    return Err(Error::new(
                        field.span(),
                        "`#[redactable(legacy_formatting)]` requires `#[sensitive(Policy)]` on the same field",
                    ));
                }
                if redactable_options.generated_formatting
                    && !matches!(strategy, Strategy::Policy(_))
                {
                    return Err(Error::new(
                        field.span(),
                        "`#[redactable(generated_formatting)]` requires `#[sensitive(Policy)]` on the same field",
                    ));
                }
                if redactable_options.legacy_formatting && redactable_options.generated_formatting {
                    return Err(Error::new(
                        field.span(),
                        "`legacy_formatting` and `generated_formatting` are mutually exclusive",
                    ));
                }
                let binding = fresh.fresh(&format!("field_{index}"));
                output.push(FieldInfo {
                    ident: binding.clone(),
                    binding,
                    ty: &field.ty,
                    formatting_route: formatting_route(generics, &field.ty, &strategy, redactable_options.legacy_formatting, redactable_options.generated_formatting),
                    strategy,
                    recursive_bound_override: redactable_options.recursive,
                    span: field.span(),
                });
            }
            Ok(output)
        }
        Fields::Unit => Ok(Vec::new()),
    }
}

/// One routing decision shared by bound collection and expression emission.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum FormattingRoute {
    Legacy,
    Declared,
    DirectMarker,
    Nominal,
}

fn formatting_route(
    generics: &Generics,
    ty: &Type,
    strategy: &Strategy,
    legacy: bool,
    generated: bool,
) -> FormattingRoute {
    if legacy {
        return FormattingRoute::Legacy;
    }
    if generated {
        return FormattingRoute::Declared;
    }
    let Strategy::Policy(policy) = strategy else {
        return FormattingRoute::Nominal;
    };
    let generic_field = !matches!(
        owner_type_parameter_usage(generics, ty),
        OwnerTypeParameterUsage::None
    );
    if generic_field && references_explicit_policy_applicable_ref(generics, ty) {
        FormattingRoute::DirectMarker
    } else if generic_field || policy_is_owner_type_parameter(generics, policy) {
        FormattingRoute::Declared
    } else {
        FormattingRoute::Nominal
    }
}
