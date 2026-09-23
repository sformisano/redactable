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
use syn::{Fields, Result, Type, WherePredicate, spanned::Spanned};

use crate::{
    fresh_ident::FreshIdentAllocator,
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
    pub(super) span: Span,
}

pub(super) struct FormatArgsOutput {
    pub(super) prelude: TokenStream,
    pub(super) predicates: Vec<WherePredicate>,
}

pub(super) fn build_fields_from_syn<'a>(
    fields: &'a Fields,
    fresh: &mut FreshIdentAllocator,
) -> Result<Vec<FieldInfo<'a>>> {
    fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let strategy = parse_field_strategy(&field.attrs)?;
            let redactable_options = parse_redactable_field_options(&field.attrs)?;
            let (ident, binding) = if let Some(ident) = &field.ident {
                (
                    ident.clone(),
                    fresh.fresh_with_ident("__redactable_field_", ident),
                )
            } else {
                let binding = fresh.fresh(&format!("field_{index}"));
                (binding.clone(), binding)
            };
            Ok(FieldInfo {
                ident,
                binding,
                ty: &field.ty,
                strategy,
                recursive_bound_override: redactable_options.recursive,
                span: field.span(),
            })
        })
        .collect()
}
