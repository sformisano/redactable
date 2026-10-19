//! Internal placeholder and field model for redacted `Display`.
//!
//! Defines the shared vocabulary of the redacted-display pipeline:
//! [`Placeholder`] / [`PlaceholderKey`] (parsed template holes) and
//! [`FieldInfo`] (a syn field paired with its strategy). It also builds that
//! field model from the syn input (`build_fields_from_syn`), which is where
//! per-field attribute parsing happens.

use proc_macro2::{Ident, Span};
use syn::{Fields, Result, Type, spanned::Spanned};

use crate::{
    fresh_ident::FreshIdentAllocator,
    strategy::{Strategy, parse_field_strategy, parse_redactable_field_options},
};

#[derive(Clone, Debug)]
pub(super) enum PlaceholderKey {
    Named(Ident),
    Index(usize),
}

#[derive(Clone, Debug)]
pub(super) struct Placeholder {
    pub(super) key: PlaceholderKey,
    pub(super) span: Span,
}

pub(super) struct FieldInfo<'a> {
    pub(super) ident: Ident,
    pub(super) binding: Ident,
    pub(super) ty: &'a Type,
    pub(super) strategy: Strategy,
    pub(super) span: Span,
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
            // Display impls infer no field bounds, so `recursive` changes nothing
            // here; malformed options are still rejected.
            parse_redactable_field_options(&field.attrs)?;
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
                span: field.span(),
            })
        })
        .collect()
}
