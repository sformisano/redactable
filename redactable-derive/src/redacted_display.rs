//! Redacted display formatting for `SensitiveDisplay`.
//!
//! This module derives a redacted formatting implementation from thiserror-style
//! `#[error("...")]` strings or displaydoc-style doc comments.
//!
//! Unannotated fields referenced in a template use `RedactableWithFormatter` by default.
//! Use `#[not_sensitive]` for raw output or `#[sensitive(Policy)]` for policy redaction.

mod bounds;
mod codegen;
mod declaration;
mod model;
mod template;

use proc_macro2::{Ident, TokenStream};
use syn::{Attribute, Result, WherePredicate};

use crate::{container::Body, fresh_ident::FreshIdentAllocator};

use self::codegen::{derive_enum_display, derive_struct_display};
pub(crate) use self::declaration::checked_display_body;

pub(crate) struct RedactedDisplayOutput {
    pub(crate) body: TokenStream,
    pub(crate) predicates: Vec<WherePredicate>,
}

/// Returns the redacted formatting body for the type's template or templates.
pub(crate) fn derive_redacted_display(
    name: &Ident,
    body: &Body,
    attrs: &[Attribute],
    formatter: &Ident,
    fresh: &mut FreshIdentAllocator,
) -> Result<RedactedDisplayOutput> {
    match body {
        Body::Struct(data) => derive_struct_display(name, data, attrs, formatter, fresh),
        Body::Enum(data) => derive_enum_display(name, data, formatter, fresh),
    }
}
