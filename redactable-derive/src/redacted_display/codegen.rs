//! Code generation for redacted `Display` impls.
//!
//! Assembles the final `Display` implementation for structs and enums:
//! builds the `format_args!` invocation from the parsed template and field
//! model, and attaches the placeholder's and field's own spans to each
//! generated expression so compiler errors point at user code rather than
//! generated tokens. Emitting tokens is this module's only job — template
//! parsing lives in `template` and the field model in `model`.

use std::collections::BTreeMap;
use syn::Error;

use proc_macro2::{Ident, TokenStream};
use quote::{quote, quote_spanned};
use syn::{Attribute, DataEnum, DataStruct, Fields, LitStr, Result};

use crate::{
    crate_path, crate_root,
    fresh_ident::{FreshIdentAllocator, canonical_name},
    strategy::{Strategy, reject_variant_sensitivity_attrs},
};

use super::{
    model::{FieldInfo, PlaceholderKey, build_fields_from_syn},
    template::{parse_placeholders, template_from_attrs, validate_positional_placeholders},
};

pub(super) fn derive_struct_display(
    name: &Ident,
    data: &DataStruct,
    attrs: &[Attribute],
    formatter: &Ident,
    fresh: &mut FreshIdentAllocator,
) -> Result<TokenStream> {
    let template = template_from_attrs(attrs, name.span())?;
    let fields = build_fields_from_syn(&data.fields, fresh)?;
    let format_prelude = build_format_args(&template, &fields, formatter, fresh)?;
    let pattern = match data.fields {
        Fields::Named(_) => {
            let patterns = fields.iter().map(|field| {
                let ident = &field.ident;
                let binding = &field.binding;
                quote! { #ident: #binding }
            });
            quote! { Self { #(#patterns),* } }
        }
        Fields::Unnamed(_) => {
            let bindings = fields.iter().map(|field| &field.binding);
            quote! { Self ( #(#bindings),* ) }
        }
        Fields::Unit => quote! { Self },
    };
    let body = quote! {
        #[allow(unused_variables, unused_assignments)]
        match self {
            #pattern => {
                #format_prelude
            }
        }
    };
    Ok(body)
}

pub(super) fn derive_enum_display(
    name: &Ident,
    data: &DataEnum,
    formatter: &Ident,
    fresh: &mut FreshIdentAllocator,
) -> Result<TokenStream> {
    let mut arms = Vec::new();

    for variant in &data.variants {
        reject_variant_sensitivity_attrs(&variant.attrs)?;
        let template = template_from_attrs(&variant.attrs, variant.ident.span())?;
        let fields = build_fields_from_syn(&variant.fields, fresh)?;
        let format_prelude = build_format_args(&template, &fields, formatter, fresh)?;
        let variant_ident = &variant.ident;
        let pattern = match &variant.fields {
            Fields::Named(_) => {
                let patterns = fields.iter().map(|field| {
                    let ident = &field.ident;
                    let binding = &field.binding;
                    quote! { #ident: #binding }
                });
                quote! { #name::#variant_ident { #(#patterns),* } }
            }
            Fields::Unnamed(_) => {
                let bindings = fields.iter().map(|field| &field.binding);
                quote! { #name::#variant_ident ( #(#bindings),* ) }
            }
            Fields::Unit => quote! { #name::#variant_ident },
        };
        arms.push(quote! {
            #pattern => {
                #format_prelude
            }
        });
    }

    let body = if arms.is_empty() {
        quote! {
            #[allow(unused_variables, unused_assignments)]
            match *self {}
        }
    } else {
        quote! {
            #[allow(unused_variables, unused_assignments)]
            match self {
                #(#arms),*
            }
        }
    };

    Ok(body)
}

#[allow(clippy::too_many_lines)]
fn build_format_args(
    template: &LitStr,
    fields: &[FieldInfo<'_>],
    formatter: &Ident,
    fresh: &mut FreshIdentAllocator,
) -> Result<TokenStream> {
    let placeholders = parse_placeholders(template)?;
    validate_positional_placeholders(&placeholders)?;
    let mut named_args: BTreeMap<String, (Ident, Ident, &'_ FieldInfo<'_>)> = BTreeMap::new();
    let mut positional_args: Vec<Option<(Ident, &'_ FieldInfo<'_>)>> = Vec::new();

    for placeholder in placeholders {
        match placeholder.key {
            PlaceholderKey::Named(name) => {
                let field = fields
                    .iter()
                    .find(|field| canonical_name(&field.ident) == canonical_name(&name))
                    .ok_or_else(|| {
                        Error::new(
                            placeholder.span,
                            format!("unknown field `{name}` in format string"),
                        )
                    })?;
                named_args.entry(canonical_name(&name)).or_insert_with(|| {
                    (
                        fresh.fresh_with_ident("__redacted_", &field.ident),
                        field.ident.clone(),
                        field,
                    )
                });
            }
            PlaceholderKey::Index(index) => {
                if positional_args.len() <= index {
                    positional_args.resize_with(index + 1, || None);
                }
                let field = fields.get(index).ok_or_else(|| {
                    Error::new(
                        placeholder.span,
                        format!("unknown positional field index {index} in format string"),
                    )
                })?;
                let arg_ident = fresh.fresh(&format!("__redacted_{index}"));
                positional_args[index].get_or_insert((arg_ident, field));
            }
        }
    }

    let mut prelude_bindings = Vec::new();
    let mut positional_idents = Vec::new();
    let mut named_pairs = Vec::new();

    for (_, (arg_ident, name_ident, field)) in named_args {
        let expr = redacted_expr_for_field(field);
        prelude_bindings.push(quote! {
            let #arg_ident = #expr;
        });
        named_pairs.push(quote! { #name_ident = #arg_ident });
    }

    for (arg_ident, field) in positional_args.into_iter().flatten() {
        let expr = redacted_expr_for_field(field);
        prelude_bindings.push(quote! {
            let #arg_ident = #expr;
        });
        positional_idents.push(arg_ident);
    }

    let format_args = match (positional_idents.is_empty(), named_pairs.is_empty()) {
        (true, true) => quote! { format_args!(#template) },
        (false, true) => quote! { format_args!(#template, #(#positional_idents),*) },
        (true, false) => quote! { format_args!(#template, #(#named_pairs),*) },
        (false, false) => {
            quote! { format_args!(#template, #(#positional_idents),*, #(#named_pairs),*) }
        }
    };

    Ok(quote! {
        #(#prelude_bindings)*
        #formatter.write_fmt(#format_args)
    })
}

fn redacted_expr_for_field(field: &FieldInfo<'_>) -> TokenStream {
    let ident = &field.binding;
    let span = field.span;
    let crate_root = crate_root();
    let redacted_display_path = crate_path("RedactableWithFormatter");
    let field_ty = field.ty;
    match &field.strategy {
        Strategy::WalkDefault => quote_spanned! { span =>
            {
                #crate_root::__private::require_declared_formatting::<#field_ty>(#ident);
                <#field_ty as #redacted_display_path>::redacted_display(&#ident)
            }
        },
        Strategy::NotSensitive => quote_spanned! { span =>
            #ident
        },
        Strategy::Policy(policy) => quote_spanned! { span =>
            #crate_root::__private::policy_formatting_ref::<#policy, _>(#ident)
        },
    }
}
