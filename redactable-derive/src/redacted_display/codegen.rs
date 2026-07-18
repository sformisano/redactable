//! Code generation for redacted `Display` impls.
//!
//! Assembles the final `Display` implementation for structs and enums:
//! builds the `format_args!` invocation from the parsed template and field
//! model, and attaches the placeholder's and field's own spans to each
//! generated expression so compiler errors point at user code rather than
//! generated tokens. Emitting tokens is this module's only job — template
//! parsing lives in `template`, the field model in `model`, and generic
//! bounds in `bounds`.

use std::collections::BTreeMap;

use proc_macro2::{Ident, TokenStream};
use quote::{quote, quote_spanned};
use syn::{Attribute, DataEnum, DataStruct, Fields, LitStr, Result};

use crate::{
    crate_path, crate_root,
    fresh_ident::{FreshIdentAllocator, canonical_name},
    strategy::{Strategy, reject_variant_sensitivity_attrs},
};

use super::{
    RedactedDisplayOutput,
    bounds::collect_bounds,
    model::{FieldInfo, FormatArgsOutput, FormatMode, PlaceholderKey, build_fields_from_syn},
    template::{
        merge_mode, parse_placeholders, template_from_attrs, validate_positional_placeholders,
    },
};

pub(super) fn derive_struct_display(
    name: &Ident,
    data: &DataStruct,
    attrs: &[Attribute],
    generics: &syn::Generics,
    formatter: &Ident,
    fresh: &mut FreshIdentAllocator,
) -> Result<RedactedDisplayOutput> {
    let template = template_from_attrs(attrs, name.span())?;
    let fields = build_fields_from_syn(&data.fields, fresh)?;
    let format_args = build_format_args(&template, &fields, generics, formatter, fresh)?;
    let format_prelude = format_args.prelude.clone();
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
    Ok(RedactedDisplayOutput {
        body,
        display_generics: format_args.display_generics,
        debug_generics: format_args.debug_generics,
        policy_ref_generics: format_args.policy_ref_generics,
        nested_generics: format_args.nested_generics,
    })
}

pub(super) fn derive_enum_display(
    name: &Ident,
    data: &DataEnum,
    generics: &syn::Generics,
    formatter: &Ident,
    fresh: &mut FreshIdentAllocator,
) -> Result<RedactedDisplayOutput> {
    let mut arms = Vec::new();
    let mut display_generics = Vec::new();
    let mut debug_generics = Vec::new();
    let mut policy_ref_generics = Vec::new();
    let mut nested_generics = Vec::new();

    for variant in &data.variants {
        reject_variant_sensitivity_attrs(&variant.attrs)?;
        let template = template_from_attrs(&variant.attrs, variant.ident.span())?;
        let fields = build_fields_from_syn(&variant.fields, fresh)?;
        let format_args = build_format_args(&template, &fields, generics, formatter, fresh)?;
        let format_prelude = format_args.prelude.clone();
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

        display_generics.extend(format_args.display_generics);
        debug_generics.extend(format_args.debug_generics);
        policy_ref_generics.extend(format_args.policy_ref_generics);
        nested_generics.extend(format_args.nested_generics);
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

    Ok(RedactedDisplayOutput {
        body,
        display_generics,
        debug_generics,
        policy_ref_generics,
        nested_generics,
    })
}

#[allow(clippy::too_many_lines)]
fn build_format_args(
    template: &LitStr,
    fields: &[FieldInfo<'_>],
    generics: &syn::Generics,
    formatter: &Ident,
    fresh: &mut FreshIdentAllocator,
) -> Result<FormatArgsOutput> {
    let placeholders = parse_placeholders(template)?;
    validate_positional_placeholders(&placeholders)?;
    let mut named_args: BTreeMap<String, (Ident, Ident, &'_ FieldInfo<'_>, FormatMode)> =
        BTreeMap::new();
    let mut positional_args: Vec<Option<(Ident, &'_ FieldInfo<'_>, FormatMode)>> = Vec::new();
    let mut display_generics = Vec::new();
    let mut debug_generics = Vec::new();
    let mut policy_ref_generics = Vec::new();
    let mut nested_generics = Vec::new();

    for placeholder in placeholders {
        match placeholder.key {
            PlaceholderKey::Named(name) => {
                let field = fields
                    .iter()
                    .find(|field| canonical_name(&field.ident) == canonical_name(&name))
                    .ok_or_else(|| {
                        syn::Error::new(
                            placeholder.span,
                            format!("unknown field `{name}` in format string"),
                        )
                    })?;
                let entry = named_args.entry(canonical_name(&name)).or_insert_with(|| {
                    (
                        fresh.fresh_with_ident("__redacted_", &field.ident),
                        field.ident.clone(),
                        field,
                        placeholder.mode,
                    )
                });
                entry.3 = merge_mode(entry.3, placeholder.mode);
            }
            PlaceholderKey::Index(index) => {
                if positional_args.len() <= index {
                    positional_args.resize_with(index + 1, || None);
                }
                let field = fields.get(index).ok_or_else(|| {
                    syn::Error::new(
                        placeholder.span,
                        format!("unknown positional field index {index} in format string"),
                    )
                })?;
                let arg_ident = fresh.fresh(&format!("__redacted_{index}"));
                let entry =
                    positional_args[index].get_or_insert((arg_ident, field, placeholder.mode));
                entry.2 = merge_mode(entry.2, placeholder.mode);
            }
        }
    }

    let mut prelude_bindings = Vec::new();
    let mut positional_idents = Vec::new();
    let mut named_pairs = Vec::new();

    for (_, (arg_ident, name_ident, field, mode)) in named_args {
        let expr = redacted_expr_for_field(field);
        collect_bounds(
            field,
            mode,
            generics,
            &mut display_generics,
            &mut debug_generics,
            &mut policy_ref_generics,
            &mut nested_generics,
        );
        prelude_bindings.push(quote! {
            let #arg_ident = #expr;
        });
        named_pairs.push(quote! { #name_ident = #arg_ident });
    }

    for (arg_ident, field, mode) in positional_args.into_iter().flatten() {
        let expr = redacted_expr_for_field(field);
        collect_bounds(
            field,
            mode,
            generics,
            &mut display_generics,
            &mut debug_generics,
            &mut policy_ref_generics,
            &mut nested_generics,
        );
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

    let prelude = quote! {
        #(#prelude_bindings)*
        #formatter.write_fmt(#format_args)
    };

    Ok(FormatArgsOutput {
        prelude,
        display_generics,
        debug_generics,
        policy_ref_generics,
        nested_generics,
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
            <#field_ty as #redacted_display_path>::redacted_display(&#ident)
        },
        Strategy::NotSensitive => quote_spanned! { span =>
            #ident
        },
        Strategy::Policy(policy) => {
            let policy = policy.clone();
            if field.legacy_formatting_override {
                quote_spanned! { span =>
                    #crate_root::__private::legacy_policy_formatting_ref::<#policy, _>(#ident)
                }
            } else {
                quote_spanned! { span =>
                    {
                        use #crate_root::__private::PolicyFormattingDispatch as _;
                        #crate_root::__private::policy_formatting_probe(#ident)
                            .redactable_policy_formatting::<#policy>()
                    }
                }
            }
        }
    }
}
