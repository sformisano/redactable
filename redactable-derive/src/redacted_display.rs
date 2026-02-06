//! Redacted display formatting for `SensitiveDisplay`.
//!
//! This module derives a redacted formatting implementation from thiserror-style
//! `#[error("...")]` strings or displaydoc-style doc comments.
//!
//! Unannotated fields referenced in a template use `RedactableDisplay` by default.
//! Use `#[not_sensitive]` for raw output or `#[sensitive(Policy)]` for policy redaction.

use std::collections::BTreeMap;

use proc_macro2::{Ident, Span, TokenStream};
use quote::{format_ident, quote, quote_spanned};
use syn::{Attribute, Data, DataEnum, DataStruct, Fields, LitStr, Result, spanned::Spanned};

use crate::{
    crate_path,
    generics::collect_generics_from_type,
    strategy::{Strategy, parse_field_strategy},
    types::is_scalar_type,
};

pub(crate) struct RedactedDisplayOutput {
    pub(crate) body: TokenStream,
    pub(crate) display_generics: Vec<Ident>,
    pub(crate) debug_generics: Vec<Ident>,
    pub(crate) policy_ref_generics: Vec<Ident>,
    pub(crate) nested_generics: Vec<Ident>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FormatMode {
    Display,
    Debug,
    Both,
}

#[derive(Clone, Debug)]
enum PlaceholderKey {
    Named(Ident),
    Index(usize),
}

#[derive(Clone, Debug)]
struct Placeholder {
    key: PlaceholderKey,
    mode: FormatMode,
    span: Span,
}

struct FieldInfo<'a> {
    ident: Ident,
    ty: &'a syn::Type,
    strategy: Strategy,
    span: Span,
}

struct FormatArgsOutput {
    prelude: TokenStream,
    display_generics: Vec<Ident>,
    debug_generics: Vec<Ident>,
    policy_ref_generics: Vec<Ident>,
    nested_generics: Vec<Ident>,
}

pub(crate) fn derive_redacted_display(
    name: &Ident,
    data: &Data,
    attrs: &[Attribute],
    generics: &syn::Generics,
) -> Result<RedactedDisplayOutput> {
    match data {
        Data::Struct(data) => derive_struct_display(name, data, attrs, generics),
        Data::Enum(data) => derive_enum_display(name, data, generics),
        Data::Union(u) => Err(syn::Error::new(
            u.union_token.span(),
            "`SensitiveDisplay` cannot be derived for unions",
        )),
    }
}

fn derive_struct_display(
    name: &Ident,
    data: &DataStruct,
    attrs: &[Attribute],
    generics: &syn::Generics,
) -> Result<RedactedDisplayOutput> {
    let template = template_from_attrs(attrs, name.span())?;
    let fields = build_fields(data)?;
    let format_args = build_format_args(&template, &fields, generics)?;
    let format_prelude = format_args.prelude.clone();
    let bindings = fields.iter().map(|field| field.ident.clone());
    let pattern = match data.fields {
        Fields::Named(_) => quote! { Self { #(#bindings),* } },
        Fields::Unnamed(_) => quote! { Self ( #(#bindings),* ) },
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

fn derive_enum_display(
    name: &Ident,
    data: &DataEnum,
    generics: &syn::Generics,
) -> Result<RedactedDisplayOutput> {
    let mut arms = Vec::new();
    let mut display_generics = Vec::new();
    let mut debug_generics = Vec::new();
    let mut policy_ref_generics = Vec::new();
    let mut nested_generics = Vec::new();

    for variant in &data.variants {
        let template = template_from_attrs(&variant.attrs, variant.ident.span())?;
        let fields = build_fields_from_variant(variant)?;
        let format_args = build_format_args(&template, &fields, generics)?;
        let format_prelude = format_args.prelude.clone();
        let bindings = fields.iter().map(|field| field.ident.clone());
        let variant_ident = &variant.ident;
        let pattern = match &variant.fields {
            Fields::Named(_) => quote! { #name::#variant_ident { #(#bindings),* } },
            Fields::Unnamed(_) => quote! { #name::#variant_ident ( #(#bindings),* ) },
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

    let body = quote! {
        #[allow(unused_variables, unused_assignments)]
        match self {
            #(#arms),*
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

fn build_fields(data: &DataStruct) -> Result<Vec<FieldInfo<'_>>> {
    match &data.fields {
        Fields::Named(fields) => fields
            .named
            .iter()
            .map(|field| {
                let strategy = parse_field_strategy(&field.attrs)?;
                let ident = field
                    .ident
                    .clone()
                    .expect("named field should have identifier");
                Ok(FieldInfo {
                    ident,
                    ty: &field.ty,
                    strategy,
                    span: field.span(),
                })
            })
            .collect(),
        Fields::Unnamed(fields) => fields
            .unnamed
            .iter()
            .enumerate()
            .map(|(index, field)| {
                let strategy = parse_field_strategy(&field.attrs)?;
                Ok(FieldInfo {
                    ident: format_ident!("field_{index}"),
                    ty: &field.ty,
                    strategy,
                    span: field.span(),
                })
            })
            .collect(),
        Fields::Unit => Ok(Vec::new()),
    }
}

fn build_fields_from_variant(variant: &syn::Variant) -> Result<Vec<FieldInfo<'_>>> {
    match &variant.fields {
        Fields::Named(fields) => fields
            .named
            .iter()
            .map(|field| {
                let strategy = parse_field_strategy(&field.attrs)?;
                let ident = field
                    .ident
                    .clone()
                    .expect("named field should have identifier");
                Ok(FieldInfo {
                    ident,
                    ty: &field.ty,
                    strategy,
                    span: field.span(),
                })
            })
            .collect(),
        Fields::Unnamed(fields) => fields
            .unnamed
            .iter()
            .enumerate()
            .map(|(index, field)| {
                let strategy = parse_field_strategy(&field.attrs)?;
                Ok(FieldInfo {
                    ident: format_ident!("field_{index}"),
                    ty: &field.ty,
                    strategy,
                    span: field.span(),
                })
            })
            .collect(),
        Fields::Unit => Ok(Vec::new()),
    }
}

#[allow(clippy::too_many_lines)]
fn build_format_args(
    template: &LitStr,
    fields: &[FieldInfo<'_>],
    generics: &syn::Generics,
) -> Result<FormatArgsOutput> {
    let placeholders = parse_placeholders(template)?;
    let mut named_args: BTreeMap<String, (Ident, &'_ FieldInfo<'_>, FormatMode)> = BTreeMap::new();
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
                    .find(|field| field.ident == name)
                    .ok_or_else(|| {
                        syn::Error::new(
                            placeholder.span,
                            format!("unknown field `{name}` in format string"),
                        )
                    })?;
                let arg_ident = format_ident!("__redacted_{}", name);
                let entry = named_args.entry(name.to_string()).or_insert((
                    arg_ident,
                    field,
                    placeholder.mode,
                ));
                entry.2 = merge_mode(entry.2, placeholder.mode);
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
                let arg_ident = format_ident!("__redacted_{index}");
                let entry =
                    positional_args[index].get_or_insert((arg_ident, field, placeholder.mode));
                entry.2 = merge_mode(entry.2, placeholder.mode);
            }
        }
    }

    let mut prelude_bindings = Vec::new();
    let mut positional_idents = Vec::new();
    let mut named_pairs = Vec::new();

    for (name, (arg_ident, field, mode)) in named_args {
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
        let name_ident = format_ident!("{name}");
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
        f.write_fmt(#format_args)
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
    let ident = &field.ident;
    let span = field.span;
    let scalar_path = crate_path("ScalarRedaction");
    let apply_policy_ref_path = crate_path("apply_policy_ref");
    let redacted_display_path = crate_path("RedactableDisplay");
    let field_ty = field.ty;
    match &field.strategy {
        Strategy::WalkDefault => quote_spanned! { span =>
            <#field_ty as #redacted_display_path>::redacted_display(&#ident)
        },
        Strategy::NotSensitive => quote_spanned! { span =>
            #ident
        },
        Strategy::Policy(policy) => {
            if is_scalar_type(field.ty) && policy.is_ident("Secret") {
                quote_spanned! { span =>
                    #scalar_path::redact(*#ident)
                }
            } else {
                let policy = policy.clone();
                quote_spanned! { span =>
                    #apply_policy_ref_path::<#policy, _>(#ident)
                }
            }
        }
    }
}

fn collect_bounds(
    field: &FieldInfo<'_>,
    mode: FormatMode,
    generics: &syn::Generics,
    display_generics: &mut Vec<Ident>,
    debug_generics: &mut Vec<Ident>,
    policy_ref_generics: &mut Vec<Ident>,
    nested_generics: &mut Vec<Ident>,
) {
    match &field.strategy {
        Strategy::WalkDefault => {
            collect_generics_from_type(field.ty, generics, nested_generics);
        }
        Strategy::NotSensitive => match mode {
            FormatMode::Display => collect_generics_from_type(field.ty, generics, display_generics),
            FormatMode::Debug => collect_generics_from_type(field.ty, generics, debug_generics),
            FormatMode::Both => {
                collect_generics_from_type(field.ty, generics, display_generics);
                collect_generics_from_type(field.ty, generics, debug_generics);
            }
        },
        Strategy::Policy(policy) => {
            if is_scalar_type(field.ty) && policy.is_ident("Secret") {
                return;
            }
            collect_generics_from_type(field.ty, generics, policy_ref_generics);
            match mode {
                FormatMode::Display => {
                    collect_generics_from_type(field.ty, generics, display_generics);
                }
                FormatMode::Debug => collect_generics_from_type(field.ty, generics, debug_generics),
                FormatMode::Both => {
                    collect_generics_from_type(field.ty, generics, display_generics);
                    collect_generics_from_type(field.ty, generics, debug_generics);
                }
            }
        }
    }
}

fn merge_mode(existing: FormatMode, next: FormatMode) -> FormatMode {
    match (existing, next) {
        (FormatMode::Both, _) | (_, FormatMode::Both) => FormatMode::Both,
        (FormatMode::Display, FormatMode::Debug) | (FormatMode::Debug, FormatMode::Display) => {
            FormatMode::Both
        }
        (FormatMode::Display, FormatMode::Display) => FormatMode::Display,
        (FormatMode::Debug, FormatMode::Debug) => FormatMode::Debug,
    }
}

fn template_from_attrs(attrs: &[Attribute], span: Span) -> Result<LitStr> {
    if let Some(error) = error_template_from_attrs(attrs)? {
        return Ok(error);
    }
    if let Some(doc) = doc_template_from_attrs(attrs) {
        return Ok(doc);
    }
    Err(syn::Error::new(
        span,
        "missing display template: add #[error(\"...\")] or a doc comment",
    ))
}

fn error_template_from_attrs(attrs: &[Attribute]) -> Result<Option<LitStr>> {
    for attr in attrs {
        if !attr.path().is_ident("error") {
            continue;
        }
        match &attr.meta {
            syn::Meta::List(list) => {
                let error_lit: Result<LitStr> = syn::parse2(list.tokens.clone());
                return error_lit
                    .map(Some)
                    .map_err(|_| syn::Error::new(attr.span(), "expected #[error(\"...\")]"));
            }
            _ => {
                return Err(syn::Error::new(attr.span(), "expected #[error(\"...\")]"));
            }
        }
    }
    Ok(None)
}

fn doc_template_from_attrs(attrs: &[Attribute]) -> Option<LitStr> {
    let mut lines = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("doc") {
            continue;
        }
        if let syn::Meta::NameValue(value) = &attr.meta
            && let syn::Expr::Lit(expr) = &value.value
            && let syn::Lit::Str(lit) = &expr.lit
        {
            lines.push(lit.value().trim_start().to_string());
        }
    }
    if lines.is_empty() {
        return None;
    }
    let text = lines.join("\n");
    Some(LitStr::new(text.trim(), Span::call_site()))
}

fn parse_placeholders(template: &LitStr) -> Result<Vec<Placeholder>> {
    let value = template.value();
    let mut chars = value.chars().peekable();
    let mut placeholders = Vec::new();
    let mut implicit_index = 0usize;

    while let Some(ch) = chars.next() {
        match ch {
            '{' => {
                if matches!(chars.peek(), Some('{')) {
                    chars.next();
                    continue;
                }
                let mut inside = String::new();
                let mut closed = false;
                for next in chars.by_ref() {
                    if next == '}' {
                        closed = true;
                        break;
                    }
                    inside.push(next);
                }
                if !closed {
                    return Err(syn::Error::new(
                        template.span(),
                        "unmatched `{` in format string",
                    ));
                }

                let mut parts = inside.splitn(2, ':');
                let arg_part = parts.next().unwrap_or("").trim();
                let spec_part = parts.next().unwrap_or("");
                let mode = format_mode_from_spec(spec_part, template.span())?;
                let key = if arg_part.is_empty() {
                    let index = implicit_index;
                    implicit_index += 1;
                    PlaceholderKey::Index(index)
                } else if arg_part.chars().all(|c| c.is_ascii_digit()) {
                    let index = arg_part
                        .parse::<usize>()
                        .map_err(|_| syn::Error::new(template.span(), "invalid index"))?;
                    PlaceholderKey::Index(index)
                } else if is_ident(arg_part) {
                    PlaceholderKey::Named(Ident::new(arg_part, template.span()))
                } else {
                    return Err(syn::Error::new(
                        template.span(),
                        format!("unsupported format placeholder `{arg_part}`"),
                    ));
                };
                placeholders.push(Placeholder {
                    key,
                    mode,
                    span: template.span(),
                });
            }
            '}' => {
                if matches!(chars.peek(), Some('}')) {
                    chars.next();
                } else {
                    return Err(syn::Error::new(
                        template.span(),
                        "unmatched `}` in format string",
                    ));
                }
            }
            _ => {}
        }
    }

    Ok(placeholders)
}

fn format_mode_from_spec(spec_part: &str, span: Span) -> Result<FormatMode> {
    let spec = spec_part.trim();
    if spec.is_empty() {
        return Ok(FormatMode::Display);
    }
    if spec.contains('$') || spec.contains('*') {
        return Err(syn::Error::new(
            span,
            "format specifiers with dynamic width/precision are not supported",
        ));
    }
    let last = spec.chars().last().unwrap_or_default();
    match last {
        '?' => Ok(FormatMode::Debug),
        'x' | 'X' | 'o' | 'b' | 'p' | 'e' | 'E' => Err(syn::Error::new(
            span,
            format!("unsupported format specifier `{spec}`; only Display and Debug are supported"),
        )),
        _ => Ok(FormatMode::Display),
    }
}

fn is_ident(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(ch) if ch == '_' || ch.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}
