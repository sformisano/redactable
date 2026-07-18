//! Redacted display formatting for `SensitiveDisplay`.
//!
//! This module derives a redacted formatting implementation from thiserror-style
//! `#[error("...")]` strings or displaydoc-style doc comments.
//!
//! Unannotated fields referenced in a template use `RedactableWithFormatter` by default.
//! Use `#[not_sensitive]` for raw output or `#[sensitive(Policy)]` for policy redaction.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{Ident, Span, TokenStream};
use quote::{quote, quote_spanned};
use syn::{Attribute, Data, DataEnum, DataStruct, Fields, LitStr, Result, spanned::Spanned};

use crate::{
    crate_path, crate_root,
    fresh_ident::{FreshIdentAllocator, canonical_name},
    generics::{
        OwnerTypeParameterUsage, owner_type_parameter_usage, policy_is_owner_type_parameter,
        push_debug_predicate, push_direct_marker_debug_formatting_predicates,
        push_direct_marker_display_formatting_predicates, push_display_predicate,
        push_generated_policy_debug_formatting_predicate,
        push_generated_policy_display_formatting_predicate,
        push_legacy_policy_debug_formatting_predicates,
        push_legacy_policy_display_formatting_predicates, push_policy_debug_formatting_predicate,
        push_policy_display_formatting_predicate, push_redacted_display_predicate,
        references_explicit_policy_applicable_ref,
    },
    strategy::{
        Strategy, parse_field_strategy, parse_redactable_field_options,
        reject_variant_sensitivity_attrs,
    },
};

pub(crate) struct RedactedDisplayOutput {
    pub(crate) body: TokenStream,
    pub(crate) display_generics: Vec<syn::WherePredicate>,
    pub(crate) debug_generics: Vec<syn::WherePredicate>,
    pub(crate) policy_ref_generics: Vec<syn::WherePredicate>,
    pub(crate) nested_generics: Vec<syn::WherePredicate>,
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
    binding: Ident,
    ty: &'a syn::Type,
    strategy: Strategy,
    recursive_bound_override: bool,
    legacy_formatting_override: bool,
    generated_formatting_override: bool,
    span: Span,
}

struct FormatArgsOutput {
    prelude: TokenStream,
    display_generics: Vec<syn::WherePredicate>,
    debug_generics: Vec<syn::WherePredicate>,
    policy_ref_generics: Vec<syn::WherePredicate>,
    nested_generics: Vec<syn::WherePredicate>,
}

pub(crate) fn derive_redacted_display(
    name: &Ident,
    data: &Data,
    attrs: &[Attribute],
    generics: &syn::Generics,
    formatter: &Ident,
    fresh: &mut FreshIdentAllocator,
) -> Result<RedactedDisplayOutput> {
    match data {
        Data::Struct(data) => derive_struct_display(name, data, attrs, generics, formatter, fresh),
        Data::Enum(data) => derive_enum_display(name, data, generics, formatter, fresh),
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

fn derive_enum_display(
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

fn build_fields_from_syn<'a>(
    fields: &'a Fields,
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
                    return Err(syn::Error::new(
                        field.span(),
                        "`#[redactable(legacy_formatting)]` requires `#[sensitive(Policy)]` on the same field",
                    ));
                }
                if redactable_options.generated_formatting
                    && !matches!(strategy, Strategy::Policy(_))
                {
                    return Err(syn::Error::new(
                        field.span(),
                        "`#[redactable(generated_formatting)]` requires `#[sensitive(Policy)]` on the same field",
                    ));
                }
                if redactable_options.legacy_formatting && redactable_options.generated_formatting {
                    return Err(syn::Error::new(
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
                    strategy,
                    recursive_bound_override: redactable_options.recursive,
                    legacy_formatting_override: redactable_options.legacy_formatting,
                    generated_formatting_override: redactable_options.generated_formatting,
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
                    return Err(syn::Error::new(
                        field.span(),
                        "`#[redactable(legacy_formatting)]` requires `#[sensitive(Policy)]` on the same field",
                    ));
                }
                if redactable_options.generated_formatting
                    && !matches!(strategy, Strategy::Policy(_))
                {
                    return Err(syn::Error::new(
                        field.span(),
                        "`#[redactable(generated_formatting)]` requires `#[sensitive(Policy)]` on the same field",
                    ));
                }
                if redactable_options.legacy_formatting && redactable_options.generated_formatting {
                    return Err(syn::Error::new(
                        field.span(),
                        "`legacy_formatting` and `generated_formatting` are mutually exclusive",
                    ));
                }
                let binding = fresh.fresh(&format!("field_{index}"));
                output.push(FieldInfo {
                    ident: binding.clone(),
                    binding,
                    ty: &field.ty,
                    strategy,
                    recursive_bound_override: redactable_options.recursive,
                    legacy_formatting_override: redactable_options.legacy_formatting,
                    generated_formatting_override: redactable_options.generated_formatting,
                    span: field.span(),
                });
            }
            Ok(output)
        }
        Fields::Unit => Ok(Vec::new()),
    }
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

#[allow(clippy::too_many_lines)]
fn collect_bounds(
    field: &FieldInfo<'_>,
    mode: FormatMode,
    generics: &syn::Generics,
    display_generics: &mut Vec<syn::WherePredicate>,
    debug_generics: &mut Vec<syn::WherePredicate>,
    policy_ref_generics: &mut Vec<syn::WherePredicate>,
    nested_generics: &mut Vec<syn::WherePredicate>,
) {
    if let Strategy::Policy(policy) = &field.strategy
        && field.legacy_formatting_override
    {
        match mode {
            FormatMode::Display => {
                push_legacy_policy_display_formatting_predicates(
                    policy_ref_generics,
                    field.ty,
                    policy,
                );
            }
            FormatMode::Debug => {
                push_legacy_policy_debug_formatting_predicates(
                    policy_ref_generics,
                    field.ty,
                    policy,
                );
            }
            FormatMode::Both => {
                push_legacy_policy_display_formatting_predicates(
                    policy_ref_generics,
                    field.ty,
                    policy,
                );
                push_legacy_policy_debug_formatting_predicates(
                    policy_ref_generics,
                    field.ty,
                    policy,
                );
            }
        }
        return;
    }

    if field.recursive_bound_override {
        return;
    }

    match &field.strategy {
        Strategy::WalkDefault => {
            push_redacted_display_predicate(nested_generics, field.ty);
        }
        Strategy::NotSensitive => match mode {
            FormatMode::Display => push_display_predicate(display_generics, field.ty),
            FormatMode::Debug => push_debug_predicate(debug_generics, field.ty),
            FormatMode::Both => {
                push_display_predicate(display_generics, field.ty);
                push_debug_predicate(debug_generics, field.ty);
            }
        },
        Strategy::Policy(policy) => match owner_type_parameter_usage(generics, field.ty) {
            OwnerTypeParameterUsage::Bare | OwnerTypeParameterUsage::Composite
                if references_explicit_policy_applicable_ref(generics, field.ty) =>
            {
                match mode {
                    FormatMode::Display => {
                        push_direct_marker_display_formatting_predicates(
                            policy_ref_generics,
                            field.ty,
                        );
                        push_policy_display_formatting_predicate(
                            policy_ref_generics,
                            field.ty,
                            policy,
                        );
                    }
                    FormatMode::Debug => {
                        push_direct_marker_debug_formatting_predicates(
                            policy_ref_generics,
                            field.ty,
                        );
                        push_policy_debug_formatting_predicate(
                            policy_ref_generics,
                            field.ty,
                            policy,
                        );
                    }
                    FormatMode::Both => {
                        push_direct_marker_display_formatting_predicates(
                            policy_ref_generics,
                            field.ty,
                        );
                        push_direct_marker_debug_formatting_predicates(
                            policy_ref_generics,
                            field.ty,
                        );
                        push_policy_display_formatting_predicate(
                            policy_ref_generics,
                            field.ty,
                            policy,
                        );
                        push_policy_debug_formatting_predicate(
                            policy_ref_generics,
                            field.ty,
                            policy,
                        );
                    }
                }
            }
            OwnerTypeParameterUsage::Bare | OwnerTypeParameterUsage::Composite => match mode {
                FormatMode::Display => push_generated_policy_display_formatting_predicate(
                    policy_ref_generics,
                    field.ty,
                    policy,
                ),
                FormatMode::Debug => push_generated_policy_debug_formatting_predicate(
                    policy_ref_generics,
                    field.ty,
                    policy,
                ),
                FormatMode::Both => {
                    push_generated_policy_display_formatting_predicate(
                        policy_ref_generics,
                        field.ty,
                        policy,
                    );
                    push_generated_policy_debug_formatting_predicate(
                        policy_ref_generics,
                        field.ty,
                        policy,
                    );
                }
            },
            // The nominal probe in the generated expression lets rustc select
            // the concrete field capability after aliases and renamed imports
            // are resolved. Constrain that resolved kind-level capability;
            // classifying a concrete field from its Syn spelling makes aliases
            // observably different from the type they name.
            OwnerTypeParameterUsage::None
                if policy_is_owner_type_parameter(generics, policy)
                    && field.generated_formatting_override =>
            {
                match mode {
                    FormatMode::Display => push_generated_policy_display_formatting_predicate(
                        policy_ref_generics,
                        field.ty,
                        policy,
                    ),
                    FormatMode::Debug => push_generated_policy_debug_formatting_predicate(
                        policy_ref_generics,
                        field.ty,
                        policy,
                    ),
                    FormatMode::Both => {
                        push_generated_policy_display_formatting_predicate(
                            policy_ref_generics,
                            field.ty,
                            policy,
                        );
                        push_generated_policy_debug_formatting_predicate(
                            policy_ref_generics,
                            field.ty,
                            policy,
                        );
                    }
                }
            }
            OwnerTypeParameterUsage::None if policy_is_owner_type_parameter(generics, policy) => {
                match mode {
                    FormatMode::Display => push_policy_display_formatting_predicate(
                        policy_ref_generics,
                        field.ty,
                        policy,
                    ),
                    FormatMode::Debug => push_policy_debug_formatting_predicate(
                        policy_ref_generics,
                        field.ty,
                        policy,
                    ),
                    FormatMode::Both => {
                        push_policy_display_formatting_predicate(
                            policy_ref_generics,
                            field.ty,
                            policy,
                        );
                        push_policy_debug_formatting_predicate(
                            policy_ref_generics,
                            field.ty,
                            policy,
                        );
                    }
                }
            }
            OwnerTypeParameterUsage::None => {}
        },
    }
}

fn validate_positional_placeholders(placeholders: &[Placeholder]) -> Result<()> {
    let indexes: BTreeSet<usize> = placeholders
        .iter()
        .filter_map(|placeholder| match placeholder.key {
            PlaceholderKey::Index(index) => Some(index),
            PlaceholderKey::Named(_) => None,
        })
        .collect();

    let Some(max_index) = indexes.iter().next_back().copied() else {
        return Ok(());
    };

    for expected in 0..=max_index {
        if !indexes.contains(&expected) {
            let span = placeholders
                .iter()
                .find_map(|placeholder| match placeholder.key {
                    PlaceholderKey::Index(index) if index > expected => Some(placeholder.span),
                    PlaceholderKey::Named(_) | PlaceholderKey::Index(_) => None,
                })
                .unwrap_or_else(Span::call_site);
            return Err(syn::Error::new(
                span,
                "positional placeholders must be contiguous starting at 0",
            ));
        }
    }

    Ok(())
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
                } else {
                    PlaceholderKey::Named(parse_placeholder_ident(arg_part, template.span())?)
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

fn parse_placeholder_ident(value: &str, span: Span) -> Result<Ident> {
    syn::parse_str::<Ident>(value)
        .or_else(|_| syn::parse_str::<Ident>(&format!("r#{value}")))
        .map_err(|_| syn::Error::new(span, format!("unsupported format placeholder `{value}`")))
}

fn format_mode_from_spec(spec_part: &str, span: Span) -> Result<FormatMode> {
    let spec = spec_part.trim();
    if spec.is_empty() {
        return Ok(FormatMode::Display);
    }
    if has_dynamic_width_or_precision(spec) {
        return Err(syn::Error::new(
            span,
            "format specifiers with dynamic width/precision are not supported",
        ));
    }
    if is_unsupported_debug_specifier(spec) {
        return Err(syn::Error::new(
            span,
            format!("unsupported format specifier `{spec}`; only Display and Debug are supported"),
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

fn has_dynamic_width_or_precision(spec: &str) -> bool {
    let spec = spec_after_fill_alignment(spec);
    spec.contains('$') || spec.contains(".*")
}

fn spec_after_fill_alignment(spec: &str) -> &str {
    let mut chars = spec.char_indices();
    let Some(_) = chars.next() else {
        return spec;
    };
    let Some((align_index, align)) = chars.next() else {
        return spec;
    };
    if matches!(align, '<' | '>' | '^') {
        &spec[align_index + align.len_utf8()..]
    } else {
        spec
    }
}

fn is_unsupported_debug_specifier(spec: &str) -> bool {
    let Some(spec) = spec.strip_suffix('?') else {
        return false;
    };
    let spec = spec.trim_end();
    spec.ends_with('x') || spec.ends_with('X')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_mode_allows_star_and_dollar_fill_chars() {
        assert_eq!(
            format_mode_from_spec("*>12", Span::call_site()).unwrap(),
            FormatMode::Display
        );
        assert_eq!(
            format_mode_from_spec("$<12", Span::call_site()).unwrap(),
            FormatMode::Display
        );
    }

    #[test]
    fn format_mode_rejects_dynamic_width_and_precision() {
        assert!(format_mode_from_spec("width$", Span::call_site()).is_err());
        assert!(format_mode_from_spec(".*", Span::call_site()).is_err());
    }

    #[test]
    fn format_mode_rejects_hex_debug_specifiers() {
        assert!(format_mode_from_spec("x?", Span::call_site()).is_err());
        assert!(format_mode_from_spec("X?", Span::call_site()).is_err());
    }
}
