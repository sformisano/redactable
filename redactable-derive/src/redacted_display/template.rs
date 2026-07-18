//! Template parsing for redacted `Display` output.
//!
//! Resolves the format template for a container or variant — an explicit
//! `#[error("...")]` attribute wins over doc-comment lines — and parses it
//! into [`Placeholder`]s. Parsing validates positional and named
//! placeholders, resolves `{field}`, `{field:?}`, and explicit `?`
//! specifiers into [`FormatMode`]s, and rejects unsupported debug format
//! specs and dynamic width/precision. Errors are reported against the
//! template literal's span so diagnostics point at the user's attribute.

use std::collections::BTreeSet;

use proc_macro2::{Ident, Span};
use syn::{Attribute, LitStr, Result, spanned::Spanned};

use super::model::{FormatMode, Placeholder, PlaceholderKey};

pub(super) fn validate_positional_placeholders(placeholders: &[Placeholder]) -> Result<()> {
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

pub(super) fn merge_mode(existing: FormatMode, next: FormatMode) -> FormatMode {
    match (existing, next) {
        (FormatMode::Both, _) | (_, FormatMode::Both) => FormatMode::Both,
        (FormatMode::Display, FormatMode::Debug) | (FormatMode::Debug, FormatMode::Display) => {
            FormatMode::Both
        }
        (FormatMode::Display, FormatMode::Display) => FormatMode::Display,
        (FormatMode::Debug, FormatMode::Debug) => FormatMode::Debug,
    }
}

pub(super) fn template_from_attrs(attrs: &[Attribute], span: Span) -> Result<LitStr> {
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

pub(super) fn parse_placeholders(template: &LitStr) -> Result<Vec<Placeholder>> {
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
