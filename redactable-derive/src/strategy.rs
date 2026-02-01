//! Parsing of `#[sensitive(...)]` field attributes.
//!
//! This module maps attribute syntax to traversal decisions and produces
//! structured errors for invalid forms.

use proc_macro2::Span;
use syn::{Attribute, Meta, Result, spanned::Spanned};

/// Field transformation strategy based on `#[sensitive(...)]` attributes.
///
/// ## Strategy Mapping
///
/// | Attribute              | Strategy           | Behavior                              |
/// |------------------------|--------------------|---------------------------------------|
/// | None                   | `WalkDefault`      | Walk containers; scalars pass through |
/// | `#[sensitive(Policy)]` | `Classify(Policy)` | Apply redaction policy                |
#[derive(Clone, Debug)]
pub(crate) enum Strategy {
    /// No annotation: walk containers, scalars pass through unchanged.
    WalkDefault,
    /// `#[sensitive(Policy)]`: apply redaction policy.
    ///
    /// The policy type (e.g., `Default`, `Token`, `Pii`) determines how
    /// the value is redacted via `RedactionPolicy`.
    Classify(syn::Path),
}

fn set_strategy(target: &mut Option<Strategy>, next: Strategy, span: Span) -> Result<()> {
    if target.is_some() {
        return Err(syn::Error::new(
            span,
            "multiple #[sensitive] attributes specified on the same field",
        ));
    }
    *target = Some(next);
    Ok(())
}

pub(crate) fn parse_field_strategy(attrs: &[Attribute]) -> Result<Strategy> {
    let mut strategy: Option<Strategy> = None;
    for attr in attrs {
        if !attr.path().is_ident("sensitive") {
            continue;
        }

        match &attr.meta {
            Meta::Path(_) => {
                return Err(syn::Error::new(
                    attr.span(),
                    "missing policy: use #[sensitive(Policy)] \
                     (e.g., #[sensitive(Default)], #[sensitive(Token)])",
                ));
            }
            Meta::List(list) => {
                // Parse as a policy path (e.g., #[sensitive(Default)])
                match syn::parse2::<syn::Path>(list.tokens.clone()) {
                    Ok(path) => {
                        set_strategy(&mut strategy, Strategy::Classify(path), attr.span())?;
                    }
                    Err(_) => {
                        return Err(syn::Error::new(
                            attr.span(),
                            "expected a policy type (e.g., #[sensitive(Default)])",
                        ));
                    }
                }
            }
            Meta::NameValue(_) => {
                return Err(syn::Error::new(
                    attr.span(),
                    "expected #[sensitive(Policy)] syntax \
                     (e.g., #[sensitive(Default)], #[sensitive(Token)])",
                ));
            }
        }
    }

    // Default: no annotation means walk containers (scalars pass through)
    Ok(strategy.unwrap_or(Strategy::WalkDefault))
}

#[cfg(test)]
mod tests {
    use quote::quote;
    use syn::DeriveInput;

    use super::*;

    fn parse_attrs(tokens: proc_macro2::TokenStream) -> Vec<Attribute> {
        let input: DeriveInput = syn::parse2(quote! {
            #tokens
            struct Dummy;
        })
        .expect("should parse as DeriveInput");
        input.attrs
    }

    #[test]
    fn no_attribute_returns_walk_default() {
        let attrs = parse_attrs(quote! {});
        let strategy = parse_field_strategy(&attrs).unwrap();
        assert!(matches!(strategy, Strategy::WalkDefault));
    }

    #[test]
    fn bare_sensitive_errors_with_missing_policy() {
        let attrs = parse_attrs(quote! { #[sensitive] });
        let result = parse_field_strategy(&attrs);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing policy"));
    }

    #[test]
    fn sensitive_with_policy_returns_classify() {
        let attrs = parse_attrs(quote! { #[sensitive(Default)] });
        let strategy = parse_field_strategy(&attrs).unwrap();
        match strategy {
            Strategy::Classify(path) => {
                assert!(path.is_ident("Default"));
            }
            Strategy::WalkDefault => panic!("expected Classify"),
        }
    }

    #[test]
    fn sensitive_with_path_policy() {
        let attrs = parse_attrs(quote! { #[sensitive(my_module::MyPolicy)] });
        let strategy = parse_field_strategy(&attrs).unwrap();
        match strategy {
            Strategy::Classify(path) => {
                assert_eq!(path.segments.len(), 2);
            }
            Strategy::WalkDefault => panic!("expected Classify"),
        }
    }

    #[test]
    fn multiple_sensitive_attributes_error() {
        let attrs = parse_attrs(quote! {
            #[sensitive(Default)]
            #[sensitive(Token)]
        });
        let result = parse_field_strategy(&attrs);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("multiple #[sensitive] attributes")
        );
    }

    #[test]
    fn name_value_syntax_error() {
        let attrs = parse_attrs(quote! { #[sensitive = "value"] });
        let result = parse_field_strategy(&attrs);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("#[sensitive(Policy)]")
        );
    }

    #[test]
    fn invalid_policy_syntax_error() {
        let attrs = parse_attrs(quote! { #[sensitive(123)] });
        let result = parse_field_strategy(&attrs);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("expected a policy type")
        );
    }

    #[test]
    fn other_attributes_ignored() {
        let attrs = parse_attrs(quote! {
            #[derive(Clone)]
            #[serde(skip)]
        });
        let strategy = parse_field_strategy(&attrs).unwrap();
        assert!(matches!(strategy, Strategy::WalkDefault));
    }
}
