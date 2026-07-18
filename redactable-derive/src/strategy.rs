//! Parsing of `#[sensitive(...)]` and `#[not_sensitive]` field attributes.
//!
//! This module maps attribute syntax to traversal decisions and produces
//! structured errors for invalid forms.

use proc_macro2::Span;
use syn::{Attribute, Meta, Result, spanned::Spanned};

/// Additive code-generation overrides for one derived field.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RedactableFieldOptions {
    /// Suppress inferred complete-type bounds for a semantically recursive field.
    pub(crate) recursive: bool,
    /// Use the normal borrowed policy projection instead of the built-in safe formatter route.
    pub(crate) legacy_formatting: bool,
    /// Select the library-owned recursive formatting projection.
    pub(crate) generated_formatting: bool,
}

/// Parses explicit code-generation overrides for one field.
///
/// Stable procedural macros cannot resolve aliases or arbitrary qualified paths
/// back to the type currently being derived. `#[redactable(recursive)]` is the
/// explicit contract for those recursive fields; it suppresses only the inferred
/// bounds for that field and leaves every unannotated field on the precise default
/// route. `#[redactable(legacy_formatting)]` explicitly selects the ordinary
/// `PolicyApplicableRef` projection for opaque downstream container compositions.
pub(crate) fn parse_redactable_field_options(
    attrs: &[Attribute],
) -> Result<RedactableFieldOptions> {
    let mut options = RedactableFieldOptions::default();
    for attr in attrs {
        if !attr.path().is_ident("redactable") {
            continue;
        }
        match &attr.meta {
            Meta::List(list) => {
                list.parse_nested_meta(|meta| {
                    if meta.path.is_ident("recursive") {
                        if options.recursive {
                            return Err(meta.error("duplicate `recursive` bound override"));
                        }
                        options.recursive = true;
                        Ok(())
                    } else if meta.path.is_ident("legacy_formatting") {
                        if options.legacy_formatting {
                            return Err(meta.error("duplicate `legacy_formatting` override"));
                        }
                        options.legacy_formatting = true;
                        Ok(())
                    } else if meta.path.is_ident("generated_formatting") {
                        if options.generated_formatting {
                            return Err(meta.error("duplicate `generated_formatting` override"));
                        }
                        options.generated_formatting = true;
                        Ok(())
                    } else {
                        Err(meta.error(
                            "unknown redactable field option; expected `recursive`, `legacy_formatting`, or `generated_formatting`",
                        ))
                    }
                })?;
            }
            Meta::Path(_) | Meta::NameValue(_) => {
                return Err(syn::Error::new(
                    attr.span(),
                    "expected `#[redactable(recursive)]`, `#[redactable(legacy_formatting)]`, or `#[redactable(generated_formatting)]`",
                ));
            }
        }
    }
    Ok(options)
}

/// Field transformation strategy based on `#[sensitive(...)]` attributes.
///
/// ## Strategy Mapping
///
/// | Attribute              | Strategy              | Behavior                              |
/// |------------------------|-----------------------|---------------------------------------|
/// | None                   | `WalkDefault`         | Walk containers; scalars pass through |
/// | `#[sensitive(Policy)]` | `Policy(policy_path)` | Apply redaction policy                |
/// | `#[not_sensitive]`     | `NotSensitive`        | Explicit passthrough (no traversal)      |
#[derive(Clone, Debug)]
pub(crate) enum Strategy {
    /// No annotation: walk containers, scalars pass through unchanged.
    WalkDefault,
    /// `#[sensitive(Policy)]`: apply redaction policy.
    ///
    /// The policy type (e.g., `Secret`, `Token`, `Pii`) determines how
    /// the value is redacted via `RedactionPolicy`.
    Policy(syn::Path),
    /// `#[not_sensitive]`: explicit passthrough, no traversal or transformation.
    NotSensitive,
}

fn set_strategy(target: &mut Option<Strategy>, next: Strategy, span: Span) -> Result<()> {
    if target.is_some() {
        return Err(syn::Error::new(
            span,
            "multiple #[sensitive] or #[not_sensitive] attributes on the same field",
        ));
    }
    *target = Some(next);
    Ok(())
}

/// Rejects field-only sensitivity and code-generation attributes on enum variants.
///
/// Sensitivity is a per-field property. A variant-level annotation used to be
/// silently ignored, which read as "this variant is protected" while redacting
/// nothing; rejecting it at compile time closes that gap.
pub(crate) fn reject_variant_sensitivity_attrs(attrs: &[Attribute]) -> Result<()> {
    for attr in attrs {
        if attr.path().is_ident("sensitive") {
            return Err(syn::Error::new(
                attr.span(),
                "`#[sensitive(...)]` is not supported on enum variants; \
                 annotate the variant's fields instead",
            ));
        }
        if attr.path().is_ident("not_sensitive") {
            return Err(syn::Error::new(
                attr.span(),
                "`#[not_sensitive]` is not supported on enum variants; \
                 annotate the variant's fields instead",
            ));
        }
        if attr.path().is_ident("redactable") {
            return Err(syn::Error::new(
                attr.span(),
                "`#[redactable(...)]` is only supported on fields; annotate the specific recursive or legacy-formatted field",
            ));
        }
    }
    Ok(())
}

pub(crate) fn parse_field_strategy(attrs: &[Attribute]) -> Result<Strategy> {
    let mut strategy: Option<Strategy> = None;
    for attr in attrs {
        // Handle #[not_sensitive]
        if attr.path().is_ident("not_sensitive") {
            match &attr.meta {
                Meta::Path(_) => {
                    set_strategy(&mut strategy, Strategy::NotSensitive, attr.span())?;
                }
                _ => {
                    return Err(syn::Error::new(
                        attr.span(),
                        "#[not_sensitive] does not take arguments",
                    ));
                }
            }
            continue;
        }

        if !attr.path().is_ident("sensitive") {
            continue;
        }

        match &attr.meta {
            Meta::Path(_) => {
                return Err(syn::Error::new(
                    attr.span(),
                    "missing policy: use #[sensitive(Policy)] \
                     (e.g., #[sensitive(Secret)], #[sensitive(Token)])",
                ));
            }
            Meta::List(list) => {
                // Parse as a policy path (e.g., #[sensitive(Secret)])
                match syn::parse2::<syn::Path>(list.tokens.clone()) {
                    Ok(path) => {
                        set_strategy(&mut strategy, Strategy::Policy(path), attr.span())?;
                    }
                    Err(_) => {
                        return Err(syn::Error::new(
                            attr.span(),
                            "expected a policy type (e.g., #[sensitive(Secret)])",
                        ));
                    }
                }
            }
            Meta::NameValue(_) => {
                return Err(syn::Error::new(
                    attr.span(),
                    "expected #[sensitive(Policy)] syntax \
                     (e.g., #[sensitive(Secret)], #[sensitive(Token)])",
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
        let attrs = parse_attrs(quote! { #[sensitive(Secret)] });
        let strategy = parse_field_strategy(&attrs).unwrap();
        match strategy {
            Strategy::Policy(path) => {
                assert!(path.is_ident("Secret"));
            }
            _ => panic!("expected Policy"),
        }
    }

    #[test]
    fn sensitive_with_path_policy() {
        let attrs = parse_attrs(quote! { #[sensitive(my_module::MyPolicy)] });
        let strategy = parse_field_strategy(&attrs).unwrap();
        match strategy {
            Strategy::Policy(path) => {
                assert_eq!(path.segments.len(), 2);
            }
            _ => panic!("expected Policy"),
        }
    }

    #[test]
    fn multiple_sensitive_attributes_error() {
        let attrs = parse_attrs(quote! {
            #[sensitive(Full)]
            #[sensitive(Token)]
        });
        let result = parse_field_strategy(&attrs);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("multiple"));
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

    #[test]
    fn not_sensitive_returns_not_sensitive() {
        let attrs = parse_attrs(quote! { #[not_sensitive] });
        let strategy = parse_field_strategy(&attrs).unwrap();
        assert!(matches!(strategy, Strategy::NotSensitive));
    }

    #[test]
    fn not_sensitive_with_args_errors() {
        let attrs = parse_attrs(quote! { #[not_sensitive(foo)] });
        let result = parse_field_strategy(&attrs);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("does not take arguments")
        );
    }

    #[test]
    fn sensitive_and_not_sensitive_errors() {
        let attrs = parse_attrs(quote! {
            #[sensitive(Full)]
            #[not_sensitive]
        });
        let result = parse_field_strategy(&attrs);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("multiple"));
    }
}
