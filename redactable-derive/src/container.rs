//! Container-level attribute parsing for `#[derive(Sensitive)]` and `#[derive(SensitiveDisplay)]`.
//!
//! This module handles attributes on the struct/enum itself, not on fields.

use syn::{Attribute, Error, Meta, Result};

/// The advice both surviving container branches give: `#[redactable(...)]`
/// carries field options, so it belongs on the field it describes.
const FIELD_PLACEMENT: &str = "`#[redactable(...)]` options belong on fields; annotate the specific recursive or legacy-formatted field";

/// The migration message for the removed structured-output selection.
const REMOVED_OUTPUT: &str = "`#[redactable(output = json)]` was removed; `Sensitive` and `SensitiveDual` always produce JSON";

/// Rejects every container-level `#[redactable(...)]`, naming the valid fix.
///
/// Three branches survive, and they differ in span and in what the author
/// actually wrote. A bare `#[redactable()]` never reaches `parse_nested_meta`
/// (it iterates nothing for an empty token list), so dropping its check would
/// silently accept the attribute. A non-`output` option and an empty list both
/// name the field-placement fix, because their author never wrote `output`.
/// Only an `output` option gets the removal message.
pub(crate) fn reject_removed_output_option(attrs: &[Attribute]) -> Result<()> {
    for attr in attrs {
        if !attr.path().is_ident("redactable") {
            continue;
        }
        if matches!(&attr.meta, Meta::List(list) if list.tokens.is_empty()) {
            return Err(Error::new_spanned(attr, FIELD_PLACEMENT));
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("output") {
                return Err(meta.error(REMOVED_OUTPUT));
            }
            Err(meta.error(FIELD_PLACEMENT))
        })?;
    }
    Ok(())
}

/// Rejects field-only helpers when they are attached to a derived container.
pub(crate) fn reject_field_only_container_attrs(attrs: &[Attribute]) -> Result<()> {
    for attr in attrs {
        if attr.path().is_ident("not_sensitive") {
            return Err(Error::new_spanned(
                attr,
                "`#[not_sensitive]` is only supported on fields; derive `NotSensitive` or `NotSensitiveDisplay` to classify the complete type",
            ));
        }
        if attr.path().is_ident("redactable") {
            return Err(Error::new_spanned(attr, FIELD_PLACEMENT));
        }
    }
    Ok(())
}

/// Options parsed from container-level `#[sensitive(...)]` attributes.
///
/// Both `Sensitive` and `SensitiveDisplay` read these options.
#[derive(Clone, Debug, Default)]
pub(crate) struct ContainerOptions {
    /// Legacy user coordination, parsed only to issue its migration error.
    /// Actual Dual coordination comes from the single SensitiveDual expansion.
    pub(crate) dual: bool,
}

/// Parses container-level `#[sensitive(...)]` attributes.
pub(crate) fn parse_container_options(attrs: &[Attribute]) -> Result<ContainerOptions> {
    let mut options = ContainerOptions::default();

    for attr in attrs {
        if !attr.path().is_ident("sensitive") {
            continue;
        }

        match &attr.meta {
            Meta::Path(_) => {
                return Err(Error::new_spanned(
                    attr,
                    "bare `#[sensitive]` on the container has no effect; \
                     use `#[derive(SensitiveDual)]` when structural and display redaction are both needed",
                ));
            }
            Meta::List(list) => {
                list.parse_nested_meta(|meta| {
                    if meta.path.is_ident("dual") {
                        options.dual = true;
                        Ok(())
                    } else {
                        Err(meta.error(format!(
                            "unknown container option `{}`; expected `dual`",
                            meta.path
                                .get_ident()
                                .map_or_else(|| "?".to_string(), ToString::to_string)
                        )))
                    }
                })?;
            }
            Meta::NameValue(nv) => {
                return Err(Error::new_spanned(
                    nv,
                    "name-value syntax is not supported for container-level #[sensitive]",
                ));
            }
        }
    }

    Ok(options)
}

#[cfg(test)]
mod tests {
    use proc_macro2::TokenStream;
    use quote::quote;
    use syn::{Attribute, DeriveInput};

    use super::{parse_container_options, reject_field_only_container_attrs};

    fn parse_attrs(tokens: TokenStream) -> Vec<Attribute> {
        let input: DeriveInput = syn::parse2(quote! {
            #tokens
            struct Dummy;
        })
        .expect("should parse as DeriveInput");
        input.attrs
    }

    #[test]
    fn no_attribute_returns_defaults() {
        let attrs = parse_attrs(quote! {});
        let options = parse_container_options(&attrs).unwrap();
        assert!(!options.dual);
    }

    #[test]
    fn field_only_helpers_are_rejected_on_containers() {
        let attrs = parse_attrs(quote! { #[not_sensitive] });
        assert!(reject_field_only_container_attrs(&attrs).is_err());

        let attrs = parse_attrs(quote! { #[redactable(recursive)] });
        assert!(reject_field_only_container_attrs(&attrs).is_err());
    }

    #[test]
    fn dual_is_parsed() {
        let attrs = parse_attrs(quote! { #[sensitive(dual)] });
        let options = parse_container_options(&attrs).unwrap();
        assert!(options.dual);
    }

    #[test]
    fn unknown_option_errors() {
        let attrs = parse_attrs(quote! { #[sensitive(unknown_option)] });
        let result = parse_container_options(&attrs);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unknown container option")
        );
    }

    #[test]
    fn bare_sensitive_on_container_is_rejected() {
        let attrs = parse_attrs(quote! { #[sensitive] });
        let result = parse_container_options(&attrs);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("bare `#[sensitive]` on the container has no effect")
        );
    }
}
