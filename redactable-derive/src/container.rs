//! Container-level attribute parsing for `#[derive(Sensitive)]` and `#[derive(SensitiveDisplay)]`.
//!
//! This module handles attributes on the struct/enum itself, not on fields.

use syn::{Attribute, Meta, Result};

/// Options parsed from container-level `#[sensitive(...)]` attributes.
#[derive(Clone, Debug, Default)]
pub(crate) struct ContainerOptions {
    /// If true, skip generating the `Debug` impl.
    pub(crate) skip_debug: bool,
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
                return Err(syn::Error::new_spanned(
                    attr,
                    "bare `#[sensitive]` on the container has no effect; use `#[sensitive(skip_debug)]` to opt out of `Debug` generation",
                ));
            }
            Meta::List(list) => {
                list.parse_nested_meta(|meta| {
                    if meta.path.is_ident("skip_debug") {
                        options.skip_debug = true;
                        Ok(())
                    } else {
                        Err(meta.error(format!(
                            "unknown container option `{}`; expected `skip_debug`",
                            meta.path
                                .get_ident()
                                .map_or_else(|| "?".to_string(), ToString::to_string)
                        )))
                    }
                })?;
            }
            Meta::NameValue(nv) => {
                return Err(syn::Error::new_spanned(
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
    fn no_attribute_returns_defaults() {
        let attrs = parse_attrs(quote! {});
        let options = parse_container_options(&attrs).unwrap();
        assert!(!options.skip_debug);
    }

    #[test]
    fn skip_debug_is_parsed() {
        let attrs = parse_attrs(quote! { #[sensitive(skip_debug)] });
        let options = parse_container_options(&attrs).unwrap();
        assert!(options.skip_debug);
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
