//! Container-level attribute parsing for `#[derive(Sensitive)]` and `#[derive(SensitiveDisplay)]`.
//!
//! This module handles attributes on the struct/enum itself, not on fields.

use syn::{Attribute, Data, DataEnum, DataStruct, Error, Meta, Result, spanned::Spanned};

/// The advice every container-level rejection gives: `#[redactable(...)]`
/// carries field options, so it belongs on the field it describes.
const FIELD_PLACEMENT: &str =
    "`#[redactable(...)]` options belong on fields; annotate the specific recursive field";

/// The two data shapes a derive expands; unions are rejected once, up front.
pub(crate) enum Body {
    Struct(DataStruct),
    Enum(DataEnum),
}

impl Body {
    /// Classifies the input, rejecting unions with the derive's own message.
    pub(crate) fn new(data: Data, derive: &str) -> Result<Self> {
        match data {
            Data::Struct(data) => Ok(Self::Struct(data)),
            Data::Enum(data) => Ok(Self::Enum(data)),
            Data::Union(union) => Err(Error::new(
                union.union_token.span(),
                format!("`{derive}` cannot be derived for unions"),
            )),
        }
    }
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
