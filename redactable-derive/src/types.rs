//! Type utilities for the derive macro.

/// Checks if a type is `PhantomData<...>` or `std::marker::PhantomData<...>`.
///
/// `PhantomData<T>` is a zero-sized type that never carries actual data,
/// so it can never contain sensitive information regardless of `T`.
/// Fields of this type should be passed through unchanged without
/// requiring `T: RedactableWithMapper`.
pub(crate) fn is_phantom_data(ty: &syn::Type) -> bool {
    if let syn::Type::Path(path) = ty {
        // Check the last segment for "PhantomData" with generic arguments.
        // Accept both bare `PhantomData<T>` and qualified paths like
        // `std::marker::PhantomData<T>` or `::std::marker::PhantomData<T>`.
        if let Some(last_segment) = path.path.segments.last() {
            return last_segment.ident == "PhantomData"
                && matches!(
                    last_segment.arguments,
                    syn::PathArguments::AngleBracketed(_)
                );
        }
    }
    false
}

/// Checks if a type is a recognized scalar primitive.
///
/// Returns `true` for bare primitive type names like `i32`, `bool`, `f64`, etc.
/// Returns `false` for qualified paths, generic types, or type aliases.
///
/// This is intentionally conservative - if we can't definitively identify
/// a type as a scalar, we treat it as a potentially sensitive value that
/// requires a policy.
pub(crate) fn is_scalar_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(path) = ty {
        if path.path.leading_colon.is_some() {
            // Absolute path (e.g., ::std::primitive::i32) - not a simple scalar
            return false;
        }
        if path.path.segments.len() != 1 {
            // Qualified path (e.g., std::primitive::i32) - not a simple scalar
            return false;
        }
        if let Some(segment) = path.path.segments.last() {
            if !segment.arguments.is_empty() {
                // Generic type (e.g., Vec<T>) - not a scalar
                return false;
            }
            let ident = &segment.ident;
            matches!(
                ident.to_string().as_str(),
                "i8" | "i16"
                    | "i32"
                    | "i64"
                    | "i128"
                    | "isize"
                    | "u8"
                    | "u16"
                    | "u32"
                    | "u64"
                    | "u128"
                    | "usize"
                    | "f32"
                    | "f64"
                    | "bool"
                    | "char"
            )
        } else {
            false
        }
    } else {
        false
    }
}

fn last_bare_segment_ident(ty: &syn::Type) -> Option<&syn::Ident> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    if !segment.arguments.is_empty() {
        return None;
    }
    Some(&segment.ident)
}

/// Checks if a type is one of the standard `NonZero*` integer types.
pub(crate) fn is_nonzero_type(ty: &syn::Type) -> bool {
    let Some(ident) = last_bare_segment_ident(ty) else {
        return false;
    };
    matches!(
        ident.to_string().as_str(),
        "NonZeroI8"
            | "NonZeroI16"
            | "NonZeroI32"
            | "NonZeroI64"
            | "NonZeroI128"
            | "NonZeroIsize"
            | "NonZeroU8"
            | "NonZeroU16"
            | "NonZeroU32"
            | "NonZeroU64"
            | "NonZeroU128"
            | "NonZeroUsize"
    )
}

/// Checks if a type is one of the built-in std IP address types.
pub(crate) fn is_ip_address_type(ty: &syn::Type) -> bool {
    let Some(ident) = last_bare_segment_ident(ty) else {
        return false;
    };
    matches!(
        ident.to_string().as_str(),
        "IpAddr" | "Ipv4Addr" | "Ipv6Addr" | "SocketAddr"
    )
}

/// Checks if a type contains a std IP address leaf that is not already wrapped
/// in `SensitiveValue<T, P>`.
pub(crate) fn contains_unwrapped_ip_address_type(ty: &syn::Type) -> bool {
    if is_ip_address_type(ty) {
        return true;
    }

    match ty {
        syn::Type::Array(array) => contains_unwrapped_ip_address_type(&array.elem),
        syn::Type::Group(group) => contains_unwrapped_ip_address_type(&group.elem),
        syn::Type::Paren(paren) => contains_unwrapped_ip_address_type(&paren.elem),
        syn::Type::Path(path) => {
            if path
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "SensitiveValue")
            {
                return false;
            }
            path.path
                .segments
                .iter()
                .any(|segment| path_arguments_contain_unwrapped_ip(&segment.arguments))
        }
        syn::Type::Reference(reference) => contains_unwrapped_ip_address_type(&reference.elem),
        syn::Type::Slice(slice) => contains_unwrapped_ip_address_type(&slice.elem),
        syn::Type::Tuple(tuple) => tuple.elems.iter().any(contains_unwrapped_ip_address_type),
        _ => false,
    }
}

fn path_arguments_contain_unwrapped_ip(arguments: &syn::PathArguments) -> bool {
    match arguments {
        syn::PathArguments::AngleBracketed(arguments) => arguments.args.iter().any(|argument| {
            matches!(
                argument,
                syn::GenericArgument::Type(ty) if contains_unwrapped_ip_address_type(ty)
            )
        }),
        syn::PathArguments::Parenthesized(arguments) => {
            arguments
                .inputs
                .iter()
                .any(contains_unwrapped_ip_address_type)
                || match &arguments.output {
                    syn::ReturnType::Default => false,
                    syn::ReturnType::Type(_, ty) => contains_unwrapped_ip_address_type(ty),
                }
        }
        syn::PathArguments::None => false,
    }
}

#[cfg(test)]
mod tests {
    use quote::quote;

    use super::*;

    fn parse_type(tokens: proc_macro2::TokenStream) -> syn::Type {
        syn::parse2(tokens).expect("should parse as Type")
    }

    // PhantomData tests

    #[test]
    fn phantom_data_bare_detected() {
        let ty = parse_type(quote! { PhantomData<T> });
        assert!(is_phantom_data(&ty));
    }

    #[test]
    fn phantom_data_std_marker_detected() {
        let ty = parse_type(quote! { std::marker::PhantomData<T> });
        assert!(is_phantom_data(&ty));
    }

    #[test]
    fn phantom_data_absolute_path_detected() {
        let ty = parse_type(quote! { ::std::marker::PhantomData<T> });
        assert!(is_phantom_data(&ty));
    }

    #[test]
    fn phantom_data_with_concrete_type_detected() {
        let ty = parse_type(quote! { PhantomData<DateTime<Utc>> });
        assert!(is_phantom_data(&ty));
    }

    #[test]
    fn not_phantom_data_string() {
        let ty = parse_type(quote! { String });
        assert!(!is_phantom_data(&ty));
    }

    #[test]
    fn not_phantom_data_option() {
        let ty = parse_type(quote! { Option<T> });
        assert!(!is_phantom_data(&ty));
    }

    #[test]
    fn not_phantom_data_without_generics() {
        // PhantomData without generic arguments is not valid Rust,
        // but we should handle it gracefully
        let ty = parse_type(quote! { PhantomData });
        assert!(!is_phantom_data(&ty));
    }

    // Scalar type tests

    #[test]
    fn scalar_i32_detected() {
        let ty = parse_type(quote! { i32 });
        assert!(is_scalar_type(&ty));
    }

    #[test]
    fn scalar_bool_detected() {
        let ty = parse_type(quote! { bool });
        assert!(is_scalar_type(&ty));
    }

    #[test]
    fn scalar_char_detected() {
        let ty = parse_type(quote! { char });
        assert!(is_scalar_type(&ty));
    }

    #[test]
    fn string_is_not_scalar() {
        let ty = parse_type(quote! { String });
        assert!(!is_scalar_type(&ty));
    }

    #[test]
    fn option_is_not_scalar() {
        let ty = parse_type(quote! { Option<i32> });
        assert!(!is_scalar_type(&ty));
    }

    #[test]
    fn qualified_path_is_not_scalar() {
        let ty = parse_type(quote! { std::primitive::i32 });
        assert!(!is_scalar_type(&ty));
    }

    #[test]
    fn absolute_path_is_not_scalar() {
        let ty = parse_type(quote! { ::std::primitive::i32 });
        assert!(!is_scalar_type(&ty));
    }

    #[test]
    fn nonzero_type_detected() {
        let ty = parse_type(quote! { NonZeroU32 });
        assert!(is_nonzero_type(&ty));
    }

    #[test]
    fn qualified_nonzero_type_detected() {
        let ty = parse_type(quote! { std::num::NonZeroU32 });
        assert!(is_nonzero_type(&ty));
    }

    #[test]
    fn ip_address_type_detected() {
        let ty = parse_type(quote! { std::net::IpAddr });
        assert!(is_ip_address_type(&ty));
    }

    #[test]
    fn option_ip_address_leaf_detected() {
        let ty = parse_type(quote! { Option<std::net::IpAddr> });
        assert!(contains_unwrapped_ip_address_type(&ty));
    }

    #[test]
    fn nested_ip_address_leaf_detected() {
        let ty = parse_type(quote! { Vec<Option<std::net::SocketAddr>> });
        assert!(contains_unwrapped_ip_address_type(&ty));
    }

    #[test]
    fn sensitive_value_ip_address_leaf_is_skipped() {
        let ty = parse_type(quote! { Option<SensitiveValue<std::net::IpAddr, IpAddress>> });
        assert!(!contains_unwrapped_ip_address_type(&ty));
    }

    #[test]
    fn bare_sensitive_value_ip_address_leaf_is_skipped() {
        let ty = parse_type(quote! { redactable::SensitiveValue<std::net::IpAddr, IpAddress> });
        assert!(!contains_unwrapped_ip_address_type(&ty));
    }
}
