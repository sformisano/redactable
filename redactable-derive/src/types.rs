//! Type utilities for the derive macro.

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

#[cfg(test)]
mod tests {
    use quote::quote;

    use super::*;

    fn parse_type(tokens: proc_macro2::TokenStream) -> syn::Type {
        syn::parse2(tokens).expect("should parse as Type")
    }

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
}
