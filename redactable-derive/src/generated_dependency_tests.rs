use proc_macro2::{TokenStream, TokenTree};
use quote::quote;

use super::*;

fn collect_paths(stream: TokenStream, paths: &mut Vec<Vec<String>>) {
    let tokens: Vec<_> = stream.into_iter().collect();
    for token in &tokens {
        if let TokenTree::Group(group) = token {
            collect_paths(group.stream(), paths);
        }
    }
    for start in 0..tokens.len() {
        if start >= 3
            && matches!(tokens[start - 1], TokenTree::Punct(ref punct) if punct.as_char() == ':')
            && matches!(tokens[start - 2], TokenTree::Punct(ref punct) if punct.as_char() == ':')
            && matches!(tokens[start - 3], TokenTree::Ident(_))
        {
            continue;
        }
        let TokenTree::Ident(first) = &tokens[start] else {
            continue;
        };
        let mut path = vec![first.to_string()];
        let mut index = start + 1;
        while index + 2 < tokens.len() {
            let (TokenTree::Punct(a), TokenTree::Punct(b), TokenTree::Ident(segment)) =
                (&tokens[index], &tokens[index + 1], &tokens[index + 2])
            else {
                break;
            };
            if a.as_char() != ':' || b.as_char() != ':' {
                break;
            }
            path.push(segment.to_string());
            index += 3;
        }
        if path.len() > 1 {
            paths.push(path);
        }
    }
}

fn assert_private_dependencies(tokens: TokenStream, requires_serde: bool) {
    let mut paths = Vec::new();
    collect_paths(tokens, &mut paths);
    assert!(
        paths
            .iter()
            .all(|path| !matches!(path.first().map(String::as_str), Some("slog" | "serde"))),
        "generated dependencies must not resolve from the consumer root: {paths:?}"
    );
    for item in ["Value", "Record", "Key", "Serializer", "Result"] {
        assert!(
            paths.iter().any(|path| {
                path.windows(2)
                    .any(|segments| segments == ["__private", "slog"])
                    && path.last().is_some_and(|segment| segment == item)
            }),
            "missing private slog::{item} path: {paths:?}"
        );
    }
    assert_eq!(
        paths.iter().any(|path| {
            path.windows(2)
                .any(|segments| segments == ["__private", "serde"])
                && path.last().is_some_and(|segment| segment == "Serialize")
        }),
        requires_serde,
        "private serde::Serialize path mismatch: {paths:?}"
    );
}

pub(super) fn run_structural_generated_dependency_roots() {
    let not_sensitive: DeriveInput = syn::parse2(quote! {
        struct PublicEvent { value: String }
    })
    .unwrap();
    assert_private_dependencies(expand_not_sensitive(not_sensitive).unwrap(), true);

    let not_sensitive_display: DeriveInput = syn::parse2(quote! {
        struct PublicDisplayEvent;
    })
    .unwrap();
    assert_private_dependencies(
        expand_not_sensitive_display(not_sensitive_display).unwrap(),
        false,
    );

    let sensitive: DeriveInput = syn::parse2(quote! {
        struct SecretEvent { #[sensitive(redactable::Secret)] value: String }
    })
    .unwrap();
    assert_private_dependencies(expand(sensitive, DeriveKind::Sensitive).unwrap(), true);

    let sensitive_display: DeriveInput = syn::parse2(quote! {
        #[error("{value}")]
        struct SecretDisplayEvent { #[sensitive(redactable::Secret)] value: String }
    })
    .unwrap();
    assert_private_dependencies(
        expand(sensitive_display, DeriveKind::SensitiveDisplay).unwrap(),
        false,
    );
}
