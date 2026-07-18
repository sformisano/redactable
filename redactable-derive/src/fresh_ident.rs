//! Deterministic identifier allocation for one derive expansion.
//!
//! The allocator reserves caller-provided names before code generation and records
//! every generated name it returns. This keeps generated binders independent of
//! proc-macro hygiene details and prevents collisions across generation helpers.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{Ident, Span, TokenStream, TokenTree};
use quote::ToTokens;
use syn::DeriveInput;

/// Allocates unique mixed-site identifiers within one derive expansion.
pub(crate) struct FreshIdentAllocator {
    used: BTreeSet<String>,
    next_suffix: BTreeMap<String, usize>,
    allocated: Vec<Ident>,
}

impl FreshIdentAllocator {
    /// Seeds an allocator with every caller-provided identifier in the derive input.
    ///
    /// Referenced identifiers matter as much as declarations here: a generated
    /// value binder can otherwise capture a module constant used in a field type,
    /// while a generated type parameter can capture a type or trait path.
    pub(crate) fn new(input: &DeriveInput) -> Self {
        let mut allocator = Self {
            used: BTreeSet::new(),
            next_suffix: BTreeMap::new(),
            allocated: Vec::new(),
        };
        // Walk the complete token tree so identifiers inside opaque attribute and
        // macro arguments are reserved too; an AST visitor cannot enter those.
        allocator.reserve_tokens(input.to_token_stream());
        allocator
    }

    /// Returns a deterministic unused identifier and reserves it immediately.
    pub(crate) fn fresh(&mut self, preferred: &str) -> Ident {
        let preferred = preferred.strip_prefix("r#").unwrap_or(preferred);
        if self.used.insert(preferred.to_owned()) {
            let ident = Ident::new(preferred, Span::mixed_site());
            self.allocated.push(ident.clone());
            return ident;
        }

        let suffix = self.next_suffix.entry(preferred.to_owned()).or_insert(1);
        loop {
            let candidate = format!("{preferred}_{suffix}");
            *suffix += 1;
            if self.used.insert(candidate.clone()) {
                let ident = Ident::new(&candidate, Span::mixed_site());
                self.allocated.push(ident.clone());
                return ident;
            }
        }
    }

    /// Allocates a name made from a generated prefix and a caller identifier.
    pub(crate) fn fresh_with_ident(&mut self, prefix: &str, ident: &Ident) -> Ident {
        self.fresh(&format!("{prefix}{}", canonical_name(ident)))
    }

    /// Returns every identifier allocated for generated code in allocation order.
    pub(crate) fn allocated(&self) -> &[Ident] {
        &self.allocated
    }

    fn reserve(&mut self, ident: &Ident) {
        self.used.insert(canonical_name(ident));
    }

    fn reserve_tokens(&mut self, tokens: TokenStream) {
        for token in tokens {
            match token {
                TokenTree::Ident(ident) => self.reserve(&ident),
                TokenTree::Group(group) => self.reserve_tokens(group.stream()),
                TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
        }
    }
}

/// Returns the lexical name shared by raw and ordinary spellings of an identifier.
pub(crate) fn canonical_name(ident: &Ident) -> String {
    let name = ident.to_string();
    name.strip_prefix("r#").unwrap_or(&name).to_owned()
}

#[cfg(test)]
mod tests {
    use syn::{DeriveInput, parse_quote};

    use super::FreshIdentAllocator;

    #[test]
    fn seeds_all_declared_name_kinds_and_prior_allocations() {
        let input: DeriveInput = parse_quote! {
            enum Example<'__redactable_f, __RedactableMapper, const key: usize> {
                __redactable_debug { field_0: &'__redactable_f __RedactableMapper },
            }
        };
        let mut allocator = FreshIdentAllocator::new(&input);

        assert_eq!(
            allocator.fresh("__redactable_f").to_string(),
            "__redactable_f_1"
        );
        assert_eq!(
            allocator.fresh("__RedactableMapper").to_string(),
            "__RedactableMapper_1"
        );
        assert_eq!(allocator.fresh("key").to_string(), "key_1");
        assert_eq!(allocator.fresh("field_0").to_string(), "field_0_1");
        assert_eq!(allocator.fresh("field_0").to_string(), "field_0_2");
    }

    #[test]
    fn canonicalizes_raw_reservations_and_identifier_fragments() {
        let input: DeriveInput = parse_quote! {
            struct Example<r#type, const r#key: usize> {
                r#match: r#type,
            }
        };
        let mut allocator = FreshIdentAllocator::new(&input);
        let raw_field = match &input.data {
            syn::Data::Struct(data) => data.fields.iter().next().unwrap().ident.as_ref().unwrap(),
            _ => unreachable!(),
        };

        assert_eq!(allocator.fresh("key").to_string(), "key_1");
        assert_eq!(allocator.fresh("r#type").to_string(), "type_1");
        assert_eq!(
            allocator
                .fresh_with_ident("__redacted_", raw_field)
                .to_string(),
            "__redacted_match"
        );
    }

    #[test]
    fn reserves_identifiers_in_paths_expressions_and_opaque_macro_tokens() {
        let input: DeriveInput = parse_quote! {
            #[sensitive(policy_alias!(__redactable_check))]
            struct Example
            where
                __RedactableMapper: __RedactablePolicyGuard,
                [u8; size!(key + serializer)]: Sized,
            {
                mapper: [u8; __redactable_mapper],
                formatter: [u8; __redactable_f],
            }
        };
        let mut allocator = FreshIdentAllocator::new(&input);

        for preferred in [
            "__RedactableMapper",
            "__RedactablePolicyGuard",
            "key",
            "serializer",
            "__redactable_mapper",
            "__redactable_f",
            "__redactable_check",
        ] {
            assert_eq!(
                allocator.fresh(preferred).to_string(),
                format!("{preferred}_1")
            );
        }
    }
}
