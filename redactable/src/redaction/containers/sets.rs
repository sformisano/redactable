//! Redaction traversal for set containers.

use std::{
    collections::{BTreeSet, HashSet},
    hash::Hash,
};

use crate::redaction::{redact::RedactableMapper, traits::RedactableWithMapper};

// =============================================================================
// Set implementations
// =============================================================================

impl<T, S> RedactableWithMapper for HashSet<T, S>
where
    T: RedactableWithMapper + Hash + Eq,
    S: std::hash::BuildHasher + Clone,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        // NOTE: Redaction can collapse distinct values into equal ones, which may
        // reduce set cardinality (e.g., multiple values redacting to "[REDACTED]").
        let hasher = self.hasher().clone();
        let mut result = HashSet::with_capacity_and_hasher(self.len(), hasher);
        result.extend(self.into_iter().map(|value| value.redact_with(mapper)));
        result
    }
}

impl<T> RedactableWithMapper for BTreeSet<T>
where
    T: RedactableWithMapper + Ord,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        // NOTE: Redaction can collapse distinct values into equal ones, which may
        // reduce set cardinality (e.g., multiple values redacting to "[REDACTED]").
        self.into_iter()
            .map(|value| value.redact_with(mapper))
            .collect()
    }
}
