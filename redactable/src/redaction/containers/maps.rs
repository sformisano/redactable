//! Redaction traversal for map containers (values only).

use std::{
    collections::{BTreeMap, HashMap},
    hash::Hash,
};

use crate::redaction::{redact::RedactableMapper, traits::RedactableContainer};

// =============================================================================
// Map implementations (values only, keys unchanged)
// =============================================================================

impl<K, V, S> RedactableContainer for HashMap<K, V, S>
where
    K: Hash + Eq,
    V: RedactableContainer,
    S: std::hash::BuildHasher + Clone,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        // NOTE: Map keys are not redacted by design. Only values are redacted to
        // preserve hashing/ordering invariants and avoid key collisions.
        let hasher = self.hasher().clone();
        let mut result = HashMap::with_hasher(hasher);
        result.extend(self.into_iter().map(|(k, v)| (k, v.redact_with(mapper))));
        result
    }
}

impl<K, V> RedactableContainer for BTreeMap<K, V>
where
    K: Ord,
    V: RedactableContainer,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        // NOTE: Map keys are not redacted by design. Only values are redacted to
        // preserve ordering invariants and avoid key collisions.
        self.into_iter()
            .map(|(k, v)| (k, v.redact_with(mapper)))
            .collect()
    }
}
