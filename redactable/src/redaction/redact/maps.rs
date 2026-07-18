//! Map implementations: `HashMap` and `BTreeMap`.
//!
//! Owned [`PolicyApplicable`] implementations consume and rebuild the map,
//! applying the policy to the values (keys pass through redaction
//! unchanged). Borrowed [`PolicyApplicableRef`] implementations produce
//! [`PolicyMapOutput`], which renders keys from the source map by reference
//! so formatting never clones a borrow-sensitive key. The
//! generated-formatting implementations render the same maps for
//! `Display`/`Debug` output. Rebuilding a `HashMap` clones its
//! `BuildHasher`, whose `Clone` behavior (including panics) is inherited.

use std::{
    collections::{BTreeMap, HashMap},
    hash::{BuildHasher, Hash},
};

use crate::{
    __private::{PolicyApplicableRefForGeneratedFormatting, PolicyFormattingOutput},
    policy::{RecursivePolicyKind, RedactionPolicy},
};

use super::core::{
    PolicyApplicable, PolicyApplicableRef, RedactableMapper, apply_child_policy_ref_for_formatting,
    collect_policy_formatting,
};

/// Owned reference-policy output for maps.
///
/// Keys are rendered from the source map by reference, so formatting never
/// clones a borrow-sensitive key. Values remain structurally redacted.
#[doc(hidden)]
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyMapOutput<V> {
    entries: Vec<(PolicyMapKey, V)>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
struct PolicyMapKey {
    rendered: String,
}

impl std::fmt::Debug for PolicyMapKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.rendered)
    }
}

impl<V: std::fmt::Debug> std::fmt::Debug for PolicyMapOutput<V> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut map = formatter.debug_map();
        for (key, value) in &self.entries {
            map.entry(key, value);
        }
        map.finish()
    }
}

impl<V: crate::RedactableWithFormatter> crate::RedactableWithFormatter for PolicyMapOutput<V> {
    fn fmt_redacted(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut map = formatter.debug_map();
        for (key, value) in &self.entries {
            map.entry(key, &value.redacted_display());
        }
        map.finish()
    }
}

// Maps: apply policy to values only (keys unchanged)
impl<K, V, S> PolicyApplicable for HashMap<K, V, S>
where
    K: Hash + Eq,
    V: PolicyApplicable,
    S: BuildHasher + Clone,
{
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let hasher = self.hasher().clone();
        let mut result = HashMap::with_capacity_and_hasher(self.len(), hasher);
        result.extend(
            self.into_iter()
                .map(|(k, v)| (k, v.apply_policy::<P, M>(mapper))),
        );
        result
    }
}

impl<K, V> PolicyApplicable for BTreeMap<K, V>
where
    K: Ord,
    V: PolicyApplicable,
{
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.into_iter()
            .map(|(k, v)| (k, v.apply_policy::<P, M>(mapper)))
            .collect()
    }
}

impl<K, V, S> PolicyApplicableRef for HashMap<K, V, S>
where
    K: Clone + Hash + Eq,
    V: PolicyApplicableRef,
    S: BuildHasher + Clone,
{
    type Output = HashMap<K, V::Output, S>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let mut result = HashMap::with_capacity_and_hasher(self.len(), self.hasher().clone());
        result.extend(
            self.iter()
                .map(|(key, value)| (key.clone(), value.apply_policy_ref::<P, M>(mapper))),
        );
        result
    }
}

impl<K, V, S> PolicyApplicableRefForGeneratedFormatting for HashMap<K, V, S>
where
    K: Hash + Eq + std::fmt::Debug,
    V: PolicyApplicableRefForGeneratedFormatting,
    S: BuildHasher,
{
    type FormattingOutput = PolicyMapOutput<V::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let mut entries = Vec::with_capacity(self.len());
        for (key, value) in self {
            match apply_child_policy_ref_for_formatting::<P, _, M>(value, mapper) {
                PolicyFormattingOutput::Value(value) => {
                    let rendered = if mapper.debug_alternate() {
                        format!("{key:#?}")
                    } else {
                        format!("{key:?}")
                    };
                    entries.push((PolicyMapKey { rendered }, value));
                }
                PolicyFormattingOutput::Borrowed => return PolicyFormattingOutput::Borrowed,
            }
        }
        PolicyFormattingOutput::Value(PolicyMapOutput { entries })
    }
}

impl<K, V> PolicyApplicableRef for BTreeMap<K, V>
where
    K: Clone + Ord,
    V: PolicyApplicableRef,
{
    type Output = BTreeMap<K, V::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.iter()
            .map(|(key, value)| (key.clone(), value.apply_policy_ref::<P, M>(mapper)))
            .collect()
    }
}

impl<K, V> PolicyApplicableRefForGeneratedFormatting for BTreeMap<K, V>
where
    K: Ord + std::fmt::Debug,
    V: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = PolicyMapOutput<V::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        collect_policy_formatting(self.iter().map(|(key, value)| {
            apply_child_policy_ref_for_formatting::<P, _, M>(value, mapper).map(|value| {
                let rendered = if mapper.debug_alternate() {
                    format!("{key:#?}")
                } else {
                    format!("{key:?}")
                };
                (PolicyMapKey { rendered }, value)
            })
        }))
        .map(|entries| PolicyMapOutput { entries })
    }
}
