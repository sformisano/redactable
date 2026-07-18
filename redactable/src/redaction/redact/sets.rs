//! Set implementations: `HashSet` and `BTreeSet`.
//!
//! Owned, borrowed, and generated-formatting implementations apply the
//! policy to every element. Because multiple distinct elements can redact to
//! the same value (for example all to `"[REDACTED]"`), a set may shrink when
//! redacted — if cardinality matters, redact a `Vec` instead. Rebuilding a
//! `HashSet` clones its `BuildHasher`, whose `Clone` behavior (including
//! panics) is inherited.

use std::{
    collections::{BTreeSet, HashSet},
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

// Sets: apply policy to elements.
//
// **Warning**: Sets may shrink after redaction. If multiple distinct values redact
// to the same string (e.g., all to `"[REDACTED]"`), the resulting set will have
// fewer elements. If cardinality matters, use `Vec` instead.
impl<T, S> PolicyApplicable for HashSet<T, S>
where
    T: PolicyApplicable + Hash + Eq,
    S: BuildHasher + Clone,
{
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let hasher = self.hasher().clone();
        let mut result = HashSet::with_capacity_and_hasher(self.len(), hasher);
        result.extend(self.into_iter().map(|v| v.apply_policy::<P, M>(mapper)));
        result
    }
}

impl<T> PolicyApplicable for BTreeSet<T>
where
    T: PolicyApplicable + Ord,
{
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.into_iter()
            .map(|v| v.apply_policy::<P, M>(mapper))
            .collect()
    }
}

impl<T, S> PolicyApplicableRef for HashSet<T, S>
where
    T: PolicyApplicableRef,
    T::Output: Hash + Eq,
    S: BuildHasher + Clone,
{
    type Output = HashSet<T::Output, S>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let hasher = self.hasher().clone();
        let mut result = HashSet::with_capacity_and_hasher(self.len(), hasher);
        result.extend(self.iter().map(|v| v.apply_policy_ref::<P, M>(mapper)));
        result
    }
}

impl<T, S> PolicyApplicableRefForGeneratedFormatting for HashSet<T, S>
where
    T: PolicyApplicableRefForGeneratedFormatting,
    T::FormattingOutput: Hash + Eq,
    S: BuildHasher,
{
    type FormattingOutput = HashSet<T::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let mut result = HashSet::with_capacity(self.len());
        for value in self {
            match apply_child_policy_ref_for_formatting::<P, _, M>(value, mapper) {
                PolicyFormattingOutput::Value(value) => {
                    result.insert(value);
                }
                PolicyFormattingOutput::Borrowed => return PolicyFormattingOutput::Borrowed,
            }
        }
        PolicyFormattingOutput::Value(result)
    }
}

impl<T> PolicyApplicableRef for BTreeSet<T>
where
    T: PolicyApplicableRef,
    T::Output: Ord,
{
    type Output = BTreeSet<T::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.iter()
            .map(|v| v.apply_policy_ref::<P, M>(mapper))
            .collect()
    }
}

impl<T> PolicyApplicableRefForGeneratedFormatting for BTreeSet<T>
where
    T: PolicyApplicableRefForGeneratedFormatting,
    T::FormattingOutput: Ord,
{
    type FormattingOutput = BTreeSet<T::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        collect_policy_formatting(
            self.iter()
                .map(|value| apply_child_policy_ref_for_formatting::<P, _, M>(value, mapper)),
        )
    }
}
