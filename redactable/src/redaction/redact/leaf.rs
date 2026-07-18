//! Leaf implementations: the base cases of policy traversal.
//!
//! `String`, `Cow<'_, str>`, and `&str` terminate recursive policy traversal.
//! Owned `String` and `Cow` traversal invokes the mapper; borrowed traversal
//! applies the policy directly. This module contains those implementations,
//! plus the formatting markers that let generated code treat these string-like
//! leaves — and, with the `json` feature, `serde_json::Value` — as directly
//! formattable leaves. Policy application for `serde_json::Value` itself lives
//! in the `json` module of `redaction`, which treats it as an opaque leaf that
//! fully redacts and deliberately ignores the mapper.

use std::borrow::Cow;

use crate::{
    __private::{
        PolicyApplicableRefForFormatting, PolicyApplicableRefForGeneratedFormatting,
        PolicyFormattingOutput,
    },
    policy::{RecursivePolicyKind, RedactionPolicy},
};

use super::core::{PolicyApplicable, PolicyApplicableRef, RedactableMapper};

// =============================================================================
// PolicyApplicable: Base case implementations (leaf types)
// =============================================================================

impl PolicyApplicable for String {
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        mapper.map_sensitive::<_, P>(self)
    }
}

impl PolicyApplicable for Cow<'_, str> {
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        mapper.map_sensitive::<_, P>(self)
    }
}

// =============================================================================
// PolicyApplicableRef: Base case implementations (leaf types)
// =============================================================================

impl PolicyApplicableRef for String {
    type Output = String;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let policy = P::policy();
        policy.apply_to(self.as_str())
    }
}

impl PolicyApplicableRef for Cow<'_, str> {
    /// Redacted `Cow` output is always owned so it never borrows from the raw input.
    type Output = Cow<'static, str>;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let policy = P::policy();
        Cow::Owned(policy.apply_to(self.as_ref()))
    }
}

impl PolicyApplicableRef for &str {
    type Output = String;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let policy = P::policy();
        policy.apply_to(self)
    }
}

macro_rules! impl_policy_ref_formatting_leaf {
    ($($ty:ty),+ $(,)?) => {$ (
        impl PolicyApplicableRefForGeneratedFormatting for $ty {
            type FormattingOutput = <Self as PolicyApplicableRef>::Output;

            fn apply_policy_ref_for_generated_formatting<P, M>(
                &self,
                mapper: &M,
            ) -> PolicyFormattingOutput<Self::FormattingOutput>
            where
                P: RedactionPolicy,
                P::Kind: RecursivePolicyKind,
                M: RedactableMapper,
            {
                PolicyFormattingOutput::Value(self.apply_policy_ref::<P, M>(mapper))
            }
        }
    )+ };
}

impl_policy_ref_formatting_leaf!(String, Cow<'_, str>, &str);

impl PolicyApplicableRefForFormatting for String {}
impl PolicyApplicableRefForFormatting for Cow<'_, str> {}
impl PolicyApplicableRefForFormatting for &str {}

#[cfg(feature = "json")]
impl_policy_ref_formatting_leaf!(serde_json::Value);

#[cfg(feature = "json")]
impl PolicyApplicableRefForFormatting for serde_json::Value {}
