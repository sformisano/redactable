//! Compatibility regressions for downstream `PolicyApplicableRef` implementations.

use std::{cell::RefCell, panic::AssertUnwindSafe};

use redactable::{
    __private::{
        PolicyApplicableRefForFormatting, PolicyApplicableRefForGeneratedFormatting,
        PolicyFormattingOutput, PolicyMapper,
    },
    PolicyApplicableRef, RedactableMapper, RedactableWithFormatter, RedactionPolicy,
    SensitiveDisplay, TextPolicyKind, TextRedactionPolicy,
    policy::RecursivePolicyKind,
};

#[derive(Debug)]
struct DownstreamLeaf(String);

impl PolicyApplicableRef for DownstreamLeaf {
    type Output = String;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        P::policy().apply_to(&self.0)
    }
}

impl PolicyApplicableRefForFormatting for DownstreamLeaf {}

struct DownstreamPolicy;

impl RedactionPolicy for DownstreamPolicy {
    type Kind = TextPolicyKind;

    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(2)
    }
}

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct DownstreamFallback {
    #[sensitive(DownstreamPolicy)]
    value: DownstreamLeaf,
}

#[test]
fn downstream_policy_applicable_ref_implementor_uses_legacy_fallback() {
    let rendered = DownstreamFallback {
        value: DownstreamLeaf("fallback-canary".to_owned()),
    }
    .redacted_display()
    .to_string();

    assert_eq!(rendered, "*************ry");
    assert!(!rendered.contains("fallback-canary"));
}

#[derive(Debug)]
struct DownstreamContainer<T>(T);

impl<T> PolicyApplicableRef for DownstreamContainer<T>
where
    T: PolicyApplicableRef,
{
    type Output = DownstreamContainer<T::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        DownstreamContainer(self.0.apply_policy_ref::<P, M>(mapper))
    }
}

impl<T> PolicyApplicableRefForGeneratedFormatting for DownstreamContainer<T>
where
    T: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = DownstreamContainer<T::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.0
            .apply_policy_ref_for_generated_formatting::<P, M>(mapper)
            .map(DownstreamContainer)
    }
}

impl<T> PolicyApplicableRefForFormatting for DownstreamContainer<T>
where
    T: PolicyApplicableRefForGeneratedFormatting,
    T::FormattingOutput: RedactableWithFormatter + std::fmt::Debug,
{
    fn fmt_policy_display<P>(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        Self: PolicyApplicableRef,
        <Self as PolicyApplicableRef>::Output: RedactableWithFormatter,
    {
        self.apply_policy_ref_for_generated_formatting::<P, _>(&PolicyMapper)
            .fmt_redacted(formatter)
    }

    fn fmt_policy_debug<P>(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        Self: PolicyApplicableRef,
        <Self as PolicyApplicableRef>::Output: std::fmt::Debug,
    {
        std::fmt::Debug::fmt(
            &self.apply_policy_ref_for_generated_formatting::<P, _>(&PolicyMapper),
            formatter,
        )
    }
}

impl<T> RedactableWithFormatter for DownstreamContainer<T>
where
    T: RedactableWithFormatter,
{
    fn fmt_redacted(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt_redacted(formatter)
    }
}

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct DownstreamRecursiveOverride {
    #[sensitive(DownstreamPolicy)]
    value: DownstreamContainer<RefCell<String>>,
}

#[test]
fn downstream_recursive_override_can_propagate_borrow_conflicts() {
    let display = DownstreamRecursiveOverride {
        value: DownstreamContainer(RefCell::new("recursive-canary".to_owned())),
    };
    let mutable_borrow = display.value.0.borrow_mut();

    let rendered =
        std::panic::catch_unwind(AssertUnwindSafe(|| display.redacted_display().to_string()))
            .expect("downstream formatting companion must not panic");
    assert_eq!(rendered, "<borrowed>");
    assert!(!rendered.contains("recursive-canary"));
    drop(mutable_borrow);
}
