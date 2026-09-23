//! Downstream `PolicyFormat` implementors in generated templates.

use std::{
    cell::RefCell,
    fmt::{Debug, Formatter, Result as FmtResult},
    panic::AssertUnwindSafe,
};

use redactable::{
    PolicyFormat, PolicyFormattingOutput, RedactableMapper, RedactableWithFormatter,
    RedactionPolicy, SensitiveDisplay, TextPolicyKind, TextRedactionPolicy,
    policy::RecursivePolicyKind,
};

#[derive(Debug)]
struct DownstreamLeaf(String);

impl PolicyFormat for DownstreamLeaf {
    type Output = String;

    fn apply_policy_for_formatting<P, M>(&self, _mapper: &M) -> PolicyFormattingOutput<String>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        PolicyFormattingOutput::Value(P::policy().apply_to(&self.0))
    }
}

struct DownstreamPolicy;

impl RedactionPolicy for DownstreamPolicy {
    type Kind = TextPolicyKind;

    fn policy() -> TextRedactionPolicy {
        TextRedactionPolicy::keep_last(2)
    }
}

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct DownstreamLeafField {
    #[sensitive(DownstreamPolicy)]
    value: DownstreamLeaf,
}

#[test]
fn downstream_leaf_formats_with_the_field_policy() {
    let rendered = DownstreamLeafField {
        value: DownstreamLeaf("fallback-canary".to_owned()),
    }
    .redacted_display()
    .to_string();

    assert_eq!(rendered, "*************ry");
    assert!(!rendered.contains("fallback-canary"));
}

struct MigratedLeaf(String);
struct RedactedLeaf(String);

impl RedactableWithFormatter for RedactedLeaf {
    fn fmt_redacted(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "display({})", self.0)
    }
}

impl Debug for RedactedLeaf {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_tuple("RedactedLeaf").field(&self.0).finish()
    }
}

impl PolicyFormat for MigratedLeaf {
    type Output = RedactedLeaf;

    fn apply_policy_for_formatting<P, M>(&self, _mapper: &M) -> PolicyFormattingOutput<RedactedLeaf>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        PolicyFormattingOutput::Value(RedactedLeaf(P::policy().apply_to(&self.0)))
    }
}

#[derive(SensitiveDisplay)]
#[error("{value} | {value:?} | {value:#?}")]
struct MigratedLeafField {
    #[sensitive(DownstreamPolicy)]
    value: MigratedLeaf,
}

#[test]
fn migrated_custom_formatter_preserves_distinct_redacted_modes() {
    let rendered = MigratedLeafField {
        value: MigratedLeaf("migration-canary".to_owned()),
    }
    .redacted_display()
    .to_string();

    assert_eq!(
        rendered,
        "display(**************ry) | RedactedLeaf(\"**************ry\") | RedactedLeaf(\n    \"**************ry\",\n)"
    );
    assert!(!rendered.contains("migration-canary"));
}

#[derive(Debug)]
struct DownstreamContainer<T>(T);

impl<T> PolicyFormat for DownstreamContainer<T>
where
    T: PolicyFormat,
{
    type Output = DownstreamContainer<T::Output>;

    fn apply_policy_for_formatting<P, M>(&self, mapper: &M) -> PolicyFormattingOutput<Self::Output>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.0
            .apply_policy_for_formatting::<P, M>(mapper)
            .map(DownstreamContainer)
    }
}

impl<T> RedactableWithFormatter for DownstreamContainer<T>
where
    T: RedactableWithFormatter,
{
    fn fmt_redacted(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        self.0.fmt_redacted(formatter)
    }
}

#[derive(SensitiveDisplay)]
#[error("{value} | {value:?} | {value:#?}")]
struct DownstreamContainerField {
    #[sensitive(DownstreamPolicy)]
    value: DownstreamContainer<RefCell<String>>,
}

#[test]
fn downstream_container_propagates_nested_borrow_conflicts() {
    let display = DownstreamContainerField {
        value: DownstreamContainer(RefCell::new("recursive-canary".to_owned())),
    };
    let mutable_borrow = display.value.0.borrow_mut();

    let rendered =
        std::panic::catch_unwind(AssertUnwindSafe(|| display.redacted_display().to_string()))
            .expect("downstream container formatting must not panic");
    assert_eq!(rendered, "<borrowed> | <borrowed> | <borrowed>");
    assert!(!rendered.contains("recursive-canary"));
    drop(mutable_borrow);
}
