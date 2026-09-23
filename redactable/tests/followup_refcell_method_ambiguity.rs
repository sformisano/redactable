//! Source-compatibility regression for downstream traits with a pre-existing formatting hook.

use redactable::{
    __private::PolicyMapper, PolicyApplicableRef, PolicyFormat, PolicyFormattingOutput,
    RedactableMapper, RedactionPolicy, Secret,
};

// This downstream-owned hook deliberately keeps its pre-existing name. Importing
// the renamed public trait above must not make calls to this hook ambiguous.
trait DownstreamPolicyFormatting: PolicyApplicableRef {
    fn apply_policy_ref_for_formatting<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        M: RedactableMapper;

    fn __redactable_apply_policy_ref_for_formatting<P, M>(value: &Self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        M: RedactableMapper;
}

impl DownstreamPolicyFormatting for String {
    fn apply_policy_ref_for_formatting<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        M: RedactableMapper,
    {
        let _ = (self, mapper);
        "[REDACTED]".to_owned()
    }

    fn __redactable_apply_policy_ref_for_formatting<P, M>(value: &Self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        M: RedactableMapper,
    {
        let _ = (value, mapper);
        "[REDACTED]".to_owned()
    }
}

fn apply_downstream_hook<T>(value: &T) -> T::Output
where
    T: DownstreamPolicyFormatting,
{
    value.apply_policy_ref_for_formatting::<Secret, _>(&PolicyMapper)
}

fn apply_downstream_associated_hook<T>(value: &T) -> T::Output
where
    T: DownstreamPolicyFormatting,
{
    T::__redactable_apply_policy_ref_for_formatting::<Secret, _>(value, &PolicyMapper)
}

#[test]
fn downstream_formatting_hook_remains_unambiguous() {
    let value = "secret".to_owned();
    assert_eq!(apply_downstream_hook(&value), "[REDACTED]");
    assert_eq!(apply_downstream_associated_hook(&value), "[REDACTED]");
    assert!(matches!(
        <String as PolicyFormat>::apply_policy_for_formatting::<Secret, _>(&value, &PolicyMapper),
        PolicyFormattingOutput::Value(output) if output == "[REDACTED]"
    ));
}
