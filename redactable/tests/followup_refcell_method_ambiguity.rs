//! Source-compatibility regression for downstream traits with a pre-existing formatting hook.

use redactable::{
    __private::PolicyMapper, PolicyApplicableRef, RedactableMapper, RedactionPolicy, Secret,
};

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
    assert_eq!(apply_downstream_hook(&"secret".to_owned()), "[REDACTED]");
    assert_eq!(
        apply_downstream_associated_hook(&"secret".to_owned()),
        "[REDACTED]"
    );
}
