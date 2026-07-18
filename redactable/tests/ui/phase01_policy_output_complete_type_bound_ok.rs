use std::{fmt, marker::PhantomData};

use redactable::{
    __private::{PolicyApplicableRefForGeneratedFormatting, PolicyFormattingOutput},
    PolicyApplicableRef, RedactableMapper, RedactableWithFormatter, RedactionPolicy, Secret,
    SensitiveDisplay, policy::RecursivePolicyKind,
};

#[derive(serde::Serialize)]
struct Opaque<T>(PhantomData<fn() -> T>);

struct OutputOnly;

impl RedactableWithFormatter for OutputOnly {
    fn fmt_redacted(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[POLICY-OUTPUT]")
    }
}

impl<T> PolicyApplicableRef for Opaque<T> {
    type Output = OutputOnly;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        OutputOnly
    }
}

impl<T> PolicyApplicableRefForGeneratedFormatting for Opaque<T> {
    type FormattingOutput = OutputOnly;

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

impl<T> redactable::__private::PolicyApplicableRefForFormatting for Opaque<T> {}

enum InputWithoutFormattingTraits {}

#[derive(serde::Serialize, SensitiveDisplay)]
#[error("policy {value}")]
struct PolicyAssociatedOutput<T> {
    #[sensitive(Secret)]
    value: Opaque<T>,
}

fn main() {
    let value = PolicyAssociatedOutput::<InputWithoutFormattingTraits> {
        value: Opaque(PhantomData),
    };
    assert_eq!(value.redacted_display().to_string(), "policy [POLICY-OUTPUT]");
}
