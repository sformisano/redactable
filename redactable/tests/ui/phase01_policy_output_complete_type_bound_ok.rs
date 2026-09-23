use std::{fmt, marker::PhantomData};

use redactable::{
    PolicyFormat, PolicyFormattingOutput, RedactableMapper,
    RedactableWithFormatter, RedactionPolicy, Secret, SensitiveDisplay, policy::RecursivePolicyKind,
};

#[derive(serde::Serialize)]
struct Opaque<T>(PhantomData<fn() -> T>);

struct OutputOnly;

impl RedactableWithFormatter for OutputOnly {
    fn fmt_redacted(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[POLICY-OUTPUT]")
    }
}

impl<T> PolicyFormat for Opaque<T> {
    type Output = OutputOnly;

    fn apply_policy_for_formatting<P, M>(
        &self,
        _mapper: &M,
    ) -> PolicyFormattingOutput<Self::Output>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        PolicyFormattingOutput::Value(OutputOnly)
    }
}

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
