use std::{fmt, marker::PhantomData};

use redactable::{
    PolicyFormat, PolicyFormattingOutput, RedactableMapper,
    RedactableWithFormatter, RedactionPolicy, Secret, SensitiveDisplay, policy::RecursivePolicyKind,
};

#[derive(serde::Serialize)]
struct Opaque<T>(PhantomData<fn() -> T>);

struct BothOutput;

impl RedactableWithFormatter for BothOutput {
    fn fmt_redacted(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DISPLAY-ONLY")
    }
}

impl fmt::Debug for BothOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DEBUG-ONLY")
    }
}

impl<T> PolicyFormat for Opaque<T> {
    type Output = BothOutput;

    fn apply_policy_for_formatting<P, M>(
        &self,
        _mapper: &M,
    ) -> PolicyFormattingOutput<Self::Output>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        PolicyFormattingOutput::Value(BothOutput)
    }
}

enum InputWithoutFormattingTraits {}

#[derive(serde::Serialize, SensitiveDisplay)]
#[error("policy {value} {value:?}")]
struct PolicyBoth<T> {
    #[sensitive(Secret)]
    value: Opaque<T>,
}

fn main() {
    let value = PolicyBoth::<InputWithoutFormattingTraits> {
        value: Opaque(PhantomData),
    };
    assert_eq!(
        value.redacted_display().to_string(),
        "policy DISPLAY-ONLY DEBUG-ONLY"
    );
}
