use std::{fmt, marker::PhantomData};

use redactable::{
    PolicyApplicableRef, RedactableMapper, RedactableWithFormatter, RedactionPolicy, Secret,
    SensitiveDisplay,
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

impl<T> PolicyApplicableRef for Opaque<T> {
    type Output = BothOutput;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        M: RedactableMapper,
    {
        BothOutput
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
