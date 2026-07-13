use std::{fmt, marker::PhantomData};

use redactable::{
    PolicyApplicableRef, RedactableMapper, RedactableWithFormatter, RedactionPolicy, Secret,
    SensitiveDisplay,
};

#[derive(serde::Serialize)]
struct Opaque<T>(PhantomData<fn() -> T>);

struct DebugOnly;

impl fmt::Debug for DebugOnly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DEBUG-ONLY")
    }
}

impl<T> PolicyApplicableRef for Opaque<T> {
    type Output = DebugOnly;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        M: RedactableMapper,
    {
        DebugOnly
    }
}

enum InputWithoutFormattingTraits {}

#[derive(serde::Serialize, SensitiveDisplay)]
#[error("policy {value:?}")]
struct PolicyDebug<T> {
    #[sensitive(Secret)]
    value: Opaque<T>,
}

fn main() {
    let value = PolicyDebug::<InputWithoutFormattingTraits> {
        value: Opaque(PhantomData),
    };
    assert_eq!(value.redacted_display().to_string(), "policy DEBUG-ONLY");
}
