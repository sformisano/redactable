use std::num::{NonZeroU8, NonZeroU16 as ImportedNonZero};

use redactable::__private::PolicyApplicableRefForFormatting;
use redactable::policy::RecursivePolicyKind;
use redactable::{
    PolicyApplicable, PolicyApplicableRef, Redactable, RedactableMapper, RedactableWithFormatter,
    RedactionPolicy, Sensitive, SensitiveDisplay,
};

type NonZeroU32 = String;

#[derive(Clone, Debug)]
#[derive(serde::Serialize)]
struct NonZeroU64(String);

impl PolicyApplicable for NonZeroU64 {
    fn apply_policy<P, M>(self, _mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self
    }
}

impl PolicyApplicableRef for NonZeroU64 {
    type Output = String;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        "custom-nonzero".into()
    }
}

impl PolicyApplicableRefForFormatting for NonZeroU64 {}

#[derive(Clone, Sensitive)]
#[derive(serde::Serialize)]
struct Named {
    #[sensitive(redactable::Secret)]
    alias: NonZeroU32,
    #[not_sensitive]
    real: NonZeroU8,
}

#[derive(Clone, Sensitive)]
#[derive(serde::Serialize)]
struct Tuple(
    #[sensitive(redactable::Secret)] NonZeroU64,
    #[not_sensitive] ImportedNonZero,
);

#[derive(Clone, Sensitive)]
#[derive(serde::Serialize)]
enum Enum {
    Value(
        #[sensitive(redactable::Secret)] NonZeroU32,
        #[not_sensitive] NonZeroU8,
    ),
}

#[derive(SensitiveDisplay)]
#[error("{alias} {real}")]
struct DisplayNamed {
    #[sensitive(redactable::Secret)]
    alias: NonZeroU32,
    #[not_sensitive]
    real: ImportedNonZero,
}

#[derive(SensitiveDisplay)]
#[error("{0} {1}")]
struct DisplayTuple(
    #[sensitive(redactable::Secret)] NonZeroU64,
    #[not_sensitive] NonZeroU8,
);

#[derive(SensitiveDisplay)]
enum DisplayEnum {
    #[error("{0} {1}")]
    Value(
        #[sensitive(redactable::Secret)] NonZeroU32,
        #[not_sensitive] ImportedNonZero,
    ),
}

fn main() {
    let named = Named {
        alias: "secret".into(),
        real: NonZeroU8::new(1).unwrap(),
    }
    .redact();
    assert_eq!(named.alias, "[REDACTED]");

    let _ = Tuple(
        NonZeroU64("custom".into()),
        ImportedNonZero::new(2).unwrap(),
    )
    .redact();
    let _ = Enum::Value("secret".into(), NonZeroU8::new(3).unwrap()).redact();

    let displayed = DisplayNamed {
        alias: "secret".into(),
        real: ImportedNonZero::new(4).unwrap(),
    }
    .redacted_display()
    .to_string();
    assert!(displayed.contains("[REDACTED]"));
    let _ = DisplayTuple(NonZeroU64("custom".into()), NonZeroU8::new(5).unwrap())
        .redacted_display()
        .to_string();
    let _ = DisplayEnum::Value("secret".into(), ImportedNonZero::new(6).unwrap())
        .redacted_display()
        .to_string();
}
