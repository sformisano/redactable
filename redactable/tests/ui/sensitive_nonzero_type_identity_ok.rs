use std::num::{NonZeroU8, NonZeroU16 as ImportedNonZero};

use redactable::{
    PolicyApplicable, PolicyApplicableRef, Redactable, RedactableMapper, RedactableWithFormatter,
    RedactionPolicy, Sensitive, SensitiveDisplay,
};

type NonZeroU32 = String;

#[derive(Clone, Debug)]
#[cfg_attr(feature = "slog", derive(serde::Serialize))]
struct NonZeroU64(String);

impl PolicyApplicable for NonZeroU64 {
    fn apply_policy<P, M>(self, _mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: redactable::policy::RecursivePolicyKind,
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
        P::Kind: redactable::policy::RecursivePolicyKind,
        M: RedactableMapper,
    {
        "custom-nonzero".into()
    }
}

impl redactable::__private::PolicyApplicableRefForFormatting for NonZeroU64 {}

#[derive(Clone, Sensitive)]
#[cfg_attr(feature = "slog", derive(serde::Serialize))]
struct Named {
    #[sensitive(redactable::Secret)]
    alias: NonZeroU32,
    real: NonZeroU8,
}

#[derive(Clone, Sensitive)]
#[cfg_attr(feature = "slog", derive(serde::Serialize))]
struct Tuple(#[sensitive(redactable::Secret)] NonZeroU64, ImportedNonZero);

#[derive(Clone, Sensitive)]
#[cfg_attr(feature = "slog", derive(serde::Serialize))]
enum Enum {
    Value(#[sensitive(redactable::Secret)] NonZeroU32, NonZeroU8),
}

#[derive(SensitiveDisplay)]
#[error("{alias} {real}")]
struct DisplayNamed {
    #[sensitive(redactable::Secret)]
    alias: NonZeroU32,
    real: ImportedNonZero,
}

#[derive(SensitiveDisplay)]
#[error("{0} {1}")]
struct DisplayTuple(#[sensitive(redactable::Secret)] NonZeroU64, NonZeroU8);

#[derive(SensitiveDisplay)]
enum DisplayEnum {
    #[error("{0} {1}")]
    Value(#[sensitive(redactable::Secret)] NonZeroU32, ImportedNonZero),
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
