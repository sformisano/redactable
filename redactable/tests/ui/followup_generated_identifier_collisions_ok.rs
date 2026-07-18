#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

use std::{fmt, marker::PhantomData};

use redactable::{
    NotSensitive, NotSensitiveDisplay, Redactable, RedactableWithFormatter, Sensitive,
    SensitiveDisplay, SensitiveDual,
};
use serde::Serialize;

const CANARY: &str = "PHASE03_IDENTIFIER_CANARY";

#[derive(Clone, Sensitive)]
struct SensitiveType<__RedactableMapper> {
    #[sensitive(redactable::Secret)]
    value: String,
    #[not_sensitive]
    marker: PhantomData<__RedactableMapper>,
}

#[derive(NotSensitive)]
struct NotSensitiveType<__RedactableMapper>(PhantomData<__RedactableMapper>);

#[derive(NotSensitiveDisplay)]
struct NotSensitiveDisplayShape<
    '__redactable_f,
    __RedactableMapper,
    const __redactable_f: usize,
>(&'__redactable_f __RedactableMapper);

impl<T: fmt::Display, const N: usize> fmt::Display for NotSensitiveDisplayShape<'_, T, N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}-{N}", self.0)
    }
}

#[derive(Clone, Serialize, Sensitive)]
struct SlogConst<const key: usize> {
    #[sensitive(redactable::Secret)]
    value: String,
}

#[derive(Clone, Serialize, Sensitive)]
struct RawSlogConst<const r#key: usize> {
    #[sensitive(redactable::Secret)]
    value: String,
}

#[derive(Clone, Serialize, Sensitive)]
struct SlogGeneratedFamilies<
    const serializer: usize,
    const __redactable_record: usize,
    const __redactable_value: usize,
> {
    #[sensitive(redactable::Secret)]
    value: String,
}

#[derive(Clone, Serialize, Sensitive)]
struct PolicyGuardGeneratedFamilies<
    const __RedactablePolicyGuard: usize,
    const __redactable_check: usize,
> {
    #[sensitive(redactable::Secret)]
    value: String,
}

#[derive(NotSensitive)]
struct RawTypeMapper<r#__RedactableMapper>(PhantomData<r#__RedactableMapper>);

#[derive(Serialize, SensitiveDisplay)]
#[error("{value}")]
struct SensitiveDisplayShape<'__redactable_f, const key: usize> {
    #[sensitive(redactable::Secret)]
    value: &'__redactable_f str,
}

#[derive(Serialize, SensitiveDisplay)]
#[error("{type}")]
struct RawNamedDisplay {
    #[sensitive(redactable::Secret)]
    r#type: String,
}

#[derive(Serialize, SensitiveDisplay)]
#[error("{value}")]
struct NamedDisplayTemporaryCollision {
    #[sensitive(redactable::Secret)]
    value: String,
    #[not_sensitive]
    __redacted_value: String,
}

#[derive(Clone, Serialize, SensitiveDual)]
#[error("{value}")]
struct DualNamed {
    #[sensitive(redactable::Secret)]
    value: String,
}

impl DualNamed {
    const __REDACTABLE_SENSITIVE_DERIVE_WITNESS: () = ();
    const __REDACTABLE_SENSITIVE_DISPLAY_DERIVE_WITNESS: () = ();
}

#[derive(Clone, Serialize, SensitiveDual)]
#[error("{__RedactableDualType}")]
struct DualGeneratedFamilies {
    #[sensitive(redactable::Secret)]
    __RedactableDualType: String,
    __redactable_require_sensitive_display: String,
    __redactable_require_sensitive: String,
}

#[derive(Clone, Serialize, Sensitive)]
struct TupleShape(#[sensitive(redactable::Secret)] String);

#[derive(Clone, Serialize, Sensitive)]
struct TupleBindingFamilies<const field_0: usize, const field_1: usize>(
    #[sensitive(redactable::Secret)] String,
    String,
);

#[derive(Clone, Serialize, Sensitive)]
struct UnitShape;

#[derive(Clone, Serialize, Sensitive)]
enum EnumShape {
    Named {
        #[sensitive(redactable::Secret)]
        value: String,
    },
    Tuple(#[sensitive(redactable::Secret)] String),
    Unit,
}

fn main() {
    let redacted = SensitiveType::<u8> {
        value: CANARY.into(),
        marker: PhantomData,
    }
    .redact();
    assert_eq!(redacted.value, "[REDACTED]");
    assert!(!format!("{redacted:?}").contains(CANARY));

    let _ = NotSensitiveType::<u8>(PhantomData).redact();
    assert_eq!(
        NotSensitiveDisplayShape::<_, 7>(&"safe")
            .redacted_display()
            .to_string(),
        "safe-7"
    );
    assert_eq!(
        SensitiveDisplayShape::<3> { value: CANARY }
            .redacted_display()
            .to_string(),
        "[REDACTED]"
    );
    assert_eq!(
        RawNamedDisplay {
            r#type: CANARY.into()
        }
        .redacted_display()
        .to_string(),
        "[REDACTED]"
    );
    assert_eq!(
        NamedDisplayTemporaryCollision {
            value: CANARY.into(),
            __redacted_value: "safe".into(),
        }
        .redacted_display()
        .to_string(),
        "[REDACTED]"
    );
    let _ = RawTypeMapper::<u8>(PhantomData).redact();
    assert_eq!(
        DualNamed {
            value: CANARY.into()
        }
        .redacted_display()
        .to_string(),
        "[REDACTED]"
    );
    assert_eq!(
        DualGeneratedFamilies {
            __RedactableDualType: CANARY.into(),
            __redactable_require_sensitive_display: "safe-display".into(),
            __redactable_require_sensitive: "safe-sensitive".into(),
        }
        .redacted_display()
        .to_string(),
        "[REDACTED]"
    );
    assert_eq!(TupleShape(CANARY.into()).redact().0, "[REDACTED]");
    let tuple = TupleBindingFamilies::<0, 1>(CANARY.into(), "safe".into()).redact();
    assert_eq!(tuple.0, "[REDACTED]");
    assert_eq!(tuple.1, "safe");
    let _ = UnitShape.redact();
    let _ = EnumShape::Named {
        value: CANARY.into(),
    }
    .redact();
    let _ = EnumShape::Tuple(CANARY.into()).redact();
    let _ = EnumShape::Unit.redact();

    #[cfg(feature = "slog")]
    {
        fn assert_value<T: slog::Value>() {}
        assert_value::<SlogConst<9>>();
        assert_value::<RawSlogConst<9>>();
        assert_value::<SlogGeneratedFamilies<1, 2, 3>>();
        assert_value::<PolicyGuardGeneratedFamilies<4, 5>>();
    }
}
