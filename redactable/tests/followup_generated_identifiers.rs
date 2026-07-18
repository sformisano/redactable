#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use std::{fmt, marker::PhantomData};

use redactable::{
    NotSensitive, NotSensitiveDisplay, Redactable, RedactableWithFormatter, Sensitive,
    SensitiveDisplay, SensitiveDual,
};
use serde::Serialize;

const CANARY: &str = "PHASE03_RUNTIME_IDENTIFIER_CANARY";
const __redactable_mapper: usize = 1;
const __redactable_f: usize = 2;
const key: usize = 1;
const serializer: usize = 1;

type __RedactableMapper = redactable::Secret;

trait __RedactablePolicyGuard {}

impl __RedactablePolicyGuard for __RedactableMapper {}

#[derive(Clone, Serialize, Sensitive)]
struct PolicyAliasCollision {
    #[sensitive(__RedactableMapper)]
    value: String,
}

#[derive(Clone, Serialize, Sensitive)]
struct CallerFieldCollision {
    #[not_sensitive]
    key: usize,
    #[not_sensitive]
    serializer: usize,
    #[sensitive(redactable::Secret)]
    value: String,
}

#[derive(Clone, Sensitive)]
struct SensitiveCollision<__RedactableMapper> {
    #[sensitive(redactable::Secret)]
    value: String,
    #[not_sensitive]
    marker: PhantomData<__RedactableMapper>,
}

#[derive(NotSensitive)]
struct NotSensitiveCollision<__RedactableMapper>(PhantomData<__RedactableMapper>);

#[derive(NotSensitiveDisplay)]
struct DisplayCollision<const __redactable_f: usize>;

impl<const N: usize> fmt::Display for DisplayCollision<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "safe-{N}")
    }
}

#[cfg(feature = "slog")]
#[derive(Clone, Serialize, Sensitive)]
struct SlogCollision<const key: usize> {
    #[sensitive(redactable::Secret)]
    value: String,
}

#[cfg(feature = "slog")]
#[derive(Clone, Serialize, Sensitive)]
struct RawSlogCollision<const r#key: usize> {
    #[sensitive(redactable::Secret)]
    value: String,
}

#[derive(Serialize, SensitiveDisplay)]
#[error("{value}")]
struct SensitiveDisplayCollision<'__redactable_f> {
    #[sensitive(redactable::Secret)]
    value: &'__redactable_f str,
}

#[derive(Serialize, SensitiveDisplay)]
#[error("{type}")]
struct RawNamedDisplayCollision {
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
struct DualCollision {
    #[sensitive(redactable::Secret)]
    value: String,
}

#[derive(Clone, Serialize, Sensitive)]
struct TupleCollision(#[sensitive(redactable::Secret)] String);

#[derive(Clone, Serialize, Sensitive)]
struct UnitCollision;

#[derive(Clone, Serialize, Sensitive)]
enum EnumCollision {
    __RedactableMapper {
        #[sensitive(redactable::Secret)]
        formatter_value: String,
    },
    Tuple(#[sensitive(redactable::Secret)] String),
    Unit,
}

#[test]
fn generated_names_do_not_change_redaction_or_safe_display() {
    let alias_redacted = PolicyAliasCollision {
        value: CANARY.into(),
    }
    .redact();
    assert_eq!(alias_redacted.value, "[REDACTED]");

    let field_redacted = CallerFieldCollision {
        key: 3,
        serializer: 4,
        value: CANARY.into(),
    }
    .redact();
    assert_eq!(field_redacted.key, 3);
    assert_eq!(field_redacted.serializer, 4);
    assert_eq!(field_redacted.value, "[REDACTED]");

    let redacted = SensitiveCollision::<u8> {
        value: CANARY.into(),
        marker: PhantomData,
    }
    .redact();
    assert_eq!(redacted.value, "[REDACTED]");
    assert!(!format!("{redacted:?}").contains(CANARY));

    let _ = NotSensitiveCollision::<u8>(PhantomData).redact();
    assert_eq!(
        DisplayCollision::<5>.redacted_display().to_string(),
        "safe-5"
    );
    let display = SensitiveDisplayCollision { value: CANARY }
        .redacted_display()
        .to_string();
    assert_eq!(display, "[REDACTED]");
    assert!(!display.contains(CANARY));
    let raw_display = RawNamedDisplayCollision {
        r#type: CANARY.into(),
    }
    .redacted_display()
    .to_string();
    assert_eq!(raw_display, "[REDACTED]");
    assert!(!raw_display.contains(CANARY));
    let temporary_collision = NamedDisplayTemporaryCollision {
        value: CANARY.into(),
        __redacted_value: "safe".into(),
    }
    .redacted_display()
    .to_string();
    assert_eq!(temporary_collision, "[REDACTED]");
    assert!(!temporary_collision.contains(CANARY));

    let dual = DualCollision {
        value: CANARY.into(),
    };
    let dual_output = dual.redacted_display().to_string();
    assert_eq!(dual_output, "[REDACTED]");
    assert!(!dual_output.contains(CANARY));

    assert_eq!(TupleCollision(CANARY.into()).redact().0, "[REDACTED]");
    let _ = UnitCollision.redact();
    let named = EnumCollision::__RedactableMapper {
        formatter_value: CANARY.into(),
    }
    .redact();
    assert!(matches!(
        named,
        EnumCollision::__RedactableMapper {
            formatter_value: redacted_field,
        } if redacted_field == "[REDACTED]"
    ));
    let tuple = EnumCollision::Tuple(CANARY.into()).redact();
    assert!(matches!(tuple, EnumCollision::Tuple(value) if value == "[REDACTED]"));
    let _ = EnumCollision::Unit.redact();
}

#[cfg(feature = "slog")]
#[test]
fn const_generic_key_does_not_capture_generated_slog_key() {
    fn assert_slog_value<T: slog::Value>() {}
    assert_slog_value::<SlogCollision<11>>();
    assert_slog_value::<RawSlogCollision<11>>();

    let value = SlogCollision::<11> {
        value: CANARY.into(),
    };
    let output = format!("{:?}", value.redact());
    assert!(!output.contains(CANARY));
}
