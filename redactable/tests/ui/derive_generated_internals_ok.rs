use std::{fmt, marker::PhantomData};

use redactable::{
    NotSensitive, NotSensitiveDisplay, Redactable, RedactableWithFormatter, Sensitive,
    SensitiveDisplay,
};

#[derive(Clone, Sensitive)]
struct SensitiveGenericM<M: Clone> {
    #[sensitive(redactable::Secret)]
    value: String,
    marker: PhantomData<M>,
}

#[derive(NotSensitive)]
struct NotSensitiveGenericM<M>(PhantomData<M>);

#[derive(NotSensitiveDisplay)]
struct NotSensitiveDisplayGenericM<M>(PhantomData<M>);

impl<M> fmt::Display for NotSensitiveDisplayGenericM<M> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("generic-m")
    }
}

#[derive(Clone, serde::Serialize, Sensitive)]
struct CollisionSensitive {
    #[sensitive(redactable::Secret)]
    __redactable_mapper: String,
    __redactable_f: String,
    __redactable_debug: String,
    __redacted_0: String,
    field_0: String,
}

#[derive(serde::Serialize, SensitiveDisplay)]
#[error("value {__redactable_mapper} {__redactable_f:?} {__redacted_0}")]
struct CollisionDisplay {
    #[sensitive(redactable::Secret)]
    __redactable_mapper: String,
    __redactable_f: String,
    __redactable_debug: String,
    __redacted_0: String,
}

#[derive(Clone, serde::Serialize, Sensitive)]
struct LegacyCollisionSensitive {
    f: String,
    mapper: String,
    debug: String,
}

#[derive(serde::Serialize, SensitiveDisplay)]
#[error("value {f}")]
struct LegacyCollisionDisplay {
    f: String,
    mapper: String,
    debug: String,
}

#[derive(Clone, serde::Serialize, Sensitive)]
struct CollisionTuple(#[sensitive(redactable::Secret)] String, String);

#[derive(serde::Serialize, SensitiveDisplay)]
#[error("tuple {0} {1:?}")]
struct CollisionDisplayTuple(#[sensitive(redactable::Secret)] String, String);

#[derive(Clone, serde::Serialize, Sensitive)]
enum CollisionEnum {
    Named {
        #[sensitive(redactable::Secret)]
        __redactable_mapper: String,
        __redactable_f: String,
        __redactable_debug: String,
        __redacted_0: String,
    },
    Tuple(#[sensitive(redactable::Secret)] String, String),
}

#[derive(serde::Serialize, SensitiveDisplay)]
enum CollisionDisplayEnum {
    #[error("named {__redactable_mapper} {__redactable_debug:?}")]
    Named {
        #[sensitive(redactable::Secret)]
        __redactable_mapper: String,
        __redactable_f: String,
        __redactable_debug: String,
        __redacted_0: String,
    },
    #[error("tuple {0} {1:?}")]
    Tuple(#[sensitive(redactable::Secret)] String, String),
}

fn main() {
    let generic = SensitiveGenericM::<u8> {
        value: "secret".into(),
        marker: PhantomData,
    }
    .redact();
    assert_eq!(generic.value, "[REDACTED]");
    let _ = NotSensitiveGenericM::<u8>(PhantomData).redact();
    assert_eq!(
        NotSensitiveDisplayGenericM::<u8>(PhantomData)
            .redacted_display()
            .to_string(),
        "generic-m"
    );

    let sensitive = CollisionSensitive {
        __redactable_mapper: "secret".to_string(),
        __redactable_f: "f".to_string(),
        __redactable_debug: "debug".to_string(),
        __redacted_0: "zero".to_string(),
        field_0: "field".to_string(),
    };
    let redacted = sensitive.redact();
    assert_eq!(redacted.__redactable_mapper, "[REDACTED]");
    assert_eq!(redacted.__redactable_f, "f");
    assert_eq!(redacted.__redactable_debug, "debug");
    assert_eq!(redacted.__redacted_0, "zero");
    assert_eq!(redacted.field_0, "field");

    let sensitive = LegacyCollisionSensitive {
        f: "field".to_string(),
        mapper: "mapper".to_string(),
        debug: "debug".to_string(),
    };
    let redacted = sensitive.redact();
    assert_eq!(redacted.f, "field");
    assert_eq!(redacted.mapper, "mapper");
    assert_eq!(redacted.debug, "debug");

    let display = CollisionDisplay {
        __redactable_mapper: "secret".to_string(),
        __redactable_f: "f".to_string(),
        __redactable_debug: "debug".to_string(),
        __redacted_0: "zero".to_string(),
    };
    assert_eq!(
        display.redacted_display().to_string(),
        "value [REDACTED] f zero"
    );
    let _ = format!("{display:?}");

    let display = LegacyCollisionDisplay {
        f: "field".to_string(),
        mapper: "mapper".to_string(),
        debug: "debug".to_string(),
    };
    assert_eq!(display.redacted_display().to_string(), "value field");
    let _ = format!("{display:?}");

    let tuple = CollisionTuple("secret".into(), "public".into()).redact();
    assert_eq!(tuple.0, "[REDACTED]");
    let display_tuple = CollisionDisplayTuple("secret".into(), "public".into());
    assert_eq!(
        display_tuple.redacted_display().to_string(),
        "tuple [REDACTED] public"
    );

    let named = CollisionEnum::Named {
        __redactable_mapper: "secret".into(),
        __redactable_f: "f".into(),
        __redactable_debug: "debug".into(),
        __redacted_0: "zero".into(),
    }
    .redact();
    assert!(matches!(
        named,
        CollisionEnum::Named { __redactable_mapper, .. } if __redactable_mapper == "[REDACTED]"
    ));
    let tuple = CollisionEnum::Tuple("secret".into(), "public".into()).redact();
    assert!(matches!(tuple, CollisionEnum::Tuple(value, _) if value == "[REDACTED]"));

    let named = CollisionDisplayEnum::Named {
        __redactable_mapper: "secret".into(),
        __redactable_f: "f".into(),
        __redactable_debug: "debug".into(),
        __redacted_0: "zero".into(),
    };
    assert_eq!(
        named.redacted_display().to_string(),
        "named [REDACTED] debug"
    );
    let tuple = CollisionDisplayEnum::Tuple("secret".into(), "public".into());
    assert_eq!(
        tuple.redacted_display().to_string(),
        "tuple [REDACTED] public"
    );
}
