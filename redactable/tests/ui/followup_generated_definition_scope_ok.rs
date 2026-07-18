#![allow(dead_code, non_camel_case_types, non_upper_case_globals)]

use std::{fmt, marker::PhantomData};

use redactable::{
    NotSensitive, NotSensitiveDisplay, Redactable, RedactableWithFormatter, Sensitive,
    SensitiveDisplay,
};
use serde::Serialize;

const __redactable_mapper: usize = 1;
const __redactable_f: usize = 2;
const key: usize = 1;
const serializer: usize = 1;

type __RedactableMapper = redactable::Secret;

trait __RedactablePolicyGuard {}

impl __RedactablePolicyGuard for __RedactableMapper {}

#[derive(Clone, Serialize, Sensitive)]
struct DefinitionScopeSensitive
where
    __RedactableMapper: __RedactablePolicyGuard,
    [u8; key + serializer]: Sized,
{
    #[sensitive(__RedactableMapper)]
    value: String,
    #[not_sensitive]
    const_path: [u8; __redactable_mapper],
    #[not_sensitive]
    alias_path: PhantomData<__RedactableMapper>,
    #[not_sensitive]
    key: usize,
}

#[derive(Serialize, NotSensitive)]
struct DefinitionScopeNotSensitive
where
    [u8; key + serializer]: Sized,
{
    const_path: [u8; __redactable_mapper],
}

#[derive(Serialize, NotSensitiveDisplay)]
struct DefinitionScopeNotSensitiveDisplay
where
    __RedactableMapper: __RedactablePolicyGuard,
{
    const_path: [u8; key + serializer],
    alias_path: PhantomData<__RedactableMapper>,
}

impl fmt::Display for DefinitionScopeNotSensitiveDisplay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("safe")
    }
}

#[derive(Serialize, SensitiveDisplay)]
#[error("{values:?}")]
struct DefinitionScopeSensitiveDisplay
where
    __RedactableMapper: __RedactablePolicyGuard,
    [u8; key + serializer]: Sized,
{
    #[sensitive(redactable::Secret)]
    values: [String; __redactable_f],
    #[not_sensitive]
    alias_path: PhantomData<__RedactableMapper>,
    #[not_sensitive]
    serializer: usize,
}

fn main() {
    const CANARY: &str = "DEFINITION_SCOPE_IDENTIFIER_CANARY";

    #[derive(Serialize, NotSensitive)]
    struct LocalDerive {
        value: u8,
    }

    let _ = LocalDerive { value: 1 }.redact();
    let redacted = DefinitionScopeSensitive {
        value: CANARY.into(),
        const_path: [0],
        alias_path: PhantomData,
        key: 7,
    }
    .redact();
    assert_eq!(redacted.value, "[REDACTED]");

    let _ = DefinitionScopeNotSensitive {
        const_path: [0],
    }
    .redact();
    assert_eq!(
        DefinitionScopeNotSensitiveDisplay {
            const_path: [0; key + serializer],
            alias_path: PhantomData,
        }
        .redacted_display()
        .to_string(),
        "safe"
    );
    let output = DefinitionScopeSensitiveDisplay {
        values: [CANARY.into(), CANARY.into()],
        alias_path: PhantomData,
        serializer: 9,
    }
    .redacted_display()
    .to_string();
    assert!(!output.contains(CANARY));

    #[cfg(feature = "slog")]
    {
        fn assert_slog_value<T: slog::Value>() {}
        assert_slog_value::<DefinitionScopeSensitive>();
        assert_slog_value::<DefinitionScopeNotSensitive>();
        assert_slog_value::<DefinitionScopeNotSensitiveDisplay>();
        assert_slog_value::<DefinitionScopeSensitiveDisplay>();
    }
}
