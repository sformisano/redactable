use std::fmt;

use safe::{NotSensitive, NotSensitiveDisplay, Sensitive, SensitiveDisplay};

#[derive(Clone, Sensitive)]
pub struct SensitiveEvent {
    #[sensitive(safe::Secret)]
    value: String,
}

#[derive(SensitiveDisplay)]
#[error("{value}")]
pub struct DisplayEvent {
    #[sensitive(safe::Secret)]
    value: String,
}

#[derive(NotSensitive)]
pub struct PublicEvent {
    pub value: String,
}

#[derive(NotSensitiveDisplay)]
pub struct PublicDisplayEvent;

impl fmt::Display for PublicDisplayEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("public")
    }
}

macro_rules! impl_serialize {
    ($($ty:ty => $name:literal),+ $(,)?) => {$ (
        impl safe::__private::serde::Serialize for $ty {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: safe::__private::serde::Serializer,
            {
                serializer.serialize_unit_struct($name)
            }
        }
    )+ };
}

impl_serialize!(
    SensitiveEvent => "SensitiveEvent",
    DisplayEvent => "DisplayEvent",
    PublicEvent => "PublicEvent",
    PublicDisplayEvent => "PublicDisplayEvent",
);

fn assert_slog_value<T: safe::__private::slog::Value>() {}
fn assert_serialize<T: safe::__private::serde::Serialize>() {}

pub fn assert_private_paths_and_emitters() {
    assert_slog_value::<SensitiveEvent>();
    assert_slog_value::<DisplayEvent>();
    assert_slog_value::<PublicEvent>();
    assert_slog_value::<PublicDisplayEvent>();
    assert_serialize::<SensitiveEvent>();
    assert_serialize::<DisplayEvent>();
    assert_serialize::<PublicEvent>();
    assert_serialize::<PublicDisplayEvent>();
}
