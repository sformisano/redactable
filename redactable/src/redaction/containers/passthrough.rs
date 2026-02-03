//! Passthrough `RedactableContainer` implementations for scalar-like types.

use std::{borrow::Cow, marker::PhantomData};

use super::impl_redactable_container_passthrough;
use crate::redaction::{redact::RedactableMapper, traits::RedactableContainer};

// =============================================================================
// Passthrough implementations (scalars and primitives)
// =============================================================================

impl_redactable_container_passthrough!(String);
impl_redactable_container_passthrough!(bool);
impl_redactable_container_passthrough!(char);
impl_redactable_container_passthrough!(i8);
impl_redactable_container_passthrough!(i16);
impl_redactable_container_passthrough!(i32);
impl_redactable_container_passthrough!(i64);
impl_redactable_container_passthrough!(i128);
impl_redactable_container_passthrough!(isize);
impl_redactable_container_passthrough!(u8);
impl_redactable_container_passthrough!(u16);
impl_redactable_container_passthrough!(u32);
impl_redactable_container_passthrough!(u64);
impl_redactable_container_passthrough!(u128);
impl_redactable_container_passthrough!(usize);
impl_redactable_container_passthrough!(f32);
impl_redactable_container_passthrough!(f64);
impl_redactable_container_passthrough!(());

impl<T> RedactableContainer for PhantomData<T> {
    fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
        self
    }
}

impl RedactableContainer for Cow<'_, str> {
    fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
        self
    }
}

// =============================================================================
// Date/time passthrough implementations (feature-gated)
// =============================================================================

#[cfg(feature = "chrono")]
mod chrono_passthrough {
    use chrono::{DateTime, FixedOffset, Local, NaiveDate, NaiveDateTime, NaiveTime, Utc};

    use super::impl_redactable_container_passthrough;

    impl_redactable_container_passthrough!(DateTime<Utc>);
    impl_redactable_container_passthrough!(DateTime<Local>);
    impl_redactable_container_passthrough!(DateTime<FixedOffset>);
    impl_redactable_container_passthrough!(Utc);
    impl_redactable_container_passthrough!(NaiveDateTime);
    impl_redactable_container_passthrough!(NaiveDate);
    impl_redactable_container_passthrough!(NaiveTime);
}

#[cfg(feature = "time")]
mod time_passthrough {
    use time::{Date, OffsetDateTime, PrimitiveDateTime, Time};

    use super::impl_redactable_container_passthrough;

    impl_redactable_container_passthrough!(OffsetDateTime);
    impl_redactable_container_passthrough!(PrimitiveDateTime);
    impl_redactable_container_passthrough!(Date);
    impl_redactable_container_passthrough!(Time);
}

// =============================================================================
// UUID passthrough implementations (feature-gated)
// =============================================================================

#[cfg(feature = "uuid")]
mod uuid_passthrough {
    use uuid::Uuid;

    use super::impl_redactable_container_passthrough;

    impl_redactable_container_passthrough!(Uuid);
}
